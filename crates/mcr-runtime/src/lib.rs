pub mod memory;
pub mod run_rootfs;

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

pub use memory::{
    DEFAULT_MMAP_BASE, GUEST_ADDRESS_SPACE_END, GUEST_PAGE_SIZE, GuestBrkOutcome, GuestMemory,
    GuestMemoryError, GuestMemoryProtection, GuestVma, GuestVmaKind, MIN_GUEST_ADDRESS,
};
pub use run_rootfs::{RunRootfsConfig, RunRootfsError, RunRootfsOutput, run_rootfs};

use mcr_elf::{GuestVma as ElfGuestVma, GuestVmaKind as ElfGuestVmaKind, SegmentPermissions};
use mcr_jit::{ExecutionError, GuestBlock, GuestRegisters, SameIsaExecutionCore, TrampolineCore};
use mcr_net::{
    GuestSocketTable, HostSocketTransport, ShutdownHow, SocketAddress, SocketId, SocketOperation,
    SocketOptionName, SocketSpec,
};
use mcr_sys::{
    Accept4SyscallArgs, Dup2SyscallArgs, Dup3SyscallArgs, DupSyscallArgs, EventSyscalls,
    FcntlSyscallArgs, FileSyscalls, FutexSyscallArgs, GuestContext, IoctlSyscallArgs,
    LINUX_AF_INET, LINUX_AF_INET6, LINUX_EPOLL_CLOEXEC, LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL,
    LINUX_EPOLL_CTL_MOD, LINUX_EPOLLERR, LINUX_EPOLLHUP, LINUX_EPOLLIN, LINUX_EPOLLOUT,
    LINUX_EPOLLPRI, LINUX_FUTEX_CMD_MASK, LINUX_FUTEX_PRIVATE_FLAG, LINUX_FUTEX_WAIT,
    LINUX_FUTEX_WAKE, LINUX_MSG_DONTWAIT, LINUX_MSG_NOSIGNAL, LINUX_POLLERR, LINUX_POLLHUP,
    LINUX_POLLIN, LINUX_POLLNVAL, LINUX_POLLOUT, LINUX_POLLPRI, LinuxEpollEvent, LinuxErrno,
    LinuxIovec, LinuxMsghdr, LinuxPollfd, LinuxStat, LinuxStatx, LinuxStatxTimestamp,
    MemorySyscalls, NetworkSyscalls, NoopSyscallTracer, Pipe2SyscallArgs, PipeSyscallArgs,
    SendRecvFromSyscallArgs, SendRecvMsgSyscallArgs, ShutdownSyscallArgs, SockaddrSyscallArgs,
    SocketSyscallArgs, SockoptSyscallArgs, SyscallDispatchResult, SyscallDispatcher,
    SyscallOutcome, SyscallRequest, SyscallReturn, SyscallTraceEvent, SyscallTracer, TimeSyscalls,
    TraceField,
};
use mcr_task::{
    CompletedWait, ExitState, GprState, GuestExecutable, GuestKernel, GuestProgram,
    INITIAL_GUEST_PID, INITIAL_GUEST_TID, TaskError, TaskState,
};
use mcr_vfs::{
    AT_REMOVEDIR, AT_SYMLINK_FOLLOW, DirectoryEntry, Fd, FdReadiness, FdTable, FileKind, FileRef,
    LinuxFileAttr, OpenFlags, ProcSelfData, SeekWhence, VfsError, VirtualFileSystem,
};
use mcr_win::SocketEvents;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub trait GuestMemoryAccess {
    fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), GuestMemoryAccessError>;
    fn write_bytes(&mut self, addr: u64, buffer: &[u8]) -> Result<(), GuestMemoryAccessError>;

    fn read_c_string(&self, addr: u64, max_len: usize) -> Result<String, GuestMemoryAccessError> {
        let mut bytes = Vec::new();
        for offset in 0..max_len {
            let mut byte = [0];
            self.read_bytes(
                addr.checked_add(offset as u64)
                    .ok_or(GuestMemoryAccessError::Fault)?,
                &mut byte,
            )?;
            if byte[0] == 0 {
                return String::from_utf8(bytes).map_err(|_| GuestMemoryAccessError::Fault);
            }
            bytes.push(byte[0]);
        }
        Err(GuestMemoryAccessError::Fault)
    }
}

#[derive(Debug)]
struct FutexWaitEntry {
    value: AtomicU32,
    waiters: AtomicU64,
}

impl FutexWaitEntry {
    fn new(value: u32) -> Self {
        Self {
            value: AtomicU32::new(value),
            waiters: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct FutexRegistry {
    entries: Arc<Mutex<BTreeMap<u64, Arc<FutexWaitEntry>>>>,
}

impl FutexRegistry {
    fn wait(
        &mut self,
        uaddr: u64,
        value: u32,
        timeout: Option<Duration>,
        memory_changed: impl Fn() -> bool,
    ) -> Result<u64, LinuxErrno> {
        let entry = {
            let mut entries = self.lock_entries();
            entries
                .entry(uaddr)
                .or_insert_with(|| Arc::new(FutexWaitEntry::new(value)))
                .clone()
        };
        entry.value.store(value, Ordering::SeqCst);
        entry.waiters.fetch_add(1, Ordering::SeqCst);

        if memory_changed() {
            self.finish_wait(uaddr, &entry);
            return Ok(0);
        }
        let Some(timeout) = timeout else {
            self.finish_wait(uaddr, &entry);
            return Err(LinuxErrno::EAGAIN);
        };
        let result = mcr_win::wait_on_address_u32(&entry.value, value, Some(timeout));
        match result {
            Ok(mcr_win::AddressWaitResult::TimedOut) => {
                self.finish_wait(uaddr, &entry);
                Err(LinuxErrno::ETIMEDOUT)
            }
            Ok(mcr_win::AddressWaitResult::ValueChanged | mcr_win::AddressWaitResult::Woken) => {
                Ok(0)
            }
            Err(error) => {
                self.finish_wait(uaddr, &entry);
                Err(host_sync_errno(error.kind()))
            }
        }
    }

    fn wake(&mut self, uaddr: u64, count: u32) -> u64 {
        if count == 0 {
            return 0;
        }

        let Some(entry) = self.lock_entries().get(&uaddr).cloned() else {
            return 0;
        };
        let woken = reserve_wake_count(&entry.waiters, u64::from(count));
        if woken == 0 {
            self.prune_entry(uaddr, &entry);
            return 0;
        }

        entry.value.fetch_add(1, Ordering::SeqCst);
        for _ in 0..woken {
            if mcr_win::wake_by_address_single_u32(&entry.value).is_err() {
                break;
            }
        }
        self.prune_entry(uaddr, &entry);
        woken
    }

    fn finish_wait(&self, uaddr: u64, entry: &Arc<FutexWaitEntry>) {
        decrement_waiter(&entry.waiters);
        self.prune_entry(uaddr, entry);
    }

    fn prune_entry(&self, uaddr: u64, entry: &Arc<FutexWaitEntry>) {
        if entry.waiters.load(Ordering::SeqCst) != 0 {
            return;
        }
        let mut entries = self.lock_entries();
        if entries
            .get(&uaddr)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(&uaddr);
        }
    }

    fn lock_entries(&self) -> MutexGuard<'_, BTreeMap<u64, Arc<FutexWaitEntry>>> {
        match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[cfg(test)]
    fn waiter_count(&self, uaddr: u64) -> u64 {
        self.lock_entries()
            .get(&uaddr)
            .map_or(0, |entry| entry.waiters.load(Ordering::SeqCst))
    }
}

fn reserve_wake_count(waiters: &AtomicU64, count: u64) -> u64 {
    let mut current = waiters.load(Ordering::SeqCst);
    loop {
        let woken = current.min(count);
        if woken == 0 {
            return 0;
        }
        match waiters.compare_exchange(current, current - woken, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return woken,
            Err(updated) => current = updated,
        }
    }
}

fn decrement_waiter(waiters: &AtomicU64) {
    let mut current = waiters.load(Ordering::SeqCst);
    while current != 0 {
        match waiters.compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(updated) => current = updated,
        }
    }
}

fn host_sync_errno(kind: mcr_win::HostErrorKind) -> LinuxErrno {
    match kind {
        mcr_win::HostErrorKind::InvalidInput => LinuxErrno::EINVAL,
        mcr_win::HostErrorKind::Interrupted => LinuxErrno::EINTR,
        mcr_win::HostErrorKind::TimedOut => LinuxErrno::ETIMEDOUT,
        mcr_win::HostErrorKind::OutOfMemory => LinuxErrno::ENOMEM,
        _ => LinuxErrno::EIO,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EpollWatch {
    fd: Fd,
    events: u32,
    data: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct EpollInstance {
    watches: BTreeMap<Fd, EpollWatch>,
}

#[derive(Debug, Default)]
struct EpollRegistry {
    next_id: u64,
    instances: BTreeMap<u64, EpollInstance>,
}

impl EpollRegistry {
    fn create(&mut self) -> Result<u64, LinuxErrno> {
        self.next_id = self.next_id.checked_add(1).ok_or(LinuxErrno::EMFILE)?;
        let id = self.next_id;
        self.instances.insert(id, EpollInstance::default());
        Ok(id)
    }

    fn close(&mut self, id: u64) {
        self.instances.remove(&id);
    }

    fn instance(&self, id: u64) -> Result<&EpollInstance, LinuxErrno> {
        self.instances.get(&id).ok_or(LinuxErrno::EBADF)
    }

    fn instance_mut(&mut self, id: u64) -> Result<&mut EpollInstance, LinuxErrno> {
        self.instances.get_mut(&id).ok_or(LinuxErrno::EBADF)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestMemoryAccessError {
    Fault,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeDiagnostics {
    executable_path: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    vmas: Vec<DiagnosticVma>,
    last_syscall: Option<DiagnosticSyscall>,
}

impl RuntimeDiagnostics {
    #[must_use]
    pub fn capture(kernel: &GuestKernel, events: &[SyscallTraceEvent]) -> Self {
        let process = kernel
            .process(mcr_task::INITIAL_GUEST_PID)
            .expect("runtime always starts with an initial process");
        let image = process.image();

        Self {
            executable_path: image.executable().path().to_vec(),
            argv: image.argv().to_vec(),
            envp: image.envp().to_vec(),
            vmas: image
                .memory()
                .vmas()
                .iter()
                .map(DiagnosticVma::from_guest_vma)
                .collect(),
            last_syscall: events.iter().rev().find_map(DiagnosticSyscall::from_event),
        }
    }

    #[must_use]
    pub fn executable_path(&self) -> &[u8] {
        &self.executable_path
    }

    #[must_use]
    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    #[must_use]
    pub fn envp(&self) -> &[Vec<u8>] {
        &self.envp
    }

    #[must_use]
    pub fn vmas(&self) -> &[DiagnosticVma] {
        &self.vmas
    }

    #[must_use]
    pub const fn last_syscall(&self) -> Option<&DiagnosticSyscall> {
        self.last_syscall.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticVma {
    start: u64,
    end: u64,
    permissions: DiagnosticPermissions,
    kind: DiagnosticVmaKind,
}

impl DiagnosticVma {
    #[must_use]
    pub fn from_guest_vma(vma: &ElfGuestVma) -> Self {
        Self {
            start: vma.start(),
            end: vma.end(),
            permissions: DiagnosticPermissions::from_segment(vma.permissions()),
            kind: DiagnosticVmaKind::from_guest_kind(vma.kind()),
        }
    }

    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }

    #[must_use]
    pub const fn permissions(&self) -> DiagnosticPermissions {
        self.permissions
    }

    #[must_use]
    pub const fn kind(&self) -> &DiagnosticVmaKind {
        &self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticPermissions {
    read: bool,
    write: bool,
    execute: bool,
}

impl DiagnosticPermissions {
    #[must_use]
    pub const fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    #[must_use]
    pub fn from_segment(permissions: SegmentPermissions) -> Self {
        Self::new(
            permissions.read(),
            permissions.write(),
            permissions.execute(),
        )
    }

    #[must_use]
    pub const fn read(self) -> bool {
        self.read
    }

    #[must_use]
    pub const fn write(self) -> bool {
        self.write
    }

    #[must_use]
    pub const fn execute(self) -> bool {
        self.execute
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticVmaKind {
    ElfLoad {
        program_header_index: u16,
        file_offset: u64,
        file_size: u64,
    },
    InterpreterLoad {
        path: Vec<u8>,
        program_header_index: u16,
        file_offset: u64,
        file_size: u64,
    },
    Stack,
}

impl DiagnosticVmaKind {
    #[must_use]
    pub fn from_guest_kind(kind: &ElfGuestVmaKind) -> Self {
        match kind {
            ElfGuestVmaKind::ElfLoad {
                program_header_index,
                file_offset,
                file_size,
            } => Self::ElfLoad {
                program_header_index: *program_header_index,
                file_offset: *file_offset,
                file_size: *file_size,
            },
            ElfGuestVmaKind::InterpreterLoad {
                path,
                program_header_index,
                file_offset,
                file_size,
            } => Self::InterpreterLoad {
                path: path.clone(),
                program_header_index: *program_header_index,
                file_offset: *file_offset,
                file_size: *file_size,
            },
            ElfGuestVmaKind::Stack => Self::Stack,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticSyscall {
    name: String,
    number: u64,
    args: [u64; 6],
    result: Option<SyscallReturn>,
    rip: u64,
}

impl DiagnosticSyscall {
    #[must_use]
    pub fn from_event(event: &SyscallTraceEvent) -> Option<Self> {
        match event {
            SyscallTraceEvent::Enter(_) => None,
            SyscallTraceEvent::Exit(event) => Some(Self {
                name: event.syscall.name().to_owned(),
                number: event.syscall.number().raw(),
                args: event.args.raw(),
                result: Some(event.result),
                rip: event.context.rip,
            }),
            SyscallTraceEvent::Unsupported(event) => Some(Self {
                name: event.syscall.name().to_owned(),
                number: event.number.raw(),
                args: event.args.raw(),
                result: Some(event.result),
                rip: event.context.rip,
            }),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn number(&self) -> u64 {
        self.number
    }

    #[must_use]
    pub const fn args(&self) -> [u64; 6] {
        self.args
    }

    #[must_use]
    pub const fn result(&self) -> Option<SyscallReturn> {
        self.result
    }

    #[must_use]
    pub const fn rip(&self) -> u64 {
        self.rip
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrashReport {
    reason: String,
    registers: GuestRegisters,
    diagnostics: RuntimeDiagnostics,
}

impl CrashReport {
    #[must_use]
    pub fn new(
        reason: impl Into<String>,
        registers: GuestRegisters,
        diagnostics: RuntimeDiagnostics,
    ) -> Self {
        Self {
            reason: reason.into(),
            registers,
            diagnostics,
        }
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub const fn registers(&self) -> GuestRegisters {
        self.registers
    }

    #[must_use]
    pub const fn diagnostics(&self) -> &RuntimeDiagnostics {
        &self.diagnostics
    }
}

impl RuntimeWithTracer<RuntimeDiagnosticsTracer> {
    pub fn with_diagnostics(program: GuestProgram) -> Result<Self, RuntimeError> {
        Runtime::with_tracer(program, RuntimeDiagnosticsTracer::new())
    }

    #[must_use]
    pub fn diagnostics(&self) -> RuntimeDiagnostics {
        RuntimeDiagnostics::capture(self.kernel(), self.tracer().events())
    }

    #[must_use]
    pub fn crash_report(
        &self,
        reason: impl Into<String>,
        registers: GuestRegisters,
    ) -> CrashReport {
        CrashReport::new(reason, registers, self.diagnostics())
    }
}

#[derive(Debug)]
pub struct RuntimeFileSystem<M> {
    vfs: VirtualFileSystem,
    memory: M,
    sockets: GuestSocketTable,
}

impl<M> RuntimeFileSystem<M> {
    pub fn new(vfs: VirtualFileSystem, memory: M) -> Self {
        Self {
            vfs,
            memory,
            sockets: GuestSocketTable::new(),
        }
    }

    pub fn with_socket_transport(
        vfs: VirtualFileSystem,
        memory: M,
        transport: impl HostSocketTransport + 'static,
    ) -> Self {
        Self {
            vfs,
            memory,
            sockets: GuestSocketTable::with_transport(transport),
        }
    }

    pub fn vfs(&self) -> &VirtualFileSystem {
        &self.vfs
    }

    pub fn vfs_mut(&mut self) -> &mut VirtualFileSystem {
        &mut self.vfs
    }

    pub fn memory(&self) -> &M {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    pub fn sockets(&self) -> &GuestSocketTable {
        &self.sockets
    }

    pub fn sockets_mut(&mut self) -> &mut GuestSocketTable {
        &mut self.sockets
    }

    pub fn into_parts(self) -> (VirtualFileSystem, M) {
        (self.vfs, self.memory)
    }
}

impl<M> FileSyscalls for RuntimeFileSystem<M>
where
    M: GuestMemoryAccess,
{
    fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let result = match request.syscall {
            mcr_sys::Syscall::Openat => self.sys_openat(request),
            mcr_sys::Syscall::Read => self.sys_read(request),
            mcr_sys::Syscall::Write => self.sys_write(request),
            mcr_sys::Syscall::Readv => self.sys_readv(request),
            mcr_sys::Syscall::Writev => self.sys_writev(request),
            mcr_sys::Syscall::Close => self.sys_close(request),
            mcr_sys::Syscall::Lseek => self.sys_lseek(request),
            mcr_sys::Syscall::Fstat => self.sys_fstat(request),
            mcr_sys::Syscall::Newfstatat => self.sys_newfstatat(request),
            mcr_sys::Syscall::Statx => self.sys_statx(request),
            mcr_sys::Syscall::Access => self.sys_access(request),
            mcr_sys::Syscall::Readlink => self.sys_readlink(request),
            mcr_sys::Syscall::Readlinkat => self.sys_readlinkat(request),
            mcr_sys::Syscall::Getdents64 => self.sys_getdents64(request),
            mcr_sys::Syscall::Pipe => self.sys_pipe(request),
            mcr_sys::Syscall::Pipe2 => self.sys_pipe2(request),
            mcr_sys::Syscall::Dup => self.sys_dup(request),
            mcr_sys::Syscall::Dup2 => self.sys_dup2(request),
            mcr_sys::Syscall::Dup3 => self.sys_dup3(request),
            mcr_sys::Syscall::Fcntl => self.sys_fcntl(request),
            mcr_sys::Syscall::Ioctl => self.sys_ioctl(request),
            mcr_sys::Syscall::Mkdirat => self.sys_mkdirat(request),
            mcr_sys::Syscall::Unlinkat => self.sys_unlinkat(request),
            mcr_sys::Syscall::Renameat2 => self.sys_renameat2(request),
            mcr_sys::Syscall::Symlinkat => self.sys_symlinkat(request),
            mcr_sys::Syscall::Linkat => self.sys_linkat(request),
            mcr_sys::Syscall::Ftruncate => self.sys_ftruncate(request),
            mcr_sys::Syscall::Getcwd => self.sys_getcwd(request),
            mcr_sys::Syscall::Chdir => self.sys_chdir(request),
            mcr_sys::Syscall::Umask => self.sys_umask(request),
            _ => return SyscallOutcome::unsupported(),
        };
        outcome(result)
    }
}

impl<M> FileSyscalls for &mut RuntimeFileSystem<M>
where
    M: GuestMemoryAccess,
{
    fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        RuntimeFileSystem::dispatch_file(self, request)
    }
}

impl<M> NetworkSyscalls for RuntimeFileSystem<M>
where
    M: GuestMemoryAccess,
{
    fn dispatch_network(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let result = match request.syscall {
            mcr_sys::Syscall::Socket => self.sys_socket(request),
            mcr_sys::Syscall::Bind => self.sys_bind(request),
            mcr_sys::Syscall::Connect => self.sys_connect(request),
            mcr_sys::Syscall::Listen => self.sys_listen(request),
            mcr_sys::Syscall::Shutdown => self.sys_shutdown(request),
            mcr_sys::Syscall::Sendto => self.sys_sendto(request),
            mcr_sys::Syscall::Recvfrom => self.sys_recvfrom(request),
            mcr_sys::Syscall::Sendmsg => self.sys_sendmsg(request),
            mcr_sys::Syscall::Recvmsg => self.sys_recvmsg(request),
            mcr_sys::Syscall::Getsockopt => self.sys_getsockopt(request),
            mcr_sys::Syscall::Setsockopt => self.sys_setsockopt(request),
            mcr_sys::Syscall::Accept | mcr_sys::Syscall::Accept4 => self.sys_accept(request),
            mcr_sys::Syscall::Getsockname | mcr_sys::Syscall::Getpeername => {
                self.sys_getsockaddr(request)
            }
            _ => return SyscallOutcome::unsupported(),
        };
        outcome(result)
    }
}

impl<M> NetworkSyscalls for &mut RuntimeFileSystem<M>
where
    M: GuestMemoryAccess,
{
    fn dispatch_network(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        RuntimeFileSystem::dispatch_network(self, request)
    }
}

impl<M> RuntimeFileSystem<M> {
    pub fn load_guest_program(
        &mut self,
        filename: impl Into<Vec<u8>>,
        argv: impl IntoIterator<Item = Vec<u8>>,
        envp: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<GuestProgram, LinuxErrno> {
        let filename = filename.into();
        let executable = self.load_guest_executable(&filename)?;
        let load_plan =
            mcr_elf::parse_load_plan(executable.bytes()).map_err(|_| LinuxErrno::ENOEXEC)?;
        let mut program = GuestProgram::new(executable).with_args(argv).with_env(envp);
        if let Some(interpreter_path) = load_plan.interpreter() {
            let interpreter = self.load_guest_executable(interpreter_path.as_bytes())?;
            mcr_elf::parse_load_plan(interpreter.bytes()).map_err(|_| LinuxErrno::ENOEXEC)?;
            program = program.with_interpreter(interpreter);
        }
        Ok(program)
    }

    fn load_guest_executable(&mut self, path: &[u8]) -> Result<GuestExecutable, LinuxErrno> {
        let path = guest_bytes_to_path(path)?;
        let fd = self
            .vfs
            .openat(
                mcr_vfs::AT_FDCWD,
                &path,
                OpenFlags::new(mcr_vfs::O_RDONLY),
                0,
            )
            .map_err(vfs_errno)?;
        let mut bytes = Vec::new();
        let read_result = read_vfs_file_to_end(&mut self.vfs, fd, &mut bytes);
        let close_result = self.vfs.close(fd).map_err(vfs_errno);
        read_result?;
        close_result?;
        Ok(GuestExecutable::new(path.into_bytes(), bytes))
    }
}

impl<M> RuntimeFileSystem<M>
where
    M: GuestMemoryAccess,
{
    fn read_guest_vector(&self, vector_addr: u64) -> Result<Vec<Vec<u8>>, LinuxErrno> {
        const MAX_VECTOR_ITEMS: usize = 4096;
        if vector_addr == 0 {
            return Ok(Vec::new());
        }

        let mut values = Vec::new();
        for index in 0..MAX_VECTOR_ITEMS {
            let item_addr = vector_addr
                .checked_add((index * 8) as u64)
                .ok_or(LinuxErrno::EFAULT)?;
            let ptr = read_guest_u64(&self.memory, item_addr)?;
            if ptr == 0 {
                return Ok(values);
            }
            values.push(read_guest_c_bytes(&self.memory, ptr)?);
        }
        Err(LinuxErrno::E2BIG)
    }

    fn sys_socket(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SocketSyscallArgs::new(
            arg_u32(request, 0),
            arg_u32(request, 1),
            arg_u32(request, 2),
        );
        let spec =
            SocketSpec::from_linux(args.domain, args.kind, args.protocol).map_err(net_errno)?;
        let socket_id = self
            .sockets
            .create_socket_from_spec(spec)
            .map_err(net_errno)?;
        let mut flags = mcr_vfs::O_RDWR;
        if spec.flags.cloexec {
            flags |= mcr_vfs::O_CLOEXEC;
        }
        if spec.flags.nonblocking {
            flags |= mcr_vfs::O_NONBLOCK;
        }
        let fd = self
            .vfs
            .insert_socket(socket_id.get(), OpenFlags::new(flags))
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    fn sys_bind(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args =
            SockaddrSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg_u32(request, 2));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let address = read_socket_address(&self.memory, args.sockaddr, args.addrlen)?;
        self.sockets.bind(socket_id, address).map_err(net_errno)?;
        Ok(0)
    }

    fn sys_connect(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args =
            SockaddrSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg_u32(request, 2));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let address = read_socket_address(&self.memory, args.sockaddr, args.addrlen)?;
        self.sockets
            .connect(socket_id, address)
            .map_err(net_errno)?;
        Ok(0)
    }

    fn sys_listen(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let backlog = arg_u32(request, 1);
        let socket_id = self.socket_id_for_fd(fd)?;
        self.sockets.listen(socket_id, backlog).map_err(net_errno)?;
        Ok(0)
    }

    fn sys_shutdown(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = ShutdownSyscallArgs::new(arg_i32(request, 0), arg_u32(request, 1));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let how = ShutdownHow::from_linux(args.how).map_err(net_errno)?;
        self.sockets.shutdown(socket_id, how).map_err(net_errno)?;
        Ok(0)
    }

    fn sys_sendto(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SendRecvFromSyscallArgs::new(
            arg_i32(request, 0),
            arg(request, 1),
            arg(request, 2),
            arg_u32(request, 3),
            arg(request, 4),
            arg(request, 5),
        );
        let socket_id = self.socket_id_for_fd(args.fd)?;
        validate_socket_message_flags(args.flags, SocketOperation::Send)?;
        let len = usize::try_from(args.len).map_err(|_| LinuxErrno::EINVAL)?;
        let mut buffer = vec![0; len];
        self.memory
            .read_bytes(args.buf, &mut buffer)
            .map_err(memory_errno)?;
        let count = if args.sockaddr != 0 || args.addrlen != 0 {
            let addrlen = u32::try_from(args.addrlen).map_err(|_| LinuxErrno::EINVAL)?;
            let address = read_socket_address(&self.memory, args.sockaddr, addrlen)?;
            self.sockets.send_to(socket_id, &buffer, address)
        } else {
            self.sockets.send_connected(socket_id, &buffer)
        }
        .map_err(net_errno)?;
        Ok(count as u64)
    }

    fn sys_recvfrom(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SendRecvFromSyscallArgs::new(
            arg_i32(request, 0),
            arg(request, 1),
            arg(request, 2),
            arg_u32(request, 3),
            arg(request, 4),
            arg(request, 5),
        );
        let socket_id = self.socket_id_for_fd(args.fd)?;
        validate_socket_message_flags(args.flags, SocketOperation::Recv)?;
        let len = usize::try_from(args.len).map_err(|_| LinuxErrno::EINVAL)?;
        let mut buffer = vec![0; len];
        let count = if args.sockaddr != 0 || args.addrlen != 0 {
            let (count, address) = self
                .sockets
                .recv_from(socket_id, &mut buffer)
                .map_err(net_errno)?;
            write_optional_socket_address(&mut self.memory, args.sockaddr, args.addrlen, address)?;
            count
        } else {
            self.sockets
                .recv_connected(socket_id, &mut buffer)
                .map_err(net_errno)?
        };
        self.memory
            .write_bytes(args.buf, &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_sendmsg(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args =
            SendRecvMsgSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg_u32(request, 2));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        validate_socket_message_flags(args.flags, SocketOperation::SendMsg)?;
        let message = read_msghdr(&self.memory, args.msg)?;
        if message.msg_control != 0 || message.msg_controllen != 0 {
            return Err(net_errno(GuestSocketTable::unsupported_socket_io(
                SocketOperation::SendMsg,
            )));
        }
        let address = if message.msg_name != 0 || message.msg_namelen != 0 {
            Some(read_socket_address(
                &self.memory,
                message.msg_name,
                message.msg_namelen,
            )?)
        } else {
            None
        };
        let iovecs = self.read_iovecs(
            message.msg_iov,
            usize::try_from(message.msg_iovlen).map_err(|_| LinuxErrno::EINVAL)?,
        )?;
        let mut total = 0u64;
        for iovec in iovecs {
            let len = usize::try_from(iovec.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
            let mut buffer = vec![0; len];
            self.memory
                .read_bytes(iovec.iov_base, &mut buffer)
                .map_err(memory_errno)?;
            let count = if let Some(address) = address {
                self.sockets
                    .send_to(socket_id, &buffer, address)
                    .map_err(net_errno)?
            } else {
                self.sockets
                    .send_connected(socket_id, &buffer)
                    .map_err(net_errno)?
            };
            total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
            if count < len {
                break;
            }
        }
        Ok(total)
    }

    fn sys_recvmsg(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args =
            SendRecvMsgSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg_u32(request, 2));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        validate_socket_message_flags(args.flags, SocketOperation::RecvMsg)?;
        let message = read_msghdr(&self.memory, args.msg)?;
        if message.msg_control != 0 || message.msg_controllen != 0 {
            return Err(net_errno(GuestSocketTable::unsupported_socket_io(
                SocketOperation::RecvMsg,
            )));
        }
        let iovecs = self.read_iovecs(
            message.msg_iov,
            usize::try_from(message.msg_iovlen).map_err(|_| LinuxErrno::EINVAL)?,
        )?;

        let total = if message.msg_name != 0 || message.msg_namelen != 0 {
            let capacity = iovecs.iter().try_fold(0usize, |total, iovec| {
                let len = usize::try_from(iovec.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
                total.checked_add(len).ok_or(LinuxErrno::EINVAL)
            })?;
            let mut buffer = vec![0; capacity];
            let (count, address) = self
                .sockets
                .recv_from(socket_id, &mut buffer)
                .map_err(net_errno)?;
            write_socket_address_to_msghdr_name(
                &mut self.memory,
                args.msg,
                message.msg_name,
                message.msg_namelen,
                address,
            )?;
            let mut consumed = 0usize;
            for iovec in iovecs {
                let len = usize::try_from(iovec.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
                let remaining = count.saturating_sub(consumed);
                let write_len = len.min(remaining);
                if write_len > 0 {
                    self.memory
                        .write_bytes(iovec.iov_base, &buffer[consumed..consumed + write_len])
                        .map_err(memory_errno)?;
                }
                consumed += write_len;
                if consumed >= count {
                    break;
                }
            }
            count as u64
        } else {
            let mut total = 0u64;
            for iovec in iovecs {
                let len = usize::try_from(iovec.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
                let mut buffer = vec![0; len];
                let count = self
                    .sockets
                    .recv_connected(socket_id, &mut buffer)
                    .map_err(net_errno)?;
                self.memory
                    .write_bytes(iovec.iov_base, &buffer[..count])
                    .map_err(memory_errno)?;
                total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
                if count < len {
                    break;
                }
            }
            total
        };
        self.memory
            .write_bytes(args.msg + 48, &0u32.to_le_bytes())
            .map_err(memory_errno)?;
        Ok(total)
    }

    fn sys_setsockopt(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SockoptSyscallArgs::new(
            arg_i32(request, 0),
            arg_u32(request, 1),
            arg_u32(request, 2),
            arg(request, 3),
            arg(request, 4),
        );
        if args.optlen != 4 {
            return Err(LinuxErrno::EINVAL);
        }
        let mut value = [0; 4];
        self.memory
            .read_bytes(args.optval, &mut value)
            .map_err(memory_errno)?;
        let option = SocketOptionName::from_linux(args.level, args.optname).map_err(net_errno)?;
        let socket_id = self.socket_id_for_fd(args.fd)?;
        self.sockets
            .set_option(socket_id, option, u32::from_le_bytes(value))
            .map_err(net_errno)?;
        Ok(0)
    }

    fn sys_getsockopt(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SockoptSyscallArgs::new(
            arg_i32(request, 0),
            arg_u32(request, 1),
            arg_u32(request, 2),
            arg(request, 3),
            arg(request, 4),
        );
        let len = read_guest_u32(&self.memory, args.optlen)?;
        if len < 4 {
            return Err(LinuxErrno::EINVAL);
        }
        let option = SocketOptionName::from_linux(args.level, args.optname).map_err(net_errno)?;
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let value = self
            .sockets
            .get_option(socket_id, option)
            .map_err(net_errno)?;
        self.memory
            .write_bytes(args.optval, &value.to_le_bytes())
            .map_err(memory_errno)?;
        self.memory
            .write_bytes(args.optlen, &4u32.to_le_bytes())
            .map_err(memory_errno)?;
        Ok(0)
    }

    fn sys_accept(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = match request.syscall {
            mcr_sys::Syscall::Accept => {
                Accept4SyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg(request, 2), 0)
            }
            mcr_sys::Syscall::Accept4 => Accept4SyscallArgs::new(
                arg_i32(request, 0),
                arg(request, 1),
                arg(request, 2),
                arg_u32(request, 3),
            ),
            _ => unreachable!(),
        };
        if args.flags & !(mcr_sys::LINUX_SOCK_CLOEXEC | mcr_sys::LINUX_SOCK_NONBLOCK) != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let (accepted, peer) = self.sockets.accept(socket_id).map_err(net_errno)?;
        write_optional_socket_address(&mut self.memory, args.sockaddr, args.addrlen, peer)?;
        let mut flags = mcr_vfs::O_RDWR;
        if args.flags & mcr_sys::LINUX_SOCK_CLOEXEC != 0 {
            flags |= mcr_vfs::O_CLOEXEC;
        }
        if args.flags & mcr_sys::LINUX_SOCK_NONBLOCK != 0 {
            flags |= mcr_vfs::O_NONBLOCK;
        }
        let fd = self
            .vfs
            .insert_socket(accepted.get(), OpenFlags::new(flags))
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    fn sys_getsockaddr(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SockaddrSyscallArgs::new(arg_i32(request, 0), arg(request, 1), 0);
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let socket = self.sockets.socket(socket_id).map_err(net_errno)?;
        let address = match request.syscall {
            mcr_sys::Syscall::Getsockname => socket.state().local_address(),
            mcr_sys::Syscall::Getpeername => socket.state().peer_address(),
            _ => unreachable!(),
        }
        .ok_or(LinuxErrno::ENOTCONN)?;
        write_socket_address(&mut self.memory, args.sockaddr, arg(request, 2), address)?;
        Ok(0)
    }

    fn socket_id_for_fd(&self, fd: Fd) -> Result<SocketId, LinuxErrno> {
        let raw = self.vfs.socket_id_for_fd(fd).map_err(vfs_errno)?;
        SocketId::new(raw).ok_or(LinuxErrno::EBADF)
    }
}

impl<M> RuntimeFileSystem<M>
where
    M: GuestMemoryAccess,
{
    fn sys_openat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let dirfd = arg_i32(request, 0);
        let path = self.read_path(arg(request, 1))?;
        let flags = arg_u32(request, 2);
        let mode = arg_u32(request, 3);
        let fd = self
            .vfs
            .openat(dirfd, &path, OpenFlags::new(flags), mode)
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    fn sys_read(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let addr = arg(request, 1);
        let len = usize_arg(request, 2)?;
        let mut buffer = vec![0; len];
        let count = self.vfs.read(fd, &mut buffer).map_err(vfs_errno)?;
        self.memory
            .write_bytes(addr, &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_write(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let addr = arg(request, 1);
        let len = usize_arg(request, 2)?;
        let mut buffer = vec![0; len];
        self.memory
            .read_bytes(addr, &mut buffer)
            .map_err(memory_errno)?;
        let count = self.vfs.write(fd, &buffer).map_err(vfs_errno)?;
        Ok(count as u64)
    }

    fn sys_readv(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let iov = self.read_iovecs(arg(request, 1), usize_arg(request, 2)?)?;
        let mut total = 0u64;
        for item in iov {
            let len = usize::try_from(item.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
            let mut buffer = vec![0; len];
            let count = self.vfs.read(fd, &mut buffer).map_err(vfs_errno)?;
            self.memory
                .write_bytes(item.iov_base, &buffer[..count])
                .map_err(memory_errno)?;
            total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
            if count < len {
                break;
            }
        }
        Ok(total)
    }

    fn sys_writev(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let iov = self.read_iovecs(arg(request, 1), usize_arg(request, 2)?)?;
        let mut total = 0u64;
        for item in iov {
            let len = usize::try_from(item.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
            let mut buffer = vec![0; len];
            self.memory
                .read_bytes(item.iov_base, &mut buffer)
                .map_err(memory_errno)?;
            let count = self.vfs.write(fd, &buffer).map_err(vfs_errno)?;
            total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
            if count < len {
                break;
            }
        }
        Ok(total)
    }

    fn sys_close(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let file = self.vfs.close_with_file(fd).map_err(vfs_errno)?;
        self.close_unshared_file_resources(&file)?;
        Ok(0)
    }

    fn close_unshared_file_resources(&mut self, file: &FileRef) -> Result<(), LinuxErrno> {
        if file.kind() == FileKind::Socket {
            let socket_id = match file.inode().backend() {
                mcr_vfs::InodeBackend::Socket(socket) => SocketId::new(socket.id()),
                _ => None,
            };
            if let Some(socket_id) = socket_id
                && self.vfs.socket_fd_count(socket_id.get()) == 0
            {
                self.sockets.close(socket_id).map_err(net_errno)?;
            }
        }
        Ok(())
    }

    fn sys_lseek(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let offset = arg(request, 1) as i64;
        let whence = SeekWhence::from_linux(arg_u32(request, 2)).map_err(vfs_errno)?;
        self.vfs
            .lseek(arg_i32(request, 0), offset, whence)
            .map_err(vfs_errno)
    }

    fn sys_fstat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let attr = self.vfs.fstat(arg_i32(request, 0)).map_err(vfs_errno)?;
        self.write_stat(arg(request, 1), attr)?;
        Ok(0)
    }

    fn sys_newfstatat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let attr = self
            .vfs
            .newfstatat(arg_i32(request, 0), &path, arg_u32(request, 3))
            .map_err(vfs_errno)?;
        self.write_stat(arg(request, 2), attr)?;
        Ok(0)
    }

    fn sys_statx(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let attr = self
            .vfs
            .statx(arg_i32(request, 0), &path, arg_u32(request, 2))
            .map_err(vfs_errno)?;
        self.write_statx(arg(request, 4), attr)?;
        Ok(0)
    }

    fn sys_access(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs
            .access(&path, arg_u32(request, 1))
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_readlink(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        let len = usize_arg(request, 2)?;
        let mut buffer = vec![0; len];
        let count = self.vfs.readlink(&path, &mut buffer).map_err(vfs_errno)?;
        self.memory
            .write_bytes(arg(request, 1), &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_readlinkat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let len = usize_arg(request, 3)?;
        let mut buffer = vec![0; len];
        let count = self
            .vfs
            .readlinkat(arg_i32(request, 0), &path, &mut buffer)
            .map_err(vfs_errno)?;
        self.memory
            .write_bytes(arg(request, 2), &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_getdents64(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let max_bytes = usize_arg(request, 2)?;
        let entries = self
            .vfs
            .getdents64(arg_i32(request, 0), max_bytes)
            .map_err(vfs_errno)?;
        let encoded = encode_dirents(&entries)?;
        if encoded.len() > max_bytes {
            return Err(LinuxErrno::EINVAL);
        }
        self.memory
            .write_bytes(arg(request, 1), &encoded)
            .map_err(memory_errno)?;
        Ok(encoded.len() as u64)
    }

    fn sys_pipe(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = PipeSyscallArgs::new(arg(request, 0));
        self.create_pipe(args.pipefd, OpenFlags::new(0))
    }

    fn sys_pipe2(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = Pipe2SyscallArgs::new(arg(request, 0), arg_u32(request, 1));
        self.create_pipe(args.pipefd, OpenFlags::new(args.flags))
    }

    fn create_pipe(&mut self, pipefd_addr: u64, flags: OpenFlags) -> Result<u64, LinuxErrno> {
        let [read_fd, write_fd] = self.vfs.pipe(flags).map_err(vfs_errno)?;
        self.memory
            .write_bytes(pipefd_addr, &read_fd.to_le_bytes())
            .map_err(memory_errno)?;
        self.memory
            .write_bytes(pipefd_addr + 4, &write_fd.to_le_bytes())
            .map_err(memory_errno)?;
        Ok(0)
    }

    fn sys_dup(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = DupSyscallArgs::new(arg_i32(request, 0));
        Ok(self.vfs.dup(args.oldfd).map_err(vfs_errno)? as u64)
    }

    fn sys_dup2(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = Dup2SyscallArgs::new(arg_i32(request, 0), arg_i32(request, 1));
        Ok(self.vfs.dup2(args.oldfd, args.newfd).map_err(vfs_errno)? as u64)
    }

    fn sys_dup3(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = Dup3SyscallArgs::new(
            arg_i32(request, 0),
            arg_i32(request, 1),
            arg_u32(request, 2),
        );
        Ok(self
            .vfs
            .dup3(args.oldfd, args.newfd, OpenFlags::new(args.flags))
            .map_err(vfs_errno)? as u64)
    }

    fn sys_fcntl(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = FcntlSyscallArgs::new(arg_i32(request, 0), arg_u32(request, 1), arg(request, 2));
        self.vfs
            .fcntl(args.fd, args.cmd, args.arg)
            .map_err(vfs_errno)
    }

    fn sys_ioctl(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = IoctlSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg(request, 2));
        match self.vfs.ioctl(args.fd, args.request).map_err(vfs_errno)? {
            mcr_vfs::IoctlReply::None => Ok(0),
            mcr_vfs::IoctlReply::U32(value) => {
                self.memory
                    .write_bytes(args.argp, &value.to_le_bytes())
                    .map_err(memory_errno)?;
                Ok(0)
            }
        }
    }

    fn sys_mkdirat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        self.vfs
            .mkdirat(arg_i32(request, 0), &path, arg_u32(request, 2))
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_unlinkat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let flags = arg_u32(request, 2);
        if flags & !AT_REMOVEDIR != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        self.vfs
            .unlinkat(arg_i32(request, 0), &path, flags)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_renameat2(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let oldpath = self.read_path(arg(request, 1))?;
        let newpath = self.read_path(arg(request, 3))?;
        self.vfs
            .renameat2(
                arg_i32(request, 0),
                &oldpath,
                arg_i32(request, 2),
                &newpath,
                arg_u32(request, 4),
            )
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_symlinkat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let target = self.read_path(arg(request, 0))?;
        let linkpath = self.read_path(arg(request, 2))?;
        self.vfs
            .symlinkat(&target, arg_i32(request, 1), &linkpath)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_linkat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let oldpath = self.read_path(arg(request, 1))?;
        let newpath = self.read_path(arg(request, 3))?;
        let flags = arg_u32(request, 4);
        if flags & !(AT_SYMLINK_FOLLOW | mcr_vfs::AT_EMPTY_PATH) != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        self.vfs
            .linkat(
                arg_i32(request, 0),
                &oldpath,
                arg_i32(request, 2),
                &newpath,
                flags,
            )
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_ftruncate(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let length = arg(request, 1) as i64;
        if length < 0 {
            return Err(LinuxErrno::EINVAL);
        }
        self.vfs
            .ftruncate(arg_i32(request, 0), length as u64)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_getcwd(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let cwd = self.vfs.getcwd().map_err(vfs_errno)?;
        let bytes = cwd.as_bytes();
        let size = usize_arg(request, 1)?;
        if size == 0 || bytes.len().checked_add(1).ok_or(LinuxErrno::ERANGE)? > size {
            return Err(LinuxErrno::ERANGE);
        }
        self.memory
            .write_bytes(arg(request, 0), bytes)
            .map_err(memory_errno)?;
        self.memory
            .write_bytes(arg(request, 0) + bytes.len() as u64, &[0])
            .map_err(memory_errno)?;
        Ok(arg(request, 0))
    }

    fn sys_chdir(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs.chdir(&path).map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_umask(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        Ok(self.vfs.umask(arg_u32(request, 0)) as u64)
    }

    fn read_path(&self, addr: u64) -> Result<String, LinuxErrno> {
        self.memory.read_c_string(addr, 4096).map_err(memory_errno)
    }

    fn read_iovecs(&self, addr: u64, count: usize) -> Result<Vec<LinuxIovec>, LinuxErrno> {
        const IOV_MAX: usize = 1024;
        if count > IOV_MAX {
            return Err(LinuxErrno::EINVAL);
        }

        let mut iovecs = Vec::with_capacity(count);
        for index in 0..count {
            let item_addr = addr
                .checked_add((index * 16) as u64)
                .ok_or(LinuxErrno::EFAULT)?;
            let mut bytes = [0; 16];
            self.memory
                .read_bytes(item_addr, &mut bytes)
                .map_err(memory_errno)?;
            iovecs.push(LinuxIovec {
                iov_base: u64::from_le_bytes(bytes[0..8].try_into().expect("slice len")),
                iov_len: u64::from_le_bytes(bytes[8..16].try_into().expect("slice len")),
            });
        }
        Ok(iovecs)
    }

    fn write_stat(&mut self, addr: u64, attr: LinuxFileAttr) -> Result<(), LinuxErrno> {
        self.memory
            .write_bytes(addr, &encode_linux_stat(attr))
            .map_err(memory_errno)
    }

    fn write_statx(&mut self, addr: u64, attr: LinuxFileAttr) -> Result<(), LinuxErrno> {
        self.memory
            .write_bytes(addr, &encode_linux_statx(attr))
            .map_err(memory_errno)
    }
}

fn outcome(result: Result<u64, LinuxErrno>) -> SyscallOutcome {
    match result {
        Ok(value) => SyscallOutcome::success(value),
        Err(errno) => SyscallOutcome::errno(errno),
    }
}

fn arg(request: &SyscallRequest, index: usize) -> u64 {
    request.arg(index).unwrap_or_default()
}

fn arg_i32(request: &SyscallRequest, index: usize) -> Fd {
    arg(request, index) as i32
}

fn arg_u32(request: &SyscallRequest, index: usize) -> u32 {
    arg(request, index) as u32
}

fn usize_arg(request: &SyscallRequest, index: usize) -> Result<usize, LinuxErrno> {
    usize::try_from(arg(request, index)).map_err(|_| LinuxErrno::EINVAL)
}

fn vfs_errno(error: VfsError) -> LinuxErrno {
    LinuxErrno::new(error.linux_errno()).unwrap_or(LinuxErrno::EINVAL)
}

fn memory_errno(_error: GuestMemoryAccessError) -> LinuxErrno {
    LinuxErrno::EFAULT
}

fn validate_socket_message_flags(flags: u32, operation: SocketOperation) -> Result<(), LinuxErrno> {
    if flags & !(LINUX_MSG_NOSIGNAL | LINUX_MSG_DONTWAIT) == 0 {
        Ok(())
    } else {
        Err(net_errno(GuestSocketTable::unsupported_socket_flags(
            operation,
        )))
    }
}

fn net_errno(error: mcr_net::SocketError) -> LinuxErrno {
    LinuxErrno::new(error.linux_errno().code() as u16).unwrap_or(LinuxErrno::EINVAL)
}

fn sync_proc_self(vfs: &mut VirtualFileSystem, kernel: &GuestKernel) {
    if let Some(process) = kernel.process(mcr_task::INITIAL_GUEST_PID) {
        let image = process.image();
        vfs.set_proc_self(ProcSelfData::new(
            image.executable().path().to_vec(),
            image.argv().to_vec(),
            image.envp().to_vec(),
        ));
    }
}

fn read_msghdr(memory: &impl GuestMemoryAccess, addr: u64) -> Result<LinuxMsghdr, LinuxErrno> {
    let mut bytes = [0; 56];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(LinuxMsghdr {
        msg_name: u64::from_le_bytes(bytes[0..8].try_into().expect("msg_name")),
        msg_namelen: u32::from_le_bytes(bytes[8..12].try_into().expect("msg_namelen")),
        __pad1: u32::from_le_bytes(bytes[12..16].try_into().expect("pad1")),
        msg_iov: u64::from_le_bytes(bytes[16..24].try_into().expect("msg_iov")),
        msg_iovlen: u64::from_le_bytes(bytes[24..32].try_into().expect("msg_iovlen")),
        msg_control: u64::from_le_bytes(bytes[32..40].try_into().expect("msg_control")),
        msg_controllen: u64::from_le_bytes(bytes[40..48].try_into().expect("msg_controllen")),
        msg_flags: u32::from_le_bytes(bytes[48..52].try_into().expect("msg_flags")),
        __pad2: u32::from_le_bytes(bytes[52..56].try_into().expect("pad2")),
    })
}

fn encode_dirents(entries: &[DirectoryEntry]) -> Result<Vec<u8>, LinuxErrno> {
    let mut bytes = Vec::new();
    for entry in entries {
        entry.encode_linux_dirent64(&mut bytes).map_err(vfs_errno)?;
    }
    Ok(bytes)
}

const SOCKADDR_IN_LEN: usize = 16;
const SOCKADDR_IN6_LEN: usize = 28;

fn read_socket_address(
    memory: &impl GuestMemoryAccess,
    sockaddr: u64,
    addrlen: u32,
) -> Result<SocketAddress, LinuxErrno> {
    if addrlen < 2 {
        return Err(LinuxErrno::EINVAL);
    }

    let mut family = [0; 2];
    memory
        .read_bytes(sockaddr, &mut family)
        .map_err(memory_errno)?;
    match u32::from(u16::from_le_bytes(family)) {
        LINUX_AF_INET => {
            if (addrlen as usize) < SOCKADDR_IN_LEN {
                return Err(LinuxErrno::EINVAL);
            }
            let mut bytes = [0; SOCKADDR_IN_LEN];
            memory
                .read_bytes(sockaddr, &mut bytes)
                .map_err(memory_errno)?;
            Ok(SocketAddress::inet(
                bytes[4..8].try_into().expect("IPv4 address length"),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            ))
        }
        LINUX_AF_INET6 => {
            if (addrlen as usize) < SOCKADDR_IN6_LEN {
                return Err(LinuxErrno::EINVAL);
            }
            let mut bytes = [0; SOCKADDR_IN6_LEN];
            memory
                .read_bytes(sockaddr, &mut bytes)
                .map_err(memory_errno)?;
            Ok(SocketAddress::inet6(
                bytes[8..24].try_into().expect("IPv6 address length"),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u32::from_le_bytes(bytes[4..8].try_into().expect("flowinfo length")),
                u32::from_le_bytes(bytes[24..28].try_into().expect("scope_id length")),
            ))
        }
        _ => Err(LinuxErrno::EAFNOSUPPORT),
    }
}

fn write_socket_address(
    memory: &mut impl GuestMemoryAccess,
    sockaddr: u64,
    addrlen_addr: u64,
    address: SocketAddress,
) -> Result<(), LinuxErrno> {
    let encoded = encode_socket_address(address);
    let addrlen = read_guest_u32(memory, addrlen_addr)? as usize;
    let write_len = addrlen.min(encoded.len());
    if write_len > 0 {
        memory
            .write_bytes(sockaddr, &encoded[..write_len])
            .map_err(memory_errno)?;
    }
    let actual_len = u32::try_from(encoded.len()).expect("sockaddr length fits socklen_t");
    memory
        .write_bytes(addrlen_addr, &actual_len.to_le_bytes())
        .map_err(memory_errno)
}

fn write_optional_socket_address(
    memory: &mut impl GuestMemoryAccess,
    sockaddr: u64,
    addrlen_addr: u64,
    address: SocketAddress,
) -> Result<(), LinuxErrno> {
    if sockaddr == 0 {
        return Ok(());
    }
    if addrlen_addr == 0 {
        return Err(LinuxErrno::EFAULT);
    }
    write_socket_address(memory, sockaddr, addrlen_addr, address)
}

fn write_socket_address_to_msghdr_name(
    memory: &mut impl GuestMemoryAccess,
    msghdr: u64,
    sockaddr: u64,
    addrlen: u32,
    address: SocketAddress,
) -> Result<(), LinuxErrno> {
    if sockaddr == 0 {
        return Ok(());
    }

    let encoded = encode_socket_address(address);
    let write_len = (addrlen as usize).min(encoded.len());
    if write_len > 0 {
        memory
            .write_bytes(sockaddr, &encoded[..write_len])
            .map_err(memory_errno)?;
    }
    let actual_len = u32::try_from(encoded.len()).expect("sockaddr length fits socklen_t");
    memory
        .write_bytes(msghdr + 8, &actual_len.to_le_bytes())
        .map_err(memory_errno)
}

fn encode_socket_address(address: SocketAddress) -> Vec<u8> {
    match address {
        SocketAddress::Inet { address, port } => {
            let mut bytes = vec![0; SOCKADDR_IN_LEN];
            bytes[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_le_bytes());
            bytes[2..4].copy_from_slice(&port.to_be_bytes());
            bytes[4..8].copy_from_slice(&address);
            bytes
        }
        SocketAddress::Inet6 {
            address,
            port,
            flowinfo,
            scope_id,
        } => {
            let mut bytes = vec![0; SOCKADDR_IN6_LEN];
            bytes[0..2].copy_from_slice(&(LINUX_AF_INET6 as u16).to_le_bytes());
            bytes[2..4].copy_from_slice(&port.to_be_bytes());
            bytes[4..8].copy_from_slice(&flowinfo.to_le_bytes());
            bytes[8..24].copy_from_slice(&address);
            bytes[24..28].copy_from_slice(&scope_id.to_le_bytes());
            bytes
        }
    }
}

fn encode_linux_stat(attr: LinuxFileAttr) -> [u8; 144] {
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: attr.inode,
        st_nlink: attr.nlink,
        st_mode: attr.mode,
        st_uid: attr.uid,
        st_gid: attr.gid,
        st_size: attr.size as i64,
        st_blksize: attr.blksize as i64,
        st_blocks: attr.blocks as i64,
        st_atime: attr.atime_sec,
        st_atime_nsec: attr.atime_nsec,
        st_mtime: attr.mtime_sec,
        st_mtime_nsec: attr.mtime_nsec,
        st_ctime: attr.ctime_sec,
        st_ctime_nsec: attr.ctime_nsec,
        ..LinuxStat::default()
    };
    let mut bytes = [0; 144];
    bytes[0..8].copy_from_slice(&stat.st_dev.to_le_bytes());
    bytes[8..16].copy_from_slice(&stat.st_ino.to_le_bytes());
    bytes[16..24].copy_from_slice(&stat.st_nlink.to_le_bytes());
    bytes[24..28].copy_from_slice(&stat.st_mode.to_le_bytes());
    bytes[28..32].copy_from_slice(&stat.st_uid.to_le_bytes());
    bytes[32..36].copy_from_slice(&stat.st_gid.to_le_bytes());
    bytes[40..48].copy_from_slice(&stat.st_rdev.to_le_bytes());
    bytes[48..56].copy_from_slice(&stat.st_size.to_le_bytes());
    bytes[56..64].copy_from_slice(&stat.st_blksize.to_le_bytes());
    bytes[64..72].copy_from_slice(&stat.st_blocks.to_le_bytes());
    bytes[72..80].copy_from_slice(&stat.st_atime.to_le_bytes());
    bytes[80..88].copy_from_slice(&stat.st_atime_nsec.to_le_bytes());
    bytes[88..96].copy_from_slice(&stat.st_mtime.to_le_bytes());
    bytes[96..104].copy_from_slice(&stat.st_mtime_nsec.to_le_bytes());
    bytes[104..112].copy_from_slice(&stat.st_ctime.to_le_bytes());
    bytes[112..120].copy_from_slice(&stat.st_ctime_nsec.to_le_bytes());
    bytes
}

fn encode_linux_statx(attr: LinuxFileAttr) -> [u8; 256] {
    let statx = LinuxStatx {
        stx_mask: 0x17ff,
        stx_blksize: attr.blksize as u32,
        stx_nlink: attr.nlink as u32,
        stx_uid: attr.uid,
        stx_gid: attr.gid,
        stx_mode: (attr.mode & 0xffff) as u16,
        stx_ino: attr.inode,
        stx_size: attr.size,
        stx_blocks: attr.blocks,
        stx_atime: statx_timestamp(attr.atime_sec, attr.atime_nsec),
        stx_ctime: statx_timestamp(attr.ctime_sec, attr.ctime_nsec),
        stx_mtime: statx_timestamp(attr.mtime_sec, attr.mtime_nsec),
        ..LinuxStatx::default()
    };
    let mut bytes = [0; 256];
    bytes[0..4].copy_from_slice(&statx.stx_mask.to_le_bytes());
    bytes[4..8].copy_from_slice(&statx.stx_blksize.to_le_bytes());
    bytes[8..16].copy_from_slice(&statx.stx_attributes.to_le_bytes());
    bytes[16..20].copy_from_slice(&statx.stx_nlink.to_le_bytes());
    bytes[20..24].copy_from_slice(&statx.stx_uid.to_le_bytes());
    bytes[24..28].copy_from_slice(&statx.stx_gid.to_le_bytes());
    bytes[28..30].copy_from_slice(&statx.stx_mode.to_le_bytes());
    bytes[32..40].copy_from_slice(&statx.stx_ino.to_le_bytes());
    bytes[40..48].copy_from_slice(&statx.stx_size.to_le_bytes());
    bytes[48..56].copy_from_slice(&statx.stx_blocks.to_le_bytes());
    bytes[56..64].copy_from_slice(&statx.stx_attributes_mask.to_le_bytes());
    write_statx_timestamp(&mut bytes[64..80], statx.stx_atime);
    write_statx_timestamp(&mut bytes[96..112], statx.stx_ctime);
    write_statx_timestamp(&mut bytes[112..128], statx.stx_mtime);
    bytes
}

fn statx_timestamp(sec: i64, nsec: i64) -> LinuxStatxTimestamp {
    LinuxStatxTimestamp {
        tv_sec: sec,
        tv_nsec: nsec as u32,
        __reserved: 0,
    }
}

fn write_statx_timestamp(bytes: &mut [u8], timestamp: LinuxStatxTimestamp) {
    bytes[0..8].copy_from_slice(&timestamp.tv_sec.to_le_bytes());
    bytes[8..12].copy_from_slice(&timestamp.tv_nsec.to_le_bytes());
    bytes[12..16].copy_from_slice(&timestamp.__reserved.to_le_bytes());
}

pub struct Runtime {
    dispatcher: SyscallDispatcher<RuntimeSubsystems>,
}

impl Runtime {
    pub fn new(program: GuestProgram) -> Result<Self, RuntimeError> {
        Ok(Self {
            dispatcher: SyscallDispatcher::new(RuntimeSubsystems::new(program)?),
        })
    }

    pub fn from_executable(
        path: impl Into<Vec<u8>>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, RuntimeError> {
        Self::new(GuestProgram::new(GuestExecutable::new(path, bytes)))
    }

    pub fn with_tracer<T>(
        program: GuestProgram,
        tracer: T,
    ) -> Result<RuntimeWithTracer<T>, RuntimeError>
    where
        T: SyscallTracer,
    {
        Self::with_tracer_and_vfs(program, RuntimeSubsystems::default_vfs(), tracer)
    }

    pub fn with_vfs(program: GuestProgram, vfs: VirtualFileSystem) -> Result<Self, RuntimeError> {
        Ok(Self {
            dispatcher: SyscallDispatcher::new(RuntimeSubsystems::with_vfs(program, vfs)?),
        })
    }

    pub fn with_vfs_and_socket_transport(
        program: GuestProgram,
        vfs: VirtualFileSystem,
        transport: impl HostSocketTransport + 'static,
    ) -> Result<Self, RuntimeError> {
        Ok(Self {
            dispatcher: SyscallDispatcher::new(RuntimeSubsystems::with_vfs_and_socket_transport(
                program, vfs, transport,
            )?),
        })
    }

    pub fn with_tracer_and_vfs<T>(
        program: GuestProgram,
        vfs: VirtualFileSystem,
        tracer: T,
    ) -> Result<RuntimeWithTracer<T>, RuntimeError>
    where
        T: SyscallTracer,
    {
        Ok(RuntimeWithTracer {
            dispatcher: SyscallDispatcher::with_tracer(
                RuntimeSubsystems::with_vfs(program, vfs)?,
                tracer,
            ),
        })
    }

    pub fn with_tracer_vfs_and_socket_transport<T>(
        program: GuestProgram,
        vfs: VirtualFileSystem,
        tracer: T,
        transport: impl HostSocketTransport + 'static,
    ) -> Result<RuntimeWithTracer<T>, RuntimeError>
    where
        T: SyscallTracer,
    {
        Ok(RuntimeWithTracer {
            dispatcher: SyscallDispatcher::with_tracer(
                RuntimeSubsystems::with_vfs_and_socket_transport(program, vfs, transport)?,
                tracer,
            ),
        })
    }

    #[must_use]
    pub fn kernel(&self) -> &GuestKernel {
        &self.dispatcher.subsystems().tasks
    }

    #[must_use]
    pub fn kernel_mut(&mut self) -> &mut GuestKernel {
        &mut self.dispatcher.subsystems_mut().tasks
    }

    #[must_use]
    pub fn memory(&self) -> &GuestMemory {
        self.dispatcher.subsystems().memory()
    }

    #[must_use]
    pub fn memory_mut(&mut self) -> &mut GuestMemory {
        self.dispatcher.subsystems_mut().memory_mut()
    }

    #[must_use]
    pub fn memory_for_process(&self, pid: mcr_sys::GuestPid) -> Option<&GuestMemory> {
        self.dispatcher.subsystems().memory_for_process(pid)
    }

    #[must_use]
    pub fn memory_for_process_mut(&mut self, pid: mcr_sys::GuestPid) -> Option<&mut GuestMemory> {
        self.dispatcher.subsystems_mut().memory_for_process_mut(pid)
    }

    #[must_use]
    pub fn vfs(&self) -> &VirtualFileSystem {
        self.dispatcher.subsystems().files.vfs()
    }

    #[must_use]
    pub fn vfs_mut(&mut self) -> &mut VirtualFileSystem {
        self.dispatcher.subsystems_mut().files.vfs_mut()
    }

    pub fn dispatch_syscall(&mut self, context: GuestContext) -> SyscallDispatchResult {
        self.dispatcher.dispatch(context)
    }

    pub fn dispatch_guest_execution(&mut self) -> Result<GuestExecutionStep, GuestExecutionError> {
        dispatch_guest_execution_with_dispatcher(&mut self.dispatcher)
    }

    pub fn run_guest_until_exit(&mut self) -> Result<i32, GuestRunError> {
        run_guest_until_exit_with_dispatcher(&mut self.dispatcher)
    }

    pub fn into_kernel(self) -> GuestKernel {
        self.dispatcher.into_parts().0.tasks
    }
}

pub struct RuntimeWithTracer<T> {
    dispatcher: SyscallDispatcher<RuntimeSubsystems, T>,
}

impl<T> RuntimeWithTracer<T>
where
    T: SyscallTracer,
{
    #[must_use]
    pub fn kernel(&self) -> &GuestKernel {
        &self.dispatcher.subsystems().tasks
    }

    #[must_use]
    pub fn kernel_mut(&mut self) -> &mut GuestKernel {
        &mut self.dispatcher.subsystems_mut().tasks
    }

    #[must_use]
    pub fn memory(&self) -> &GuestMemory {
        self.dispatcher.subsystems().memory()
    }

    #[must_use]
    pub fn memory_mut(&mut self) -> &mut GuestMemory {
        self.dispatcher.subsystems_mut().memory_mut()
    }

    #[must_use]
    pub fn memory_for_process(&self, pid: mcr_sys::GuestPid) -> Option<&GuestMemory> {
        self.dispatcher.subsystems().memory_for_process(pid)
    }

    #[must_use]
    pub fn memory_for_process_mut(&mut self, pid: mcr_sys::GuestPid) -> Option<&mut GuestMemory> {
        self.dispatcher.subsystems_mut().memory_for_process_mut(pid)
    }

    #[must_use]
    pub const fn tracer(&self) -> &T {
        self.dispatcher.tracer()
    }

    #[must_use]
    pub const fn tracer_mut(&mut self) -> &mut T {
        self.dispatcher.tracer_mut()
    }

    #[must_use]
    pub fn vfs(&self) -> &VirtualFileSystem {
        self.dispatcher.subsystems().files.vfs()
    }

    #[must_use]
    pub fn vfs_mut(&mut self) -> &mut VirtualFileSystem {
        self.dispatcher.subsystems_mut().files.vfs_mut()
    }

    pub fn dispatch_syscall(&mut self, context: GuestContext) -> SyscallDispatchResult {
        self.dispatcher.dispatch(context)
    }

    pub fn dispatch_guest_execution(&mut self) -> Result<GuestExecutionStep, GuestExecutionError> {
        dispatch_guest_execution_with_dispatcher(&mut self.dispatcher)
    }

    pub fn run_guest_until_exit(&mut self) -> Result<i32, GuestRunError> {
        run_guest_until_exit_with_dispatcher(&mut self.dispatcher)
    }

    pub fn into_parts(self) -> (GuestKernel, T) {
        let (subsystems, tracer) = self.dispatcher.into_parts();
        (subsystems.tasks, tracer)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestExecutionStep {
    tid: mcr_sys::GuestTid,
    before_rip: u64,
    after_rip: u64,
    encoded_rax: u64,
    task_state: TaskState,
}

impl GuestExecutionStep {
    #[must_use]
    pub const fn new(
        tid: mcr_sys::GuestTid,
        before_rip: u64,
        after_rip: u64,
        encoded_rax: u64,
        task_state: TaskState,
    ) -> Self {
        Self {
            tid,
            before_rip,
            after_rip,
            encoded_rax,
            task_state,
        }
    }

    #[must_use]
    pub const fn tid(self) -> mcr_sys::GuestTid {
        self.tid
    }

    #[must_use]
    pub const fn before_rip(self) -> u64 {
        self.before_rip
    }

    #[must_use]
    pub const fn after_rip(self) -> u64 {
        self.after_rip
    }

    #[must_use]
    pub const fn encoded_rax(self) -> u64 {
        self.encoded_rax
    }

    #[must_use]
    pub const fn task_state(self) -> TaskState {
        self.task_state
    }
}

#[derive(Debug)]
pub enum GuestExecutionError {
    MissingInitialTask,
    MissingTask(mcr_sys::GuestTid),
    TaskExited {
        tid: mcr_sys::GuestTid,
        state: TaskState,
    },
    Memory(GuestMemoryError),
    Execution(ExecutionError),
}

impl fmt::Display for GuestExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingInitialTask => write!(formatter, "initial guest task is missing"),
            Self::MissingTask(tid) => write!(formatter, "guest task {tid} is missing"),
            Self::TaskExited { tid, state } => {
                write!(formatter, "guest task {tid} is not runnable: {state:?}")
            }
            Self::Memory(error) => write!(formatter, "guest memory fault: {error:?}"),
            Self::Execution(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for GuestExecutionError {}

impl From<GuestMemoryError> for GuestExecutionError {
    fn from(value: GuestMemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<ExecutionError> for GuestExecutionError {
    fn from(value: ExecutionError) -> Self {
        Self::Execution(value)
    }
}

#[derive(Debug)]
pub enum GuestRunError {
    MissingInitialProcess,
    MissingInitialTask,
    InitialTaskNotRunnable {
        tid: mcr_sys::GuestTid,
        state: TaskState,
    },
    NoRunnableTasks,
    WaitResume {
        errno: LinuxErrno,
    },
    GuestExecution(GuestExecutionError),
}

impl GuestRunError {
    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        match self {
            Self::MissingInitialProcess
            | Self::MissingInitialTask
            | Self::InitialTaskNotRunnable { .. }
            | Self::NoRunnableTasks => LinuxErrno::ESRCH,
            Self::WaitResume { errno } => *errno,
            Self::GuestExecution(error) => error.linux_errno(),
        }
    }
}

impl fmt::Display for GuestRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingInitialProcess => write!(formatter, "initial guest process is missing"),
            Self::MissingInitialTask => write!(formatter, "initial guest task is missing"),
            Self::InitialTaskNotRunnable { tid, state } => {
                write!(
                    formatter,
                    "initial guest task {tid} is not runnable: {state:?}"
                )
            }
            Self::NoRunnableTasks => write!(formatter, "no runnable guest tasks remain"),
            Self::WaitResume { errno } => {
                write!(formatter, "failed to resume waiting guest task: {errno}")
            }
            Self::GuestExecution(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for GuestRunError {}

impl GuestExecutionError {
    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        match self {
            Self::MissingInitialTask | Self::MissingTask(_) | Self::TaskExited { .. } => {
                LinuxErrno::ESRCH
            }
            Self::Memory(error) => error.errno(),
            Self::Execution(_) => LinuxErrno::ENOEXEC,
        }
    }
}

impl From<GuestExecutionError> for GuestRunError {
    fn from(value: GuestExecutionError) -> Self {
        Self::GuestExecution(value)
    }
}

fn run_guest_until_exit_with_dispatcher<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
) -> Result<i32, GuestRunError>
where
    T: SyscallTracer,
{
    loop {
        if let Some(status) = initial_process_exit_status(&dispatcher.subsystems().tasks)? {
            return Ok(status);
        }
        dispatcher
            .subsystems_mut()
            .resume_waiting_tasks()
            .map_err(|errno| GuestRunError::WaitResume { errno })?;
        let runnable_tids = dispatcher.subsystems().tasks.runnable_tids();
        if runnable_tids.is_empty() {
            return Err(GuestRunError::NoRunnableTasks);
        }
        for tid in runnable_tids {
            if !matches!(
                dispatcher
                    .subsystems()
                    .tasks
                    .task(tid)
                    .map(mcr_task::GuestTask::state),
                Some(TaskState::Runnable)
            ) {
                continue;
            }
            dispatch_guest_task_with_dispatcher(dispatcher, tid)?;
            if initial_process_exit_status(&dispatcher.subsystems().tasks)?.is_some() {
                break;
            }
        }
    }
}

fn initial_process_exit_status(kernel: &GuestKernel) -> Result<Option<i32>, GuestRunError> {
    let process = kernel
        .process(INITIAL_GUEST_PID)
        .ok_or(GuestRunError::MissingInitialProcess)?;
    match process.exit_state() {
        ExitState::Running => Ok(None),
        ExitState::Exited { status } => Ok(Some(status)),
    }
}

fn dispatch_guest_execution_with_dispatcher<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
) -> Result<GuestExecutionStep, GuestExecutionError>
where
    T: SyscallTracer,
{
    let task = dispatcher
        .subsystems()
        .tasks
        .task(INITIAL_GUEST_TID)
        .ok_or(GuestExecutionError::MissingInitialTask)?;
    if task.pid() != INITIAL_GUEST_PID {
        return Err(GuestExecutionError::MissingInitialTask);
    }
    if !matches!(task.state(), TaskState::Runnable) {
        return Err(GuestExecutionError::TaskExited {
            tid: INITIAL_GUEST_TID,
            state: task.state(),
        });
    }
    dispatch_guest_task_with_dispatcher(dispatcher, INITIAL_GUEST_TID)
}

fn dispatch_guest_task_with_dispatcher<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
    tid: mcr_sys::GuestTid,
) -> Result<GuestExecutionStep, GuestExecutionError>
where
    T: SyscallTracer,
{
    const MAX_GUEST_BLOCK_BYTES: usize = 4096;

    let task = dispatcher
        .subsystems()
        .tasks
        .task(tid)
        .ok_or(GuestExecutionError::MissingTask(tid))?;
    let pid = task.pid();
    let gpr = task.regs();
    if !matches!(task.state(), TaskState::Runnable) {
        return Err(GuestExecutionError::TaskExited {
            tid,
            state: task.state(),
        });
    }

    let before_rip = gpr.rip();
    let memory = dispatcher
        .subsystems()
        .memory_for_process(pid)
        .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
    let block = read_guest_block(memory, before_rip, MAX_GUEST_BLOCK_BYTES)?;
    let mut registers = registers_from_gpr(gpr);
    let mut trampoline =
        TrampolineCore::new(pid, tid, |context| dispatcher.dispatch(context).encoded_rax);

    SameIsaExecutionCore::new().execute_until_syscall(
        GuestBlock::new(&block, before_rip),
        &mut registers,
        &mut trampoline,
    )?;

    let task = dispatcher
        .subsystems_mut()
        .tasks
        .task_mut(tid)
        .ok_or(GuestExecutionError::MissingInitialTask)?;
    let final_regs = if task.regs() == gpr {
        let updated_regs = gpr_from_registers(registers);
        task.set_regs(updated_regs);
        updated_regs
    } else {
        task.regs()
    };
    Ok(GuestExecutionStep::new(
        tid,
        before_rip,
        final_regs.rip(),
        final_regs.rax(),
        task.state(),
    ))
}

fn read_guest_block(
    memory: &GuestMemory,
    rip: u64,
    max_len: usize,
) -> Result<Vec<u8>, GuestMemoryError> {
    let Some(vma) = memory.vma_containing(rip) else {
        return Err(GuestMemoryError::NotMapped);
    };
    if !vma.protection().execute {
        return Err(GuestMemoryError::AccessDenied);
    }

    let len = usize::try_from((vma.end() - rip).min(max_len as u64))
        .map_err(|_| GuestMemoryError::RegionTooLarge)?;
    let mut bytes = vec![0; len];
    memory.read(rip, &mut bytes)?;
    Ok(bytes)
}

fn registers_from_gpr(value: GprState) -> GuestRegisters {
    GuestRegisters {
        rax: value.rax(),
        rdi: value.rdi(),
        rsi: value.rsi(),
        rdx: value.rdx(),
        r10: value.r10(),
        r8: value.r8(),
        r9: value.r9(),
        rip: value.rip(),
        rsp: value.rsp(),
        ..GuestRegisters::default()
    }
}

fn gpr_from_registers(value: GuestRegisters) -> GprState {
    GprState::with_syscall_registers(
        value.rip,
        value.rsp,
        value.rax,
        [
            value.rdi, value.rsi, value.rdx, value.r10, value.r8, value.r9,
        ],
    )
}

#[derive(Debug)]
pub struct RuntimeSubsystems {
    tasks: GuestKernel,
    files: RuntimeFileSystem<GuestMemory>,
    process_memory: BTreeMap<mcr_sys::GuestPid, GuestMemory>,
    selected_memory_pid: mcr_sys::GuestPid,
    process_fds: BTreeMap<mcr_sys::GuestPid, FdTable>,
    selected_fds_pid: mcr_sys::GuestPid,
    futexes: FutexRegistry,
    epolls: EpollRegistry,
}

impl RuntimeSubsystems {
    pub fn new(program: GuestProgram) -> Result<Self, RuntimeError> {
        Self::with_vfs(program, Self::default_vfs())
    }

    pub fn with_vfs(
        program: GuestProgram,
        mut vfs: VirtualFileSystem,
    ) -> Result<Self, RuntimeError> {
        let tasks = GuestKernel::new(program)?;
        let memory = GuestMemory::from_image(
            tasks
                .process(mcr_task::INITIAL_GUEST_PID)
                .expect("runtime always starts with an initial process")
                .image()
                .memory(),
        )?;
        sync_proc_self(&mut vfs, &tasks);
        Ok(Self {
            tasks,
            files: RuntimeFileSystem::new(vfs, memory),
            process_memory: BTreeMap::new(),
            selected_memory_pid: mcr_task::INITIAL_GUEST_PID,
            process_fds: BTreeMap::new(),
            selected_fds_pid: mcr_task::INITIAL_GUEST_PID,
            futexes: FutexRegistry::default(),
            epolls: EpollRegistry::default(),
        })
    }

    pub fn with_vfs_and_socket_transport(
        program: GuestProgram,
        mut vfs: VirtualFileSystem,
        transport: impl HostSocketTransport + 'static,
    ) -> Result<Self, RuntimeError> {
        let tasks = GuestKernel::new(program)?;
        let memory = GuestMemory::from_image(
            tasks
                .process(mcr_task::INITIAL_GUEST_PID)
                .expect("runtime always starts with an initial process")
                .image()
                .memory(),
        )?;
        sync_proc_self(&mut vfs, &tasks);
        Ok(Self {
            tasks,
            files: RuntimeFileSystem::with_socket_transport(vfs, memory, transport),
            process_memory: BTreeMap::new(),
            selected_memory_pid: mcr_task::INITIAL_GUEST_PID,
            process_fds: BTreeMap::new(),
            selected_fds_pid: mcr_task::INITIAL_GUEST_PID,
            futexes: FutexRegistry::default(),
            epolls: EpollRegistry::default(),
        })
    }

    fn default_vfs() -> VirtualFileSystem {
        // Runtime::new has no rootfs argument yet. Keep the placeholder explicit and route
        // future rootfs-aware callers through Runtime::with_vfs after loading their VFS.
        let mut vfs = VirtualFileSystem::new("/");
        vfs.mount_minimal_procfs()
            .expect("minimal procfs nodes do not conflict in a new VFS");
        vfs
    }

    #[must_use]
    pub const fn tasks(&self) -> &GuestKernel {
        &self.tasks
    }

    #[must_use]
    pub const fn tasks_mut(&mut self) -> &mut GuestKernel {
        &mut self.tasks
    }

    #[must_use]
    pub fn memory(&self) -> &GuestMemory {
        self.memory_for_process(mcr_task::INITIAL_GUEST_PID)
            .expect("initial guest process memory is present")
    }

    #[must_use]
    pub fn memory_mut(&mut self) -> &mut GuestMemory {
        self.select_memory_for_process(mcr_task::INITIAL_GUEST_PID)
            .expect("initial guest process memory is present");
        self.files.memory_mut()
    }

    #[must_use]
    pub fn memory_for_process(&self, pid: mcr_sys::GuestPid) -> Option<&GuestMemory> {
        if pid == self.selected_memory_pid {
            Some(self.files.memory())
        } else {
            self.process_memory.get(&pid)
        }
    }

    #[must_use]
    pub fn memory_for_process_mut(&mut self, pid: mcr_sys::GuestPid) -> Option<&mut GuestMemory> {
        if pid == self.selected_memory_pid {
            Some(self.files.memory_mut())
        } else {
            self.process_memory.get_mut(&pid)
        }
    }

    #[must_use]
    pub fn current_image(&self) -> &mcr_elf::GuestMemoryImage {
        self.tasks
            .process(mcr_task::INITIAL_GUEST_PID)
            .expect("runtime always starts with an initial process")
            .image()
            .memory()
    }
}

impl FileSyscalls for RuntimeSubsystems {
    fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = if matches!(request.syscall, mcr_sys::Syscall::Close) {
            outcome(self.close_process_fd(arg_i32(request, 0)))
        } else {
            self.files.dispatch_file(request)
        };
        if matches!(outcome.result, SyscallReturn::Success(_)) {
            if let Err(errno) = self.store_selected_process_fds(pid) {
                return SyscallOutcome::errno(errno);
            }
            if let Err(errno) = self.store_selected_process_memory(pid) {
                return SyscallOutcome::errno(errno);
            }
        }
        outcome
    }
}
impl MemorySyscalls for RuntimeSubsystems {
    fn dispatch_memory(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = if matches!(request.syscall, mcr_sys::Syscall::Mmap) {
            outcome(self.mmap(
                arg(request, 0),
                arg(request, 1),
                arg_u32(request, 2),
                arg_u32(request, 3),
                arg_i32(request, 4),
                arg(request, 5) as i64,
            ))
        } else {
            self.files.memory_mut().dispatch_memory(request)
        };
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_memory(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }
}
impl TimeSyscalls for RuntimeSubsystems {}
impl NetworkSyscalls for RuntimeSubsystems {
    fn dispatch_network(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = self.files.dispatch_network(request);
        if matches!(outcome.result, SyscallReturn::Success(_)) {
            if let Err(errno) = self.store_selected_process_fds(pid) {
                return SyscallOutcome::errno(errno);
            }
            if let Err(errno) = self.store_selected_process_memory(pid) {
                return SyscallOutcome::errno(errno);
            }
        }
        outcome
    }
}
impl EventSyscalls for RuntimeSubsystems {
    fn dispatch_event(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        match request.syscall {
            mcr_sys::Syscall::Poll => self.dispatch_poll(request),
            mcr_sys::Syscall::Ppoll => self.dispatch_ppoll(request),
            mcr_sys::Syscall::EpollCreate1 => self.dispatch_epoll_create1(request),
            mcr_sys::Syscall::EpollCtl => self.dispatch_epoll_ctl(request),
            mcr_sys::Syscall::EpollWait => self.dispatch_epoll_wait(request),
            _ => SyscallOutcome::unsupported(),
        }
    }
}

impl mcr_sys::TaskSyscalls for RuntimeSubsystems {
    fn dispatch_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        match request.syscall {
            mcr_sys::Syscall::Futex => self.dispatch_futex(request),
            mcr_sys::Syscall::Execve => self.dispatch_execve(request),
            mcr_sys::Syscall::Fork | mcr_sys::Syscall::Vfork | mcr_sys::Syscall::Clone => {
                self.dispatch_fork_like(request)
            }
            _ => self.dispatch_kernel_task(request),
        }
    }
}

impl RuntimeSubsystems {
    fn mmap(
        &mut self,
        addr: u64,
        length: u64,
        prot: u32,
        flags: u32,
        fd: Fd,
        offset: i64,
    ) -> Result<u64, LinuxErrno> {
        let args = mcr_sys::MmapSyscallArgs {
            addr,
            length,
            prot,
            flags,
            fd,
            offset,
        };
        let mapped = self
            .files
            .memory_mut()
            .mmap(args)
            .map_err(|error| error.errno())?;
        if !args.is_anonymous() {
            self.populate_file_backed_mmap(mapped, length, prot, fd, offset)?;
        }
        Ok(mapped)
    }

    fn populate_file_backed_mmap(
        &mut self,
        mapped: u64,
        length: u64,
        prot: u32,
        fd: Fd,
        offset: i64,
    ) -> Result<(), LinuxErrno> {
        if offset < 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let len = usize::try_from(length).map_err(|_| LinuxErrno::ENOMEM)?;
        let mut bytes = vec![0; len];
        let count = self
            .files
            .vfs()
            .pread(fd, offset as u64, &mut bytes)
            .map_err(vfs_errno)?;
        let writable = mcr_sys::MprotectSyscallArgs {
            addr: mapped,
            length,
            prot: mcr_sys::LINUX_PROT_READ | mcr_sys::LINUX_PROT_WRITE,
        };
        self.files
            .memory_mut()
            .mprotect(writable)
            .map_err(|error| error.errno())?;
        let write_result = self.files.memory_mut().write(mapped, &bytes[..count]);
        let restore_result = self
            .files
            .memory_mut()
            .mprotect(mcr_sys::MprotectSyscallArgs {
                addr: mapped,
                length,
                prot,
            });
        write_result.map_err(|error| error.errno())?;
        restore_result.map_err(|error| error.errno())?;
        Ok(())
    }

    fn select_process_context(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        self.select_memory_for_process(pid)?;
        self.select_fds_for_process(pid)
    }

    fn select_memory_for_process(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        if pid == self.selected_memory_pid {
            return Ok(());
        }
        if self.tasks.process(self.selected_memory_pid).is_some() {
            let selected = self
                .files
                .memory()
                .try_clone_runtime()
                .map_err(|error| error.errno())?;
            self.process_memory
                .insert(self.selected_memory_pid, selected);
        }
        let memory = self.process_memory.remove(&pid).ok_or(LinuxErrno::ESRCH)?;
        *self.files.memory_mut() = memory;
        self.selected_memory_pid = pid;
        Ok(())
    }

    fn store_selected_process_memory(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        if pid != self.selected_memory_pid {
            return Err(LinuxErrno::ESRCH);
        }
        if self.tasks.process(pid).is_none() {
            return Ok(());
        }
        Ok(())
    }

    fn select_fds_for_process(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        if pid == self.selected_fds_pid {
            return Ok(());
        }
        if self.tasks.process(self.selected_fds_pid).is_some() {
            let selected = self.files.vfs().fds().clone();
            self.process_fds.insert(self.selected_fds_pid, selected);
        }
        let fds = self.process_fds.remove(&pid).ok_or(LinuxErrno::ESRCH)?;
        self.files.vfs_mut().replace_fds(fds);
        self.selected_fds_pid = pid;
        Ok(())
    }

    fn store_selected_process_fds(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        if pid != self.selected_fds_pid {
            return Err(LinuxErrno::ESRCH);
        }
        if self.tasks.process(pid).is_none() {
            return Ok(());
        }
        Ok(())
    }

    fn drop_process_fds(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        if pid == self.selected_fds_pid {
            if pid != mcr_task::INITIAL_GUEST_PID {
                let fds = self
                    .process_fds
                    .remove(&mcr_task::INITIAL_GUEST_PID)
                    .ok_or(LinuxErrno::ESRCH)?;
                self.files.vfs_mut().replace_fds(fds);
                self.selected_fds_pid = mcr_task::INITIAL_GUEST_PID;
            }
        } else {
            self.process_fds.remove(&pid);
        }
        Ok(())
    }

    fn drop_process_resources(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        self.close_unshared_process_sockets(pid)?;
        self.drop_process_memory(pid)?;
        self.drop_process_fds(pid)
    }

    fn close_unshared_process_sockets(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        let Some((socket_ids, epoll_ids)) = self.fd_table_for_process(pid).map(|fds| {
            (
                fds.socket_ids()
                    .filter_map(SocketId::new)
                    .collect::<Vec<_>>(),
                fds.epoll_ids().collect::<Vec<_>>(),
            )
        }) else {
            return Ok(());
        };
        for socket_id in socket_ids {
            if self.socket_fd_ref_count_excluding_current(pid, socket_id) == 0 {
                self.files
                    .sockets_mut()
                    .close(socket_id)
                    .map_err(net_errno)?;
            }
        }
        for epoll_id in epoll_ids {
            if self.epoll_fd_ref_count_excluding_current(pid, epoll_id) == 0 {
                self.epolls.close(epoll_id);
            }
        }
        Ok(())
    }

    fn close_process_fd(&mut self, fd: Fd) -> Result<u64, LinuxErrno> {
        let file = self
            .files
            .vfs_mut()
            .close_with_file(fd)
            .map_err(vfs_errno)?;
        self.close_unshared_process_file_resources(&file)?;
        Ok(0)
    }

    fn close_unshared_process_file_resources(&mut self, file: &FileRef) -> Result<(), LinuxErrno> {
        match file.kind() {
            FileKind::Socket => {
                let socket_id = match file.inode().backend() {
                    mcr_vfs::InodeBackend::Socket(socket) => SocketId::new(socket.id()),
                    _ => None,
                };
                if let Some(socket_id) = socket_id
                    && self.socket_fd_ref_count_excluding_current(self.selected_fds_pid, socket_id)
                        + self.files.vfs().socket_fd_count(socket_id.get())
                        == 0
                {
                    self.files
                        .sockets_mut()
                        .close(socket_id)
                        .map_err(net_errno)?;
                }
            }
            FileKind::Epoll => {
                let epoll_id = match file.inode().backend() {
                    mcr_vfs::InodeBackend::Epoll(epoll) => Some(epoll.id()),
                    _ => None,
                };
                if let Some(epoll_id) = epoll_id
                    && self.epoll_fd_ref_count_excluding_current(self.selected_fds_pid, epoll_id)
                        + self.files.vfs().epoll_fd_count(epoll_id)
                        == 0
                {
                    self.epolls.close(epoll_id);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn fd_table_for_process(&self, pid: mcr_sys::GuestPid) -> Option<&FdTable> {
        if pid == self.selected_fds_pid {
            Some(self.files.vfs().fds())
        } else {
            self.process_fds.get(&pid)
        }
    }

    fn socket_fd_ref_count_excluding_current(
        &self,
        excluded_pid: mcr_sys::GuestPid,
        socket_id: SocketId,
    ) -> usize {
        let selected_count = if self.selected_fds_pid != excluded_pid {
            self.files
                .vfs()
                .socket_ids()
                .filter(|raw| *raw == socket_id.get())
                .count()
        } else {
            0
        };
        selected_count
            + self
                .process_fds
                .iter()
                .filter(|(pid, _)| **pid != excluded_pid)
                .map(|(_, fds)| {
                    fds.socket_ids()
                        .filter(|raw| *raw == socket_id.get())
                        .count()
                })
                .sum::<usize>()
    }

    fn epoll_fd_ref_count_excluding_current(
        &self,
        excluded_pid: mcr_sys::GuestPid,
        epoll_id: u64,
    ) -> usize {
        let selected_count = if self.selected_fds_pid != excluded_pid {
            self.files
                .vfs()
                .epoll_ids()
                .filter(|raw| *raw == epoll_id)
                .count()
        } else {
            0
        };
        selected_count
            + self
                .process_fds
                .iter()
                .filter(|(pid, _)| **pid != excluded_pid)
                .map(|(_, fds)| fds.epoll_ids().filter(|raw| *raw == epoll_id).count())
                .sum::<usize>()
    }

    fn drop_process_memory(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        if pid == self.selected_memory_pid {
            if pid != mcr_task::INITIAL_GUEST_PID {
                let memory = self
                    .process_memory
                    .remove(&mcr_task::INITIAL_GUEST_PID)
                    .ok_or(LinuxErrno::ESRCH)?;
                *self.files.memory_mut() = memory;
                self.selected_memory_pid = mcr_task::INITIAL_GUEST_PID;
            }
        } else {
            self.process_memory.remove(&pid);
        }
        Ok(())
    }

    fn dispatch_kernel_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = self.tasks.dispatch_for_current_task(request);
        if !matches!(outcome.result, SyscallReturn::Success(_)) {
            return outcome;
        }
        match request.syscall {
            mcr_sys::Syscall::Exit | mcr_sys::Syscall::ExitGroup => {
                if let Err(errno) = self.drop_process_resources(pid) {
                    return SyscallOutcome::errno(errno);
                }
            }
            mcr_sys::Syscall::Wait4 => {
                if let Some(child_pid) = fork_child_pid(&outcome.decoded) {
                    if let Err(errno) = self.write_wait_status_from_outcome(pid, request, &outcome)
                    {
                        return SyscallOutcome::errno(errno);
                    }
                    if let Err(errno) = self.drop_process_resources(child_pid) {
                        return SyscallOutcome::errno(errno);
                    }
                }
            }
            _ => {}
        }
        outcome
    }

    fn resume_waiting_tasks(&mut self) -> Result<Vec<CompletedWait>, LinuxErrno> {
        let completed = self.tasks.resume_waiting_tasks();
        for wait in &completed {
            self.write_wait_status(*wait)?;
            self.drop_process_resources(wait.waited().pid())?;
        }
        Ok(completed)
    }

    fn write_wait_status_from_outcome(
        &mut self,
        pid: mcr_sys::GuestPid,
        request: &SyscallRequest,
        outcome: &SyscallOutcome,
    ) -> Result<(), LinuxErrno> {
        let wstatus = arg(request, 1);
        let Some(wait_status) = wait_status_from_decoded(&outcome.decoded) else {
            return Ok(());
        };
        self.write_wait_status_to_process(pid, wstatus, wait_status)
    }

    fn write_wait_status(&mut self, wait: CompletedWait) -> Result<(), LinuxErrno> {
        self.write_wait_status_to_process(
            wait.pid(),
            wait.args().wstatus,
            wait.waited().wait_status(),
        )
    }

    fn write_wait_status_to_process(
        &mut self,
        pid: mcr_sys::GuestPid,
        wstatus: u64,
        wait_status: u32,
    ) -> Result<(), LinuxErrno> {
        if wstatus == 0 {
            return Ok(());
        }
        self.memory_for_process_mut(pid)
            .ok_or(LinuxErrno::ESRCH)?
            .write(wstatus, &wait_status.to_le_bytes())
            .map_err(|error| error.errno())
    }

    fn dispatch_fork_like(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = self.tasks.dispatch_for_current_task(request);
        if !matches!(outcome.result, SyscallReturn::Success(_)) {
            return outcome;
        }
        let Some(child_pid) = fork_child_pid(&outcome.decoded) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        match self.files.memory().try_clone_runtime() {
            Ok(memory) => {
                self.process_memory.insert(child_pid, memory);
                self.process_fds
                    .insert(child_pid, self.files.vfs().fds().clone());
                outcome
            }
            Err(error) => {
                self.tasks
                    .wait4_child(
                        pid,
                        mcr_sys::Wait4SyscallArgs::new(child_pid as i32, 0, 0, 0),
                    )
                    .ok();
                SyscallOutcome::errno(error.errno())
            }
        }
    }

    fn dispatch_execve(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        match self.execve(request) {
            Ok(()) => SyscallOutcome::success(0),
            Err(errno) => SyscallOutcome::errno(errno),
        }
    }

    fn execve(&mut self, request: &SyscallRequest) -> Result<(), LinuxErrno> {
        self.select_process_context(request.context.pid)?;
        let filename = read_guest_c_bytes(self.files.memory(), arg(request, 0))?;
        let argv = self.files.read_guest_vector(arg(request, 1))?;
        let envp = self.files.read_guest_vector(arg(request, 2))?;
        let program = self.files.load_guest_program(filename, argv, envp)?;
        self.tasks
            .exec_task(request.context.tid, program)
            .map_err(|error| error.linux_errno())?;
        let closed_fd_ids = self.files.vfs_mut().fds_mut().close_on_exec();
        for socket_id in closed_fd_ids
            .socket_ids
            .into_iter()
            .filter_map(SocketId::new)
        {
            if self.socket_fd_ref_count_excluding_current(request.context.pid, socket_id)
                + self.files.vfs().socket_fd_count(socket_id.get())
                == 0
            {
                self.files
                    .sockets_mut()
                    .close(socket_id)
                    .map_err(net_errno)?;
            }
        }
        for epoll_id in closed_fd_ids.epoll_ids {
            if self.epoll_fd_ref_count_excluding_current(request.context.pid, epoll_id)
                + self.files.vfs().epoll_fd_count(epoll_id)
                == 0
            {
                self.epolls.close(epoll_id);
            }
        }
        sync_proc_self(self.files.vfs_mut(), &self.tasks);
        self.replace_memory_from_image(request.context.pid)?;
        self.store_selected_process_fds(request.context.pid)?;
        self.store_selected_process_memory(request.context.pid)
    }

    fn replace_memory_from_image(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        let image = self
            .tasks
            .process(pid)
            .ok_or(LinuxErrno::ESRCH)?
            .image()
            .memory();
        let memory = GuestMemory::from_image(image).map_err(|error| error.errno())?;
        *self.memory_for_process_mut(pid).ok_or(LinuxErrno::ESRCH)? = memory;
        Ok(())
    }

    fn dispatch_futex(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        outcome(self.futex(FutexSyscallArgs::new(
            arg(request, 0),
            arg_u32(request, 1),
            arg_u32(request, 2),
            arg(request, 3),
            arg(request, 4),
            arg_u32(request, 5),
        )))
    }

    fn futex(&mut self, args: FutexSyscallArgs) -> Result<u64, LinuxErrno> {
        if args.op & !(LINUX_FUTEX_CMD_MASK | LINUX_FUTEX_PRIVATE_FLAG) != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        if !args.is_private() {
            return Err(LinuxErrno::ENOSYS);
        }
        if args.uaddr % 4 != 0 {
            return Err(LinuxErrno::EINVAL);
        }

        match args.command() {
            LINUX_FUTEX_WAIT => self.futex_wait(args),
            LINUX_FUTEX_WAKE => Ok(self.futex_wake(args)),
            _ => Err(LinuxErrno::EINVAL),
        }
    }

    fn futex_wait(&mut self, args: FutexSyscallArgs) -> Result<u64, LinuxErrno> {
        let value = read_guest_u32(self.files.memory(), args.uaddr)?;
        if value != args.val {
            return Err(LinuxErrno::EAGAIN);
        }
        let timeout = read_futex_timeout(self.files.memory(), args.timeout)?;
        let memory = self.files.memory();
        self.futexes.wait(args.uaddr, value, timeout, || {
            read_guest_u32(memory, args.uaddr).is_ok_and(|current| current != args.val)
        })
    }

    fn futex_wake(&mut self, args: FutexSyscallArgs) -> u64 {
        self.futexes.wake(args.uaddr, args.val)
    }

    fn dispatch_poll(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let nfds = match usize_arg(request, 1) {
            Ok(nfds) => nfds,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let timeout = match poll_timeout(arg(request, 2)) {
            Ok(timeout) => timeout,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let outcome = outcome(self.poll_fds(arg(request, 0), nfds, timeout));
        if matches!(outcome.result, SyscallReturn::Success(_)) {
            if let Err(errno) = self.store_selected_process_fds(pid) {
                return SyscallOutcome::errno(errno);
            }
            if let Err(errno) = self.store_selected_process_memory(pid) {
                return SyscallOutcome::errno(errno);
            }
        }
        outcome
    }

    fn dispatch_ppoll(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        if arg(request, 3) != 0 || arg(request, 4) != 0 {
            return SyscallOutcome::errno(LinuxErrno::EINVAL);
        }
        let nfds = match usize_arg(request, 1) {
            Ok(nfds) => nfds,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let timeout = match read_futex_timeout(self.files.memory(), arg(request, 2)) {
            Ok(timeout) => timeout,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let outcome = outcome(self.poll_fds(arg(request, 0), nfds, timeout));
        if matches!(outcome.result, SyscallReturn::Success(_)) {
            if let Err(errno) = self.store_selected_process_fds(pid) {
                return SyscallOutcome::errno(errno);
            }
            if let Err(errno) = self.store_selected_process_memory(pid) {
                return SyscallOutcome::errno(errno);
            }
        }
        outcome
    }

    fn poll_fds(
        &mut self,
        fds_addr: u64,
        nfds: usize,
        timeout: Option<Duration>,
    ) -> Result<u64, LinuxErrno> {
        const MAX_POLL_FDS: usize = 4096;
        if nfds > MAX_POLL_FDS {
            return Err(LinuxErrno::EINVAL);
        }

        let mut ready = 0u64;
        for index in 0..nfds {
            let pollfd_addr = fds_addr
                .checked_add((index * POLLFD_SIZE) as u64)
                .ok_or(LinuxErrno::EFAULT)?;
            let mut pollfd = read_pollfd(self.files.memory(), pollfd_addr)?;
            pollfd.revents = self.poll_fd_revents(pollfd.fd, pollfd.events, timeout)?;
            write_pollfd_revents(self.files.memory_mut(), pollfd_addr, pollfd.revents)?;
            if pollfd.revents != 0 {
                ready = ready.checked_add(1).ok_or(LinuxErrno::EINVAL)?;
            }
        }
        Ok(ready)
    }

    fn poll_fd_revents(
        &mut self,
        fd: Fd,
        events: i16,
        timeout: Option<Duration>,
    ) -> Result<i16, LinuxErrno> {
        if fd < 0 {
            return Ok(0);
        }

        let mut revents = match self.files.vfs().poll_readiness(fd) {
            Ok(readiness) => poll_revents_from_vfs(readiness, events),
            Err(VfsError::BadFd) => return Ok(LINUX_POLLNVAL),
            Err(error) => return Err(vfs_errno(error)),
        };

        if self.files.vfs().socket_id_for_fd(fd).is_ok() {
            let socket_id = self.files.socket_id_for_fd(fd)?;
            let socket_events = poll_interest_to_socket_events(events);
            if !socket_events.is_empty() {
                let readiness = self
                    .files
                    .sockets_mut()
                    .poll(socket_id, socket_events, timeout)
                    .map_err(net_errno)?;
                revents |= poll_revents_from_socket_events(readiness, events);
            }
        }
        Ok(revents)
    }

    fn dispatch_epoll_create1(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = outcome(self.epoll_create1(arg_u32(request, 0)));
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_fds(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }

    fn dispatch_epoll_ctl(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        outcome(self.epoll_ctl(
            arg_i32(request, 0),
            arg_u32(request, 1),
            arg_i32(request, 2),
            arg(request, 3),
        ))
    }

    fn dispatch_epoll_wait(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let maxevents = match usize_arg(request, 2) {
            Ok(maxevents) => maxevents,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let timeout = match poll_timeout(arg(request, 3)) {
            Ok(timeout) => timeout,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let outcome =
            outcome(self.epoll_wait(arg_i32(request, 0), arg(request, 1), maxevents, timeout));
        if matches!(outcome.result, SyscallReturn::Success(_)) {
            if let Err(errno) = self.store_selected_process_fds(pid) {
                return SyscallOutcome::errno(errno);
            }
            if let Err(errno) = self.store_selected_process_memory(pid) {
                return SyscallOutcome::errno(errno);
            }
        }
        outcome
    }

    fn epoll_create1(&mut self, flags: u32) -> Result<u64, LinuxErrno> {
        if flags & !LINUX_EPOLL_CLOEXEC != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let epoll_id = self.epolls.create()?;
        let mut open_flags = 0;
        if flags & LINUX_EPOLL_CLOEXEC != 0 {
            open_flags |= mcr_vfs::O_CLOEXEC;
        }
        match self
            .files
            .vfs_mut()
            .insert_epoll(epoll_id, OpenFlags::new(open_flags))
        {
            Ok(fd) => Ok(fd as u64),
            Err(error) => {
                self.epolls.close(epoll_id);
                Err(vfs_errno(error))
            }
        }
    }

    fn epoll_ctl(
        &mut self,
        epfd: Fd,
        operation: u32,
        fd: Fd,
        event_addr: u64,
    ) -> Result<u64, LinuxErrno> {
        if fd < 0 {
            return Err(LinuxErrno::EBADF);
        }
        let epoll_id = self.files.vfs().epoll_id_for_fd(epfd).map_err(vfs_errno)?;
        if fd == epfd {
            return Err(LinuxErrno::EINVAL);
        }
        self.files.vfs().poll_readiness(fd).map_err(vfs_errno)?;

        match operation {
            LINUX_EPOLL_CTL_ADD => {
                let event = read_epoll_event(self.files.memory(), event_addr)?;
                let instance = self.epolls.instance_mut(epoll_id)?;
                if instance.watches.contains_key(&fd) {
                    return Err(LinuxErrno::EEXIST);
                }
                instance.watches.insert(
                    fd,
                    EpollWatch {
                        fd,
                        events: event.events,
                        data: event.data,
                    },
                );
            }
            LINUX_EPOLL_CTL_MOD => {
                let event = read_epoll_event(self.files.memory(), event_addr)?;
                let instance = self.epolls.instance_mut(epoll_id)?;
                let watch = instance.watches.get_mut(&fd).ok_or(LinuxErrno::ENOENT)?;
                watch.events = event.events;
                watch.data = event.data;
            }
            LINUX_EPOLL_CTL_DEL => {
                let instance = self.epolls.instance_mut(epoll_id)?;
                if instance.watches.remove(&fd).is_none() {
                    return Err(LinuxErrno::ENOENT);
                }
            }
            _ => return Err(LinuxErrno::EINVAL),
        }
        Ok(0)
    }

    fn epoll_wait(
        &mut self,
        epfd: Fd,
        events_addr: u64,
        maxevents: usize,
        _timeout: Option<Duration>,
    ) -> Result<u64, LinuxErrno> {
        const MAX_EPOLL_EVENTS: usize = 4096;
        if maxevents == 0 || maxevents > MAX_EPOLL_EVENTS {
            return Err(LinuxErrno::EINVAL);
        }
        let epoll_id = self.files.vfs().epoll_id_for_fd(epfd).map_err(vfs_errno)?;
        let watches = self
            .epolls
            .instance(epoll_id)?
            .watches
            .values()
            .cloned()
            .collect::<Vec<_>>();

        let mut ready = Vec::new();
        for watch in watches {
            let poll_events = epoll_events_to_poll_events(watch.events);
            let revents = self.epoll_watch_revents(watch.fd, poll_events)?;
            let epoll_events = poll_revents_to_epoll_events(revents, watch.events);
            if epoll_events != 0 {
                ready.push(LinuxEpollEvent {
                    events: epoll_events,
                    data: watch.data,
                });
                if ready.len() == maxevents {
                    break;
                }
            }
        }

        for (index, event) in ready.iter().enumerate() {
            let event_addr = events_addr
                .checked_add((index * EPOLL_EVENT_SIZE) as u64)
                .ok_or(LinuxErrno::EFAULT)?;
            write_epoll_event(self.files.memory_mut(), event_addr, *event)?;
        }
        Ok(ready.len() as u64)
    }

    fn epoll_watch_revents(&mut self, fd: Fd, events: i16) -> Result<i16, LinuxErrno> {
        match self.poll_fd_revents(fd, events, Some(Duration::ZERO)) {
            Ok(revents) if revents & LINUX_POLLNVAL != 0 => Ok(LINUX_POLLERR | LINUX_POLLHUP),
            Ok(revents) => Ok(revents),
            Err(errno) => Err(errno),
        }
    }
}

const POLLFD_SIZE: usize = std::mem::size_of::<LinuxPollfd>();
const EPOLL_EVENT_SIZE: usize = std::mem::size_of::<LinuxEpollEvent>();

fn poll_timeout(raw: u64) -> Result<Option<Duration>, LinuxErrno> {
    let timeout_ms = raw as i32;
    if timeout_ms < 0 {
        return Ok(None);
    }
    Ok(Some(Duration::from_millis(timeout_ms as u64)))
}

fn read_pollfd(memory: &impl GuestMemoryAccess, addr: u64) -> Result<LinuxPollfd, LinuxErrno> {
    let mut bytes = [0; POLLFD_SIZE];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(LinuxPollfd {
        fd: i32::from_le_bytes(bytes[0..4].try_into().expect("pollfd fd")),
        events: i16::from_le_bytes(bytes[4..6].try_into().expect("pollfd events")),
        revents: i16::from_le_bytes(bytes[6..8].try_into().expect("pollfd revents")),
    })
}

fn write_pollfd_revents(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    revents: i16,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(
            addr.checked_add(6).ok_or(LinuxErrno::EFAULT)?,
            &revents.to_le_bytes(),
        )
        .map_err(memory_errno)
}

fn read_epoll_event(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<LinuxEpollEvent, LinuxErrno> {
    let mut bytes = [0; EPOLL_EVENT_SIZE];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(LinuxEpollEvent {
        events: u32::from_le_bytes(bytes[0..4].try_into().expect("epoll events")),
        data: u64::from_le_bytes(bytes[4..12].try_into().expect("epoll data")),
    })
}

fn write_epoll_event(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    event: LinuxEpollEvent,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &event.events.to_le_bytes())
        .map_err(memory_errno)?;
    memory
        .write_bytes(
            addr.checked_add(4).ok_or(LinuxErrno::EFAULT)?,
            &event.data.to_le_bytes(),
        )
        .map_err(memory_errno)
}

fn epoll_events_to_poll_events(events: u32) -> i16 {
    let mut poll_events = 0;
    if events & LINUX_EPOLLIN != 0 {
        poll_events |= LINUX_POLLIN;
    }
    if events & LINUX_EPOLLOUT != 0 {
        poll_events |= LINUX_POLLOUT;
    }
    if events & LINUX_EPOLLPRI != 0 {
        poll_events |= LINUX_POLLPRI;
    }
    poll_events
}

fn poll_revents_to_epoll_events(revents: i16, interest: u32) -> u32 {
    let mut events = 0;
    if revents & LINUX_POLLIN != 0 && interest & LINUX_EPOLLIN != 0 {
        events |= LINUX_EPOLLIN;
    }
    if revents & LINUX_POLLOUT != 0 && interest & LINUX_EPOLLOUT != 0 {
        events |= LINUX_EPOLLOUT;
    }
    if revents & LINUX_POLLPRI != 0 && interest & LINUX_EPOLLPRI != 0 {
        events |= LINUX_EPOLLPRI;
    }
    if revents & LINUX_POLLERR != 0 {
        events |= LINUX_EPOLLERR;
    }
    if revents & LINUX_POLLHUP != 0 {
        events |= LINUX_EPOLLHUP;
    }
    events
}

fn poll_revents_from_vfs(readiness: FdReadiness, events: i16) -> i16 {
    let mut revents = 0;
    if readiness.readable && events & (LINUX_POLLIN | LINUX_POLLPRI) != 0 {
        revents |= LINUX_POLLIN;
    }
    if readiness.writable && events & LINUX_POLLOUT != 0 {
        revents |= LINUX_POLLOUT;
    }
    if readiness.error {
        revents |= LINUX_POLLERR;
    }
    if readiness.hang_up {
        revents |= LINUX_POLLHUP;
    }
    revents
}

fn poll_interest_to_socket_events(events: i16) -> SocketEvents {
    SocketEvents {
        readable: events & LINUX_POLLIN != 0,
        writable: events & LINUX_POLLOUT != 0,
        priority: events & LINUX_POLLPRI != 0,
        error: false,
        hang_up: false,
        invalid: false,
    }
}

fn poll_revents_from_socket_events(readiness: SocketEvents, events: i16) -> i16 {
    let mut revents = 0;
    if readiness.readable && events & LINUX_POLLIN != 0 {
        revents |= LINUX_POLLIN;
    }
    if readiness.writable && events & LINUX_POLLOUT != 0 {
        revents |= LINUX_POLLOUT;
    }
    if readiness.priority && events & LINUX_POLLPRI != 0 {
        revents |= LINUX_POLLPRI;
    }
    if readiness.error {
        revents |= LINUX_POLLERR;
    }
    if readiness.hang_up {
        revents |= LINUX_POLLHUP;
    }
    if readiness.invalid {
        revents |= LINUX_POLLNVAL;
    }
    revents
}

fn fork_child_pid(decoded: &[TraceField]) -> Option<mcr_sys::GuestPid> {
    decoded
        .iter()
        .find(|field| field.name == "guest_pid")
        .and_then(|field| field.value.parse().ok())
}

fn wait_status_from_decoded(decoded: &[TraceField]) -> Option<u32> {
    decoded
        .iter()
        .find(|field| field.name == "wait_status")
        .and_then(|field| {
            field.value.strip_prefix("0x").map_or_else(
                || field.value.parse().ok(),
                |hex| u32::from_str_radix(hex, 16).ok(),
            )
        })
}

fn read_futex_timeout(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<Option<Duration>, LinuxErrno> {
    if addr == 0 {
        return Ok(None);
    }
    let tv_sec = read_guest_i64(memory, addr)?;
    let tv_nsec = read_guest_i64(memory, addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?)?;
    if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(Some(Duration::new(tv_sec as u64, tv_nsec as u32)))
}

fn read_guest_u32(memory: &impl GuestMemoryAccess, addr: u64) -> Result<u32, LinuxErrno> {
    let mut bytes = [0; 4];
    memory
        .read_bytes(addr, &mut bytes)
        .map_err(|_| LinuxErrno::EFAULT)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_guest_i64(memory: &impl GuestMemoryAccess, addr: u64) -> Result<i64, LinuxErrno> {
    let mut bytes = [0; 8];
    memory
        .read_bytes(addr, &mut bytes)
        .map_err(|_| LinuxErrno::EFAULT)?;
    Ok(i64::from_le_bytes(bytes))
}

fn read_guest_u64(memory: &impl GuestMemoryAccess, addr: u64) -> Result<u64, LinuxErrno> {
    let mut bytes = [0; 8];
    memory
        .read_bytes(addr, &mut bytes)
        .map_err(|_| LinuxErrno::EFAULT)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_guest_c_bytes(memory: &impl GuestMemoryAccess, addr: u64) -> Result<Vec<u8>, LinuxErrno> {
    const MAX_C_STRING_LEN: usize = 4096;
    let mut bytes = Vec::new();
    for offset in 0..MAX_C_STRING_LEN {
        let mut byte = [0];
        memory
            .read_bytes(
                addr.checked_add(offset as u64).ok_or(LinuxErrno::EFAULT)?,
                &mut byte,
            )
            .map_err(|_| LinuxErrno::EFAULT)?;
        if byte[0] == 0 {
            return Ok(bytes);
        }
        bytes.push(byte[0]);
    }
    Err(LinuxErrno::ENAMETOOLONG)
}

fn guest_bytes_to_path(bytes: &[u8]) -> Result<String, LinuxErrno> {
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(LinuxErrno::ENOENT);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| LinuxErrno::ENOENT)
}

fn read_vfs_file_to_end(
    vfs: &mut VirtualFileSystem,
    fd: Fd,
    output: &mut Vec<u8>,
) -> Result<(), LinuxErrno> {
    let mut buffer = [0; 8192];
    loop {
        let count = vfs.read(fd, &mut buffer).map_err(vfs_errno)?;
        if count == 0 {
            return Ok(());
        }
        output.len().checked_add(count).ok_or(LinuxErrno::EFBIG)?;
        output.extend_from_slice(&buffer[..count]);
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Task(TaskError),
    Memory(GuestMemoryError),
    Network(mcr_net::HostIoError),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Task(error) => write!(formatter, "{error}"),
            Self::Memory(error) => write!(formatter, "{error:?}"),
            Self::Network(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<TaskError> for RuntimeError {
    fn from(value: TaskError) -> Self {
        Self::Task(value)
    }
}

impl From<GuestMemoryError> for RuntimeError {
    fn from(value: GuestMemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<mcr_net::HostIoError> for RuntimeError {
    fn from(value: mcr_net::HostIoError) -> Self {
        Self::Network(value)
    }
}

impl From<Runtime> for SyscallDispatcher<RuntimeSubsystems, NoopSyscallTracer> {
    fn from(value: Runtime) -> Self {
        value.dispatcher
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeDiagnosticsTracer {
    events: Vec<SyscallTraceEvent>,
}

impl RuntimeDiagnosticsTracer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn events(&self) -> &[SyscallTraceEvent] {
        &self.events
    }

    #[must_use]
    pub fn last_syscall(&self) -> Option<DiagnosticSyscall> {
        self.events
            .iter()
            .rev()
            .find_map(DiagnosticSyscall::from_event)
    }

    #[must_use]
    pub fn into_events(self) -> Vec<SyscallTraceEvent> {
        self.events
    }
}

impl SyscallTracer for RuntimeDiagnosticsTracer {
    fn record(&mut self, event: SyscallTraceEvent) {
        self.events.push(event);
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

    use mcr_net::SocketState;
    use mcr_sys::{
        GuestContext, InMemorySyscallTracer, LINUX_AF_INET, LINUX_AF_INET6, LINUX_EPOLL_CLOEXEC,
        LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD, LINUX_EPOLLERR,
        LINUX_EPOLLHUP, LINUX_EPOLLIN, LINUX_EPOLLOUT, LINUX_IPPROTO_TCP, LINUX_MAP_ANONYMOUS,
        LINUX_MAP_FIXED, LINUX_MAP_PRIVATE, LINUX_POLLHUP, LINUX_POLLIN, LINUX_POLLNVAL,
        LINUX_POLLOUT, LINUX_PROT_READ, LINUX_PROT_WRITE, LINUX_SHUT_RDWR, LINUX_SO_ERROR,
        LINUX_SO_KEEPALIVE, LINUX_SO_REUSEADDR, LINUX_SO_TYPE, LINUX_SOCK_CLOEXEC,
        LINUX_SOCK_DGRAM, LINUX_SOCK_NONBLOCK, LINUX_SOCK_STREAM, LINUX_SOL_SOCKET,
        LINUX_TCP_NODELAY, Syscall, SyscallRegisters, SyscallReturn, SyscallTraceEvent,
    };
    use mcr_task::{ARCH_SET_FS, ExitState, INITIAL_GUEST_PID, INITIAL_GUEST_TID};
    use mcr_testkit::elf::{Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X};
    use mcr_vfs::{
        AT_FDCWD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, FIONREAD, FdTable, O_CLOEXEC, O_CREAT,
        O_DIRECTORY, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, PathTree, RENAME_NOREPLACE, Rootfs,
        TIOCGWINSZ, VirtualFileSystem,
    };

    use super::*;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-runtime");
    }

    #[test]
    fn dispatcher_connects_openat_read_write_lseek_and_close_to_vfs() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
        runtime.memory_mut().write(0x2000, b"!!");
        let fd = dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDWR), 0, 0, 0],
        );
        assert_eq!(fd, SyscallReturn::Success(3));

        assert_eq!(
            dispatch(&mut runtime, Syscall::Lseek, [3, 5, 0, 0, 0, 0]),
            SyscallReturn::Success(5)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Write, [3, 0x2000, 2, 0, 0, 0]),
            SyscallReturn::Success(2)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Lseek, [3, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Read, [3, 0x3000, 7, 0, 0, 0]),
            SyscallReturn::Success(7)
        );
        assert_eq!(runtime.memory().read(0x3000, 7), b"hello!!");
        assert_eq!(
            dispatch(&mut runtime, Syscall::Close, [3, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Read, [3, 0x3000, 1, 0, 0, 0]),
            SyscallReturn::Errno(LinuxErrno::EBADF)
        );
    }

    #[test]
    fn close_releases_socket_table_entry_after_vfs_fd() {
        let transport = runtime_socket_transport();
        let mut runtime = RuntimeFileSystem::with_socket_transport(
            sample_vfs(),
            TestMemory::default(),
            transport.handle(),
        );
        runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Connect,
                [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Close, [3, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );

        let socket_id = SocketId::new(1).unwrap();
        assert_eq!(
            runtime.sockets().socket(socket_id).unwrap().state(),
            SocketState::Closed
        );
        assert_eq!(
            dispatch_network(&mut runtime, Syscall::Sendto, [3, 0x2000, 0, 0, 0, 0],),
            SyscallReturn::Errno(LinuxErrno::EBADF)
        );
    }

    #[test]
    fn runtime_wires_task_syscalls_through_dispatcher() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        let result = runtime.dispatch_syscall(context(Syscall::Getpid, [0; 6]));

        assert_eq!(result.result, SyscallReturn::Success(1));
        assert_eq!(result.encoded_rax, 1);
        assert_eq!(
            runtime.kernel().process(INITIAL_GUEST_PID).unwrap().pid(),
            1
        );
    }

    #[test]
    fn runtime_file_backed_mmap_populates_private_mapping_from_vfs_fd() {
        let mut runtime =
            Runtime::with_vfs(test_program("/bin/app", 0x401000), sample_vfs()).unwrap();
        runtime
            .memory_mut()
            .write(0x402000, b"/tmp/file\0")
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Openat,
                    [AT_FDCWD as u64, 0x402000, u64::from(O_RDONLY), 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(3)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Lseek, [3, 2, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(2)
        );

        let mapped = runtime.dispatch_syscall(context(
            Syscall::Mmap,
            [
                0x7000_0000,
                GUEST_PAGE_SIZE,
                u64::from(mcr_sys::LINUX_PROT_READ),
                u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_FIXED),
                3,
                0,
            ],
        ));

        assert_eq!(mapped.result, SyscallReturn::Success(0x7000_0000));
        let mut bytes = [0; 8];
        runtime.memory().read(0x7000_0000, &mut bytes).unwrap();
        assert_eq!(&bytes[..5], b"hello");
        assert_eq!(&bytes[5..], &[0, 0, 0]);
        assert_eq!(runtime.vfs().fds().get(3).unwrap().offset(), 2);
        assert_eq!(
            runtime.memory_mut().write(0x7000_0000, b"x"),
            Err(GuestMemoryError::AccessDenied)
        );
    }

    #[test]
    fn private_futex_wait_mismatch_returns_eagain() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        runtime
            .memory_mut()
            .write(0x402000, &0u32.to_le_bytes())
            .unwrap();

        let result = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x402000,
                u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
                1,
                0,
                0,
                0,
            ],
        ));

        assert_eq!(result.result, SyscallReturn::Errno(LinuxErrno::EAGAIN));
    }

    #[test]
    fn private_futex_wait_unmapped_returns_efault() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        let result = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x7000_0000,
                u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
                0,
                0,
                0,
                0,
            ],
        ));

        assert_eq!(result.result, SyscallReturn::Errno(LinuxErrno::EFAULT));
    }

    #[test]
    fn private_futex_unaligned_uaddr_returns_einval() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        let result = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x402001,
                u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
                0,
                0,
                0,
                0,
            ],
        ));

        assert_eq!(result.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
    }

    #[test]
    fn process_shared_futex_wait_and_wake_return_enosys() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        let wait = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [0x402000, u64::from(LINUX_FUTEX_WAIT), 0, 0, 0, 0],
        ));
        let wake = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [0x402000, u64::from(LINUX_FUTEX_WAKE), 1, 0, 0, 0],
        ));

        assert_eq!(wait.result, SyscallReturn::Errno(LinuxErrno::ENOSYS));
        assert_eq!(wake.result, SyscallReturn::Errno(LinuxErrno::ENOSYS));
    }

    #[test]
    fn futex_unknown_command_and_unsupported_flags_return_einval() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        let unknown = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x402000,
                u64::from(99 | LINUX_FUTEX_PRIVATE_FLAG),
                0,
                0,
                0,
                0,
            ],
        ));
        let unsupported_flags = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x402000,
                u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG | 0x100),
                0,
                0,
                0,
                0,
            ],
        ));

        assert_eq!(unknown.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
        assert_eq!(
            unsupported_flags.result,
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
    }

    #[test]
    fn private_futex_wake_returns_zero_without_waiter_registry() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        let result = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x402000,
                u64::from(LINUX_FUTEX_WAKE | LINUX_FUTEX_PRIVATE_FLAG),
                1,
                0,
                0,
                0,
            ],
        ));

        assert_eq!(result.result, SyscallReturn::Success(0));
    }

    #[test]
    fn private_futex_null_timeout_wait_does_not_return_success_or_count_fake_waiter() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        runtime
            .memory_mut()
            .write(0x402000, &7u32.to_le_bytes())
            .unwrap();

        let wait = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x402000,
                u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
                7,
                0,
                0,
                0,
            ],
        ));
        let wake = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x402000,
                u64::from(LINUX_FUTEX_WAKE | LINUX_FUTEX_PRIVATE_FLAG),
                1,
                0,
                0,
                0,
            ],
        ));

        assert_eq!(wait.result, SyscallReturn::Errno(LinuxErrno::EAGAIN));
        assert_eq!(wake.result, SyscallReturn::Success(0));
    }

    #[test]
    fn runtime_memory_syscalls_update_memory_used_by_futex() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        let mmap = runtime.dispatch_syscall(context(
            Syscall::Mmap,
            [
                0,
                GUEST_PAGE_SIZE,
                u64::from(LINUX_PROT_READ | LINUX_PROT_WRITE),
                u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS),
                u64::MAX,
                0,
            ],
        ));
        let SyscallReturn::Success(addr) = mmap.result else {
            panic!("mmap should succeed: {:?}", mmap.result);
        };
        runtime
            .memory_mut()
            .write(addr, &9u32.to_le_bytes())
            .unwrap();
        runtime.memory_mut().write(0x402000, &[0; 16]).unwrap();

        let wait = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                addr,
                u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
                9,
                0x402000,
                0,
                0,
            ],
        ));

        assert_eq!(wait.result, SyscallReturn::Errno(LinuxErrno::ETIMEDOUT));
    }

    #[test]
    fn private_futex_wait_timeout_pointer_is_validated_and_controls_timeout() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        runtime
            .memory_mut()
            .write(0x402000, &1u32.to_le_bytes())
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402100, &0i64.to_le_bytes())
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402108, &1_000_000_000i64.to_le_bytes())
            .unwrap();

        let invalid = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x402000,
                u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
                1,
                0x402100,
                0,
                0,
            ],
        ));
        runtime
            .memory_mut()
            .write(0x402108, &0i64.to_le_bytes())
            .unwrap();
        let timed_out = runtime.dispatch_syscall(context(
            Syscall::Futex,
            [
                0x402000,
                u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
                1,
                0x402100,
                0,
                0,
            ],
        ));

        assert_eq!(invalid.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
        assert_eq!(
            timed_out.result,
            SyscallReturn::Errno(LinuxErrno::ETIMEDOUT)
        );
    }

    #[test]
    fn private_futex_registry_wake_releases_registered_waiter() {
        let mut registry = FutexRegistry::default();
        let waiter_registry = registry.clone();
        let waiter = std::thread::spawn(move || {
            let mut registry = waiter_registry;
            registry.wait(0x402000, 3, Some(Duration::from_secs(5)), || false)
        });

        while registry.waiter_count(0x402000) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }

        assert_eq!(registry.wake(0x402000, 1), 1);
        assert_eq!(waiter.join().unwrap(), Ok(0));
        assert_eq!(registry.waiter_count(0x402000), 0);
    }

    #[test]
    fn runtime_dispatch_routes_socket_control_syscalls_through_vfs() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        let socket = runtime.dispatch_syscall(context(
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM | LINUX_SOCK_CLOEXEC | LINUX_SOCK_NONBLOCK),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ));
        assert_eq!(socket.result, SyscallReturn::Success(3));

        let fcntl_fd =
            runtime.dispatch_syscall(context(Syscall::Fcntl, [3, u64::from(F_GETFD), 0, 0, 0, 0]));
        assert_eq!(
            fcntl_fd.result,
            SyscallReturn::Success(u64::from(mcr_vfs::FD_CLOEXEC))
        );

        let fcntl_fl =
            runtime.dispatch_syscall(context(Syscall::Fcntl, [3, u64::from(F_GETFL), 0, 0, 0, 0]));
        assert_eq!(
            fcntl_fl.result,
            SyscallReturn::Success(u64::from(O_RDWR | O_NONBLOCK))
        );

        let fstat = runtime.dispatch_syscall(context(Syscall::Fstat, [3, 0x402000, 0, 0, 0, 0]));
        assert_eq!(fstat.result, SyscallReturn::Success(0));
        let mut mode = [0; 4];
        runtime.memory().read(0x402000 + 24, &mut mode).unwrap();
        assert_eq!(
            u32::from_le_bytes(mode) & mcr_vfs::S_IFMT,
            mcr_vfs::S_IFSOCK
        );
    }

    #[test]
    fn runtime_dispatch_reads_proc_self_from_current_process_image() {
        let mut runtime = Runtime::new(test_program_with_args(
            "/bin/app",
            0x401000,
            ["/bin/app", "--flag"],
            ["A=B"],
        ))
        .unwrap();
        runtime
            .memory_mut()
            .write(0x402100, b"/proc/self/cmdline\0")
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402140, b"/proc/self/environ\0")
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402180, b"/proc/self/exe\0")
            .unwrap();
        runtime
            .memory_mut()
            .write(0x4021c0, b"/proc/self/fd/3\0")
            .unwrap();

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Openat,
                    [AT_FDCWD as u64, 0x402100, u64::from(O_RDONLY), 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(3)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Read, [3, 0x402300, 64, 0, 0, 0]))
                .result,
            SyscallReturn::Success(16)
        );
        let mut cmdline = [0; 16];
        runtime.memory().read(0x402300, &mut cmdline).unwrap();
        assert_eq!(&cmdline, b"/bin/app\0--flag\0");

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Openat,
                    [AT_FDCWD as u64, 0x402140, u64::from(O_RDONLY), 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(4)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Read, [4, 0x402320, 64, 0, 0, 0]))
                .result,
            SyscallReturn::Success(4)
        );
        let mut environ = [0; 4];
        runtime.memory().read(0x402320, &mut environ).unwrap();
        assert_eq!(&environ, b"A=B\0");

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Readlink,
                    [0x402180, 0x402340, 64, 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(8)
        );
        let mut exe = [0; 8];
        runtime.memory().read(0x402340, &mut exe).unwrap();
        assert_eq!(&exe, b"/bin/app");

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Readlink,
                    [0x4021c0, 0x402360, 64, 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(18)
        );
        let mut fd_target = [0; 18];
        runtime.memory().read(0x402360, &mut fd_target).unwrap();
        assert_eq!(&fd_target, b"/proc/self/cmdline");
    }

    #[test]
    fn runtime_dispatch_routes_socket_address_and_option_controls() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Socket,
                    [
                        u64::from(LINUX_AF_INET),
                        u64::from(LINUX_SOCK_STREAM),
                        u64::from(LINUX_IPPROTO_TCP),
                        0,
                        0,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(3)
        );

        runtime
            .memory_mut()
            .write(0x402000, &ipv4_sockaddr(8080))
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Bind,
                    [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Listen, [3, 16, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(0)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Accept4, [3, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Errno(LinuxErrno::EAGAIN)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Accept, [3, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Errno(LinuxErrno::EAGAIN)
        );

        runtime
            .memory_mut()
            .write(0x402100, &(SOCKADDR_IN_LEN as u32).to_le_bytes())
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Getsockname,
                    [3, 0x402200, 0x402100, 0, 0, 0],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        let mut len = [0; 4];
        runtime.memory().read(0x402100, &mut len).unwrap();
        assert_eq!(u32::from_le_bytes(len), SOCKADDR_IN_LEN as u32);

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Socket,
                    [
                        u64::from(LINUX_AF_INET),
                        u64::from(LINUX_SOCK_STREAM),
                        u64::from(LINUX_IPPROTO_TCP),
                        0,
                        0,
                        0,
                    ]
                ))
                .result,
            SyscallReturn::Success(4)
        );
        runtime
            .memory_mut()
            .write(0x402300, &ipv4_sockaddr(443))
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Connect,
                    [4, 0x402300, SOCKADDR_IN_LEN as u64, 0, 0, 0],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        runtime
            .memory_mut()
            .write(0x402400, &(SOCKADDR_IN_LEN as u32).to_le_bytes())
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Getpeername,
                    [4, 0x402500, 0x402400, 0, 0, 0],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Shutdown,
                    [4, u64::from(LINUX_SHUT_RDWR), 0, 0, 0, 0],
                ))
                .result,
            SyscallReturn::Success(0)
        );

        runtime
            .memory_mut()
            .write(0x402600, &1u32.to_le_bytes())
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Setsockopt,
                    [
                        4,
                        u64::from(LINUX_SOL_SOCKET),
                        u64::from(LINUX_SO_REUSEADDR),
                        0x402600,
                        4,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        runtime
            .memory_mut()
            .write(0x402800, &4u32.to_le_bytes())
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Getsockopt,
                    [
                        4,
                        u64::from(LINUX_SOL_SOCKET),
                        u64::from(LINUX_SO_REUSEADDR),
                        0x402700,
                        0x402800,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        let mut opt = [0; 4];
        runtime.memory().read(0x402700, &mut opt).unwrap();
        assert_eq!(u32::from_le_bytes(opt), 1);
    }

    #[test]
    fn poll_reports_regular_file_readiness_and_invalid_fds() {
        let mut runtime =
            Runtime::with_vfs(test_program("/bin/app", 0x401000), sample_vfs()).unwrap();
        runtime
            .memory_mut()
            .write(0x402000, b"/tmp/file\0")
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Openat,
                    [AT_FDCWD as u64, 0x402000, u64::from(O_RDONLY), 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(3)
        );
        write_pollfd(
            runtime.memory_mut(),
            0x402100,
            3,
            LINUX_POLLIN | LINUX_POLLOUT,
        );
        write_pollfd(runtime.memory_mut(), 0x402108, 99, LINUX_POLLIN);

        let result = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 2, 0, 0, 0, 0]));

        assert_eq!(result.result, SyscallReturn::Success(2));
        assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLIN);
        assert_eq!(pollfd_revents(runtime.memory(), 0x402108), LINUX_POLLNVAL);

        write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLIN);
        let infinite_timeout =
            runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, u64::MAX, 0, 0, 0]));
        assert_eq!(infinite_timeout.result, SyscallReturn::Success(1));
        assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLIN);
    }

    #[test]
    fn poll_reports_pipe_buffer_state_and_hangup() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(0)
        );
        let read_fd = i32_from_memory(runtime.memory(), 0x402000);
        let write_fd = i32_from_memory(runtime.memory(), 0x402004);
        write_pollfd(runtime.memory_mut(), 0x402100, read_fd, LINUX_POLLIN);

        let empty = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
        assert_eq!(empty.result, SyscallReturn::Success(0));
        assert_eq!(pollfd_revents(runtime.memory(), 0x402100), 0);

        runtime.memory_mut().write(0x402200, b"x").unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Write,
                    [write_fd as u64, 0x402200, 1, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(1)
        );
        write_pollfd(runtime.memory_mut(), 0x402100, read_fd, LINUX_POLLIN);
        let readable = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
        assert_eq!(readable.result, SyscallReturn::Success(1));
        assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLIN);

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Read,
                    [read_fd as u64, 0x402300, 1, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(1)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Close, [write_fd as u64, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(0)
        );
        write_pollfd(runtime.memory_mut(), 0x402100, read_fd, LINUX_POLLIN);
        let hangup = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
        assert_eq!(hangup.result, SyscallReturn::Success(1));
        assert_eq!(
            pollfd_revents(runtime.memory(), 0x402100),
            LINUX_POLLIN | LINUX_POLLHUP
        );
    }

    #[test]
    fn poll_reports_socket_transport_readiness() {
        let transport = runtime_socket_transport();
        transport.push_incoming(b"pong");
        let mut runtime = Runtime::with_vfs_and_socket_transport(
            test_program("/bin/app", 0x401000),
            sample_vfs(),
            transport.handle(),
        )
        .unwrap();
        runtime
            .memory_mut()
            .write(0x402000, &ipv4_sockaddr(8080))
            .unwrap();

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Socket,
                    [
                        u64::from(LINUX_AF_INET),
                        u64::from(LINUX_SOCK_STREAM),
                        u64::from(LINUX_IPPROTO_TCP),
                        0,
                        0,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(3)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Connect,
                    [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(0)
        );
        write_pollfd(
            runtime.memory_mut(),
            0x402100,
            3,
            LINUX_POLLIN | LINUX_POLLOUT,
        );

        let result = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));

        assert_eq!(result.result, SyscallReturn::Success(1));
        assert_eq!(
            pollfd_revents(runtime.memory(), 0x402100),
            LINUX_POLLIN | LINUX_POLLOUT
        );
    }

    #[test]
    fn runtime_nonblocking_connect_completes_after_poll_writable() {
        let transport = runtime_socket_transport();
        transport.set_connect_would_block_once();
        let mut runtime = Runtime::with_vfs_and_socket_transport(
            test_program("/bin/app", 0x401000),
            sample_vfs(),
            transport.handle(),
        )
        .unwrap();
        runtime
            .memory_mut()
            .write(0x402000, &ipv4_sockaddr(8080))
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402300, &4u32.to_le_bytes())
            .unwrap();

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Socket,
                    [
                        u64::from(LINUX_AF_INET),
                        u64::from(LINUX_SOCK_STREAM | LINUX_SOCK_NONBLOCK),
                        u64::from(LINUX_IPPROTO_TCP),
                        0,
                        0,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(3)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Connect,
                    [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Errno(LinuxErrno::EINPROGRESS)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Getsockopt,
                    [
                        3,
                        u64::from(LINUX_SOL_SOCKET),
                        u64::from(LINUX_SO_ERROR),
                        0x402200,
                        0x402300,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        assert_eq!(
            u32_from_guest(runtime.memory(), 0x402200),
            u32::from(LinuxErrno::EINPROGRESS.raw())
        );

        write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLOUT);
        let ready = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
        assert_eq!(ready.result, SyscallReturn::Success(1));
        assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLOUT);

        runtime
            .memory_mut()
            .write(0x402300, &4u32.to_le_bytes())
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Getsockopt,
                    [
                        3,
                        u64::from(LINUX_SOL_SOCKET),
                        u64::from(LINUX_SO_ERROR),
                        0x402200,
                        0x402300,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        assert_eq!(u32_from_guest(runtime.memory(), 0x402200), 0);
    }

    #[test]
    fn ppoll_reads_timespec_and_rejects_signal_masks() {
        let mut runtime =
            Runtime::with_vfs(test_program("/bin/app", 0x401000), sample_vfs()).unwrap();
        runtime
            .memory_mut()
            .write(0x402000, b"/tmp/file\0")
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Openat,
                    [AT_FDCWD as u64, 0x402000, u64::from(O_RDONLY), 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(3)
        );
        write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLIN);
        write_timespec(runtime.memory_mut(), 0x402200, 0, 0);

        let ready =
            runtime.dispatch_syscall(context(Syscall::Ppoll, [0x402100, 1, 0x402200, 0, 0, 0]));
        assert_eq!(ready.result, SyscallReturn::Success(1));
        assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLIN);

        write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLIN);
        write_timespec(runtime.memory_mut(), 0x402200, 0, 1_000_000_000);
        let invalid_timespec =
            runtime.dispatch_syscall(context(Syscall::Ppoll, [0x402100, 1, 0x402200, 0, 0, 0]));
        assert_eq!(
            invalid_timespec.result,
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );

        let sigmask =
            runtime.dispatch_syscall(context(Syscall::Ppoll, [0x402100, 1, 0x402200, 1, 8, 0]));
        assert_eq!(sigmask.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
    }

    #[test]
    fn epoll_create1_allocates_cloexec_event_fd() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        let epfd = runtime.dispatch_syscall(context(
            Syscall::EpollCreate1,
            [u64::from(LINUX_EPOLL_CLOEXEC), 0, 0, 0, 0, 0],
        ));
        assert_eq!(epfd.result, SyscallReturn::Success(3));
        assert!(runtime.vfs().fds().cloexec(3).unwrap());

        let invalid =
            runtime.dispatch_syscall(context(Syscall::EpollCreate1, [0x8000_0000, 0, 0, 0, 0, 0]));
        assert_eq!(invalid.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
    }

    #[test]
    fn epoll_wait_reports_pipe_readiness_level_triggered() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(0)
        );
        let read_fd = i32_from_memory(runtime.memory(), 0x402000);
        let write_fd = i32_from_memory(runtime.memory(), 0x402004);
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(5)
        );
        write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 0xfeed);
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::EpollCtl,
                    [
                        5,
                        u64::from(LINUX_EPOLL_CTL_ADD),
                        read_fd as u64,
                        0x402100,
                        0,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        let empty =
            runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
        assert_eq!(empty.result, SyscallReturn::Success(0));

        runtime.memory_mut().write(0x402300, b"x").unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Write,
                    [write_fd as u64, 0x402300, 1, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(1)
        );

        let ready =
            runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
        assert_eq!(ready.result, SyscallReturn::Success(1));
        assert_eq!(
            epoll_event_from_memory(runtime.memory(), 0x402200),
            (LINUX_EPOLLIN, 0xfeed)
        );

        let still_ready =
            runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
        assert_eq!(still_ready.result, SyscallReturn::Success(1));
    }

    #[test]
    fn epoll_ctl_mod_and_del_update_watch_set() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(0)
        );
        let read_fd = i32_from_memory(runtime.memory(), 0x402000);
        let write_fd = i32_from_memory(runtime.memory(), 0x402004);
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(5)
        );
        write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 1);
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::EpollCtl,
                    [
                        5,
                        u64::from(LINUX_EPOLL_CTL_ADD),
                        read_fd as u64,
                        0x402100,
                        0,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        write_epoll_event_for_test(runtime.memory_mut(), 0x402110, LINUX_EPOLLOUT, 2);
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::EpollCtl,
                    [
                        5,
                        u64::from(LINUX_EPOLL_CTL_MOD),
                        write_fd as u64,
                        0x402110,
                        0,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Errno(LinuxErrno::ENOENT)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::EpollCtl,
                    [
                        5,
                        u64::from(LINUX_EPOLL_CTL_MOD),
                        read_fd as u64,
                        0x402110,
                        0,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(0)
        );

        let not_ready =
            runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
        assert_eq!(not_ready.result, SyscallReturn::Success(0));
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::EpollCtl,
                    [5, u64::from(LINUX_EPOLL_CTL_DEL), read_fd as u64, 0, 0, 0,],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::EpollCtl,
                    [5, u64::from(LINUX_EPOLL_CTL_DEL), read_fd as u64, 0, 0, 0,],
                ))
                .result,
            SyscallReturn::Errno(LinuxErrno::ENOENT)
        );
    }

    #[test]
    fn epoll_wait_reports_closed_watch_as_hup_error() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(0)
        );
        let read_fd = i32_from_memory(runtime.memory(), 0x402000);
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(5)
        );
        write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 9);
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::EpollCtl,
                    [
                        5,
                        u64::from(LINUX_EPOLL_CTL_ADD),
                        read_fd as u64,
                        0x402100,
                        0,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Success(0)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Close, [read_fd as u64, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(0)
        );

        let ready =
            runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
        assert_eq!(ready.result, SyscallReturn::Success(1));
        assert_eq!(
            epoll_event_from_memory(runtime.memory(), 0x402200),
            (LINUX_EPOLLERR | LINUX_EPOLLHUP, 9)
        );
    }

    #[test]
    fn connected_socket_sendto_and_recvfrom_move_guest_buffers() {
        let transport = runtime_socket_transport();
        transport.push_incoming(b"pong");
        let mut runtime = RuntimeFileSystem::with_socket_transport(
            sample_vfs(),
            TestMemory::default(),
            transport.handle(),
        );
        runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));
        runtime.memory_mut().write(0x2000, b"ping");

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Connect,
                [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Sendto,
                [3, 0x2000, 4, u64::from(LINUX_MSG_NOSIGNAL), 0, 0],
            ),
            SyscallReturn::Success(4)
        );
        assert_eq!(transport.sent_bytes(), b"ping");

        assert_eq!(
            dispatch_network(&mut runtime, Syscall::Recvfrom, [3, 0x2100, 8, 0, 0, 0],),
            SyscallReturn::Success(4)
        );
        assert_eq!(runtime.memory().read(0x2100, 4), b"pong");
    }

    #[test]
    fn connected_socket_sendmsg_and_recvmsg_move_iovecs() {
        let transport = runtime_socket_transport();
        transport.push_incoming(b"abcdef");
        let mut runtime = RuntimeFileSystem::with_socket_transport(
            sample_vfs(),
            TestMemory::default(),
            transport.handle(),
        );
        runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));
        runtime.memory_mut().write(0x2000, b"ab");
        runtime.memory_mut().write(0x2010, b"cd");
        runtime.memory_mut().write_iovec(0x3000, 0x2000, 2);
        runtime.memory_mut().write_iovec(0x3010, 0x2010, 2);
        runtime.memory_mut().write_msghdr(0x4000, 0, 0, 0x3000, 2);
        runtime.memory_mut().write_iovec(0x5000, 0x6000, 3);
        runtime.memory_mut().write_iovec(0x5010, 0x6010, 3);
        runtime.memory_mut().write_msghdr(0x5100, 0, 0, 0x5000, 2);

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Connect,
                [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );

        assert_eq!(
            dispatch_network(&mut runtime, Syscall::Sendmsg, [3, 0x4000, 0, 0, 0, 0],),
            SyscallReturn::Success(4)
        );
        assert_eq!(transport.sent_bytes(), b"abcd");
        assert_eq!(
            dispatch_network(&mut runtime, Syscall::Recvmsg, [3, 0x5100, 0, 0, 0, 0],),
            SyscallReturn::Success(6)
        );
        assert_eq!(runtime.memory().read(0x6000, 3), b"abc");
        assert_eq!(runtime.memory().read(0x6010, 3), b"def");
        assert_eq!(u32_at(runtime.memory(), 0x5100 + 48), 0);
    }

    #[test]
    fn datagram_sendto_and_recvfrom_move_guest_buffers_and_addresses() {
        let transport = runtime_socket_transport();
        transport.push_incoming(b"dns!");
        let mut runtime = RuntimeFileSystem::with_socket_transport(
            sample_vfs(),
            TestMemory::default(),
            transport.handle(),
        );
        runtime.memory_mut().write(0x1000, &ipv4_sockaddr(53));
        runtime.memory_mut().write(0x2000, b"query");
        runtime.memory_mut().write(0x2200, &[0xaa; SOCKADDR_IN_LEN]);
        runtime
            .memory_mut()
            .write(0x2300, &(SOCKADDR_IN_LEN as u32).to_le_bytes());

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_DGRAM),
                    u64::from(mcr_sys::LINUX_IPPROTO_UDP),
                    0,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Sendto,
                [
                    3,
                    0x2000,
                    5,
                    u64::from(LINUX_MSG_DONTWAIT | LINUX_MSG_NOSIGNAL),
                    0x1000,
                    SOCKADDR_IN_LEN as u64,
                ],
            ),
            SyscallReturn::Success(5)
        );
        assert_eq!(transport.sent_bytes(), b"query");

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Recvfrom,
                [3, 0x2100, 8, u64::from(LINUX_MSG_DONTWAIT), 0x2200, 0x2300],
            ),
            SyscallReturn::Success(4)
        );
        assert_eq!(runtime.memory().read(0x2100, 4), b"dns!");
        assert_eq!(u32_at(runtime.memory(), 0x2300), SOCKADDR_IN_LEN as u32);
        assert_eq!(
            runtime.memory().read(0x2200, SOCKADDR_IN_LEN),
            ipv4_sockaddr(53)
        );
    }

    #[test]
    fn datagram_sendmsg_and_recvmsg_move_iovecs_and_addresses() {
        let transport = runtime_socket_transport();
        transport.push_incoming(b"dns!");
        let mut runtime = RuntimeFileSystem::with_socket_transport(
            sample_vfs(),
            TestMemory::default(),
            transport.handle(),
        );
        runtime.memory_mut().write(0x1000, &ipv4_sockaddr(53));
        runtime.memory_mut().write(0x2000, b"dn");
        runtime.memory_mut().write(0x2010, b"s?");
        runtime.memory_mut().write_iovec(0x3000, 0x2000, 2);
        runtime.memory_mut().write_iovec(0x3010, 0x2010, 2);
        runtime
            .memory_mut()
            .write_msghdr(0x4000, 0x1000, SOCKADDR_IN_LEN as u32, 0x3000, 2);
        runtime.memory_mut().write_iovec(0x5000, 0x6000, 2);
        runtime.memory_mut().write_iovec(0x5010, 0x6010, 2);
        runtime.memory_mut().write(0x5200, &[0xaa; SOCKADDR_IN_LEN]);
        runtime
            .memory_mut()
            .write_msghdr(0x5100, 0x5200, SOCKADDR_IN_LEN as u32, 0x5000, 2);

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_DGRAM),
                    u64::from(mcr_sys::LINUX_IPPROTO_UDP),
                    0,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Sendmsg,
                [3, 0x4000, u64::from(LINUX_MSG_DONTWAIT), 0, 0, 0],
            ),
            SyscallReturn::Success(4)
        );
        assert_eq!(transport.sent_bytes(), b"dns?");

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Recvmsg,
                [3, 0x5100, u64::from(LINUX_MSG_DONTWAIT), 0, 0, 0],
            ),
            SyscallReturn::Success(4)
        );
        assert_eq!(runtime.memory().read(0x6000, 2), b"dn");
        assert_eq!(runtime.memory().read(0x6010, 2), b"s!");
        assert_eq!(
            runtime.memory().read(0x5200, SOCKADDR_IN_LEN),
            ipv4_sockaddr(53)
        );
        assert_eq!(u32_at(runtime.memory(), 0x5100 + 8), SOCKADDR_IN_LEN as u32);
        assert_eq!(u32_at(runtime.memory(), 0x5100 + 48), 0);
    }

    #[test]
    fn readv_writev_move_multiple_guest_buffers() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/tmp/iov");
        runtime.memory_mut().write(0x2100, b"ab");
        runtime.memory_mut().write(0x2200, b"cd");
        runtime.memory_mut().write_iovec(0x2000, 0x2100, 2);
        runtime.memory_mut().write_iovec(0x2010, 0x2200, 2);
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [
                    AT_FDCWD as u64,
                    0x1000,
                    u64::from(mcr_vfs::O_CREAT | O_RDWR),
                    0o644,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Writev, [3, 0x2000, 2, 0, 0, 0]),
            SyscallReturn::Success(4)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Lseek, [3, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        runtime.memory_mut().write_iovec(0x3000, 0x3100, 2);
        runtime.memory_mut().write_iovec(0x3010, 0x3200, 2);
        assert_eq!(
            dispatch(&mut runtime, Syscall::Readv, [3, 0x3000, 2, 0, 0, 0]),
            SyscallReturn::Success(4)
        );
        assert_eq!(runtime.memory().read(0x3100, 2), b"ab");
        assert_eq!(runtime.memory().read(0x3200, 2), b"cd");
    }

    #[test]
    fn stat_access_readlink_and_getdents64_write_linux_layouts() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
        runtime.memory_mut().write_cstr(0x1100, "/tmp");
        runtime.memory_mut().write_cstr(0x1200, "/link");

        let fd = dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
        );
        assert_eq!(fd, SyscallReturn::Success(3));
        assert_eq!(
            dispatch(&mut runtime, Syscall::Fstat, [3, 0x4000, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(u64_at(runtime.memory(), 0x4000 + 48), 5);
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Newfstatat,
                [AT_FDCWD as u64, 0x1000, 0x4100, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(u64_at(runtime.memory(), 0x4100 + 48), 5);
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Statx,
                [AT_FDCWD as u64, 0x1000, 0, 0, 0x4200, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(u64_at(runtime.memory(), 0x4200 + 40), 5);
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Access,
                [0x1000, u64::from(mcr_vfs::R_OK), 0, 0, 0, 0]
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Readlink,
                [0x1200, 0x4300, 32, 0, 0, 0]
            ),
            SyscallReturn::Success(9)
        );
        assert_eq!(runtime.memory().read(0x4300, 9), b"/tmp/file");

        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [
                    AT_FDCWD as u64,
                    0x1100,
                    u64::from(O_RDONLY | O_DIRECTORY),
                    0,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(4)
        );
        let dents = dispatch(&mut runtime, Syscall::Getdents64, [4, 0x5000, 256, 0, 0, 0]);
        assert!(matches!(dents, SyscallReturn::Success(value) if value > 0));
        let first_reclen = u16_at(runtime.memory(), 0x5000 + 16);
        assert_eq!(first_reclen % 8, 0);
        assert_eq!(runtime.memory().read(0x5000 + 19, 2), b".\0");
    }

    #[test]
    fn writable_vfs_syscalls_mutate_paths_and_cwd() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/tmp/pkg");
        runtime.memory_mut().write_cstr(0x1100, "file");
        runtime.memory_mut().write_cstr(0x1200, "/tmp/pkg/file");
        runtime.memory_mut().write_cstr(0x1300, "/tmp/pkg/link");
        runtime.memory_mut().write_cstr(0x1400, "../file");
        runtime.memory_mut().write_cstr(0x1500, "/tmp/pkg/renamed");

        assert_eq!(
            dispatch(&mut runtime, Syscall::Umask, [0o077, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0o022)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Mkdirat,
                [AT_FDCWD as u64, 0x1000, 0o777, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Chdir, [0x1000, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Getcwd, [0x3000, 64, 0, 0, 0, 0]),
            SyscallReturn::Success(0x3000)
        );
        assert_eq!(runtime.memory().read(0x3000, 9), b"/tmp/pkg\0");

        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [
                    AT_FDCWD as u64,
                    0x1100,
                    u64::from(O_CREAT | O_WRONLY),
                    0o666,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Ftruncate, [3, 7, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(runtime.vfs().fstat(3).unwrap().size, 7);

        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Symlinkat,
                [0x1400, AT_FDCWD as u64, 0x1300, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Readlinkat,
                [AT_FDCWD as u64, 0x1300, 0x3100, 32, 0, 0],
            ),
            SyscallReturn::Success(7)
        );
        assert_eq!(runtime.memory().read(0x3100, 7), b"../file");

        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Linkat,
                [AT_FDCWD as u64, 0x1200, AT_FDCWD as u64, 0x1500, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Renameat2,
                [
                    AT_FDCWD as u64,
                    0x1500,
                    AT_FDCWD as u64,
                    0x1200,
                    u64::from(RENAME_NOREPLACE),
                    0,
                ],
            ),
            SyscallReturn::Errno(LinuxErrno::EEXIST)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Unlinkat,
                [AT_FDCWD as u64, 0x1500, 0, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
    }

    #[test]
    fn fd_management_syscalls_wire_to_vfs_and_guest_memory() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [AT_FDCWD as u64, 0x1000, u64::from(O_RDWR), 0, 0, 0],
            ),
            SyscallReturn::Success(3)
        );

        assert_eq!(
            dispatch(&mut runtime, Syscall::Dup, [3, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(4)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Dup2, [3, 7, 0, 0, 0, 0]),
            SyscallReturn::Success(7)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Dup3,
                [3, 8, u64::from(O_CLOEXEC), 0, 0, 0]
            ),
            SyscallReturn::Success(8)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Fcntl,
                [8, u64::from(F_GETFD), 0, 0, 0, 0]
            ),
            SyscallReturn::Success(1)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Fcntl,
                [3, u64::from(F_DUPFD_CLOEXEC), 20, 0, 0, 0],
            ),
            SyscallReturn::Success(20)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Fcntl,
                [
                    4,
                    u64::from(mcr_vfs::F_SETFL),
                    u64::from(O_NONBLOCK),
                    0,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Fcntl,
                [3, u64::from(F_GETFL), 0, 0, 0, 0]
            ),
            SyscallReturn::Success(u64::from(O_RDWR | O_NONBLOCK))
        );

        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Pipe2,
                [0x2000, u64::from(O_CLOEXEC | O_NONBLOCK), 0, 0, 0, 0]
            ),
            SyscallReturn::Success(0)
        );
        let read_fd = i32_at(runtime.memory(), 0x2000);
        let write_fd = i32_at(runtime.memory(), 0x2004);
        assert!(runtime.vfs().fds().cloexec(read_fd).unwrap());
        assert!(runtime.vfs().fds().cloexec(write_fd).unwrap());

        runtime.memory_mut().write(0x2100, b"pipe");
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Write,
                [write_fd as u64, 0x2100, 4, 0, 0, 0]
            ),
            SyscallReturn::Success(4)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Ioctl,
                [read_fd as u64, FIONREAD, 0x2200, 0, 0, 0]
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(u32_at(runtime.memory(), 0x2200), 4);
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Read,
                [read_fd as u64, 0x2300, 4, 0, 0, 0]
            ),
            SyscallReturn::Success(4)
        );
        assert_eq!(runtime.memory().read(0x2300, 4), b"pipe");
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Ioctl,
                [1, TIOCGWINSZ, 0x2400, 0, 0, 0]
            ),
            SyscallReturn::Errno(LinuxErrno::ENOTTY)
        );
    }

    #[test]
    fn errno_cases_match_linux_shapes() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/missing");
        runtime.memory_mut().write_cstr(0x1100, "/tmp/file");
        runtime.memory_mut().write_cstr(0x1200, "child");
        runtime.memory_mut().write_cstr(0x1300, "/private/secret");
        runtime
            .vfs_mut()
            .tree_mut()
            .lookup_path_mut(&guest_path("/private"))
            .unwrap()
            .set_mode(0o600);

        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::ENOENT)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Read, [99, 0x2000, 1, 0, 0, 0]),
            SyscallReturn::Errno(LinuxErrno::EBADF)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [AT_FDCWD as u64, 0x1100, u64::from(O_RDONLY), 0, 0, 0],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [3, 0x1200, u64::from(O_RDONLY), 0, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::ENOTDIR)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Access,
                [0x1300, u64::from(mcr_vfs::R_OK), 0, 0, 0, 0]
            ),
            SyscallReturn::Errno(LinuxErrno::EACCES)
        );
    }

    #[test]
    fn socket_syscall_creates_vfs_socket_fd_with_flags_and_metadata() {
        let mut runtime = runtime_with_sample_vfs();

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM | LINUX_SOCK_CLOEXEC | LINUX_SOCK_NONBLOCK),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );

        assert_eq!(runtime.vfs().socket_id_for_fd(3).unwrap(), 1);
        assert_eq!(
            dispatch(&mut runtime, Syscall::Fstat, [3, 0x3000, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            u32_at(runtime.memory(), 0x3000 + 24) & mcr_vfs::S_IFMT,
            mcr_vfs::S_IFSOCK
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Fcntl,
                [3, u64::from(F_GETFD), 0, 0, 0, 0],
            ),
            SyscallReturn::Success(u64::from(mcr_vfs::FD_CLOEXEC))
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Fcntl,
                [3, u64::from(F_GETFL), 0, 0, 0, 0],
            ),
            SyscallReturn::Success(u64::from(O_RDWR | O_NONBLOCK))
        );
    }

    #[test]
    fn bind_listen_and_getsockname_round_trip_ipv4_sockaddr() {
        let mut runtime = runtime_with_bound_ipv4_socket(8080);

        assert_eq!(
            dispatch_network(&mut runtime, Syscall::Listen, [3, 128, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );

        runtime.memory_mut().write(0x2100, &[0xaa; SOCKADDR_IN_LEN]);
        runtime.memory_mut().write(0x2200, &8u32.to_le_bytes());
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Getsockname,
                [3, 0x2100, 0x2200, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(u32_at(runtime.memory(), 0x2200), SOCKADDR_IN_LEN as u32);
        assert_eq!(runtime.memory().read(0x2100, 8), ipv4_sockaddr(8080)[..8]);
    }

    #[test]
    fn accept4_creates_socket_fd_and_writes_peer_sockaddr() {
        let transport = runtime_socket_transport();
        let peer = SocketAddress::inet([127, 0, 0, 1], 49152);
        transport.push_accepted(peer, b"hello");
        let mut runtime = RuntimeFileSystem::with_socket_transport(
            sample_vfs(),
            TestMemory::default(),
            transport.handle(),
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );
        runtime.memory_mut().write(0x2000, &ipv4_sockaddr(8080));
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Bind,
                [3, 0x2000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch_network(&mut runtime, Syscall::Listen, [3, 1, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        runtime.memory_mut().write(0x2100, &[0xaa; SOCKADDR_IN_LEN]);
        runtime
            .memory_mut()
            .write(0x2200, &(SOCKADDR_IN_LEN as u32).to_le_bytes());

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Accept4,
                [
                    3,
                    0x2100,
                    0x2200,
                    u64::from(LINUX_SOCK_CLOEXEC | LINUX_SOCK_NONBLOCK),
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(4)
        );
        assert_eq!(runtime.vfs().socket_id_for_fd(4).unwrap(), 2);
        assert!(runtime.vfs().fds().cloexec(4).unwrap());
        assert_eq!(
            runtime.vfs().fds().status_flags(4).unwrap(),
            O_RDWR | O_NONBLOCK
        );
        assert_eq!(u32_at(runtime.memory(), 0x2200), SOCKADDR_IN_LEN as u32);
        assert_eq!(
            runtime.memory().read(0x2100, SOCKADDR_IN_LEN),
            ipv4_sockaddr(49152)
        );
        assert_eq!(
            runtime
                .sockets()
                .socket(SocketId::new(2).unwrap())
                .unwrap()
                .state(),
            SocketState::Connected(peer)
        );
    }

    #[test]
    fn connect_getpeername_and_shutdown_round_trip_ipv6_sockaddr() {
        let mut runtime = runtime_with_socket(LINUX_AF_INET6);
        let peer_addr = 0x3000;
        let out_addr = 0x3100;
        let out_len = 0x3200;
        let address = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        runtime
            .memory_mut()
            .write(peer_addr, &ipv6_sockaddr(address, 443, 7, 2));

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Connect,
                [3, peer_addr, SOCKADDR_IN6_LEN as u64, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );

        runtime
            .memory_mut()
            .write(out_len, &(SOCKADDR_IN6_LEN as u32).to_le_bytes());
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Getpeername,
                [3, out_addr, out_len, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(u32_at(runtime.memory(), out_len), SOCKADDR_IN6_LEN as u32);
        assert_eq!(
            runtime.memory().read(out_addr, SOCKADDR_IN6_LEN),
            ipv6_sockaddr(address, 443, 7, 2)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Shutdown,
                [3, u64::from(LINUX_SHUT_RDWR), 0, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert!(
            runtime
                .sockets()
                .socket(SocketId::new(1).unwrap())
                .unwrap()
                .shutdown()
                .read
        );
        assert!(
            runtime
                .sockets()
                .socket(SocketId::new(1).unwrap())
                .unwrap()
                .shutdown()
                .write
        );
    }

    #[test]
    fn setsockopt_and_getsockopt_use_socklen_pointer() {
        let mut runtime = runtime_with_socket(LINUX_AF_INET);
        runtime.memory_mut().write(0x4000, &1u32.to_le_bytes());
        runtime.memory_mut().write(0x4010, &0u32.to_le_bytes());
        runtime.memory_mut().write(0x4020, &8u32.to_le_bytes());

        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Setsockopt,
                [
                    3,
                    u64::from(LINUX_SOL_SOCKET),
                    u64::from(LINUX_SO_REUSEADDR),
                    0x4000,
                    4,
                    0,
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Setsockopt,
                [
                    3,
                    u64::from(LINUX_SOL_SOCKET),
                    u64::from(LINUX_SO_KEEPALIVE),
                    0x4000,
                    4,
                    0,
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Setsockopt,
                [
                    3,
                    u64::from(mcr_net::LINUX_IPPROTO_TCP_LEVEL),
                    u64::from(LINUX_TCP_NODELAY),
                    0x4000,
                    4,
                    0,
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Getsockopt,
                [
                    3,
                    u64::from(LINUX_SOL_SOCKET),
                    u64::from(LINUX_SO_REUSEADDR),
                    0x4010,
                    0x4020,
                    0,
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(u32_at(runtime.memory(), 0x4010), 1);
        assert_eq!(u32_at(runtime.memory(), 0x4020), 4);

        runtime.memory_mut().write(0x4020, &4u32.to_le_bytes());
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Getsockopt,
                [
                    3,
                    u64::from(LINUX_SOL_SOCKET),
                    u64::from(LINUX_SO_TYPE),
                    0x4010,
                    0x4020,
                    0,
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(u32_at(runtime.memory(), 0x4010), LINUX_SOCK_STREAM);
    }

    #[test]
    fn socket_control_error_paths_match_linux_shapes() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch_network(&mut runtime, Syscall::Listen, [3, 1, 0, 0, 0, 0]),
            SyscallReturn::Errno(LinuxErrno::ENOTSOCK)
        );

        let mut socket_runtime = runtime_with_socket(LINUX_AF_INET);
        socket_runtime
            .memory_mut()
            .write(0x2000, &ipv6_sockaddr([0; 16], 80, 0, 0));
        assert_eq!(
            dispatch_network(
                &mut socket_runtime,
                Syscall::Bind,
                [3, 0x2000, SOCKADDR_IN6_LEN as u64, 0, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::EAFNOSUPPORT)
        );
        socket_runtime
            .memory_mut()
            .write(0x2100, &ipv4_sockaddr(80));
        assert_eq!(
            dispatch_network(&mut socket_runtime, Syscall::Bind, [3, 0x2100, 4, 0, 0, 0],),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
        assert_eq!(
            dispatch_network(
                &mut socket_runtime,
                Syscall::Getpeername,
                [3, 0x2200, 0x2300, 0, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::ENOTCONN)
        );
        assert_eq!(
            dispatch_network(
                &mut socket_runtime,
                Syscall::Shutdown,
                [3, u64::from(LINUX_SHUT_RDWR), 0, 0, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::ENOTCONN)
        );
        socket_runtime
            .memory_mut()
            .write(0x2400, &2u32.to_le_bytes());
        assert_eq!(
            dispatch_network(
                &mut socket_runtime,
                Syscall::Getsockopt,
                [
                    3,
                    u64::from(LINUX_SOL_SOCKET),
                    u64::from(LINUX_SO_ERROR),
                    0x2500,
                    0x2400,
                    0,
                ],
            ),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
        assert_eq!(
            dispatch_network(
                &mut socket_runtime,
                Syscall::Accept4,
                [3, 0, 0, 0x8000_0000, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );

        let mut listener = runtime_with_bound_ipv4_socket(9090);
        assert_eq!(
            dispatch_network(&mut listener, Syscall::Listen, [3, 1, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch_network(&mut listener, Syscall::Accept, [3, 0, 0, 0, 0, 0]),
            SyscallReturn::Errno(LinuxErrno::EAGAIN)
        );
    }

    #[derive(Clone, Default)]
    struct TestMemory {
        bytes: BTreeMap<u64, u8>,
    }

    impl TestMemory {
        fn write(&mut self, addr: u64, bytes: &[u8]) {
            for (index, byte) in bytes.iter().copied().enumerate() {
                self.bytes.insert(addr + index as u64, byte);
            }
        }

        fn write_cstr(&mut self, addr: u64, value: &str) {
            self.write(addr, value.as_bytes());
            self.write(addr + value.len() as u64, &[0]);
        }

        fn write_iovec(&mut self, addr: u64, base: u64, len: u64) {
            self.write(addr, &base.to_le_bytes());
            self.write(addr + 8, &len.to_le_bytes());
        }

        fn write_msghdr(&mut self, addr: u64, name: u64, namelen: u32, iov: u64, iovlen: u64) {
            self.write(addr, &name.to_le_bytes());
            self.write(addr + 8, &namelen.to_le_bytes());
            self.write(addr + 12, &0u32.to_le_bytes());
            self.write(addr + 16, &iov.to_le_bytes());
            self.write(addr + 24, &iovlen.to_le_bytes());
            self.write(addr + 32, &0u64.to_le_bytes());
            self.write(addr + 40, &0u64.to_le_bytes());
            self.write(addr + 48, &0u32.to_le_bytes());
            self.write(addr + 52, &0u32.to_le_bytes());
        }

        fn read(&self, addr: u64, len: usize) -> Vec<u8> {
            let mut bytes = vec![0; len];
            self.read_bytes(addr, &mut bytes).unwrap();
            bytes
        }
    }

    impl GuestMemoryAccess for TestMemory {
        fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), GuestMemoryAccessError> {
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = *self
                    .bytes
                    .get(&(addr + index as u64))
                    .ok_or(GuestMemoryAccessError::Fault)?;
            }
            Ok(())
        }

        fn write_bytes(&mut self, addr: u64, buffer: &[u8]) -> Result<(), GuestMemoryAccessError> {
            self.write(addr, buffer);
            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct TestSocketTransport {
        state: Rc<RefCell<TestSocketState>>,
    }

    impl TestSocketTransport {
        fn handle(&self) -> TestSocketTransportHandle {
            TestSocketTransportHandle {
                state: self.state.clone(),
            }
        }

        fn sent_bytes(&self) -> Vec<u8> {
            self.state.borrow().sent.clone()
        }

        fn push_incoming(&self, bytes: &[u8]) {
            self.state.borrow_mut().incoming.extend_from_slice(bytes);
        }

        fn set_connect_would_block_once(&self) {
            self.state.borrow_mut().connect_would_block_once = true;
        }

        fn push_accepted(&self, peer: SocketAddress, incoming: &[u8]) {
            self.state.borrow_mut().accepted.push((
                Rc::new(RefCell::new(TestSocketState {
                    incoming: incoming.to_vec(),
                    connected: Some(peer),
                    ..TestSocketState::default()
                })),
                peer,
            ));
        }
    }

    #[derive(Debug, Default)]
    struct TestSocketState {
        sent: Vec<u8>,
        incoming: Vec<u8>,
        connected: Option<SocketAddress>,
        connect_would_block_once: bool,
        accepted: Vec<(Rc<RefCell<TestSocketState>>, SocketAddress)>,
        bound: Option<SocketAddress>,
        listened: bool,
    }

    #[derive(Clone, Debug)]
    struct TestSocketTransportHandle {
        state: Rc<RefCell<TestSocketState>>,
    }

    impl HostSocketTransport for TestSocketTransportHandle {
        fn open_socket(
            &self,
            _spec: SocketSpec,
            _options: mcr_net::SocketOptions,
        ) -> Result<Box<dyn mcr_net::HostSocketHandle>, mcr_net::HostIoError> {
            Ok(Box::new(TestSocketHandle {
                state: self.state.clone(),
            }))
        }
    }

    #[derive(Debug)]
    struct TestSocketHandle {
        state: Rc<RefCell<TestSocketState>>,
    }

    impl mcr_net::HostSocketHandle for TestSocketHandle {
        fn bind(&mut self, address: SocketAddress) -> Result<SocketAddress, mcr_net::HostIoError> {
            self.state.borrow_mut().bound = Some(address);
            Ok(address)
        }

        fn listen(&mut self, _backlog: u32) -> Result<(), mcr_net::HostIoError> {
            self.state.borrow_mut().listened = true;
            Ok(())
        }

        fn accept(
            &mut self,
        ) -> Result<(Box<dyn mcr_net::HostSocketHandle>, SocketAddress), mcr_net::HostIoError>
        {
            let mut state = self.state.borrow_mut();
            if state.accepted.is_empty() {
                return Err(mcr_net::HostIoError::new(
                    mcr_net::LinuxErrno::OperationWouldBlock,
                    "no pending test socket",
                ));
            }
            let (accepted, peer) = state.accepted.remove(0);
            Ok((Box::new(TestSocketHandle { state: accepted }), peer))
        }

        fn connect(
            &mut self,
            address: SocketAddress,
        ) -> Result<SocketAddress, mcr_net::HostIoError> {
            let mut state = self.state.borrow_mut();
            if state.connect_would_block_once {
                state.connect_would_block_once = false;
                return Err(mcr_net::HostIoError::new(
                    mcr_net::LinuxErrno::OperationWouldBlock,
                    "connect would block",
                ));
            }
            state.connected = Some(address);
            Ok(address)
        }

        fn send(&mut self, buffer: &[u8]) -> Result<usize, mcr_net::HostIoError> {
            self.state.borrow_mut().sent.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn send_to(
            &mut self,
            buffer: &[u8],
            address: SocketAddress,
        ) -> Result<usize, mcr_net::HostIoError> {
            self.state.borrow_mut().connected = Some(address);
            self.send(buffer)
        }

        fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, mcr_net::HostIoError> {
            let mut state = self.state.borrow_mut();
            let count = buffer.len().min(state.incoming.len());
            buffer[..count].copy_from_slice(&state.incoming[..count]);
            state.incoming.drain(..count);
            Ok(count)
        }

        fn recv_from(
            &mut self,
            buffer: &mut [u8],
        ) -> Result<(usize, SocketAddress), mcr_net::HostIoError> {
            let count = self.recv(buffer)?;
            let address = self
                .state
                .borrow()
                .connected
                .unwrap_or_else(|| SocketAddress::inet([127, 0, 0, 1], 53));
            Ok((count, address))
        }

        fn poll(
            &mut self,
            interest: SocketEvents,
            _timeout: Option<Duration>,
        ) -> Result<SocketEvents, mcr_net::HostIoError> {
            let state = self.state.borrow();
            Ok(SocketEvents {
                readable: interest.readable && !state.incoming.is_empty(),
                writable: interest.writable,
                priority: false,
                error: false,
                hang_up: false,
                invalid: false,
            })
        }

        fn shutdown(&mut self, _how: ShutdownHow) -> Result<(), mcr_net::HostIoError> {
            Ok(())
        }
    }

    fn runtime_socket_transport() -> TestSocketTransport {
        TestSocketTransport::default()
    }

    fn sample_vfs() -> VirtualFileSystem {
        let rootfs = Rootfs::new("/host/root");
        let mut tree = PathTree::new();
        tree.create_dir("/tmp").unwrap();
        tree.create_file_with_content("/tmp/file", b"hello", 0o644)
            .unwrap();
        tree.create_dir("/private").unwrap();
        tree.create_file_with_content("/private/secret", b"secret", 0o600)
            .unwrap();
        tree.create_symlink("/link", "/tmp/file").unwrap();
        VirtualFileSystem::from_parts(rootfs, tree, FdTable::with_stdio())
    }

    fn runtime_with_sample_vfs() -> RuntimeFileSystem<TestMemory> {
        RuntimeFileSystem::new(sample_vfs(), TestMemory::default())
    }

    fn runtime_from_program_and_tree(program: GuestProgram, tree: PathTree) -> Runtime {
        Runtime::with_vfs(
            program,
            VirtualFileSystem::from_parts(Rootfs::new("/host/root"), tree, FdTable::with_stdio()),
        )
        .unwrap()
    }

    fn runtime_with_socket(domain: u32) -> RuntimeFileSystem<TestMemory> {
        let mut runtime = runtime_with_sample_vfs();
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Socket,
                [
                    u64::from(domain),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );
        runtime
    }

    fn runtime_with_bound_ipv4_socket(port: u16) -> RuntimeFileSystem<TestMemory> {
        let mut runtime = runtime_with_socket(LINUX_AF_INET);
        runtime.memory_mut().write(0x2000, &ipv4_sockaddr(port));
        assert_eq!(
            dispatch_network(
                &mut runtime,
                Syscall::Bind,
                [3, 0x2000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        runtime
    }

    fn ipv4_sockaddr(port: u16) -> Vec<u8> {
        let mut bytes = vec![0; SOCKADDR_IN_LEN];
        bytes[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&port.to_be_bytes());
        bytes[4..8].copy_from_slice(&[127, 0, 0, 1]);
        bytes
    }

    fn ipv6_sockaddr(address: [u8; 16], port: u16, flowinfo: u32, scope_id: u32) -> Vec<u8> {
        let mut bytes = vec![0; SOCKADDR_IN6_LEN];
        bytes[0..2].copy_from_slice(&(LINUX_AF_INET6 as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&port.to_be_bytes());
        bytes[4..8].copy_from_slice(&flowinfo.to_le_bytes());
        bytes[8..24].copy_from_slice(&address);
        bytes[24..28].copy_from_slice(&scope_id.to_le_bytes());
        bytes
    }

    fn dispatch(
        runtime: &mut RuntimeFileSystem<TestMemory>,
        syscall: Syscall,
        args: [u64; 6],
    ) -> SyscallReturn {
        let registers = SyscallRegisters {
            rax: syscall.number().raw(),
            rdi: args[0],
            rsi: args[1],
            rdx: args[2],
            r10: args[3],
            r8: args[4],
            r9: args[5],
            rip: 0,
        };
        let request =
            mcr_sys::SyscallRequest::from_guest_context(GuestContext::new(1, 1, registers));
        runtime.dispatch_file(&request).result
    }

    fn dispatch_network(
        runtime: &mut RuntimeFileSystem<TestMemory>,
        syscall: Syscall,
        args: [u64; 6],
    ) -> SyscallReturn {
        let registers = SyscallRegisters {
            rax: syscall.number().raw(),
            rdi: args[0],
            rsi: args[1],
            rdx: args[2],
            r10: args[3],
            r8: args[4],
            r9: args[5],
            rip: 0,
        };
        let request =
            mcr_sys::SyscallRequest::from_guest_context(GuestContext::new(1, 1, registers));
        runtime.dispatch_network(&request).result
    }

    fn guest_path(path: &str) -> mcr_vfs::GuestPath {
        Rootfs::new("/host")
            .resolve_path(path, &PathTree::new())
            .unwrap()
            .guest_path()
            .clone()
    }

    fn u64_at(memory: &TestMemory, addr: u64) -> u64 {
        u64::from_le_bytes(memory.read(addr, 8).try_into().expect("slice len"))
    }

    fn u32_at(memory: &TestMemory, addr: u64) -> u32 {
        u32::from_le_bytes(memory.read(addr, 4).try_into().expect("slice len"))
    }

    fn i32_at(memory: &TestMemory, addr: u64) -> i32 {
        i32::from_le_bytes(memory.read(addr, 4).try_into().expect("slice len"))
    }

    fn i32_from_memory(memory: &GuestMemory, addr: u64) -> i32 {
        let mut bytes = [0; 4];
        memory.read(addr, &mut bytes).unwrap();
        i32::from_le_bytes(bytes)
    }

    fn u32_from_guest(memory: &GuestMemory, addr: u64) -> u32 {
        let mut bytes = [0; 4];
        memory.read(addr, &mut bytes).unwrap();
        u32::from_le_bytes(bytes)
    }

    fn write_pollfd(memory: &mut GuestMemory, addr: u64, fd: i32, events: i16) {
        memory.write(addr, &fd.to_le_bytes()).unwrap();
        memory.write(addr + 4, &events.to_le_bytes()).unwrap();
        memory.write(addr + 6, &0i16.to_le_bytes()).unwrap();
    }

    fn pollfd_revents(memory: &GuestMemory, addr: u64) -> i16 {
        let mut bytes = [0; 2];
        memory.read(addr + 6, &mut bytes).unwrap();
        i16::from_le_bytes(bytes)
    }

    fn write_timespec(memory: &mut GuestMemory, addr: u64, sec: i64, nsec: i64) {
        memory.write(addr, &sec.to_le_bytes()).unwrap();
        memory.write(addr + 8, &nsec.to_le_bytes()).unwrap();
    }

    fn write_epoll_event_for_test(memory: &mut GuestMemory, addr: u64, events: u32, data: u64) {
        memory.write(addr, &events.to_le_bytes()).unwrap();
        memory.write(addr + 4, &data.to_le_bytes()).unwrap();
    }

    fn epoll_event_from_memory(memory: &GuestMemory, addr: u64) -> (u32, u64) {
        let mut events = [0; 4];
        let mut data = [0; 8];
        memory.read(addr, &mut events).unwrap();
        memory.read(addr + 4, &mut data).unwrap();
        (u32::from_le_bytes(events), u64::from_le_bytes(data))
    }

    fn u16_at(memory: &TestMemory, addr: u64) -> u16 {
        u16::from_le_bytes(memory.read(addr, 2).try_into().expect("slice len"))
    }

    #[test]
    fn runtime_dispatch_supports_tls_and_exit_state() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

        let arch = runtime.dispatch_syscall(context(
            Syscall::ArchPrctl,
            [ARCH_SET_FS, 0x7000_0000, 0, 0, 0, 0],
        ));
        assert_eq!(arch.result, SyscallReturn::Success(0));
        assert_eq!(
            runtime
                .kernel()
                .task(INITIAL_GUEST_TID)
                .unwrap()
                .tls()
                .fs_base(),
            0x7000_0000
        );

        let exit = runtime.dispatch_syscall(context(Syscall::ExitGroup, [9, 0, 0, 0, 0, 0]));
        assert_eq!(exit.result, SyscallReturn::Success(0));
        assert_eq!(
            runtime
                .kernel()
                .process(INITIAL_GUEST_PID)
                .unwrap()
                .exit_state(),
            ExitState::Exited { status: 9 }
        );
    }

    #[test]
    fn guest_execution_dispatch_advances_registers_and_exposes_exit_state() {
        let mut runtime = Runtime::new(test_program_with_entry_code(
            "/bin/app",
            0x401000,
            &[
                0x0f, 0x05, // syscall
            ],
        ))
        .unwrap();
        let rsp = runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rsp();
        runtime
            .kernel_mut()
            .task_mut(INITIAL_GUEST_TID)
            .unwrap()
            .set_regs(GprState::with_syscall_registers(
                0x401000,
                rsp,
                Syscall::ExitGroup.number().raw(),
                [42, 0, 0, 0, 0, 0],
            ));

        let step = runtime
            .dispatch_guest_execution()
            .expect("execute guest syscall block");

        assert_eq!(step.tid(), INITIAL_GUEST_TID);
        assert_eq!(step.before_rip(), 0x401000);
        assert_eq!(step.after_rip(), 0x401002);
        assert_eq!(step.encoded_rax(), 0);
        assert_eq!(step.task_state(), TaskState::Exited { status: 42 });
        assert_eq!(
            runtime
                .kernel()
                .task(INITIAL_GUEST_TID)
                .unwrap()
                .regs()
                .rip(),
            0x401002
        );
        assert_eq!(
            runtime
                .kernel()
                .process(INITIAL_GUEST_PID)
                .unwrap()
                .exit_state(),
            ExitState::Exited { status: 42 }
        );
    }

    #[test]
    fn guest_run_loop_returns_exit_group_status() {
        let mut runtime = Runtime::new(test_program_with_entry_code(
            "/bin/app",
            0x401000,
            &[
                0x0f, 0x05, // syscall
            ],
        ))
        .unwrap();
        set_initial_syscall_regs(
            &mut runtime,
            0x401000,
            Syscall::ExitGroup,
            [42, 0, 0, 0, 0, 0],
        );

        let status = runtime
            .run_guest_until_exit()
            .expect("guest run exits through exit_group");

        assert_eq!(status, 42);
        assert_eq!(
            runtime
                .kernel()
                .process(INITIAL_GUEST_PID)
                .unwrap()
                .exit_state(),
            ExitState::Exited { status: 42 }
        );
        assert_eq!(
            runtime
                .kernel()
                .task(INITIAL_GUEST_TID)
                .unwrap()
                .regs()
                .rip(),
            0x401002
        );
    }

    #[test]
    fn guest_run_loop_returns_exit_status_from_exit_syscall() {
        let mut runtime = Runtime::new(test_program_with_entry_code(
            "/bin/app",
            0x401000,
            &[
                0x0f, 0x05, // syscall
            ],
        ))
        .unwrap();
        set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::Exit, [300, 0, 0, 0, 0, 0]);

        let status = runtime
            .run_guest_until_exit()
            .expect("guest run exits through exit");

        assert_eq!(status, 44);
        assert_eq!(
            runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
            TaskState::Exited { status: 44 }
        );
    }

    #[test]
    fn guest_run_loop_schedules_child_when_parent_waits() {
        let mut runtime = Runtime::new(test_program_with_entry_code(
            "/bin/app",
            0x401000,
            &[
                0x0f, 0x05, // syscall
                0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, exit_group
                0xbf, 0x00, 0x00, 0x00, 0x00, // mov edi, 0
                0x0f, 0x05, // syscall
            ],
        ))
        .unwrap();
        set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::Fork, [0; 6]);

        let fork = runtime
            .dispatch_guest_execution()
            .expect("parent fork syscall executes");
        assert_eq!(fork.encoded_rax(), 2);
        runtime
            .kernel_mut()
            .task_mut(INITIAL_GUEST_TID)
            .unwrap()
            .set_regs(GprState::with_syscall_registers(
                0x401000,
                0x8000_0000,
                Syscall::Wait4.number().raw(),
                [-1i64 as u64, 0x402000, 0, 0, 0, 0],
            ));
        runtime
            .kernel_mut()
            .task_mut(2)
            .unwrap()
            .set_regs(GprState::with_syscall_registers(
                0x401000,
                0x8000_0000,
                Syscall::ExitGroup.number().raw(),
                [23, 0, 0, 0, 0, 0],
            ));

        let status = runtime
            .run_guest_until_exit()
            .expect("parent exits after reaping child");

        assert_eq!(status, 0);
        let parent = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
        assert_eq!(parent.state(), TaskState::Exited { status: 0 });
        assert_eq!(u32_from_guest(runtime.memory(), 0x402000), 23 << 8);
        assert!(runtime.kernel().process(2).is_none());
        assert!(runtime.memory_for_process(2).is_none());
    }

    #[test]
    fn guest_run_loop_returns_existing_exit_status() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        let exit = runtime.dispatch_syscall(context(Syscall::ExitGroup, [9, 0, 0, 0, 0, 0]));
        assert_eq!(exit.result, SyscallReturn::Success(0));

        let status = runtime
            .run_guest_until_exit()
            .expect("guest run returns already exited process status");

        assert_eq!(status, 9);
    }

    #[test]
    fn guest_run_loop_surfaces_guest_execution_error() {
        let mut runtime = Runtime::new(test_program_with_entry_code(
            "/bin/app",
            0x401000,
            &[
                0xc3, // ret
            ],
        ))
        .unwrap();
        set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::ExitGroup, [0; 6]);

        let error = runtime
            .run_guest_until_exit()
            .expect_err("guest run should stop on a block without syscall");

        assert_eq!(error.linux_errno(), LinuxErrno::ENOEXEC);
        assert!(matches!(
            error,
            GuestRunError::GuestExecution(GuestExecutionError::Execution(
                ExecutionError::MissingSyscall { .. }
            ))
        ));
    }

    #[test]
    fn guest_run_errors_expose_linux_errno_shapes() {
        assert_eq!(
            GuestRunError::MissingInitialProcess.linux_errno(),
            LinuxErrno::ESRCH
        );
        assert_eq!(
            GuestRunError::MissingInitialTask.linux_errno(),
            LinuxErrno::ESRCH
        );
        assert_eq!(
            GuestRunError::InitialTaskNotRunnable {
                tid: INITIAL_GUEST_TID,
                state: TaskState::Exited { status: 1 },
            }
            .linux_errno(),
            LinuxErrno::ESRCH
        );
        assert_eq!(
            GuestRunError::GuestExecution(GuestExecutionError::Memory(GuestMemoryError::NotMapped))
                .linux_errno(),
            LinuxErrno::ENOMEM
        );
    }

    #[test]
    fn guest_run_loop_surfaces_guest_memory_error() {
        let mut runtime = Runtime::new(test_program_with_entry_code(
            "/bin/app",
            0x401000,
            &[
                0x0f, 0x05, // syscall
            ],
        ))
        .unwrap();
        set_initial_syscall_regs(&mut runtime, 0x402000, Syscall::ExitGroup, [0; 6]);

        let error = runtime
            .run_guest_until_exit()
            .expect_err("guest run should stop on non-executable rip");

        assert_eq!(error.linux_errno(), LinuxErrno::EACCES);
        assert!(matches!(
            error,
            GuestRunError::GuestExecution(GuestExecutionError::Memory(
                GuestMemoryError::AccessDenied
            ))
        ));
    }

    #[test]
    fn runtime_dispatches_fork_child_exit_and_wait4() {
        let mut runtime = Runtime::new(test_program("/bin/parent", 0x401000)).unwrap();

        let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
        assert_eq!(fork.result, SyscallReturn::Success(2));
        assert_eq!(
            runtime.kernel().process(2).unwrap().parent(),
            Some(INITIAL_GUEST_PID)
        );

        let child_exit =
            runtime.dispatch_syscall(context_for(2, 2, Syscall::ExitGroup, [23, 0, 0, 0, 0, 0]));
        assert_eq!(child_exit.result, SyscallReturn::Success(0));
        assert_eq!(
            runtime.kernel().process(2).unwrap().exit_state(),
            ExitState::Exited { status: 23 }
        );

        let wait = runtime.dispatch_syscall(context(Syscall::Wait4, [-1i64 as u64, 0, 0, 0, 0, 0]));
        assert_eq!(wait.result, SyscallReturn::Success(2));
        assert!(runtime.kernel().process(2).is_none());
        assert!(runtime.kernel().task(2).is_none());
        assert!(
            !runtime
                .kernel()
                .process(INITIAL_GUEST_PID)
                .unwrap()
                .children()
                .contains(&2)
        );
    }

    #[test]
    fn guest_execution_can_dispatch_forked_child_task() {
        let mut runtime = Runtime::new(test_program_with_entry_code(
            "/bin/app",
            0x401000,
            &[
                0x0f, 0x05, // syscall
            ],
        ))
        .unwrap();
        set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::Fork, [0; 6]);

        let parent_step = runtime
            .dispatch_guest_execution()
            .expect("parent fork syscall executes");
        assert_eq!(parent_step.tid(), INITIAL_GUEST_TID);
        assert_eq!(parent_step.encoded_rax(), 2);

        runtime
            .kernel_mut()
            .task_mut(2)
            .unwrap()
            .set_regs(GprState::with_syscall_registers(
                0x401000,
                0x8000_0000,
                Syscall::ExitGroup.number().raw(),
                [17, 0, 0, 0, 0, 0],
            ));

        let child_step = dispatch_guest_task_with_dispatcher(&mut runtime.dispatcher, 2)
            .expect("child exit syscall executes");
        assert_eq!(child_step.tid(), 2);
        assert_eq!(child_step.task_state(), TaskState::Exited { status: 17 });
        assert_eq!(
            runtime.kernel().process(2).unwrap().exit_state(),
            ExitState::Exited { status: 17 }
        );
    }

    #[test]
    fn forked_child_memory_is_isolated_from_parent_memory() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        let marker_addr = 0x402000;
        runtime.memory_mut().write(marker_addr, b"parent").unwrap();

        let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
        assert_eq!(fork.result, SyscallReturn::Success(2));
        assert_eq!(
            runtime
                .dispatch_syscall(context_for(
                    2,
                    2,
                    Syscall::Write,
                    [1, marker_addr, 5, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(5)
        );

        runtime
            .memory_for_process_mut(2)
            .unwrap()
            .write(marker_addr, b"child!")
            .unwrap();

        let mut parent_bytes = [0; 6];
        runtime
            .memory()
            .read(marker_addr, &mut parent_bytes)
            .unwrap();
        let mut child_bytes = [0; 6];
        runtime
            .memory_for_process(2)
            .unwrap()
            .read(marker_addr, &mut child_bytes)
            .unwrap();
        assert_eq!(&parent_bytes, b"parent");
        assert_eq!(&child_bytes, b"child!");
    }

    #[test]
    fn runtime_fork_child_dup2_close_does_not_mutate_parent_fds() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(0)
        );
        let parent_read_fd = i32_from_memory(runtime.memory(), 0x402000);
        let parent_write_fd = i32_from_memory(runtime.memory(), 0x402004);
        assert_eq!(parent_read_fd, 3);
        assert_eq!(parent_write_fd, 4);

        let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
        assert_eq!(fork.result, SyscallReturn::Success(2));
        assert_eq!(
            runtime
                .dispatch_syscall(context_for(
                    2,
                    2,
                    Syscall::Dup2,
                    [parent_write_fd as u64, 7, 0, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(7)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context_for(
                    2,
                    2,
                    Syscall::Close,
                    [parent_write_fd as u64, 0, 0, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(0)
        );

        runtime.memory_mut().write(0x402100, b"ok").unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Write,
                    [parent_write_fd as u64, 0x402100, 2, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(2)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Read,
                    [parent_read_fd as u64, 0x402200, 2, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(2)
        );
        let mut bytes = [0; 2];
        runtime.memory().read(0x402200, &mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Close, [7, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Errno(LinuxErrno::EBADF)
        );
    }

    #[test]
    fn runtime_fork_child_close_shared_socket_keeps_parent_socket_open() {
        let transport = runtime_socket_transport();
        let mut runtime = Runtime::with_vfs_and_socket_transport(
            test_program("/bin/app", 0x401000),
            sample_vfs(),
            transport.handle(),
        )
        .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Socket,
                    [
                        u64::from(LINUX_AF_INET),
                        u64::from(LINUX_SOCK_STREAM),
                        u64::from(LINUX_IPPROTO_TCP),
                        0,
                        0,
                        0,
                    ]
                ))
                .result,
            SyscallReturn::Success(3)
        );
        runtime.memory_mut().write(0x402000, b"ping").unwrap();
        runtime
            .memory_mut()
            .write(0x402100, &ipv4_sockaddr(8080))
            .unwrap();

        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Connect,
                    [3, 0x402100, SOCKADDR_IN_LEN as u64, 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(0)
        );
        let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
        assert_eq!(fork.result, SyscallReturn::Success(2));
        assert_eq!(
            runtime
                .dispatch_syscall(context_for(2, 2, Syscall::Close, [3, 0, 0, 0, 0, 0]))
                .result,
            SyscallReturn::Success(0)
        );

        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Sendto, [3, 0x402000, 4, 0, 0, 0]))
                .result,
            SyscallReturn::Success(4)
        );
    }

    #[test]
    fn forked_child_exec_replaces_only_child_memory() {
        let mut tree = PathTree::new();
        tree.create_dir("/bin").unwrap();
        tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
            .unwrap();
        tree.create_file_with_content(
            "/bin/new",
            test_program_bytes_with_marker(0x501000, 0x5a),
            0o755,
        )
        .unwrap();
        let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
        runtime.memory_mut().write(0x402000, b"parent").unwrap();
        runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();

        let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
        assert_eq!(fork.result, SyscallReturn::Success(2));
        let exec = runtime.dispatch_syscall(context_for(
            2,
            2,
            Syscall::Execve,
            [0x402100, 0, 0, 0, 0, 0],
        ));

        assert_eq!(exec.result, SyscallReturn::Success(0));
        assert_eq!(
            runtime
                .kernel()
                .process(2)
                .unwrap()
                .image()
                .executable()
                .path(),
            b"/bin/new"
        );
        assert_eq!(runtime.kernel().task(2).unwrap().regs().rip(), 0x501000);
        let mut parent_bytes = [0; 6];
        runtime.memory().read(0x402000, &mut parent_bytes).unwrap();
        assert_eq!(&parent_bytes, b"parent");

        let mut loaded_text = [0; 4];
        runtime
            .memory_for_process(2)
            .unwrap()
            .read(0x501200, &mut loaded_text)
            .unwrap();
        assert_eq!(loaded_text, [0x5a; 4]);
        assert_eq!(
            runtime
                .memory_for_process(2)
                .unwrap()
                .read(0x402000, &mut [0; 1]),
            Err(GuestMemoryError::NotMapped)
        );
    }

    #[test]
    fn memory_syscalls_route_to_request_process_memory() {
        let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
        let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
        assert_eq!(fork.result, SyscallReturn::Success(2));

        let child_mmap = runtime.dispatch_syscall(context_for(
            2,
            2,
            Syscall::Mmap,
            [
                0x600000,
                4096,
                u64::from(LINUX_PROT_READ | LINUX_PROT_WRITE),
                u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED),
                u64::MAX,
                0,
            ],
        ));

        assert_eq!(child_mmap.result, SyscallReturn::Success(0x600000));
        assert!(runtime.memory().vma_containing(0x600000).is_none());
        assert!(
            runtime
                .memory_for_process(2)
                .unwrap()
                .vma_containing(0x600000)
                .is_some()
        );
    }

    #[test]
    fn runtime_execve_reads_filename_argv_envp_from_guest_memory_and_vfs() {
        let mut tree = PathTree::new();
        tree.create_dir("/bin").unwrap();
        tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
            .unwrap();
        tree.create_file_with_content(
            "/bin/new",
            test_program_bytes_with_marker(0x501000, 0x5a),
            0o755,
        )
        .unwrap();
        tree.mount_minimal_procfs().unwrap();
        let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

        runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();
        runtime.memory_mut().write(0x402120, b"/bin/new\0").unwrap();
        runtime.memory_mut().write(0x402140, b"--flag\0").unwrap();
        runtime
            .memory_mut()
            .write(0x402160, b"PATH=/bin\0")
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402000, &0x402120u64.to_le_bytes())
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402008, &0x402140u64.to_le_bytes())
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402010, &0u64.to_le_bytes())
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402040, &0x402160u64.to_le_bytes())
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402048, &0u64.to_le_bytes())
            .unwrap();

        let exec = runtime.dispatch_syscall(context(
            Syscall::Execve,
            [0x402100, 0x402000, 0x402040, 0, 0, 0],
        ));

        assert_eq!(exec.result, SyscallReturn::Success(0));
        let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
        let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
        assert_eq!(process.image().executable().path(), b"/bin/new");
        assert_eq!(
            process.image().argv(),
            &[b"/bin/new".to_vec(), b"--flag".to_vec()]
        );
        assert_eq!(process.image().envp(), &[b"PATH=/bin".to_vec()]);
        assert_eq!(task.regs().rip(), 0x501000);
        let mut loaded_text = [0; 4];
        runtime.memory().read(0x501200, &mut loaded_text).unwrap();
        assert_eq!(loaded_text, [0x5a; 4]);

        runtime
            .memory_mut()
            .write(0x502100, b"/proc/self/cmdline\0")
            .unwrap();
        runtime
            .memory_mut()
            .write(0x502140, b"/proc/self/environ\0")
            .unwrap();
        runtime
            .memory_mut()
            .write(0x502180, b"/proc/self/exe\0")
            .unwrap();
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Openat,
                    [AT_FDCWD as u64, 0x502100, u64::from(O_RDONLY), 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(3)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Read, [3, 0x502300, 64, 0, 0, 0]))
                .result,
            SyscallReturn::Success(16)
        );
        let mut cmdline = [0; 16];
        runtime.memory().read(0x502300, &mut cmdline).unwrap();
        assert_eq!(&cmdline, b"/bin/new\0--flag\0");
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Openat,
                    [AT_FDCWD as u64, 0x502140, u64::from(O_RDONLY), 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(4)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(Syscall::Read, [4, 0x502320, 64, 0, 0, 0]))
                .result,
            SyscallReturn::Success(10)
        );
        let mut environ = [0; 10];
        runtime.memory().read(0x502320, &mut environ).unwrap();
        assert_eq!(&environ, b"PATH=/bin\0");
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Readlink,
                    [0x502180, 0x502340, 64, 0, 0, 0,]
                ))
                .result,
            SyscallReturn::Success(8)
        );
        let mut exe = [0; 8];
        runtime.memory().read(0x502340, &mut exe).unwrap();
        assert_eq!(&exe, b"/bin/new");
    }

    #[test]
    fn runtime_execve_loads_interpreter_from_vfs() {
        let mut tree = PathTree::new();
        tree.create_dir("/bin").unwrap();
        tree.create_dir("/lib").unwrap();
        tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
            .unwrap();
        tree.create_file_with_content(
            "/bin/dynamic",
            dynamic_program_bytes("/lib/ld-musl-x86_64.so.1"),
            0o755,
        )
        .unwrap();
        tree.create_file_with_content("/lib/ld-musl-x86_64.so.1", interpreter_bytes(), 0o755)
            .unwrap();
        let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

        runtime
            .memory_mut()
            .write(0x402100, b"/bin/dynamic\0")
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402120, b"/bin/dynamic\0")
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402000, &0x402120u64.to_le_bytes())
            .unwrap();
        runtime
            .memory_mut()
            .write(0x402008, &0u64.to_le_bytes())
            .unwrap();

        let exec =
            runtime.dispatch_syscall(context(Syscall::Execve, [0x402100, 0x402000, 0, 0, 0, 0]));

        assert_eq!(exec.result, SyscallReturn::Success(0));
        let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
        let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
        assert_eq!(process.image().executable().path(), b"/bin/dynamic");
        assert_eq!(
            process.image().interpreter().unwrap().path(),
            b"/lib/ld-musl-x86_64.so.1"
        );
        assert_eq!(
            task.regs().rip(),
            mcr_elf::DEFAULT_INTERPRETER_LOAD_BASE + 0x400
        );
    }

    #[test]
    fn runtime_execve_missing_vfs_target_keeps_current_image() {
        let mut tree = PathTree::new();
        tree.create_dir("/bin").unwrap();
        tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
            .unwrap();
        let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

        runtime
            .memory_mut()
            .write(0x402100, b"/bin/missing\0")
            .unwrap();

        let exec = runtime.dispatch_syscall(context(Syscall::Execve, [0x402100, 0, 0, 0, 0, 0]));

        assert_eq!(exec.result, SyscallReturn::Errno(LinuxErrno::ENOENT));
        let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
        let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
        assert_eq!(process.image().executable().path(), b"/bin/old");
        assert_eq!(task.regs().rip(), 0x401000);
    }

    #[test]
    fn runtime_tracer_records_task_syscall_events() {
        let mut runtime = Runtime::with_tracer(
            test_program("/bin/app", 0x401000),
            InMemorySyscallTracer::new(),
        )
        .unwrap();

        let result = runtime.dispatch_syscall(context(Syscall::Gettid, [0; 6]));

        assert_eq!(result.result, SyscallReturn::Success(1));
        assert!(matches!(
            runtime.tracer().events(),
            [SyscallTraceEvent::Enter(_), SyscallTraceEvent::Exit(_)]
        ));
    }

    #[test]
    fn runtime_exec_replaces_guest_image_and_keeps_guest_identity() {
        let mut runtime = Runtime::new(test_program("/bin/old", 0x401000)).unwrap();

        runtime
            .kernel_mut()
            .exec_task(INITIAL_GUEST_TID, test_program("/bin/new", 0x501000))
            .unwrap();

        let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
        let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();

        assert_eq!(process.pid(), INITIAL_GUEST_PID);
        assert_eq!(task.tid(), INITIAL_GUEST_TID);
        assert_eq!(process.image().executable().path(), b"/bin/new");
        assert_eq!(task.regs().rip(), 0x501000);
    }

    #[test]
    fn diagnostics_capture_image_vmas_and_last_syscall() {
        let mut runtime = RuntimeWithTracer::with_diagnostics(test_program_with_args(
            "/bin/app",
            0x401000,
            ["/bin/app", "--flag"],
            ["A=B"],
        ))
        .unwrap();

        let result = runtime.dispatch_syscall(context(Syscall::Getpid, [0; 6]));
        assert_eq!(result.result, SyscallReturn::Success(1));

        let diagnostics = runtime.diagnostics();
        let last = diagnostics.last_syscall().unwrap();

        assert_eq!(diagnostics.executable_path(), b"/bin/app");
        assert_eq!(
            diagnostics.argv(),
            &[b"/bin/app".to_vec(), b"--flag".to_vec()]
        );
        assert_eq!(diagnostics.envp(), &[b"A=B".to_vec()]);
        assert!(diagnostics.vmas().iter().any(|vma| {
            vma.start() <= 0x401000
                && 0x401000 < vma.end()
                && vma.permissions().execute()
                && matches!(
                    vma.kind(),
                    DiagnosticVmaKind::ElfLoad {
                        program_header_index: 0,
                        ..
                    }
                )
        }));
        assert!(diagnostics.vmas().iter().any(|vma| {
            matches!(vma.kind(), DiagnosticVmaKind::Stack) && vma.permissions().write()
        }));
        assert_eq!(last.name(), "getpid");
        assert_eq!(last.number(), Syscall::GETPID.raw());
        assert_eq!(last.args(), [0; 6]);
        assert_eq!(last.result(), Some(SyscallReturn::Success(1)));
        assert_eq!(last.rip(), 0x401234);
    }

    #[test]
    fn crash_report_includes_registers_and_runtime_diagnostics() {
        let mut runtime =
            RuntimeWithTracer::with_diagnostics(test_program("/bin/app", 0x401000)).unwrap();
        runtime.dispatch_syscall(context(Syscall::Gettid, [0; 6]));

        let registers = GuestRegisters {
            rax: Syscall::Gettid.number().raw(),
            rip: 0x401234,
            rsp: runtime
                .kernel()
                .task(INITIAL_GUEST_TID)
                .unwrap()
                .regs()
                .rsp(),
            ..GuestRegisters::default()
        };
        let report = runtime.crash_report("invalid instruction", registers);

        assert_eq!(report.reason(), "invalid instruction");
        assert_eq!(report.registers(), registers);
        assert_eq!(report.diagnostics().executable_path(), b"/bin/app");
        assert_eq!(
            report.diagnostics().last_syscall().unwrap().name(),
            "gettid"
        );
    }

    fn context(syscall: Syscall, args: [u64; 6]) -> GuestContext {
        context_for(INITIAL_GUEST_PID, INITIAL_GUEST_TID, syscall, args)
    }

    fn context_for(pid: u32, tid: u32, syscall: Syscall, args: [u64; 6]) -> GuestContext {
        GuestContext::new(
            pid,
            tid,
            SyscallRegisters {
                rax: syscall.number().raw(),
                rdi: args[0],
                rsi: args[1],
                rdx: args[2],
                r10: args[3],
                r8: args[4],
                r9: args[5],
                rip: 0x401234,
            },
        )
    }

    fn set_initial_syscall_regs(runtime: &mut Runtime, rip: u64, syscall: Syscall, args: [u64; 6]) {
        let rsp = runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rsp();
        runtime
            .kernel_mut()
            .task_mut(INITIAL_GUEST_TID)
            .unwrap()
            .set_regs(GprState::with_syscall_registers(
                rip,
                rsp,
                syscall.number().raw(),
                args,
            ));
    }

    fn test_program(path: &str, entrypoint: u64) -> GuestProgram {
        GuestProgram::new(GuestExecutable::new(
            path.as_bytes().to_vec(),
            test_program_bytes(entrypoint),
        ))
    }

    fn test_program_bytes(entrypoint: u64) -> Vec<u8> {
        test_program_bytes_with_marker(entrypoint, 0x90)
    }

    fn test_program_with_entry_code(path: &str, entrypoint: u64, code: &[u8]) -> GuestProgram {
        GuestProgram::new(GuestExecutable::new(
            path.as_bytes().to_vec(),
            test_program_bytes_with_entry_code(entrypoint, code),
        ))
    }

    fn test_program_bytes_with_entry_code(entrypoint: u64, code: &[u8]) -> Vec<u8> {
        Elf64Builder::new()
            .entrypoint(entrypoint)
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_X,
                0x1000,
                entrypoint & !0xfff,
                0x1000,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000,
                (entrypoint & !0xfff) + 0x1000,
                0x08,
                0x100,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R,
                0,
                (entrypoint & !0xfff) + 0x2000,
                0x100,
                0x100,
            ))
            .data_at(0x1000 + (entrypoint & 0xfff), code.to_vec())
            .data_at(0x2000, vec![0; 0x08])
            .build()
    }

    fn test_program_bytes_with_marker(entrypoint: u64, marker: u8) -> Vec<u8> {
        Elf64Builder::new()
            .entrypoint(entrypoint)
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_X,
                0,
                entrypoint & !0xfff,
                0x1000,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000,
                (entrypoint & !0xfff) + 0x1000,
                0x08,
                0x100,
            ))
            .data_at(0x200, vec![marker; 0x20])
            .data_at(0x2000, vec![0; 0x08])
            .build()
    }

    fn dynamic_program_bytes(interpreter: &str) -> Vec<u8> {
        let mut interpreter_path = interpreter.as_bytes().to_vec();
        interpreter_path.push(0);
        Elf64Builder::new()
            .object_type(mcr_testkit::elf::ET_DYN)
            .entrypoint(0x1010)
            .program_header(Elf64ProgramHeader::new(
                mcr_testkit::elf::PT_INTERP,
                PF_R,
                0x300,
                0,
                interpreter_path.len() as u64,
                interpreter_path.len() as u64,
                1,
            ))
            .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x2000))
            .data_at(0x300, interpreter_path)
            .data_at(0x400, vec![0x90; 4])
            .build()
    }

    fn interpreter_bytes() -> Vec<u8> {
        Elf64Builder::new()
            .object_type(mcr_testkit::elf::ET_DYN)
            .entrypoint(0x400)
            .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x1000))
            .data_at(0x400, vec![0x90; 4])
            .build()
    }

    fn test_program_with_args<const A: usize, const E: usize>(
        path: &str,
        entrypoint: u64,
        argv: [&str; A],
        envp: [&str; E],
    ) -> GuestProgram {
        test_program(path, entrypoint)
            .with_args(argv.map(|value| value.as_bytes().to_vec()))
            .with_env(envp.map(|value| value.as_bytes().to_vec()))
    }
}
