pub mod memory;

pub use memory::{
    DEFAULT_MMAP_BASE, GUEST_ADDRESS_SPACE_END, GUEST_PAGE_SIZE, GuestBrkOutcome, GuestMemory,
    GuestMemoryError, GuestMemoryProtection, GuestVma, GuestVmaKind, MIN_GUEST_ADDRESS,
};

use mcr_elf::{
    GuestMemoryImage, GuestVma as ElfGuestVma, GuestVmaKind as ElfGuestVmaKind, SegmentPermissions,
};
use mcr_jit::GuestRegisters;
use mcr_sys::{
    EventSyscalls, FileSyscalls, GuestContext, LinuxErrno, LinuxIovec, LinuxStat, LinuxStatx,
    LinuxStatxTimestamp, MemorySyscalls, NetworkSyscalls, NoopSyscallTracer, SyscallDispatchResult,
    SyscallDispatcher, SyscallOutcome, SyscallRequest, SyscallReturn, SyscallTraceEvent,
    SyscallTracer, TimeSyscalls,
};
use mcr_task::{GuestExecutable, GuestKernel, GuestProgram, TaskError};
use mcr_vfs::{
    DirectoryEntry, Fd, LinuxFileAttr, OpenFlags, SeekWhence, VfsError, VirtualFileSystem,
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestMemoryAccessError {
    Fault,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    Stack,
}

impl DiagnosticVmaKind {
    #[must_use]
    pub const fn from_guest_kind(kind: &ElfGuestVmaKind) -> Self {
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

pub struct RuntimeFileSystem<M> {
    vfs: VirtualFileSystem,
    memory: M,
}

impl<M> RuntimeFileSystem<M> {
    pub fn new(vfs: VirtualFileSystem, memory: M) -> Self {
        Self { vfs, memory }
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
            mcr_sys::Syscall::Getdents64 => self.sys_getdents64(request),
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
        self.vfs.close(arg_i32(request, 0)).map_err(vfs_errno)?;
        Ok(0)
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

fn encode_dirents(entries: &[DirectoryEntry]) -> Result<Vec<u8>, LinuxErrno> {
    let mut bytes = Vec::new();
    for entry in entries {
        entry.encode_linux_dirent64(&mut bytes).map_err(vfs_errno)?;
    }
    Ok(bytes)
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
        Ok(RuntimeWithTracer {
            dispatcher: SyscallDispatcher::with_tracer(RuntimeSubsystems::new(program)?, tracer),
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

    pub fn dispatch_syscall(&mut self, context: GuestContext) -> SyscallDispatchResult {
        self.dispatcher.dispatch(context)
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
    pub const fn tracer(&self) -> &T {
        self.dispatcher.tracer()
    }

    #[must_use]
    pub const fn tracer_mut(&mut self) -> &mut T {
        self.dispatcher.tracer_mut()
    }

    pub fn dispatch_syscall(&mut self, context: GuestContext) -> SyscallDispatchResult {
        self.dispatcher.dispatch(context)
    }

    pub fn into_parts(self) -> (GuestKernel, T) {
        let (subsystems, tracer) = self.dispatcher.into_parts();
        (subsystems.tasks, tracer)
    }
}

#[derive(Debug)]
pub struct RuntimeSubsystems {
    tasks: GuestKernel,
}

impl RuntimeSubsystems {
    pub fn new(program: GuestProgram) -> Result<Self, RuntimeError> {
        Ok(Self {
            tasks: GuestKernel::new(program)?,
        })
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
    pub fn current_image(&self) -> &GuestMemoryImage {
        self.tasks
            .process(mcr_task::INITIAL_GUEST_PID)
            .expect("runtime always starts with an initial process")
            .image()
            .memory()
    }
}

impl FileSyscalls for RuntimeSubsystems {}
impl MemorySyscalls for RuntimeSubsystems {}
impl TimeSyscalls for RuntimeSubsystems {}
impl NetworkSyscalls for RuntimeSubsystems {}
impl EventSyscalls for RuntimeSubsystems {}

impl mcr_sys::TaskSyscalls for RuntimeSubsystems {
    fn dispatch_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        self.tasks.dispatch_for_current_task(request)
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Task(TaskError),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Task(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<TaskError> for RuntimeError {
    fn from(value: TaskError) -> Self {
        Self::Task(value)
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
    use std::collections::BTreeMap;

    use mcr_sys::{
        GuestContext, InMemorySyscallTracer, Syscall, SyscallRegisters, SyscallReturn,
        SyscallTraceEvent,
    };
    use mcr_task::{ARCH_SET_FS, ExitState, INITIAL_GUEST_PID, INITIAL_GUEST_TID};
    use mcr_testkit::elf::{Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X};
    use mcr_vfs::{
        AT_FDCWD, FdTable, O_DIRECTORY, O_RDONLY, O_RDWR, PathTree, Rootfs, VirtualFileSystem,
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

    fn runtime_with_sample_vfs() -> RuntimeFileSystem<TestMemory> {
        let rootfs = Rootfs::new("/host/root");
        let mut tree = PathTree::new();
        tree.create_dir("/tmp").unwrap();
        tree.create_file_with_content("/tmp/file", b"hello", 0o644)
            .unwrap();
        tree.create_dir("/private").unwrap();
        tree.create_file_with_content("/private/secret", b"secret", 0o600)
            .unwrap();
        tree.create_symlink("/link", "/tmp/file").unwrap();
        RuntimeFileSystem::new(
            VirtualFileSystem::from_parts(rootfs, tree, FdTable::with_stdio()),
            TestMemory::default(),
        )
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
        GuestContext::new(
            INITIAL_GUEST_PID,
            INITIAL_GUEST_TID,
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

    fn test_program(path: &str, entrypoint: u64) -> GuestProgram {
        let elf = Elf64Builder::new()
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
            .data_at(0x200, vec![0x90; 0x20])
            .data_at(0x2000, vec![0; 0x08])
            .build();

        GuestProgram::new(GuestExecutable::new(path.as_bytes().to_vec(), elf))
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
