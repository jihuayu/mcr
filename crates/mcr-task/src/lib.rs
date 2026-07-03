use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mcr_elf::{GuestImageError, GuestMemoryImage, InitialStackConfig, parse_load_plan};
use mcr_sys::{
    CloneSyscallArgs, GuestAddress, GuestPid, GuestTid, KillSyscallArgs,
    LINUX_CLONE_EXIT_SIGNAL_MASK, LINUX_CLONE_VFORK, LINUX_CLONE_VM, LINUX_KERNEL_SIGSET_SIZE,
    LINUX_ROBUST_LIST_HEAD_SIZE, LINUX_SIG_BLOCK, LINUX_SIG_SETMASK, LINUX_SIG_UNBLOCK,
    LINUX_SIGCHLD, LinuxErrno, LinuxUtsname, RtSigactionSyscallArgs, RtSigprocmaskSyscallArgs,
    SetRobustListSyscallArgs, SetTidAddressSyscallArgs, Syscall, SyscallOutcome, SyscallRequest,
    TaskSyscalls, TgkillSyscallArgs, Wait4SyscallArgs,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub const INITIAL_GUEST_PID: GuestPid = 1;
pub const INITIAL_GUEST_TID: GuestTid = 1;
#[cfg(not(windows))]
pub const DEFAULT_STACK_TOP: GuestAddress = 0x8000_0000;
#[cfg(windows)]
pub const DEFAULT_STACK_TOP: GuestAddress = 0x1_0020_0000;
pub const DEFAULT_STACK_SIZE: u64 = 0x20_0000;
const X86_64_SYSCALL_INSTRUCTION_LEN: GuestAddress = 2;
const X86_64_DEFAULT_RFLAGS: u64 = 0x202;

pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;
pub const LINUX_SIGKILL: u32 = 9;
pub const LINUX_SIGTERM: u32 = 15;
pub const LINUX_SIGNAL_COUNT: u32 = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestExecutable {
    path: Vec<u8>,
    bytes: Vec<u8>,
}

impl GuestExecutable {
    #[must_use]
    pub fn new(path: impl Into<Vec<u8>>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            bytes: bytes.into(),
        }
    }

    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestProgram {
    executable: GuestExecutable,
    interpreter: Option<GuestExecutable>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
}

impl GuestProgram {
    #[must_use]
    pub fn new(executable: GuestExecutable) -> Self {
        let argv = vec![executable.path().to_vec()];
        Self {
            executable,
            interpreter: None,
            argv,
            envp: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_interpreter(mut self, interpreter: GuestExecutable) -> Self {
        self.interpreter = Some(interpreter);
        self
    }

    #[must_use]
    pub fn with_args<I, A>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<Vec<u8>>,
    {
        self.argv = argv.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_env<I, E>(mut self, envp: I) -> Self
    where
        I: IntoIterator<Item = E>,
        E: Into<Vec<u8>>,
    {
        self.envp = envp.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn executable(&self) -> &GuestExecutable {
        &self.executable
    }

    #[must_use]
    pub fn interpreter(&self) -> Option<&GuestExecutable> {
        self.interpreter.as_ref()
    }

    #[must_use]
    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    #[must_use]
    pub fn envp(&self) -> &[Vec<u8>] {
        &self.envp
    }

    fn into_parts(self) -> GuestProgramParts {
        GuestProgramParts {
            executable: self.executable,
            interpreter: self.interpreter,
            argv: self.argv,
            envp: self.envp,
        }
    }
}

#[derive(Debug)]
struct GuestProgramParts {
    executable: GuestExecutable,
    interpreter: Option<GuestExecutable>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestImageState {
    executable: GuestExecutable,
    interpreter: Option<GuestExecutable>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    memory: GuestMemoryImage,
}

impl GuestImageState {
    #[must_use]
    pub fn executable(&self) -> &GuestExecutable {
        &self.executable
    }

    #[must_use]
    pub fn interpreter(&self) -> Option<&GuestExecutable> {
        self.interpreter.as_ref()
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
    pub fn memory(&self) -> &GuestMemoryImage {
        &self.memory
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsState {
    fs_base: GuestAddress,
    gs_base: GuestAddress,
}

impl TlsState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fs_base: 0,
            gs_base: 0,
        }
    }

    #[must_use]
    pub const fn fs_base(self) -> GuestAddress {
        self.fs_base
    }

    #[must_use]
    pub const fn gs_base(self) -> GuestAddress {
        self.gs_base
    }
}

impl Default for TlsState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GprState {
    rip: GuestAddress,
    rsp: GuestAddress,
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rbp: u64,
    r10: u64,
    r8: u64,
    r9: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rflags: u64,
}

impl GprState {
    #[must_use]
    pub const fn new(rip: GuestAddress, rsp: GuestAddress) -> Self {
        Self::with_syscall_registers(rip, rsp, 0, [0; 6])
    }

    #[must_use]
    pub const fn with_syscall_registers(
        rip: GuestAddress,
        rsp: GuestAddress,
        rax: u64,
        args: [u64; 6],
    ) -> Self {
        Self {
            rip,
            rsp,
            rax,
            rbx: 0,
            rcx: 0,
            rdi: args[0],
            rsi: args[1],
            rdx: args[2],
            rbp: 0,
            r10: args[3],
            r8: args[4],
            r9: args[5],
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rflags: X86_64_DEFAULT_RFLAGS,
        }
    }

    #[must_use]
    pub const fn with_full_registers(
        rip: GuestAddress,
        rsp: GuestAddress,
        registers: [u64; 15],
        rflags: u64,
    ) -> Self {
        Self {
            rip,
            rsp,
            rax: registers[0],
            rbx: registers[1],
            rcx: registers[2],
            rdx: registers[3],
            rsi: registers[4],
            rdi: registers[5],
            rbp: registers[6],
            r8: registers[7],
            r9: registers[8],
            r10: registers[9],
            r11: registers[10],
            r12: registers[11],
            r13: registers[12],
            r14: registers[13],
            r15: registers[14],
            rflags,
        }
    }

    #[must_use]
    pub const fn with_syscall_return(self, rip: GuestAddress, rax: u64) -> Self {
        Self { rip, rax, ..self }
    }

    #[must_use]
    pub const fn rip(self) -> GuestAddress {
        self.rip
    }

    #[must_use]
    pub const fn rsp(self) -> GuestAddress {
        self.rsp
    }

    #[must_use]
    pub const fn rax(self) -> u64 {
        self.rax
    }

    #[must_use]
    pub const fn rbx(self) -> u64 {
        self.rbx
    }

    #[must_use]
    pub const fn rcx(self) -> u64 {
        self.rcx
    }

    #[must_use]
    pub const fn rdi(self) -> u64 {
        self.rdi
    }

    #[must_use]
    pub const fn rsi(self) -> u64 {
        self.rsi
    }

    #[must_use]
    pub const fn rdx(self) -> u64 {
        self.rdx
    }

    #[must_use]
    pub const fn rbp(self) -> u64 {
        self.rbp
    }

    #[must_use]
    pub const fn r10(self) -> u64 {
        self.r10
    }

    #[must_use]
    pub const fn r8(self) -> u64 {
        self.r8
    }

    #[must_use]
    pub const fn r9(self) -> u64 {
        self.r9
    }

    #[must_use]
    pub const fn r11(self) -> u64 {
        self.r11
    }

    #[must_use]
    pub const fn r12(self) -> u64 {
        self.r12
    }

    #[must_use]
    pub const fn r13(self) -> u64 {
        self.r13
    }

    #[must_use]
    pub const fn r14(self) -> u64 {
        self.r14
    }

    #[must_use]
    pub const fn r15(self) -> u64 {
        self.r15
    }

    #[must_use]
    pub const fn rflags(self) -> u64 {
        self.rflags
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    Runnable,
    WaitingForChild { args: Wait4SyscallArgs },
    Exited { status: i32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestTask {
    tid: GuestTid,
    pid: GuestPid,
    regs: GprState,
    tls: TlsState,
    state: TaskState,
    robust_list: Option<GuestAddress>,
    clear_child_tid: Option<GuestAddress>,
}

impl GuestTask {
    fn initial(tid: GuestTid, pid: GuestPid, image: &GuestMemoryImage) -> Self {
        Self {
            tid,
            pid,
            regs: GprState::new(image.entrypoint(), image.initial_stack_pointer()),
            tls: TlsState::new(),
            state: TaskState::Runnable,
            robust_list: None,
            clear_child_tid: None,
        }
    }

    #[must_use]
    pub const fn tid(&self) -> GuestTid {
        self.tid
    }

    #[must_use]
    pub const fn pid(&self) -> GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn regs(&self) -> GprState {
        self.regs
    }

    pub fn set_regs(&mut self, regs: GprState) {
        self.regs = regs;
    }

    #[must_use]
    pub const fn tls(&self) -> TlsState {
        self.tls
    }

    #[must_use]
    pub const fn state(&self) -> TaskState {
        self.state
    }

    #[must_use]
    pub const fn robust_list(&self) -> Option<GuestAddress> {
        self.robust_list
    }

    #[must_use]
    pub const fn clear_child_tid(&self) -> Option<GuestAddress> {
        self.clear_child_tid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitState {
    Running,
    Exited { status: i32 },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestSignalAction {
    action: GuestAddress,
}

impl GuestSignalAction {
    #[must_use]
    pub const fn new(action: GuestAddress) -> Self {
        Self { action }
    }

    #[must_use]
    pub const fn action(self) -> GuestAddress {
        self.action
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignalState {
    actions: BTreeMap<u32, GuestSignalAction>,
    blocked: u64,
}

impl SignalState {
    #[must_use]
    pub fn action(&self, signal: u32) -> Option<GuestSignalAction> {
        self.actions.get(&signal).copied()
    }

    #[must_use]
    pub const fn blocked(&self) -> u64 {
        self.blocked
    }

    fn set_action(&mut self, signal: u32, action: GuestSignalAction) {
        self.actions.insert(signal, action);
    }

    fn apply_mask(&mut self, how: u32, mask: u64) -> Result<(), TaskError> {
        match how {
            LINUX_SIG_BLOCK => {
                self.blocked |= mask;
                Ok(())
            }
            LINUX_SIG_UNBLOCK => {
                self.blocked &= !mask;
                Ok(())
            }
            LINUX_SIG_SETMASK => {
                self.blocked = mask;
                Ok(())
            }
            _ => Err(TaskError::InvalidSignalMaskHow(how)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitedChild {
    pid: GuestPid,
    status: i32,
    wait_status: u32,
}

impl WaitedChild {
    #[must_use]
    pub const fn new(pid: GuestPid, status: i32) -> Self {
        Self {
            pid,
            status,
            wait_status: linux_wait_exit_status(status),
        }
    }

    #[must_use]
    pub const fn pid(self) -> GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn status(self) -> i32 {
        self.status
    }

    #[must_use]
    pub const fn wait_status(self) -> u32 {
        self.wait_status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletedWait {
    tid: GuestTid,
    pid: GuestPid,
    args: Wait4SyscallArgs,
    waited: WaitedChild,
}

impl CompletedWait {
    #[must_use]
    pub const fn new(
        tid: GuestTid,
        pid: GuestPid,
        args: Wait4SyscallArgs,
        waited: WaitedChild,
    ) -> Self {
        Self {
            tid,
            pid,
            args,
            waited,
        }
    }

    #[must_use]
    pub const fn tid(self) -> GuestTid {
        self.tid
    }

    #[must_use]
    pub const fn pid(self) -> GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn args(self) -> Wait4SyscallArgs {
        self.args
    }

    #[must_use]
    pub const fn waited(self) -> WaitedChild {
        self.waited
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestFdTable {
    entries: BTreeMap<i32, GuestFdEntry>,
}

impl GuestFdTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_stdio() -> Self {
        let mut table = Self::new();
        table
            .insert_exact(0, GuestFdEntry::stdio("stdin"), false)
            .expect("stdio fd 0 is available in a new fd table");
        table
            .insert_exact(1, GuestFdEntry::stdio("stdout"), false)
            .expect("stdio fd 1 is available in a new fd table");
        table
            .insert_exact(2, GuestFdEntry::stdio("stderr"), false)
            .expect("stdio fd 2 is available in a new fd table");
        table
    }

    pub fn insert_exact(
        &mut self,
        fd: i32,
        mut entry: GuestFdEntry,
        cloexec: bool,
    ) -> Result<(), TaskError> {
        if fd < 0 || self.entries.contains_key(&fd) {
            return Err(TaskError::BadFd(fd));
        }

        entry.cloexec = cloexec;
        self.entries.insert(fd, entry);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, fd: i32) -> Option<&GuestFdEntry> {
        self.entries.get(&fd)
    }

    #[must_use]
    pub fn contains(&self, fd: i32) -> bool {
        self.entries.contains_key(&fd)
    }

    pub fn set_cloexec(&mut self, fd: i32, cloexec: bool) -> Result<(), TaskError> {
        let entry = self.entries.get_mut(&fd).ok_or(TaskError::BadFd(fd))?;
        entry.cloexec = cloexec;
        Ok(())
    }

    pub fn close_on_exec(&mut self) {
        self.entries.retain(|_, entry| !entry.cloexec);
    }
}

impl Default for GuestFdTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestFdEntry {
    description: String,
    cloexec: bool,
}

impl GuestFdEntry {
    #[must_use]
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            cloexec: false,
        }
    }

    #[must_use]
    pub fn stdio(name: impl Into<String>) -> Self {
        Self::new(name)
    }

    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    #[must_use]
    pub const fn cloexec(&self) -> bool {
        self.cloexec
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestProcess {
    pid: GuestPid,
    parent: Option<GuestPid>,
    pgid: GuestPid,
    sid: GuestPid,
    image: GuestImageState,
    files: GuestFdTable,
    signals: SignalState,
    children: BTreeSet<GuestPid>,
    exit_state: ExitState,
}

impl GuestProcess {
    #[must_use]
    pub const fn pid(&self) -> GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn parent(&self) -> Option<GuestPid> {
        self.parent
    }

    #[must_use]
    pub const fn pgid(&self) -> GuestPid {
        self.pgid
    }

    #[must_use]
    pub const fn sid(&self) -> GuestPid {
        self.sid
    }

    #[must_use]
    pub fn image(&self) -> &GuestImageState {
        &self.image
    }

    #[must_use]
    pub const fn files(&self) -> &GuestFdTable {
        &self.files
    }

    #[must_use]
    pub const fn files_mut(&mut self) -> &mut GuestFdTable {
        &mut self.files
    }

    #[must_use]
    pub const fn signals(&self) -> &SignalState {
        &self.signals
    }

    #[must_use]
    pub const fn signals_mut(&mut self) -> &mut SignalState {
        &mut self.signals
    }

    #[must_use]
    pub fn children(&self) -> &BTreeSet<GuestPid> {
        &self.children
    }

    #[must_use]
    pub const fn exit_state(&self) -> ExitState {
        self.exit_state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestKernel {
    next_pid: GuestPid,
    next_tid: GuestTid,
    processes: BTreeMap<GuestPid, GuestProcess>,
    tasks: BTreeMap<GuestTid, GuestTask>,
}

impl GuestKernel {
    pub fn new(program: GuestProgram) -> Result<Self, TaskError> {
        let mut kernel = Self {
            next_pid: INITIAL_GUEST_PID,
            next_tid: INITIAL_GUEST_TID,
            processes: BTreeMap::new(),
            tasks: BTreeMap::new(),
        };
        kernel.create_initial_process(program)?;
        Ok(kernel)
    }

    #[must_use]
    pub const fn next_pid(&self) -> GuestPid {
        self.next_pid
    }

    #[must_use]
    pub const fn next_tid(&self) -> GuestTid {
        self.next_tid
    }

    #[must_use]
    pub fn process(&self, pid: GuestPid) -> Option<&GuestProcess> {
        self.processes.get(&pid)
    }

    #[must_use]
    pub fn process_mut(&mut self, pid: GuestPid) -> Option<&mut GuestProcess> {
        self.processes.get_mut(&pid)
    }

    #[must_use]
    pub fn task(&self, tid: GuestTid) -> Option<&GuestTask> {
        self.tasks.get(&tid)
    }

    #[must_use]
    pub fn task_mut(&mut self, tid: GuestTid) -> Option<&mut GuestTask> {
        self.tasks.get_mut(&tid)
    }

    pub fn dispatch_for_current_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let tid = request.context.tid;
        let Some(task) = self.tasks.get(&tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };

        if task.pid != request.context.pid {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }

        match request.syscall {
            Syscall::Getpid => SyscallOutcome::success(u64::from(task.pid)),
            Syscall::Gettid => SyscallOutcome::success(u64::from(task.tid)),
            Syscall::Getppid => {
                SyscallOutcome::success(u64::from(task_process(self, task.pid).parent.unwrap_or(0)))
            }
            Syscall::Getpgrp => {
                SyscallOutcome::success(u64::from(task_process(self, task.pid).pgid))
            }
            Syscall::Getuid | Syscall::Geteuid | Syscall::Getgid | Syscall::Getegid => {
                SyscallOutcome::success(0)
            }
            Syscall::Setuid | Syscall::Setgid | Syscall::Setreuid | Syscall::Setregid => {
                SyscallOutcome::success(0)
            }
            Syscall::Setpgid => self.setpgid_current(task.pid, arg(request, 0), arg(request, 1)),
            Syscall::Setsid => self.setsid_current(task.pid),
            Syscall::Fork => self.fork_like_current(tid, "fork", child_return_rip(request)),
            Syscall::Vfork => self.fork_like_current(tid, "vfork", child_return_rip(request)),
            Syscall::Clone => self.clone_current_with_return(
                tid,
                CloneSyscallArgs::new(
                    arg(request, 0),
                    arg(request, 1),
                    arg(request, 2),
                    arg(request, 3),
                    arg(request, 4),
                ),
                child_return_rip(request),
            ),
            Syscall::Exit => self.exit_task(tid, low_exit_status(arg(request, 0))),
            Syscall::ExitGroup => self.exit_group(task.pid, low_exit_status(arg(request, 0))),
            Syscall::Wait4 => self.wait4_current_with_return(
                tid,
                Wait4SyscallArgs::new(
                    arg(request, 0) as i32,
                    arg(request, 1),
                    arg(request, 2) as u32,
                    arg(request, 3),
                ),
                child_return_rip(request),
            ),
            Syscall::RtSigaction => self.rt_sigaction_current(
                tid,
                RtSigactionSyscallArgs::new(
                    arg(request, 0) as u32,
                    arg(request, 1),
                    arg(request, 2),
                    arg(request, 3),
                ),
            ),
            Syscall::RtSigprocmask => self.rt_sigprocmask_current(
                tid,
                RtSigprocmaskSyscallArgs::new(
                    arg(request, 0) as u32,
                    arg(request, 1),
                    arg(request, 2),
                    arg(request, 3),
                ),
            ),
            Syscall::RtSigreturn => SyscallOutcome::success(0),
            Syscall::Kill => self.kill_current(KillSyscallArgs::new(
                arg(request, 0) as i32,
                arg(request, 1) as u32,
            )),
            Syscall::Tgkill => self.tgkill_current(TgkillSyscallArgs::new(
                arg(request, 0) as i32,
                arg(request, 1) as i32,
                arg(request, 2) as u32,
            )),
            Syscall::SetTidAddress => {
                self.set_tid_address_current(tid, SetTidAddressSyscallArgs::new(arg(request, 0)))
            }
            Syscall::SetRobustList => self.set_robust_list_current(
                tid,
                SetRobustListSyscallArgs::new(arg(request, 0), arg(request, 1)),
            ),
            Syscall::Uname => self.uname(arg(request, 0)),
            Syscall::ArchPrctl => self.arch_prctl(tid, arg(request, 0), arg(request, 1)),
            Syscall::Execve => {
                let image = &task_process(self, task.pid).image;
                let mut program = GuestProgram::new(image.executable.clone());
                if let Some(interpreter) = &image.interpreter {
                    program = program.with_interpreter(interpreter.clone());
                }
                self.execve_current(tid, program)
            }
            _ => SyscallOutcome::unsupported(),
        }
    }

    pub fn fork_current(&mut self, tid: GuestTid) -> SyscallOutcome {
        self.fork_like_current(tid, "fork", current_syscall_return_rip(self, tid))
    }

    pub fn vfork_current(&mut self, tid: GuestTid) -> SyscallOutcome {
        self.fork_like_current(tid, "vfork", current_syscall_return_rip(self, tid))
    }

    pub fn clone_current(&mut self, tid: GuestTid, args: CloneSyscallArgs) -> SyscallOutcome {
        self.clone_current_with_return(tid, args, current_syscall_return_rip(self, tid))
    }

    fn setpgid_current(
        &mut self,
        current_pid: GuestPid,
        raw_pid: u64,
        raw_pgid: u64,
    ) -> SyscallOutcome {
        let pid = if raw_pid == 0 {
            current_pid
        } else {
            match GuestPid::try_from(raw_pid) {
                Ok(pid) => pid,
                Err(_) => return SyscallOutcome::errno(LinuxErrno::EINVAL),
            }
        };
        let pgid = if raw_pgid == 0 {
            pid
        } else {
            match GuestPid::try_from(raw_pgid) {
                Ok(pgid) => pgid,
                Err(_) => return SyscallOutcome::errno(LinuxErrno::EINVAL),
            }
        };
        let Some(process) = self.processes.get_mut(&pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if process.parent != Some(current_pid) && pid != current_pid {
            return SyscallOutcome::errno(LinuxErrno::EPERM);
        }
        process.pgid = pgid;
        SyscallOutcome::success(0)
    }

    fn setsid_current(&mut self, current_pid: GuestPid) -> SyscallOutcome {
        let Some(process) = self.processes.get_mut(&current_pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        process.sid = current_pid;
        process.pgid = current_pid;
        SyscallOutcome::success(current_pid.into())
    }

    pub fn fork_current_with_child_regs(
        &mut self,
        tid: GuestTid,
        child_regs: GprState,
    ) -> SyscallOutcome {
        self.fork_like_current_with_child_regs(tid, "fork", child_regs)
    }

    pub fn vfork_current_with_child_regs(
        &mut self,
        tid: GuestTid,
        child_regs: GprState,
    ) -> SyscallOutcome {
        self.fork_like_current_with_child_regs(tid, "vfork", child_regs)
    }

    pub fn clone_current_with_child_regs(
        &mut self,
        tid: GuestTid,
        args: CloneSyscallArgs,
        child_regs: GprState,
    ) -> SyscallOutcome {
        if !is_supported_fork_like_clone(args.flags) {
            return TaskError::InvalidCloneFlags(args.flags).into_outcome();
        }

        self.fork_like_current_with_child_regs(tid, "clone", child_regs)
            .with_decoded_field("clone_flags", format!("{:#x}", args.flags))
    }

    fn clone_current_with_return(
        &mut self,
        tid: GuestTid,
        args: CloneSyscallArgs,
        child_return_rip: GuestAddress,
    ) -> SyscallOutcome {
        if !is_supported_fork_like_clone(args.flags) {
            return TaskError::InvalidCloneFlags(args.flags).into_outcome();
        }

        self.fork_like_current(tid, "clone", child_return_rip)
            .with_decoded_field("clone_flags", format!("{:#x}", args.flags))
    }

    pub fn fork_child(&mut self, tid: GuestTid) -> Result<GuestPid, TaskError> {
        let (child_pid, _) = self.fork_child_task(tid)?;

        Ok(child_pid)
    }

    fn fork_child_task(&mut self, tid: GuestTid) -> Result<(GuestPid, GuestTid), TaskError> {
        let parent_task = self.task(tid).cloned().ok_or(TaskError::UnknownTid(tid))?;
        let parent_pid = parent_task.pid;
        let parent = self
            .process(parent_pid)
            .cloned()
            .ok_or(TaskError::UnknownPid(parent_pid))?;
        if !matches!(parent.exit_state, ExitState::Running) {
            return Err(TaskError::UnknownPid(parent_pid));
        }

        let child_pid = self.allocate_pid()?;
        let child_tid = self.allocate_tid()?;
        let mut child_task = parent_task;
        child_task.pid = child_pid;
        child_task.tid = child_tid;
        child_task.state = TaskState::Runnable;

        self.processes.insert(
            child_pid,
            GuestProcess {
                pid: child_pid,
                parent: Some(parent_pid),
                pgid: parent.pgid,
                sid: parent.sid,
                image: parent.image,
                files: parent.files,
                signals: parent.signals,
                children: BTreeSet::new(),
                exit_state: ExitState::Running,
            },
        );
        self.tasks.insert(child_tid, child_task);
        self.process_mut(parent_pid)
            .ok_or(TaskError::UnknownPid(parent_pid))?
            .children
            .insert(child_pid);

        Ok((child_pid, child_tid))
    }

    pub fn wait4_child(
        &mut self,
        parent_pid: GuestPid,
        args: Wait4SyscallArgs,
    ) -> Result<Option<WaitedChild>, TaskError> {
        if args.has_unsupported_options() {
            return Err(TaskError::InvalidWaitOptions(args.options));
        }

        let child_pid = self.exited_waitable_child(parent_pid, args.pid)?;
        match child_pid {
            Some(child_pid) => self.reap_child(parent_pid, child_pid).map(Some),
            None if self.has_waitable_child(parent_pid, args.pid)? && args.no_hang() => Ok(None),
            None if self.has_waitable_child(parent_pid, args.pid)? => Err(TaskError::WouldBlock),
            None => Err(TaskError::NoChild),
        }
    }

    pub fn execve_current(&mut self, tid: GuestTid, program: GuestProgram) -> SyscallOutcome {
        match self.exec_task(tid, program) {
            Ok(()) => SyscallOutcome::success(0),
            Err(error) => error.into_outcome(),
        }
    }

    pub fn exec_task(&mut self, tid: GuestTid, program: GuestProgram) -> Result<(), TaskError> {
        let pid = self
            .task(tid)
            .ok_or(TaskError::UnknownTid(tid))
            .map(|task| task.pid)?;
        let image = load_program(program)?;

        {
            let process = self.process_mut(pid).ok_or(TaskError::UnknownPid(pid))?;
            process.files.close_on_exec();
            process.image = image;
            process.exit_state = ExitState::Running;
        }

        let (entrypoint, stack_pointer) = {
            let memory = self
                .process(pid)
                .ok_or(TaskError::UnknownPid(pid))?
                .image
                .memory();
            (memory.entrypoint(), memory.initial_stack_pointer())
        };
        let task = self.task_mut(tid).ok_or(TaskError::UnknownTid(tid))?;
        task.regs = GprState::new(entrypoint, stack_pointer);
        task.tls = TlsState::new();
        task.state = TaskState::Runnable;
        task.robust_list = None;
        task.clear_child_tid = None;

        Ok(())
    }

    pub fn exit_task(&mut self, tid: GuestTid, status: i32) -> SyscallOutcome {
        let Some(task) = self.tasks.get_mut(&tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };

        task.state = TaskState::Exited { status };
        let pid = task.pid;

        let all_exited = self
            .tasks
            .values()
            .filter(|candidate| candidate.pid == pid)
            .all(|candidate| matches!(candidate.state, TaskState::Exited { .. }));
        if all_exited {
            if let Some(process) = self.processes.get_mut(&pid) {
                process.exit_state = ExitState::Exited { status };
            }
        }

        SyscallOutcome::success(0)
            .with_decoded_field("guest_tid", tid.to_string())
            .with_decoded_field("exit_status", status.to_string())
    }

    pub fn exit_group(&mut self, pid: GuestPid, status: i32) -> SyscallOutcome {
        if !self.processes.contains_key(&pid) {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }

        for task in self.tasks.values_mut().filter(|task| task.pid == pid) {
            task.state = TaskState::Exited { status };
        }
        if let Some(process) = self.processes.get_mut(&pid) {
            process.exit_state = ExitState::Exited { status };
        }

        SyscallOutcome::success(0)
            .with_decoded_field("guest_pid", pid.to_string())
            .with_decoded_field("exit_status", status.to_string())
    }

    pub fn wait4_current(&mut self, tid: GuestTid, args: Wait4SyscallArgs) -> SyscallOutcome {
        self.wait4_current_with_return(tid, args, current_syscall_return_rip(self, tid))
    }

    fn wait4_current_with_return(
        &mut self,
        tid: GuestTid,
        args: Wait4SyscallArgs,
        return_rip: GuestAddress,
    ) -> SyscallOutcome {
        let Some(parent_pid) = self.task(tid).map(|task| task.pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };

        match self.wait4_child(parent_pid, args) {
            Ok(Some(waited)) => SyscallOutcome::success(u64::from(waited.pid()))
                .with_decoded_field("guest_pid", waited.pid().to_string())
                .with_decoded_field("exit_status", waited.status().to_string())
                .with_decoded_field("wait_status", format!("{:#x}", waited.wait_status())),
            Ok(None) => SyscallOutcome::success(0),
            Err(TaskError::WouldBlock) => {
                let Some(task) = self.task_mut(tid) else {
                    return SyscallOutcome::errno(LinuxErrno::ESRCH);
                };
                task.regs = task.regs.with_syscall_return(return_rip, task.regs.rax());
                task.state = TaskState::WaitingForChild { args };
                SyscallOutcome::success(0).with_decoded_field("task_blocked", "wait4")
            }
            Err(error) => error.into_outcome(),
        }
    }

    #[must_use]
    pub fn runnable_tids(&self) -> Vec<GuestTid> {
        self.tasks
            .values()
            .filter(|task| matches!(task.state, TaskState::Runnable))
            .map(|task| task.tid)
            .collect()
    }

    pub fn resume_waiting_tasks(&mut self) -> Vec<CompletedWait> {
        let waiting_tasks: Vec<(GuestTid, GuestPid, Wait4SyscallArgs)> = self
            .tasks
            .values()
            .filter_map(|task| match task.state {
                TaskState::WaitingForChild { args } => Some((task.tid, task.pid, args)),
                TaskState::Runnable | TaskState::Exited { .. } => None,
            })
            .collect();
        let mut completed = Vec::new();

        for (tid, parent_pid, args) in waiting_tasks {
            let Ok(Some(waited)) = self.wait4_child(parent_pid, args) else {
                continue;
            };
            if let Some(task) = self.task_mut(tid) {
                task.regs = task
                    .regs
                    .with_syscall_return(task.regs.rip(), u64::from(waited.pid()));
                task.state = TaskState::Runnable;
            }
            completed.push(CompletedWait::new(tid, parent_pid, args, waited));
        }
        completed
    }

    pub fn rt_sigaction_current(
        &mut self,
        tid: GuestTid,
        args: RtSigactionSyscallArgs,
    ) -> SyscallOutcome {
        let Some(pid) = self.task(tid).map(|task| task.pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if let Err(error) = validate_signal(args.sig) {
            return error.into_outcome();
        }
        if args.sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
            return TaskError::InvalidSigsetSize(args.sigsetsize).into_outcome();
        }
        if args.act != 0 {
            let Some(process) = self.process_mut(pid) else {
                return SyscallOutcome::errno(LinuxErrno::ESRCH);
            };
            process
                .signals
                .set_action(args.sig, GuestSignalAction::new(args.act));
        }
        SyscallOutcome::success(0).with_decoded_field("signal", args.sig.to_string())
    }

    pub fn rt_sigprocmask_current(
        &mut self,
        tid: GuestTid,
        args: RtSigprocmaskSyscallArgs,
    ) -> SyscallOutcome {
        let Some(pid) = self.task(tid).map(|task| task.pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if args.sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
            return TaskError::InvalidSigsetSize(args.sigsetsize).into_outcome();
        }
        if !args.supported_how() {
            return TaskError::InvalidSignalMaskHow(args.how).into_outcome();
        }
        if args.set != 0 {
            let Some(process) = self.process_mut(pid) else {
                return SyscallOutcome::errno(LinuxErrno::ESRCH);
            };
            if let Err(error) = process.signals.apply_mask(args.how, args.set) {
                return error.into_outcome();
            }
        }
        SyscallOutcome::success(0).with_decoded_field("signal_mask", format!("{:#x}", args.set))
    }

    pub fn kill_current(&mut self, args: KillSyscallArgs) -> SyscallOutcome {
        if args.pid <= 0 {
            return TaskError::UnsupportedSignalTarget(args.pid).into_outcome();
        }
        let pid = args.pid as GuestPid;
        if !self.processes.contains_key(&pid) {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }
        if let Err(error) = validate_signal_or_probe(args.sig) {
            return error.into_outcome();
        }
        if args.sig == 0 {
            return SyscallOutcome::success(0);
        }
        if is_terminating_signal(args.sig) {
            return self.exit_group(pid, signal_exit_status(args.sig));
        }
        SyscallOutcome::success(0).with_decoded_field("queued_signal", args.sig.to_string())
    }

    pub fn tgkill_current(&mut self, args: TgkillSyscallArgs) -> SyscallOutcome {
        if args.tgid <= 0 || args.tid <= 0 {
            return TaskError::UnsupportedSignalTarget(args.tid).into_outcome();
        }
        let pid = args.tgid as GuestPid;
        let tid = args.tid as GuestTid;
        let Some(task) = self.task(tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if task.pid != pid {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }
        if let Err(error) = validate_signal_or_probe(args.sig) {
            return error.into_outcome();
        }
        if args.sig == 0 {
            return SyscallOutcome::success(0);
        }
        if is_terminating_signal(args.sig) {
            return self.exit_task(tid, signal_exit_status(args.sig));
        }
        SyscallOutcome::success(0).with_decoded_field("queued_signal", args.sig.to_string())
    }

    pub fn set_tid_address_current(
        &mut self,
        tid: GuestTid,
        args: SetTidAddressSyscallArgs,
    ) -> SyscallOutcome {
        let Some(task) = self.task_mut(tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        task.clear_child_tid = (args.tidptr != 0).then_some(args.tidptr);
        SyscallOutcome::success(u64::from(tid))
            .with_decoded_field("clear_child_tid", format!("{:#x}", args.tidptr))
    }

    pub fn set_robust_list_current(
        &mut self,
        tid: GuestTid,
        args: SetRobustListSyscallArgs,
    ) -> SyscallOutcome {
        if args.len != LINUX_ROBUST_LIST_HEAD_SIZE {
            return TaskError::InvalidRobustListLength(args.len).into_outcome();
        }
        let Some(task) = self.task_mut(tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        task.robust_list = (args.head != 0).then_some(args.head);
        SyscallOutcome::success(0).with_decoded_field("robust_list", format!("{:#x}", args.head))
    }

    pub fn arch_prctl(
        &mut self,
        tid: GuestTid,
        code: u64,
        address: GuestAddress,
    ) -> SyscallOutcome {
        let Some(task) = self.tasks.get_mut(&tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };

        match code {
            ARCH_SET_FS => {
                task.tls.fs_base = address;
                SyscallOutcome::success(0).with_decoded_field("fs_base", format!("{address:#x}"))
            }
            ARCH_SET_GS => {
                task.tls.gs_base = address;
                SyscallOutcome::success(0).with_decoded_field("gs_base", format!("{address:#x}"))
            }
            ARCH_GET_FS => SyscallOutcome::success(task.tls.fs_base)
                .with_decoded_field("fs_base", format!("{:#x}", task.tls.fs_base)),
            ARCH_GET_GS => SyscallOutcome::success(task.tls.gs_base)
                .with_decoded_field("gs_base", format!("{:#x}", task.tls.gs_base)),
            _ => SyscallOutcome::errno(LinuxErrno::EINVAL)
                .with_decoded_field("arch_prctl_code", format!("{code:#x}")),
        }
    }

    pub fn uname(&self, buffer: GuestAddress) -> SyscallOutcome {
        if buffer == 0 {
            return SyscallOutcome::errno(LinuxErrno::EFAULT);
        }

        SyscallOutcome::success(0)
            .with_decoded_field("sysname", "Linux")
            .with_decoded_field("nodename", "mcr")
            .with_decoded_field("release", "6.6.0-mcr")
            .with_decoded_field("version", "#1 MCR")
            .with_decoded_field("machine", "x86_64")
            .with_decoded_field("domainname", "(none)")
    }

    #[must_use]
    pub fn uname_value(&self) -> LinuxUtsname {
        linux_utsname()
    }

    fn create_initial_process(&mut self, program: GuestProgram) -> Result<(), TaskError> {
        let pid = self.allocate_pid()?;
        let tid = self.allocate_tid()?;
        let image = load_program(program)?;
        let task = GuestTask::initial(tid, pid, image.memory());

        self.processes.insert(
            pid,
            GuestProcess {
                pid,
                parent: None,
                pgid: pid,
                sid: pid,
                image,
                files: GuestFdTable::with_stdio(),
                signals: SignalState::default(),
                children: BTreeSet::new(),
                exit_state: ExitState::Running,
            },
        );
        self.tasks.insert(tid, task);

        Ok(())
    }

    fn allocate_pid(&mut self) -> Result<GuestPid, TaskError> {
        let pid = self.next_pid;
        self.next_pid = self
            .next_pid
            .checked_add(1)
            .ok_or(TaskError::PidExhausted)?;
        Ok(pid)
    }

    fn allocate_tid(&mut self) -> Result<GuestTid, TaskError> {
        let tid = self.next_tid;
        self.next_tid = self
            .next_tid
            .checked_add(1)
            .ok_or(TaskError::TidExhausted)?;
        Ok(tid)
    }

    fn fork_like_current(
        &mut self,
        tid: GuestTid,
        syscall: &'static str,
        child_return_rip: GuestAddress,
    ) -> SyscallOutcome {
        match self.fork_child_task(tid) {
            Ok((child_pid, child_tid)) => {
                if let Some(child_task) = self.task_mut(child_tid) {
                    child_task.regs = child_task.regs.with_syscall_return(child_return_rip, 0);
                }
                SyscallOutcome::success(u64::from(child_pid))
                    .with_decoded_field("guest_pid", child_pid.to_string())
                    .with_decoded_field("fork_kind", syscall)
            }
            Err(error) => error.into_outcome(),
        }
    }

    fn fork_like_current_with_child_regs(
        &mut self,
        tid: GuestTid,
        syscall: &'static str,
        child_regs: GprState,
    ) -> SyscallOutcome {
        match self.fork_child_task(tid) {
            Ok((child_pid, child_tid)) => {
                if let Some(child_task) = self.task_mut(child_tid) {
                    child_task.regs = child_regs;
                }
                SyscallOutcome::success(u64::from(child_pid))
                    .with_decoded_field("guest_pid", child_pid.to_string())
                    .with_decoded_field("fork_kind", syscall)
            }
            Err(error) => error.into_outcome(),
        }
    }

    fn exited_waitable_child(
        &self,
        parent_pid: GuestPid,
        selector: i32,
    ) -> Result<Option<GuestPid>, TaskError> {
        Ok(self
            .matching_children(parent_pid, selector)?
            .into_iter()
            .find(|pid| {
                matches!(
                    self.process(*pid).map(GuestProcess::exit_state),
                    Some(ExitState::Exited { .. })
                )
            }))
    }

    fn has_waitable_child(&self, parent_pid: GuestPid, selector: i32) -> Result<bool, TaskError> {
        Ok(!self.matching_children(parent_pid, selector)?.is_empty())
    }

    fn matching_children(
        &self,
        parent_pid: GuestPid,
        selector: i32,
    ) -> Result<Vec<GuestPid>, TaskError> {
        let parent = self
            .process(parent_pid)
            .ok_or(TaskError::UnknownPid(parent_pid))?;
        let children = parent
            .children
            .iter()
            .copied()
            .filter(|child_pid| self.child_matches(parent, *child_pid, selector))
            .collect();
        Ok(children)
    }

    fn child_matches(&self, parent: &GuestProcess, child_pid: GuestPid, selector: i32) -> bool {
        let Some(child) = self.process(child_pid) else {
            return false;
        };

        match selector {
            -1 => true,
            0 => child.pgid == parent.pgid,
            value if value > 0 => child_pid == value as GuestPid,
            value => child.pgid == value.unsigned_abs(),
        }
    }

    fn reap_child(
        &mut self,
        parent_pid: GuestPid,
        child_pid: GuestPid,
    ) -> Result<WaitedChild, TaskError> {
        let status = match self
            .process(child_pid)
            .ok_or(TaskError::UnknownPid(child_pid))?
            .exit_state()
        {
            ExitState::Exited { status } => status,
            ExitState::Running => return Err(TaskError::WouldBlock),
        };

        self.tasks.retain(|_, task| task.pid != child_pid);
        self.processes.remove(&child_pid);
        self.process_mut(parent_pid)
            .ok_or(TaskError::UnknownPid(parent_pid))?
            .children
            .remove(&child_pid);

        Ok(WaitedChild::new(child_pid, status))
    }
}

impl TaskSyscalls for GuestKernel {
    fn dispatch_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        self.dispatch_for_current_task(request)
    }
}

#[derive(Debug)]
pub enum TaskError {
    BadFd(i32),
    InvalidCloneFlags(u64),
    InvalidRobustListLength(u64),
    InvalidSignal(u32),
    InvalidSignalMaskHow(u32),
    InvalidSigsetSize(u64),
    InvalidWaitOptions(u32),
    NoChild,
    PidExhausted,
    TidExhausted,
    UnknownPid(GuestPid),
    UnknownTid(GuestTid),
    UnsupportedSignalTarget(i32),
    WouldBlock,
    Elf(mcr_elf::ElfValidationError),
    Image(GuestImageError),
}

impl TaskError {
    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        match self {
            Self::BadFd(_) => LinuxErrno::EBADF,
            Self::InvalidCloneFlags(_)
            | Self::InvalidRobustListLength(_)
            | Self::InvalidSignal(_)
            | Self::InvalidSignalMaskHow(_)
            | Self::InvalidSigsetSize(_)
            | Self::InvalidWaitOptions(_)
            | Self::UnsupportedSignalTarget(_) => LinuxErrno::EINVAL,
            Self::NoChild => LinuxErrno::ECHILD,
            Self::PidExhausted | Self::TidExhausted => LinuxErrno::EAGAIN,
            Self::UnknownPid(_) | Self::UnknownTid(_) => LinuxErrno::ESRCH,
            Self::WouldBlock => LinuxErrno::EAGAIN,
            Self::Elf(_) | Self::Image(_) => LinuxErrno::ENOEXEC,
        }
    }

    #[must_use]
    pub fn into_outcome(self) -> SyscallOutcome {
        SyscallOutcome::errno(self.linux_errno()).with_decoded_field("task_error", self.to_string())
    }
}

impl fmt::Display for TaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFd(fd) => write!(formatter, "bad guest fd {fd}"),
            Self::InvalidCloneFlags(flags) => {
                write!(formatter, "unsupported clone flags {flags:#x}")
            }
            Self::InvalidRobustListLength(length) => {
                write!(formatter, "invalid robust list length {length}")
            }
            Self::InvalidSignal(signal) => write!(formatter, "invalid signal {signal}"),
            Self::InvalidSignalMaskHow(how) => write!(formatter, "invalid signal mask how {how}"),
            Self::InvalidSigsetSize(size) => write!(formatter, "invalid sigset size {size}"),
            Self::InvalidWaitOptions(options) => {
                write!(formatter, "unsupported wait4 options {options:#x}")
            }
            Self::NoChild => write!(formatter, "no waitable child process"),
            Self::PidExhausted => write!(formatter, "guest PID namespace exhausted"),
            Self::TidExhausted => write!(formatter, "guest TID namespace exhausted"),
            Self::UnknownPid(pid) => write!(formatter, "unknown guest pid {pid}"),
            Self::UnknownTid(tid) => write!(formatter, "unknown guest tid {tid}"),
            Self::UnsupportedSignalTarget(pid) => {
                write!(formatter, "unsupported signal target {pid}")
            }
            Self::WouldBlock => write!(formatter, "waitable child has not exited"),
            Self::Elf(error) => write!(formatter, "{error}"),
            Self::Image(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for TaskError {}

impl From<mcr_elf::ElfValidationError> for TaskError {
    fn from(value: mcr_elf::ElfValidationError) -> Self {
        Self::Elf(value)
    }
}

impl From<GuestImageError> for TaskError {
    fn from(value: GuestImageError) -> Self {
        Self::Image(value)
    }
}

fn load_program(program: GuestProgram) -> Result<GuestImageState, TaskError> {
    let parts = program.into_parts();
    let load_plan = parse_load_plan(parts.executable.bytes())?;
    let memory = mcr_elf::build_guest_memory_image_with_interpreter(
        &load_plan,
        parts.executable.bytes(),
        parts.interpreter.as_ref().map(GuestExecutable::bytes),
        InitialStackConfig::new(
            DEFAULT_STACK_TOP,
            DEFAULT_STACK_SIZE,
            parts.executable.path().to_vec(),
        )
        .with_argv(parts.argv.clone())
        .with_envp(parts.envp.clone()),
    )?;

    Ok(GuestImageState {
        executable: parts.executable,
        interpreter: parts.interpreter,
        argv: parts.argv,
        envp: parts.envp,
        memory,
    })
}

fn task_process(kernel: &GuestKernel, pid: GuestPid) -> &GuestProcess {
    kernel
        .process(pid)
        .expect("validated task pid must reference a process")
}

fn arg(request: &SyscallRequest, index: usize) -> u64 {
    request.arg(index).unwrap_or_default()
}

const fn child_return_rip(request: &SyscallRequest) -> GuestAddress {
    request
        .context
        .rip
        .saturating_add(X86_64_SYSCALL_INSTRUCTION_LEN)
}

fn current_syscall_return_rip(kernel: &GuestKernel, tid: GuestTid) -> GuestAddress {
    kernel.task(tid).map_or(0, |task| {
        task.regs()
            .rip()
            .saturating_add(X86_64_SYSCALL_INSTRUCTION_LEN)
    })
}

fn low_exit_status(raw: u64) -> i32 {
    (raw & 0xff) as i32
}

const fn linux_wait_exit_status(status: i32) -> u32 {
    ((status as u32) & 0xff) << 8
}

const fn is_supported_fork_like_clone(flags: u64) -> bool {
    let semantic_flags = flags & !LINUX_CLONE_EXIT_SIGNAL_MASK;
    let exit_signal = flags & LINUX_CLONE_EXIT_SIGNAL_MASK;
    (exit_signal == 0 || exit_signal == LINUX_SIGCHLD)
        && (semantic_flags == 0 || semantic_flags == (LINUX_CLONE_VM | LINUX_CLONE_VFORK))
        && flags & !(LINUX_CLONE_EXIT_SIGNAL_MASK | LINUX_CLONE_VM | LINUX_CLONE_VFORK) == 0
}

const fn validate_signal(signal: u32) -> Result<(), TaskError> {
    if signal > 0 && signal <= LINUX_SIGNAL_COUNT {
        Ok(())
    } else {
        Err(TaskError::InvalidSignal(signal))
    }
}

const fn validate_signal_or_probe(signal: u32) -> Result<(), TaskError> {
    if signal <= LINUX_SIGNAL_COUNT {
        Ok(())
    } else {
        Err(TaskError::InvalidSignal(signal))
    }
}

const fn is_terminating_signal(signal: u32) -> bool {
    matches!(signal, LINUX_SIGKILL | LINUX_SIGTERM)
}

const fn signal_exit_status(signal: u32) -> i32 {
    128 + (signal as i32)
}

fn linux_utsname() -> LinuxUtsname {
    let mut uts = LinuxUtsname::default();
    write_uts_field(&mut uts.sysname, b"Linux");
    write_uts_field(&mut uts.nodename, b"mcr");
    write_uts_field(&mut uts.release, b"6.6.0-mcr");
    write_uts_field(&mut uts.version, b"#1 MCR");
    write_uts_field(&mut uts.machine, b"x86_64");
    write_uts_field(&mut uts.domainname, b"(none)");
    uts
}

fn write_uts_field(field: &mut [u8], value: &[u8]) {
    let len = value.len().min(field.len().saturating_sub(1));
    field[..len].copy_from_slice(&value[..len]);
}

#[cfg(test)]
mod tests {
    use mcr_sys::{LINUX_WNOHANG, Syscall, SyscallRegisters, SyscallReturn};
    use mcr_testkit::elf::{ET_DYN, Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X, PT_INTERP};

    use super::*;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-task");
    }

    #[test]
    fn gpr_state_new_initializes_full_guest_register_defaults() {
        let regs = GprState::new(0x401000, 0x8000_0000);

        assert_eq!(regs.rip(), 0x401000);
        assert_eq!(regs.rsp(), 0x8000_0000);
        assert_eq!(regs.rax(), 0);
        assert_eq!(regs.rbx(), 0);
        assert_eq!(regs.rcx(), 0);
        assert_eq!(regs.rdi(), 0);
        assert_eq!(regs.rsi(), 0);
        assert_eq!(regs.rdx(), 0);
        assert_eq!(regs.rbp(), 0);
        assert_eq!(regs.r8(), 0);
        assert_eq!(regs.r9(), 0);
        assert_eq!(regs.r10(), 0);
        assert_eq!(regs.r11(), 0);
        assert_eq!(regs.r12(), 0);
        assert_eq!(regs.r13(), 0);
        assert_eq!(regs.r14(), 0);
        assert_eq!(regs.r15(), 0);
        assert_eq!(regs.rflags(), 0x202);
    }

    #[test]
    fn gpr_state_syscall_constructor_preserves_full_guest_register_defaults() {
        let regs = GprState::with_syscall_registers(
            0x401002,
            0x8000_0008,
            Syscall::Write.number().raw(),
            [1, 0x402000, 3, 4, 5, 6],
        );

        assert_eq!(regs.rip(), 0x401002);
        assert_eq!(regs.rsp(), 0x8000_0008);
        assert_eq!(regs.rax(), Syscall::Write.number().raw());
        assert_eq!(regs.rdi(), 1);
        assert_eq!(regs.rsi(), 0x402000);
        assert_eq!(regs.rdx(), 3);
        assert_eq!(regs.r10(), 4);
        assert_eq!(regs.r8(), 5);
        assert_eq!(regs.r9(), 6);
        assert_eq!(regs.rbx(), 0);
        assert_eq!(regs.rcx(), 0);
        assert_eq!(regs.rbp(), 0);
        assert_eq!(regs.r11(), 0);
        assert_eq!(regs.r12(), 0);
        assert_eq!(regs.r13(), 0);
        assert_eq!(regs.r14(), 0);
        assert_eq!(regs.r15(), 0);
        assert_eq!(regs.rflags(), 0x202);
    }

    #[test]
    fn initial_process_allocates_guest_ids_and_register_state() {
        let kernel = GuestKernel::new(test_program("/bin/init", 0x401000)).unwrap();

        assert_eq!(kernel.next_pid(), 2);
        assert_eq!(kernel.next_tid(), 2);

        let process = kernel.process(INITIAL_GUEST_PID).unwrap();
        let task = kernel.task(INITIAL_GUEST_TID).unwrap();

        assert_eq!(process.pid(), INITIAL_GUEST_PID);
        assert_eq!(process.parent(), None);
        assert_eq!(process.pgid(), INITIAL_GUEST_PID);
        assert_eq!(process.sid(), INITIAL_GUEST_PID);
        assert_eq!(process.exit_state(), ExitState::Running);
        assert_eq!(task.pid(), INITIAL_GUEST_PID);
        assert_eq!(task.tid(), INITIAL_GUEST_TID);
        assert_eq!(task.regs().rip(), 0x401000);
        assert_eq!(
            task.regs().rsp(),
            process.image().memory().initial_stack_pointer()
        );
        assert!(process.files().contains(0));
        assert!(process.files().contains(1));
        assert!(process.files().contains(2));
    }

    #[test]
    fn dynamic_initial_process_enters_interpreter() {
        let kernel = GuestKernel::new(dynamic_test_program("/bin/sh")).unwrap();
        let process = kernel.process(INITIAL_GUEST_PID).unwrap();
        let task = kernel.task(INITIAL_GUEST_TID).unwrap();

        assert_eq!(process.image().executable().path(), b"/bin/sh");
        assert_eq!(
            process.image().interpreter().unwrap().path(),
            b"/lib/ld-musl-x86_64.so.1"
        );
        assert_eq!(
            task.regs().rip(),
            mcr_elf::DEFAULT_INTERPRETER_LOAD_BASE + 0x400
        );
        assert!(process.image().memory().interpreter().is_some());
    }

    #[test]
    fn getpid_gettid_and_exit_syscalls_use_guest_state() {
        let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::Getpid, [0; 6]),
            SyscallReturn::Success(u64::from(INITIAL_GUEST_PID))
        );
        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::Gettid, [0; 6]),
            SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
        );

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::Exit, [300, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().state(),
            TaskState::Exited { status: 44 }
        );
        assert_eq!(
            kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
            ExitState::Exited { status: 44 }
        );
    }

    #[test]
    fn exit_group_marks_all_tasks_in_process_exited() {
        let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::ExitGroup, [7, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );

        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().state(),
            TaskState::Exited { status: 7 }
        );
        assert_eq!(
            kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
            ExitState::Exited { status: 7 }
        );
    }

    #[test]
    fn fork_creates_child_process_with_inherited_files() {
        let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
        kernel
            .process_mut(INITIAL_GUEST_PID)
            .unwrap()
            .files_mut()
            .insert_exact(3, GuestFdEntry::new("pipe-read"), true)
            .unwrap();

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::Fork, [0; 6]),
            SyscallReturn::Success(2)
        );

        let parent = kernel.process(INITIAL_GUEST_PID).unwrap();
        let child = kernel.process(2).unwrap();
        let child_task = kernel.task(2).unwrap();

        assert!(parent.children().contains(&2));
        assert_eq!(child.parent(), Some(INITIAL_GUEST_PID));
        assert_eq!(child.pgid(), parent.pgid());
        assert_eq!(child.sid(), parent.sid());
        assert_eq!(child.image().executable().path(), b"/bin/parent");
        assert_eq!(child.files().get(3).unwrap().description(), "pipe-read");
        assert!(child.files().get(3).unwrap().cloexec());
        assert_eq!(child_task.pid(), 2);
        assert_eq!(child_task.tid(), 2);
        assert_eq!(kernel.next_pid(), 3);
        assert_eq!(kernel.next_tid(), 3);
    }

    #[test]
    fn fork_syscall_prepares_child_zero_return_after_syscall() {
        let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::Fork, [0; 6]),
            SyscallReturn::Success(2)
        );

        let child_task = kernel.task(2).unwrap();
        assert_eq!(child_task.regs().rax(), 0);
        assert_eq!(child_task.regs().rip(), 0x401236);
    }

    #[test]
    fn clone_accepts_vfork_exec_shape_and_rejects_thread_flags() {
        let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::Clone,
                [
                    LINUX_CLONE_VM | LINUX_CLONE_VFORK | LINUX_SIGCHLD,
                    0,
                    0,
                    0,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(2)
        );
        assert_eq!(kernel.process(2).unwrap().parent(), Some(INITIAL_GUEST_PID));
        assert_eq!(kernel.task(2).unwrap().regs().rax(), 0);
        assert_eq!(kernel.task(2).unwrap().regs().rip(), 0x401236);

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::Clone,
                [LINUX_CLONE_VM | 0x0001_0000, 0, 0, 0, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
    }

    #[test]
    fn wait4_reaps_exited_child_and_reports_linux_status() {
        let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
        let child_pid = kernel.fork_child(INITIAL_GUEST_TID).unwrap();

        assert!(
            kernel
                .wait4_child(
                    INITIAL_GUEST_PID,
                    Wait4SyscallArgs::new(-1, 0x1000, LINUX_WNOHANG, 0),
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            kernel.exit_group(child_pid, 42).result,
            SyscallReturn::Success(0)
        );

        let waited = kernel
            .wait4_child(
                INITIAL_GUEST_PID,
                Wait4SyscallArgs::new(child_pid as i32, 0x1000, 0, 0),
            )
            .unwrap()
            .unwrap();

        assert_eq!(waited.pid(), child_pid);
        assert_eq!(waited.status(), 42);
        assert_eq!(waited.wait_status(), 42 << 8);
        assert!(
            !kernel
                .process(INITIAL_GUEST_PID)
                .unwrap()
                .children()
                .contains(&child_pid)
        );
        assert!(kernel.process(child_pid).is_none());
        assert!(kernel.task(child_pid).is_none());
    }

    #[test]
    fn wait4_blocks_and_resumes_when_child_exits() {
        let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
        let child_pid = kernel.fork_child(INITIAL_GUEST_TID).unwrap();

        let wait = kernel.wait4_current(
            INITIAL_GUEST_TID,
            Wait4SyscallArgs::new(child_pid as i32, 0x1000, 0, 0),
        );
        assert_eq!(wait.result, SyscallReturn::Success(0));
        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().state(),
            TaskState::WaitingForChild {
                args: Wait4SyscallArgs::new(child_pid as i32, 0x1000, 0, 0)
            }
        );

        assert_eq!(
            kernel.exit_group(child_pid, 37).result,
            SyscallReturn::Success(0)
        );
        let completed = kernel.resume_waiting_tasks();

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].tid(), INITIAL_GUEST_TID);
        assert_eq!(completed[0].pid(), INITIAL_GUEST_PID);
        assert_eq!(completed[0].waited().pid(), child_pid);
        assert_eq!(completed[0].waited().wait_status(), 37 << 8);
        let parent = kernel.task(INITIAL_GUEST_TID).unwrap();
        assert_eq!(parent.state(), TaskState::Runnable);
        assert_eq!(parent.regs().rax(), u64::from(child_pid));
        assert_eq!(parent.regs().rip(), 0x401002);
        assert!(kernel.process(child_pid).is_none());
        assert!(kernel.task(child_pid).is_none());
    }

    #[test]
    fn wait4_reports_no_child_and_unsupported_options() {
        let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::Wait4, [-1i64 as u64, 0, 0, 0, 0, 0]),
            SyscallReturn::Errno(LinuxErrno::ECHILD)
        );

        let child_pid = kernel.fork_child(INITIAL_GUEST_TID).unwrap();
        assert_eq!(
            kernel
                .wait4_child(
                    INITIAL_GUEST_PID,
                    Wait4SyscallArgs::new(child_pid as i32, 0, 0x8000_0000, 0),
                )
                .unwrap_err()
                .linux_errno(),
            LinuxErrno::EINVAL
        );
    }

    #[test]
    fn arch_prctl_updates_task_tls_state() {
        let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::ArchPrctl,
                [ARCH_SET_FS, 0x7000_1234, 0, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().tls().fs_base(),
            0x7000_1234
        );
        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::ArchPrctl,
                [ARCH_GET_FS, 0, 0, 0, 0, 0],
            ),
            SyscallReturn::Success(0x7000_1234)
        );
        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::ArchPrctl, [0xffff, 0, 0, 0, 0, 0],),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
    }

    #[test]
    fn uname_returns_linux_x86_64_identity() {
        let kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();
        let uts = kernel.uname_value();

        assert_eq!(c_field(&uts.sysname), b"Linux");
        assert_eq!(c_field(&uts.nodename), b"mcr");
        assert_eq!(c_field(&uts.release), b"6.6.0-mcr");
        assert_eq!(c_field(&uts.machine), b"x86_64");
    }

    #[test]
    fn execve_replaces_image_preserves_identity_and_applies_close_on_exec() {
        let mut kernel = GuestKernel::new(test_program("/bin/old", 0x401000)).unwrap();
        let process = kernel.process_mut(INITIAL_GUEST_PID).unwrap();
        process
            .files_mut()
            .insert_exact(3, GuestFdEntry::new("keep"), false)
            .unwrap();
        process
            .files_mut()
            .insert_exact(4, GuestFdEntry::new("close"), true)
            .unwrap();

        assert!(
            kernel
                .arch_prctl(INITIAL_GUEST_TID, ARCH_SET_FS, 0x7fff_aaaa)
                .result
                .is_success()
        );
        kernel
            .exec_task(
                INITIAL_GUEST_TID,
                test_program("/bin/new", 0x501000)
                    .with_args([b"/bin/new".to_vec(), b"--flag".to_vec()])
                    .with_env([b"PATH=/bin".to_vec()]),
            )
            .unwrap();

        let process = kernel.process(INITIAL_GUEST_PID).unwrap();
        let task = kernel.task(INITIAL_GUEST_TID).unwrap();

        assert_eq!(process.pid(), INITIAL_GUEST_PID);
        assert_eq!(task.tid(), INITIAL_GUEST_TID);
        assert_eq!(process.image().executable().path(), b"/bin/new");
        assert_eq!(
            process.image().argv(),
            &[b"/bin/new".to_vec(), b"--flag".to_vec()]
        );
        assert_eq!(process.image().envp(), &[b"PATH=/bin".to_vec()]);
        assert_eq!(task.regs().rip(), 0x501000);
        assert_eq!(
            task.regs().rsp(),
            process.image().memory().initial_stack_pointer()
        );
        assert_eq!(task.tls(), TlsState::new());
        assert!(process.files().contains(3));
        assert!(!process.files().contains(4));
    }

    #[test]
    fn rt_sigaction_saves_action_and_rejects_invalid_signal_or_sigset_size() {
        let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigaction,
                [
                    LINUX_SIGTERM as u64,
                    0x7000,
                    0,
                    LINUX_KERNEL_SIGSET_SIZE,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel
                .process(INITIAL_GUEST_PID)
                .unwrap()
                .signals()
                .action(LINUX_SIGTERM)
                .unwrap()
                .action(),
            0x7000
        );

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigaction,
                [0, 0x8000, 0, LINUX_KERNEL_SIGSET_SIZE, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigaction,
                [
                    LINUX_SIGTERM as u64,
                    0x8000,
                    0,
                    LINUX_KERNEL_SIGSET_SIZE + 1,
                    0,
                    0
                ],
            ),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
    }

    #[test]
    fn rt_sigprocmask_updates_mask_and_rejects_invalid_how_or_sigset_size() {
        let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigprocmask,
                [
                    LINUX_SIG_SETMASK as u64,
                    0b1010,
                    0,
                    LINUX_KERNEL_SIGSET_SIZE,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel
                .process(INITIAL_GUEST_PID)
                .unwrap()
                .signals()
                .blocked(),
            0b1010
        );

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigprocmask,
                [
                    LINUX_SIG_BLOCK as u64,
                    0b0101,
                    0,
                    LINUX_KERNEL_SIGSET_SIZE,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel
                .process(INITIAL_GUEST_PID)
                .unwrap()
                .signals()
                .blocked(),
            0b1111
        );

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigprocmask,
                [
                    LINUX_SIG_UNBLOCK as u64,
                    0b0011,
                    0,
                    LINUX_KERNEL_SIGSET_SIZE,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel
                .process(INITIAL_GUEST_PID)
                .unwrap()
                .signals()
                .blocked(),
            0b1100
        );

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigprocmask,
                [99, 0b1111, 0, LINUX_KERNEL_SIGSET_SIZE, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigprocmask,
                [
                    LINUX_SIG_SETMASK as u64,
                    0b1111,
                    0,
                    LINUX_KERNEL_SIGSET_SIZE + 1,
                    0,
                    0
                ],
            ),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
    }

    #[test]
    fn kill_probe_checks_process_and_sigterm_exits_group() {
        let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::Kill,
                [INITIAL_GUEST_PID as u64, 0, 0, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
            ExitState::Running
        );

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::Kill, [999, 0, 0, 0, 0, 0]),
            SyscallReturn::Errno(LinuxErrno::ESRCH)
        );

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::Kill,
                [INITIAL_GUEST_PID as u64, LINUX_SIGTERM as u64, 0, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().state(),
            TaskState::Exited { status: 143 }
        );
        assert_eq!(
            kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
            ExitState::Exited { status: 143 }
        );
    }

    #[test]
    fn tgkill_sigkill_exits_target_task() {
        let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::Tgkill,
                [
                    INITIAL_GUEST_PID as u64,
                    INITIAL_GUEST_TID as u64,
                    LINUX_SIGKILL as u64,
                    0,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().state(),
            TaskState::Exited { status: 137 }
        );
        assert_eq!(
            kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
            ExitState::Exited { status: 137 }
        );
    }

    #[test]
    fn set_tid_address_sets_and_clears_clear_child_tid() {
        let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::SetTidAddress, [0x9000, 0, 0, 0, 0, 0],),
            SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
        );
        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().clear_child_tid(),
            Some(0x9000)
        );

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::SetTidAddress, [0, 0, 0, 0, 0, 0],),
            SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
        );
        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().clear_child_tid(),
            None
        );
    }

    #[test]
    fn set_robust_list_sets_list_and_rejects_invalid_len() {
        let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::SetRobustList,
                [0xa000, LINUX_ROBUST_LIST_HEAD_SIZE, 0, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().robust_list(),
            Some(0xa000)
        );

        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::SetRobustList,
                [0xb000, LINUX_ROBUST_LIST_HEAD_SIZE + 1, 0, 0, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
        assert_eq!(
            kernel.task(INITIAL_GUEST_TID).unwrap().robust_list(),
            Some(0xa000)
        );
    }

    #[test]
    fn fork_child_inherits_signal_action_and_mask() {
        let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigaction,
                [
                    LINUX_SIGTERM as u64,
                    0x7000,
                    0,
                    LINUX_KERNEL_SIGSET_SIZE,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch_task_syscall(
                &mut kernel,
                Syscall::RtSigprocmask,
                [
                    LINUX_SIG_SETMASK as u64,
                    0x55,
                    0,
                    LINUX_KERNEL_SIGSET_SIZE,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(0)
        );

        assert_eq!(
            dispatch_task_syscall(&mut kernel, Syscall::Fork, [0; 6]),
            SyscallReturn::Success(2)
        );

        let child_signals = kernel.process(2).unwrap().signals();
        assert_eq!(
            child_signals.action(LINUX_SIGTERM).unwrap().action(),
            0x7000
        );
        assert_eq!(child_signals.blocked(), 0x55);
    }

    fn dispatch_task_syscall(
        kernel: &mut GuestKernel,
        syscall: Syscall,
        args: [u64; 6],
    ) -> SyscallReturn {
        let request = SyscallRequest::from_guest_context(mcr_sys::GuestContext::new(
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
        ));

        kernel.dispatch_task(&request).result
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
            .data_at(0x1000, vec![0x90; 0x80])
            .data_at(0x2000, vec![0; 0x08])
            .build();

        GuestProgram::new(GuestExecutable::new(path.as_bytes().to_vec(), elf))
    }

    fn dynamic_test_program(path: &str) -> GuestProgram {
        let interpreter_path = b"/lib/ld-musl-x86_64.so.1\0";
        let executable = Elf64Builder::new()
            .object_type(ET_DYN)
            .entrypoint(0x1010)
            .program_header(Elf64ProgramHeader::new(
                PT_INTERP,
                PF_R,
                0x300,
                0,
                interpreter_path.len() as u64,
                interpreter_path.len() as u64,
                1,
            ))
            .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x2000))
            .data_at(0x300, interpreter_path.to_vec())
            .data_at(0x400, vec![0x90; 4])
            .build();
        let interpreter = Elf64Builder::new()
            .object_type(ET_DYN)
            .entrypoint(0x400)
            .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x1000))
            .data_at(0x400, vec![0x90; 4])
            .build();

        GuestProgram::new(GuestExecutable::new(path.as_bytes().to_vec(), executable))
            .with_interpreter(GuestExecutable::new(
                b"/lib/ld-musl-x86_64.so.1".to_vec(),
                interpreter,
            ))
    }

    fn c_field(field: &[u8]) -> &[u8] {
        let len = field
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(field.len());
        &field[..len]
    }
}
