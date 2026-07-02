use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mcr_elf::{GuestImageError, GuestMemoryImage, InitialStackConfig, parse_load_plan};
use mcr_sys::{
    CloneSyscallArgs, GuestAddress, GuestPid, GuestTid, LINUX_CLONE_EXIT_SIGNAL_MASK,
    LINUX_CLONE_VFORK, LINUX_CLONE_VM, LINUX_SIGCHLD, LinuxErrno, LinuxUtsname, Syscall,
    SyscallOutcome, SyscallRequest, TaskSyscalls, Wait4SyscallArgs,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub const INITIAL_GUEST_PID: GuestPid = 1;
pub const INITIAL_GUEST_TID: GuestTid = 1;
pub const DEFAULT_STACK_TOP: GuestAddress = 0x8000_0000;
pub const DEFAULT_STACK_SIZE: u64 = 0x20_0000;

pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;

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
}

impl GprState {
    #[must_use]
    pub const fn new(rip: GuestAddress, rsp: GuestAddress) -> Self {
        Self { rip, rsp }
    }

    #[must_use]
    pub const fn rip(self) -> GuestAddress {
        self.rip
    }

    #[must_use]
    pub const fn rsp(self) -> GuestAddress {
        self.rsp
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    Runnable,
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
            Syscall::Fork => self.fork_current(tid),
            Syscall::Vfork => self.vfork_current(tid),
            Syscall::Clone => self.clone_current(
                tid,
                CloneSyscallArgs::new(
                    arg(request, 0),
                    arg(request, 1),
                    arg(request, 2),
                    arg(request, 3),
                    arg(request, 4),
                ),
            ),
            Syscall::Exit => self.exit_task(tid, low_exit_status(arg(request, 0))),
            Syscall::ExitGroup => self.exit_group(task.pid, low_exit_status(arg(request, 0))),
            Syscall::Wait4 => self.wait4_current(
                tid,
                Wait4SyscallArgs::new(
                    arg(request, 0) as i32,
                    arg(request, 1),
                    arg(request, 2) as u32,
                    arg(request, 3),
                ),
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
        self.fork_like_current(tid, "fork")
    }

    pub fn vfork_current(&mut self, tid: GuestTid) -> SyscallOutcome {
        self.fork_like_current(tid, "vfork")
    }

    pub fn clone_current(&mut self, tid: GuestTid, args: CloneSyscallArgs) -> SyscallOutcome {
        if !is_supported_fork_like_clone(args.flags) {
            return TaskError::InvalidCloneFlags(args.flags).into_outcome();
        }

        self.fork_like_current(tid, "clone")
            .with_decoded_field("clone_flags", format!("{:#x}", args.flags))
    }

    pub fn fork_child(&mut self, tid: GuestTid) -> Result<GuestPid, TaskError> {
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
                children: BTreeSet::new(),
                exit_state: ExitState::Running,
            },
        );
        self.tasks.insert(child_tid, child_task);
        self.process_mut(parent_pid)
            .ok_or(TaskError::UnknownPid(parent_pid))?
            .children
            .insert(child_pid);

        Ok(child_pid)
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
        let Some(parent_pid) = self.task(tid).map(|task| task.pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };

        match self.wait4_child(parent_pid, args) {
            Ok(Some(waited)) => SyscallOutcome::success(u64::from(waited.pid()))
                .with_decoded_field("guest_pid", waited.pid().to_string())
                .with_decoded_field("exit_status", waited.status().to_string())
                .with_decoded_field("wait_status", format!("{:#x}", waited.wait_status())),
            Ok(None) => SyscallOutcome::success(0),
            Err(error) => error.into_outcome(),
        }
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

    fn fork_like_current(&mut self, tid: GuestTid, syscall: &'static str) -> SyscallOutcome {
        match self.fork_child(tid) {
            Ok(child_pid) => SyscallOutcome::success(u64::from(child_pid))
                .with_decoded_field("guest_pid", child_pid.to_string())
                .with_decoded_field("fork_kind", syscall),
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
    InvalidWaitOptions(u32),
    NoChild,
    PidExhausted,
    TidExhausted,
    UnknownPid(GuestPid),
    UnknownTid(GuestTid),
    WouldBlock,
    Elf(mcr_elf::ElfValidationError),
    Image(GuestImageError),
}

impl TaskError {
    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        match self {
            Self::BadFd(_) => LinuxErrno::EBADF,
            Self::InvalidCloneFlags(_) | Self::InvalidWaitOptions(_) => LinuxErrno::EINVAL,
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
            Self::InvalidWaitOptions(options) => {
                write!(formatter, "unsupported wait4 options {options:#x}")
            }
            Self::NoChild => write!(formatter, "no waitable child process"),
            Self::PidExhausted => write!(formatter, "guest PID namespace exhausted"),
            Self::TidExhausted => write!(formatter, "guest TID namespace exhausted"),
            Self::UnknownPid(pid) => write!(formatter, "unknown guest pid {pid}"),
            Self::UnknownTid(tid) => write!(formatter, "unknown guest tid {tid}"),
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
