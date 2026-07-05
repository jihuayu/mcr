#[allow(unused_imports)]
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDiagnostics {
    executable_path: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    vmas: Vec<DiagnosticVma>,
    tasks: Vec<DiagnosticTask>,
    worker_pools: Vec<HostWorkerPoolDiagnostics>,
    last_syscall: Option<DiagnosticSyscall>,
    in_flight_syscall: Option<DiagnosticSyscall>,
    native_execution_enabled: bool,
    perf: RuntimePerfDiagnostics,
}

impl RuntimeDiagnostics {
    #[must_use]
    pub fn capture(kernel: &GuestKernel, events: &[SyscallTraceEvent]) -> Self {
        Self::capture_with_native_execution(kernel, events, false)
    }

    #[must_use]
    pub(crate) fn capture_runtime(
        subsystems: &RuntimeSubsystems,
        events: &[SyscallTraceEvent],
    ) -> Self {
        let mut diagnostics = Self::capture_with_native_execution(
            subsystems.tasks(),
            events,
            subsystems.native_execution_enabled(),
        );
        diagnostics.worker_pools = subsystems.host_worker_pool_diagnostics().to_vec();
        diagnostics.perf = subsystems.perf_diagnostics();
        diagnostics
    }

    #[must_use]
    fn capture_with_native_execution(
        kernel: &GuestKernel,
        events: &[SyscallTraceEvent],
        native_execution_enabled: bool,
    ) -> Self {
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
            tasks: kernel
                .tasks()
                .map(DiagnosticTask::from_guest_task)
                .collect(),
            worker_pools: kernel.host_worker_pool_diagnostics().to_vec(),
            last_syscall: events.iter().rev().find_map(DiagnosticSyscall::from_event),
            in_flight_syscall: in_flight_syscall(events),
            native_execution_enabled,
            perf: RuntimePerfDiagnostics::default(),
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

    #[must_use]
    pub const fn in_flight_syscall(&self) -> Option<&DiagnosticSyscall> {
        self.in_flight_syscall.as_ref()
    }

    #[must_use]
    pub fn tasks(&self) -> &[DiagnosticTask] {
        &self.tasks
    }

    #[must_use]
    pub fn worker_pools(&self) -> &[HostWorkerPoolDiagnostics] {
        &self.worker_pools
    }

    #[must_use]
    pub const fn native_execution_enabled(&self) -> bool {
        self.native_execution_enabled
    }

    #[must_use]
    pub const fn perf(&self) -> RuntimePerfDiagnostics {
        self.perf
    }

    #[must_use]
    pub fn stall_diagnostic(&self) -> RuntimeStallDiagnostic {
        RuntimeStallDiagnostic::from_diagnostics(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStallKind {
    GuestWaitFutex,
    Readiness,
    Scheduling,
    NativeExecution,
    Unknown,
}

impl RuntimeStallKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuestWaitFutex => "guest wait/futex",
            Self::Readiness => "readiness",
            Self::Scheduling => "scheduling",
            Self::NativeExecution => "native execution",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for RuntimeStallKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStallDiagnostic {
    kind: RuntimeStallKind,
    reason: String,
    in_flight_syscall: Option<DiagnosticSyscall>,
    last_syscall: Option<DiagnosticSyscall>,
    runnable_tasks: usize,
    fd_wait_tasks: usize,
    child_wait_tasks: usize,
    futex_wait_tasks: usize,
}

impl RuntimeStallDiagnostic {
    #[must_use]
    pub(crate) fn capture_runtime(
        subsystems: &RuntimeSubsystems,
        events: &[SyscallTraceEvent],
    ) -> Self {
        RuntimeDiagnostics::capture_runtime(subsystems, events).stall_diagnostic()
    }

    #[must_use]
    pub fn from_diagnostics(diagnostics: &RuntimeDiagnostics) -> Self {
        let runnable_tasks = diagnostics
            .tasks()
            .iter()
            .filter(|task| matches!(task.state(), DiagnosticTaskState::Runnable))
            .count();
        let fd_wait_tasks = diagnostics
            .tasks()
            .iter()
            .filter(|task| matches!(task.state(), DiagnosticTaskState::WaitingForFd { .. }))
            .count();
        let child_wait_tasks = diagnostics
            .tasks()
            .iter()
            .filter(|task| matches!(task.state(), DiagnosticTaskState::WaitingForChild))
            .count();
        let futex_wait_tasks = diagnostics
            .tasks()
            .iter()
            .filter(|task| matches!(task.state(), DiagnosticTaskState::WaitingForFutex { .. }))
            .count();

        let (kind, reason) = if let Some(syscall) = diagnostics.in_flight_syscall() {
            if syscall.name() == "futex" {
                (
                    RuntimeStallKind::GuestWaitFutex,
                    format!("in-flight futex syscall at rip=0x{:x}", syscall.rip()),
                )
            } else if readiness_syscall_name(syscall.name()) {
                (
                    RuntimeStallKind::Readiness,
                    format!("in-flight readiness syscall `{}`", syscall.name()),
                )
            } else {
                (
                    RuntimeStallKind::Unknown,
                    format!("in-flight syscall `{}`", syscall.name()),
                )
            }
        } else if fd_wait_tasks > 0 {
            (
                RuntimeStallKind::Readiness,
                format!("{fd_wait_tasks} task(s) waiting for fd readiness"),
            )
        } else if child_wait_tasks > 0 {
            (
                RuntimeStallKind::Scheduling,
                format!("{child_wait_tasks} task(s) waiting for child process completion"),
            )
        } else if futex_wait_tasks > 0 {
            (
                RuntimeStallKind::GuestWaitFutex,
                format!("{futex_wait_tasks} task(s) waiting for futex wake"),
            )
        } else if diagnostics.native_execution_enabled() && runnable_tasks > 0 {
            (
                RuntimeStallKind::NativeExecution,
                format!("{runnable_tasks} runnable task(s) in native execution mode"),
            )
        } else if runnable_tasks == 0 && !diagnostics.tasks().is_empty() {
            (
                RuntimeStallKind::Scheduling,
                "no runnable guest tasks remain".to_owned(),
            )
        } else {
            (
                RuntimeStallKind::Unknown,
                "no known stall signal captured".to_owned(),
            )
        };

        Self {
            kind,
            reason,
            in_flight_syscall: diagnostics.in_flight_syscall().cloned(),
            last_syscall: diagnostics.last_syscall().cloned(),
            runnable_tasks,
            fd_wait_tasks,
            child_wait_tasks,
            futex_wait_tasks,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> RuntimeStallKind {
        self.kind
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub const fn in_flight_syscall(&self) -> Option<&DiagnosticSyscall> {
        self.in_flight_syscall.as_ref()
    }

    #[must_use]
    pub const fn last_syscall(&self) -> Option<&DiagnosticSyscall> {
        self.last_syscall.as_ref()
    }

    #[must_use]
    pub const fn runnable_tasks(&self) -> usize {
        self.runnable_tasks
    }

    #[must_use]
    pub const fn fd_wait_tasks(&self) -> usize {
        self.fd_wait_tasks
    }

    #[must_use]
    pub const fn child_wait_tasks(&self) -> usize {
        self.child_wait_tasks
    }

    #[must_use]
    pub const fn futex_wait_tasks(&self) -> usize {
        self.futex_wait_tasks
    }
}

impl fmt::Display for RuntimeStallDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} stall: {}", self.kind, self.reason)?;
        if let Some(syscall) = &self.in_flight_syscall {
            write!(
                formatter,
                "; in-flight syscall={}({}) rip=0x{:x}",
                syscall.name(),
                syscall.number(),
                syscall.rip()
            )?;
        }
        if let Some(syscall) = &self.last_syscall {
            write!(
                formatter,
                "; last syscall={}({}) result={:?}",
                syscall.name(),
                syscall.number(),
                syscall.result()
            )?;
        }
        write!(
            formatter,
            "; tasks runnable={} fd_wait={} child_wait={} futex_wait={}",
            self.runnable_tasks, self.fd_wait_tasks, self.child_wait_tasks, self.futex_wait_tasks
        )
    }
}

fn readiness_syscall_name(name: &str) -> bool {
    matches!(name, "poll" | "ppoll" | "epoll_wait" | "epoll_pwait2")
}

fn in_flight_syscall(events: &[SyscallTraceEvent]) -> Option<DiagnosticSyscall> {
    let mut completed = Vec::new();
    for event in events.iter().rev() {
        match event {
            SyscallTraceEvent::Enter(event) => {
                let key = (event.context.pid, event.context.tid);
                if !completed.contains(&key) {
                    return Some(DiagnosticSyscall::from_enter_event(event));
                }
            }
            SyscallTraceEvent::Exit(event) => {
                completed.push((event.context.pid, event.context.tid));
            }
            SyscallTraceEvent::Unsupported(event) => {
                completed.push((event.context.pid, event.context.tid));
            }
        }
    }
    None
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
pub struct DiagnosticTask {
    pid: mcr_sys::GuestPid,
    tid: mcr_sys::GuestTid,
    rip: u64,
    state: DiagnosticTaskState,
}

impl DiagnosticTask {
    #[must_use]
    pub fn from_guest_task(task: &GuestTask) -> Self {
        Self {
            pid: task.pid(),
            tid: task.tid(),
            rip: task.regs().rip(),
            state: DiagnosticTaskState::from_task_state(task.state()),
        }
    }

    #[must_use]
    pub const fn pid(&self) -> mcr_sys::GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn tid(&self) -> mcr_sys::GuestTid {
        self.tid
    }

    #[must_use]
    pub const fn rip(&self) -> u64 {
        self.rip
    }

    #[must_use]
    pub const fn state(&self) -> DiagnosticTaskState {
        self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticTaskState {
    Runnable,
    WaitingForChild,
    WaitingForFd { fd: i32, write: bool },
    WaitingForFutex { uaddr: u64 },
    Exited { status: i32 },
}

impl DiagnosticTaskState {
    #[must_use]
    pub const fn from_task_state(state: TaskState) -> Self {
        match state {
            TaskState::Runnable => Self::Runnable,
            TaskState::WaitingForChild { .. }
            | TaskState::WaitingForVfork { .. }
            | TaskState::WaitingForSignalSet { .. } => Self::WaitingForChild,
            TaskState::WaitingForFd { fd, write } => Self::WaitingForFd { fd, write },
            TaskState::WaitingForFutex { key } => Self::WaitingForFutex { uaddr: key.uaddr() },
            TaskState::Exited { status } => Self::Exited { status },
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
    pub fn from_enter_event(event: &mcr_sys::SyscallEnterEvent) -> Self {
        Self {
            name: event.syscall.name().to_owned(),
            number: event.syscall.number().raw(),
            args: event.args.raw(),
            result: None,
            rip: event.context.rip,
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
        RuntimeDiagnostics::capture_runtime(self.dispatcher.subsystems(), self.tracer().events())
    }

    #[must_use]
    pub fn stall_diagnostic(&self) -> RuntimeStallDiagnostic {
        RuntimeStallDiagnostic::capture_runtime(
            self.dispatcher.subsystems(),
            self.tracer().events(),
        )
    }

    pub fn run_guest_until_exit_with_step_limit(
        &mut self,
        max_guest_steps: u64,
    ) -> Result<i32, GuestRunError> {
        run_guest_until_exit_with_diagnostic_step_limit(&mut self.dispatcher, max_guest_steps)
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
