#[allow(unused_imports)]
use super::*;

pub struct Runtime {
    pub(crate) dispatcher: SyscallDispatcher<RuntimeSubsystems>,
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
        self.dispatcher.subsystems().tasks()
    }

    #[must_use]
    pub fn kernel_mut(&mut self) -> &mut GuestKernel {
        self.dispatcher.subsystems_mut().tasks_mut()
    }

    #[must_use]
    pub fn memory(&self) -> &GuestMemory {
        self.dispatcher.subsystems().memory()
    }

    #[must_use]
    pub fn memory_mut(&mut self) -> &mut GuestMemory {
        let subsystems = self.dispatcher.subsystems_mut();
        subsystems
            .prepare_memory_mut_for_process(mcr_task::INITIAL_GUEST_PID)
            .expect("initial guest process memory is present");
        subsystems.memory_mut()
    }

    #[must_use]
    pub fn memory_for_process(&self, pid: mcr_sys::GuestPid) -> Option<&GuestMemory> {
        self.dispatcher.subsystems().memory_for_process(pid)
    }

    #[must_use]
    pub fn memory_for_process_mut(&mut self, pid: mcr_sys::GuestPid) -> Option<&mut GuestMemory> {
        let subsystems = self.dispatcher.subsystems_mut();
        subsystems.prepare_memory_mut_for_process(pid).ok()?;
        subsystems.memory_for_process_mut(pid)
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

    pub fn enable_native_execution(&mut self) {
        self.dispatcher.subsystems_mut().enable_native_execution();
    }

    pub fn into_kernel(self) -> GuestKernel {
        self.dispatcher.into_parts().0.into_tasks()
    }
}

pub struct RuntimeWithTracer<T> {
    pub(crate) dispatcher: SyscallDispatcher<RuntimeSubsystems, T>,
}

impl<T> RuntimeWithTracer<T>
where
    T: SyscallTracer,
{
    #[must_use]
    pub fn kernel(&self) -> &GuestKernel {
        self.dispatcher.subsystems().tasks()
    }

    #[must_use]
    pub fn kernel_mut(&mut self) -> &mut GuestKernel {
        self.dispatcher.subsystems_mut().tasks_mut()
    }

    #[must_use]
    pub fn memory(&self) -> &GuestMemory {
        self.dispatcher.subsystems().memory()
    }

    #[must_use]
    pub fn memory_mut(&mut self) -> &mut GuestMemory {
        let subsystems = self.dispatcher.subsystems_mut();
        subsystems
            .prepare_memory_mut_for_process(mcr_task::INITIAL_GUEST_PID)
            .expect("initial guest process memory is present");
        subsystems.memory_mut()
    }

    #[must_use]
    pub fn memory_for_process(&self, pid: mcr_sys::GuestPid) -> Option<&GuestMemory> {
        self.dispatcher.subsystems().memory_for_process(pid)
    }

    #[must_use]
    pub fn memory_for_process_mut(&mut self, pid: mcr_sys::GuestPid) -> Option<&mut GuestMemory> {
        let subsystems = self.dispatcher.subsystems_mut();
        subsystems.prepare_memory_mut_for_process(pid).ok()?;
        subsystems.memory_for_process_mut(pid)
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

    pub fn enable_native_execution(&mut self) {
        self.dispatcher.subsystems_mut().enable_native_execution();
    }

    pub fn into_parts(self) -> (GuestKernel, T) {
        let (subsystems, tracer) = self.dispatcher.into_parts();
        (subsystems.into_tasks(), tracer)
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

pub(crate) fn memory_error_from_errno(errno: LinuxErrno) -> GuestMemoryError {
    if errno == LinuxErrno::ENOMEM {
        GuestMemoryError::OutOfMemory
    } else if errno == LinuxErrno::EACCES {
        GuestMemoryError::AccessDenied
    } else if errno == LinuxErrno::EEXIST {
        GuestMemoryError::AddressInUse
    } else if errno == LinuxErrno::ESRCH || errno == LinuxErrno::ENOENT {
        GuestMemoryError::NotMapped
    } else {
        GuestMemoryError::InvalidAddress
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
    StepLimitExceeded {
        steps: u64,
        diagnostic: RuntimeStallDiagnostic,
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
            Self::StepLimitExceeded { .. } => LinuxErrno::ETIMEDOUT,
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
            Self::StepLimitExceeded { steps, diagnostic } => {
                write!(
                    formatter,
                    "guest execution step limit exceeded after {steps} step(s): {diagnostic}"
                )
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

pub(crate) fn run_guest_until_exit_with_dispatcher<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
) -> Result<i32, GuestRunError>
where
    T: SyscallTracer,
{
    run_guest_until_exit_loop(dispatcher, None, |_| {
        unreachable!("step-limit diagnostic is only captured when a limit is set")
    })
}

pub(crate) fn run_guest_until_exit_with_diagnostic_step_limit(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, RuntimeDiagnosticsTracer>,
    max_guest_steps: u64,
) -> Result<i32, GuestRunError> {
    run_guest_until_exit_loop(dispatcher, Some(max_guest_steps), |dispatcher| {
        RuntimeStallDiagnostic::capture_runtime(
            dispatcher.subsystems(),
            dispatcher.tracer().events(),
        )
    })
}

pub(crate) fn run_guest_until_exit_loop<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
    max_guest_steps: Option<u64>,
    mut capture_diagnostic: impl FnMut(
        &SyscallDispatcher<RuntimeSubsystems, T>,
    ) -> RuntimeStallDiagnostic,
) -> Result<i32, GuestRunError>
where
    T: SyscallTracer,
{
    dispatcher.subsystems_mut().perf_begin_run();
    let sticky_scheduler = sticky_scheduler_enabled();
    let result = (|| -> Result<i32, GuestRunError> {
        let mut guest_steps = 0u64;
        let mut last_dispatched_tid = None;
        loop {
            if let Some(status) = initial_process_exit_status(dispatcher.subsystems().tasks())? {
                return Ok(status);
            }
            dispatcher.subsystems_mut().perf_record_scheduler_enter();
            dispatcher
                .subsystems_mut()
                .resume_waiting_tasks()
                .map_err(|errno| GuestRunError::WaitResume { errno })?;
            dispatcher.subsystems_mut().resume_fd_waiters();
            dispatcher.subsystems_mut().resume_expired_futex_timeouts();
            dispatcher.subsystems_mut().resume_expired_sleep_timeouts();
            let mut runnable_tids = if sticky_scheduler {
                last_dispatched_tid
                    .and_then(|tid| dispatcher.subsystems().sticky_scheduler_candidate(tid))
                    .map_or_else(
                        || dispatcher.subsystems().tasks().runnable_tids(),
                        |tid| vec![tid],
                    )
            } else {
                dispatcher.subsystems().tasks().runnable_tids()
            };
            if runnable_tids.len() != 1 {
                dispatcher
                    .subsystems()
                    .prioritize_pending_fork_exec_tids(&mut runnable_tids);
            }
            if runnable_tids.is_empty() {
                if dispatcher.subsystems_mut().expire_next_futex_timeout() {
                    continue;
                }
                if dispatcher.subsystems_mut().expire_next_sleep_timeout() {
                    continue;
                }
                dispatcher.subsystems_mut().perf_record_no_runnable();
                return Err(GuestRunError::NoRunnableTasks);
            }
            for tid in runnable_tids {
                let Some((pid, state)) = dispatcher
                    .subsystems()
                    .tasks()
                    .task(tid)
                    .map(|task| (task.pid(), task.state()))
                else {
                    continue;
                };
                if !matches!(state, TaskState::Runnable) {
                    continue;
                }
                if max_guest_steps.is_some_and(|limit| guest_steps >= limit) {
                    return Err(GuestRunError::StepLimitExceeded {
                        steps: guest_steps,
                        diagnostic: capture_diagnostic(dispatcher),
                    });
                }
                dispatcher.subsystems_mut().perf_record_dispatch(tid, pid);
                dispatch_guest_task_with_dispatcher(dispatcher, tid)?;
                last_dispatched_tid = Some(tid);
                guest_steps = guest_steps.saturating_add(1);
                if initial_process_exit_status(dispatcher.subsystems().tasks())?.is_some() {
                    break;
                }
            }
        }
    })();
    dispatcher.subsystems_mut().perf_finish_run();
    result
}

pub(crate) fn sticky_scheduler_enabled() -> bool {
    let Some(value) = std::env::var_os(STICKY_SCHED_ENV) else {
        return true;
    };
    let value = value.to_string_lossy();
    !matches!(
        value.to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    )
}

pub(crate) fn initial_process_exit_status(
    kernel: &GuestKernel,
) -> Result<Option<i32>, GuestRunError> {
    let process = kernel
        .process(INITIAL_GUEST_PID)
        .ok_or(GuestRunError::MissingInitialProcess)?;
    match process.exit_state() {
        ExitState::Running => Ok(None),
        ExitState::Exited { status } => Ok(Some(status)),
    }
}

pub(crate) fn dispatch_guest_execution_with_dispatcher<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
) -> Result<GuestExecutionStep, GuestExecutionError>
where
    T: SyscallTracer,
{
    let task = dispatcher
        .subsystems()
        .tasks()
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

pub(crate) fn is_nonreturning_exit_syscall(
    registers: mcr_sys::SyscallRegisters,
    result: &SyscallDispatchResult,
) -> bool {
    matches!(result.result, SyscallReturn::Success(_))
        && matches!(
            registers.syscall(),
            mcr_sys::Syscall::Exit | mcr_sys::Syscall::ExitGroup
        )
}

struct ReadOnlyGuestMemory<'a> {
    memory: &'a GuestMemory,
}

const fn runtime_memory_operand_error(error: GuestMemoryError) -> mcr_jit::GuestMemoryOperandError {
    match error {
        GuestMemoryError::NotMapped => mcr_jit::GuestMemoryOperandError::NotMapped,
        GuestMemoryError::AccessDenied => mcr_jit::GuestMemoryOperandError::AccessDenied,
        GuestMemoryError::InvalidAddress
        | GuestMemoryError::InvalidLength
        | GuestMemoryError::InvalidProtection
        | GuestMemoryError::InvalidFlags
        | GuestMemoryError::InvalidOffset
        | GuestMemoryError::BadFileDescriptor
        | GuestMemoryError::AddressInUse
        | GuestMemoryError::OutOfMemory
        | GuestMemoryError::RegionTooLarge
        | GuestMemoryError::Host(_) => mcr_jit::GuestMemoryOperandError::Fault,
    }
}

impl mcr_jit::GuestMemoryOperandAccess for ReadOnlyGuestMemory<'_> {
    fn read_memory_operand(
        &self,
        address: u64,
        buffer: &mut [u8],
    ) -> Result<(), mcr_jit::GuestMemoryOperandError> {
        self.memory
            .read(address, buffer)
            .map_err(runtime_memory_operand_error)
    }

    fn write_memory_operand(
        &mut self,
        _address: u64,
        _bytes: &[u8],
    ) -> Result<(), mcr_jit::GuestMemoryOperandError> {
        Err(mcr_jit::GuestMemoryOperandError::AccessDenied)
    }
}

const MAX_GUEST_BLOCK_BYTES: usize = 4096;

fn read_interpreted_guest_block(
    subsystems: &mut RuntimeSubsystems,
    pid: mcr_sys::GuestPid,
    rip: u64,
) -> Result<Vec<u8>, GuestExecutionError> {
    let block = {
        let memory = subsystems
            .memory_for_process(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
        read_guest_block(memory, rip, MAX_GUEST_BLOCK_BYTES)?
    };
    subsystems.perf_record_interpreted_block_fallback(block.len(), 1);
    Ok(block)
}

pub(crate) fn try_dispatch_pending_fork_exec_child_task<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
    tid: mcr_sys::GuestTid,
    pid: mcr_sys::GuestPid,
    gpr: GprState,
    before_rip: u64,
) -> Result<Option<GuestExecutionStep>, GuestExecutionError>
where
    T: SyscallTracer,
{
    let fs_base = dispatcher
        .subsystems()
        .tasks()
        .task(tid)
        .ok_or(GuestExecutionError::MissingTask(tid))?
        .tls()
        .fs_base();
    let interpreted_block_len;
    let trap = {
        let Some(memory) = dispatcher.subsystems().memory_for_process(pid) else {
            dispatcher
                .subsystems_mut()
                .materialize_pending_fork_exec_child_memory(pid)
                .map_err(GuestExecutionError::Memory)?;
            return Ok(None);
        };
        let block = read_guest_block(memory, before_rip, MAX_GUEST_BLOCK_BYTES)?;
        interpreted_block_len = block.len();
        let mut read_only_memory = ReadOnlyGuestMemory { memory };
        SameIsaExecutionCore::new().execute_to_syscall_trap_with_memory(
            GuestBlock::new(&block, before_rip),
            registers_from_gpr_with_fs_base(gpr, fs_base),
            &mut read_only_memory,
        )
    };
    dispatcher
        .subsystems_mut()
        .perf_record_interpreted_block_fallback(interpreted_block_len, 1);
    let Ok(trap) = trap else {
        dispatcher
            .subsystems_mut()
            .materialize_pending_fork_exec_child_memory(pid)
            .map_err(GuestExecutionError::Memory)?;
        return Ok(None);
    };
    let syscall_registers = trap.registers().syscall_registers();
    if !matches!(
        syscall_registers.syscall(),
        mcr_sys::Syscall::Execve | mcr_sys::Syscall::Exit | mcr_sys::Syscall::ExitGroup
    ) {
        dispatcher
            .subsystems_mut()
            .materialize_pending_fork_exec_child_memory(pid)
            .map_err(GuestExecutionError::Memory)?;
        return Ok(None);
    }

    let dispatch_result = dispatcher.dispatch(GuestContext::new(pid, tid, syscall_registers));
    if is_nonreturning_exit_syscall(syscall_registers, &dispatch_result) {
        let trap_regs = gpr_from_registers(trap.registers());
        let task = dispatcher
            .subsystems_mut()
            .tasks_mut()
            .task_mut(tid)
            .ok_or(GuestExecutionError::MissingTask(tid))?;
        if task.regs() == gpr {
            task.set_regs(trap_regs);
        }
        return Ok(Some(GuestExecutionStep::new(
            tid,
            before_rip,
            task.regs().rip(),
            dispatch_result.encoded_rax,
            task.state(),
        )));
    }

    let mut registers = trap.registers();
    registers.apply_syscall_return(dispatch_result.encoded_rax, trap.site().next_rip);
    let task = dispatcher
        .subsystems_mut()
        .tasks_mut()
        .task_mut(tid)
        .ok_or(GuestExecutionError::MissingTask(tid))?;
    let final_regs = if task.regs() == gpr {
        let updated_regs = gpr_from_registers(registers);
        task.set_regs(updated_regs);
        updated_regs
    } else {
        task.regs()
    };
    Ok(Some(GuestExecutionStep::new(
        tid,
        before_rip,
        final_regs.rip(),
        final_regs.rax(),
        task.state(),
    )))
}

pub(crate) fn dispatch_guest_task_with_dispatcher<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
    tid: mcr_sys::GuestTid,
) -> Result<GuestExecutionStep, GuestExecutionError>
where
    T: SyscallTracer,
{
    let task = dispatcher
        .subsystems()
        .tasks()
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
    if dispatcher.subsystems().has_pending_fork_exec_children(pid) {
        let materialize_start = Instant::now();
        host_step_trace(format_args!(
            "runtime materialize-fork-children start parent_pid={pid}"
        ));
        dispatcher
            .subsystems_mut()
            .materialize_pending_fork_exec_children(pid)
            .map_err(GuestExecutionError::Memory)?;
        host_step_trace(format_args!(
            "runtime materialize-fork-children done parent_pid={pid} elapsed_ms={}",
            host_step_elapsed_ms(materialize_start)
        ));
    }
    if dispatcher.subsystems().has_pending_fork_exec_child(pid)
        && let Some(step) =
            try_dispatch_pending_fork_exec_child_task(dispatcher, tid, pid, gpr, before_rip)?
    {
        return Ok(step);
    }
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(windows, target_arch = "x86_64")
    ))]
    if dispatcher.subsystems().native_execution_enabled() {
        return dispatch_native_guest_task_with_dispatcher(dispatcher, tid, pid, gpr, before_rip);
    }

    let block = read_interpreted_guest_block(dispatcher.subsystems_mut(), pid, before_rip)?;
    let fs_base = dispatcher
        .subsystems()
        .tasks()
        .task(tid)
        .ok_or(GuestExecutionError::MissingTask(tid))?
        .tls()
        .fs_base();
    let trap = {
        let memory = dispatcher
            .subsystems_mut()
            .memory_for_process_mut(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
        SameIsaExecutionCore::new().execute_to_syscall_trap_with_memory(
            GuestBlock::new(&block, before_rip),
            registers_from_gpr_with_fs_base(gpr, fs_base),
            memory,
        )?
    };
    let syscall_registers = trap.registers().syscall_registers();
    dispatcher
        .subsystems_mut()
        .perf_record_syscall(syscall_registers.syscall());
    if syscall_registers.syscall() == mcr_sys::Syscall::RtSigreturn {
        return dispatch_rt_sigreturn_guest_task(
            dispatcher,
            tid,
            pid,
            before_rip,
            gpr,
            trap.registers(),
        );
    }
    let dispatch_result = dispatcher.dispatch(GuestContext::new(pid, tid, syscall_registers));
    if is_nonreturning_exit_syscall(syscall_registers, &dispatch_result) {
        let trap_regs = gpr_from_registers(trap.registers());
        let task = dispatcher
            .subsystems_mut()
            .tasks_mut()
            .task_mut(tid)
            .ok_or(GuestExecutionError::MissingTask(tid))?;
        if task.regs() == gpr {
            task.set_regs(trap_regs);
        }
        return Ok(GuestExecutionStep::new(
            tid,
            before_rip,
            task.regs().rip(),
            dispatch_result.encoded_rax,
            task.state(),
        ));
    }
    let mut registers = trap.registers();
    registers.apply_syscall_return(dispatch_result.encoded_rax, trap.site().next_rip);

    let task = dispatcher
        .subsystems_mut()
        .tasks_mut()
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

pub(crate) fn dispatch_interpreted_guest_task_from_registers<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
    tid: mcr_sys::GuestTid,
    pid: mcr_sys::GuestPid,
    before_rip: u64,
    expected_task_regs: GprState,
    registers: GuestRegisters,
) -> Result<GuestExecutionStep, GuestExecutionError>
where
    T: SyscallTracer,
{
    let block = read_interpreted_guest_block(dispatcher.subsystems_mut(), pid, registers.rip)?;
    let trap = {
        let memory = dispatcher
            .subsystems_mut()
            .memory_for_process_mut(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
        SameIsaExecutionCore::new().execute_to_syscall_trap_with_memory(
            GuestBlock::new(&block, registers.rip),
            registers,
            memory,
        )?
    };

    let syscall_registers = trap.registers().syscall_registers();
    dispatcher
        .subsystems_mut()
        .perf_record_syscall(syscall_registers.syscall());
    if syscall_registers.syscall() == mcr_sys::Syscall::RtSigreturn {
        return dispatch_rt_sigreturn_guest_task(
            dispatcher,
            tid,
            pid,
            before_rip,
            expected_task_regs,
            trap.registers(),
        );
    }
    let dispatch_result = dispatcher.dispatch(GuestContext::new(pid, tid, syscall_registers));
    if is_nonreturning_exit_syscall(syscall_registers, &dispatch_result) {
        let trap_regs = gpr_from_registers(trap.registers());
        let task = dispatcher
            .subsystems_mut()
            .tasks_mut()
            .task_mut(tid)
            .ok_or(GuestExecutionError::MissingTask(tid))?;
        if task.regs() == expected_task_regs {
            task.set_regs(trap_regs);
        }
        return Ok(GuestExecutionStep::new(
            tid,
            before_rip,
            task.regs().rip(),
            dispatch_result.encoded_rax,
            task.state(),
        ));
    }

    let mut registers = trap.registers();
    registers.apply_syscall_return(dispatch_result.encoded_rax, trap.site().next_rip);
    let updated_regs = gpr_from_registers(registers);
    let task = dispatcher
        .subsystems_mut()
        .tasks_mut()
        .task_mut(tid)
        .ok_or(GuestExecutionError::MissingTask(tid))?;
    let final_regs = if task.regs() == expected_task_regs {
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

pub(crate) fn dispatch_rt_sigreturn_guest_task<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
    tid: mcr_sys::GuestTid,
    pid: mcr_sys::GuestPid,
    before_rip: u64,
    expected_task_regs: GprState,
    registers: GuestRegisters,
) -> Result<GuestExecutionStep, GuestExecutionError>
where
    T: SyscallTracer,
{
    let restored = {
        let memory = dispatcher
            .subsystems_mut()
            .memory_for_process_mut(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
        restore_rt_signal_frame(memory, registers)
            .map_err(|errno| GuestExecutionError::Memory(memory_error_from_errno(errno)))?
    };
    if let Some(process) = dispatcher.subsystems_mut().tasks_mut().process_mut(pid) {
        process.signals_mut().set_blocked(restored.signal_mask);
    }
    let updated_regs = gpr_from_registers(restored.registers);
    let task = dispatcher
        .subsystems_mut()
        .tasks_mut()
        .task_mut(tid)
        .ok_or(GuestExecutionError::MissingTask(tid))?;
    let final_regs = if task.regs() == expected_task_regs {
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

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn try_deliver_native_guest_fault_signal<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
    tid: mcr_sys::GuestTid,
    pid: mcr_sys::GuestPid,
    before_rip: u64,
    expected_task_regs: GprState,
    native_registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    fault_address: u64,
) -> Result<Option<GuestExecutionStep>, GuestExecutionError>
where
    T: SyscallTracer,
{
    let Some((action, signal_mask)) =
        dispatcher
            .subsystems()
            .tasks()
            .process(pid)
            .and_then(|process| {
                process
                    .signals()
                    .action(LINUX_SIGSEGV)
                    .map(|action| (action, process.signals().blocked()))
            })
    else {
        return Ok(None);
    };
    if action.action() == LINUX_SIG_DFL
        || action.action() == LINUX_SIG_IGN
        || action.flags() & LINUX_SA_RESTORER == 0
        || action.restorer() == 0
    {
        return Ok(None);
    }

    let alt_stack = dispatcher
        .subsystems()
        .events
        .signal_alt_stacks
        .get(&tid)
        .copied();
    let mut guest_registers = guest_registers_from_host(native_registers);
    guest_registers.fs_base = fs_base;
    let handler_registers = {
        let memory = dispatcher
            .subsystems_mut()
            .memory_for_process_mut(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
        setup_rt_signal_frame(
            memory,
            guest_registers,
            action,
            LINUX_SIGSEGV,
            signal_mask,
            fault_address,
            alt_stack,
        )
        .map_err(|errno| GuestExecutionError::Memory(memory_error_from_errno(errno)))?
    };

    if let Some(process) = dispatcher.subsystems_mut().tasks_mut().process_mut(pid) {
        let mut blocked = signal_mask | action.mask();
        if action.flags() & LINUX_SA_NODEFER == 0 {
            blocked |= signal_mask_for(LINUX_SIGSEGV);
        }
        process.signals_mut().set_blocked(blocked);
    }
    dispatcher.subsystems_mut().set_native_fp(
        tid,
        mcr_win::HostFloatingPointState {
            xmm: native_registers.xmm,
            mxcsr: native_registers.mxcsr,
        },
    );
    let gpr = gpr_from_registers(handler_registers);
    let task = dispatcher
        .subsystems_mut()
        .tasks_mut()
        .task_mut(tid)
        .ok_or(GuestExecutionError::MissingTask(tid))?;
    let final_regs = if task.regs() == expected_task_regs {
        task.set_regs(gpr);
        gpr
    } else {
        task.regs()
    };
    Ok(Some(GuestExecutionStep::new(
        tid,
        before_rip,
        final_regs.rip(),
        final_regs.rax(),
        task.state(),
    )))
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) const WINDOWS_EXCEPTION_ACCESS_VIOLATION: u32 = 0xc000_0005;

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) const WINDOWS_EXCEPTION_PRIVILEGED_INSTRUCTION: u32 = 0xc000_0096;

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) const fn native_fault_delivers_sigsegv(signal: u32) -> bool {
    matches!(
        signal,
        WINDOWS_EXCEPTION_ACCESS_VIOLATION | WINDOWS_EXCEPTION_PRIVILEGED_INSTRUCTION
    )
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn dispatch_native_guest_task_with_dispatcher<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
    tid: mcr_sys::GuestTid,
    pid: mcr_sys::GuestPid,
    gpr: GprState,
    before_rip: u64,
) -> Result<GuestExecutionStep, GuestExecutionError>
where
    T: SyscallTracer,
{
    dispatcher
        .subsystems_mut()
        .select_memory_for_process(pid)
        .map_err(|errno| GuestExecutionError::Memory(memory_error_from_errno(errno)))?;
    let native_fp = dispatcher
        .subsystems()
        .native_fp(tid)
        .copied()
        .unwrap_or_default();
    let fs_base = dispatcher
        .subsystems()
        .tasks()
        .task(tid)
        .ok_or(GuestExecutionError::MissingTask(tid))?
        .tls()
        .fs_base();
    host_step_trace(format_args!(
        "runtime native-step start pid={pid} tid={tid} rip=0x{before_rip:016x} fs_base=0x{fs_base:016x}"
    ));
    {
        let memory = dispatcher
            .subsystems_mut()
            .memory_for_process_mut(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
        let Some(vma) = memory.vma_containing(before_rip) else {
            return Err(GuestExecutionError::Memory(GuestMemoryError::NotMapped));
        };
        if !vma.protection().execute {
            return Err(GuestExecutionError::Memory(GuestMemoryError::AccessDenied));
        }
    }
    dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, fs_base)?;
    {
        let memory = dispatcher
            .subsystems_mut()
            .memory_for_process_mut(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
        let mut native_registers = host_registers_from_gpr(gpr);
        native_registers.xmm = native_fp.xmm;
        native_registers.mxcsr = native_fp.mxcsr;
        let native_start = Instant::now();
        host_step_trace(format_args!(
            "runtime native-enter pid={pid} tid={tid} rip=0x{:016x}",
            native_registers.rip
        ));
        let native_result = mcr_win::execute_x86_64_until_trap(&mut native_registers, fs_base);
        host_step_trace(format_args!(
            "runtime native-return pid={pid} tid={tid} rip=0x{:016x} elapsed_ms={}",
            native_registers.rip,
            host_step_elapsed_ms(native_start)
        ));
        let fault_instruction = native_fault_instruction(memory, native_registers.rip);
        let stack_words = native_fault_stack_words(memory, native_registers.rsp);
        if let Err(error) = native_result {
            if let Some(instruction) = fault_instruction.as_ref() {
                host_step_trace(format_args!(
                    "runtime native-fault pid={pid} tid={tid} {instruction}"
                ));
            }
            #[cfg(all(windows, target_arch = "x86_64"))]
            if matches!(&error, mcr_win::NativeExecutionError::GuestFault { .. })
                && let Some(instruction) = fault_instruction.as_ref()
                && let Some(registers) = emulate_fs_relative_native_fault(
                    memory,
                    native_registers,
                    fs_base,
                    instruction,
                )?
            {
                host_step_trace(format_args!(
                    "runtime native-fs-emulate pid={pid} tid={tid} rip=0x{:016x} next=0x{:016x}",
                    native_registers.rip, registers.rip
                ));
                dispatcher.subsystems_mut().set_native_fp(
                    tid,
                    mcr_win::HostFloatingPointState {
                        xmm: registers.xmm,
                        mxcsr: registers.mxcsr,
                    },
                );
                let gpr = gpr_from_registers(guest_registers_from_host(registers));
                let task = dispatcher
                    .subsystems_mut()
                    .tasks_mut()
                    .task_mut(tid)
                    .ok_or(GuestExecutionError::MissingTask(tid))?;
                task.set_regs(gpr);
                return Ok(GuestExecutionStep::new(
                    tid,
                    before_rip,
                    gpr.rip(),
                    gpr.rax(),
                    task.state(),
                ));
            }
            #[cfg(all(windows, target_arch = "x86_64"))]
            if matches!(&error, mcr_win::NativeExecutionError::GuestFault { .. })
                && fault_instruction
                    .as_ref()
                    .is_some_and(native_fault_is_unrewritten_fs_relative)
            {
                host_step_trace(format_args!(
                    "runtime native-fs-fallback pid={pid} tid={tid} rip=0x{:016x} fs_base=0x{fs_base:016x}",
                    native_registers.rip
                ));
                dispatcher.subsystems_mut().set_native_fp(
                    tid,
                    mcr_win::HostFloatingPointState {
                        xmm: native_registers.xmm,
                        mxcsr: native_registers.mxcsr,
                    },
                );
                let mut registers = guest_registers_from_host(native_registers);
                registers.fs_base = fs_base;
                return dispatch_interpreted_guest_task_from_registers(
                    dispatcher, tid, pid, before_rip, gpr, registers,
                );
            }
            #[cfg(all(windows, target_arch = "x86_64"))]
            if let mcr_win::NativeExecutionError::GuestFault {
                signal, address, ..
            } = &error
                && native_fault_delivers_sigsegv(*signal as u32)
                && let Some(step) = try_deliver_native_guest_fault_signal(
                    dispatcher,
                    tid,
                    pid,
                    before_rip,
                    gpr,
                    native_registers,
                    fs_base,
                    *address,
                )?
            {
                host_step_trace(format_args!(
                    "runtime native-signal-deliver pid={pid} tid={tid} signal={LINUX_SIGSEGV} rip=0x{:016x}",
                    native_registers.rip
                ));
                return Ok(step);
            }
            return Err(native_execution_error(
                error,
                native_registers,
                fs_base,
                fault_instruction,
                stack_words,
            ));
        }
        dispatcher.subsystems_mut().set_native_fp(
            tid,
            mcr_win::HostFloatingPointState {
                xmm: native_registers.xmm,
                mxcsr: native_registers.mxcsr,
            },
        );

        let mut registers = guest_registers_from_host(native_registers);
        if let Some(intrinsic) = dispatcher
            .subsystems()
            .libc_intrinsic_patch(pid, registers.rip)
        {
            return dispatch_native_libc_intrinsic_task(
                dispatcher, tid, pid, before_rip, registers, intrinsic,
            );
        }
        let site = mcr_jit::SyscallSite {
            rip: registers.rip,
            next_rip: registers.rip + 2,
        };
        let syscall_registers = registers.syscall_registers();
        dispatcher
            .subsystems_mut()
            .perf_record_syscall(syscall_registers.syscall());
        if syscall_registers.syscall() == mcr_sys::Syscall::RtSigreturn {
            return dispatch_rt_sigreturn_guest_task(
                dispatcher, tid, pid, before_rip, gpr, registers,
            );
        }
        if is_fork_like_syscall_number(syscall_registers.rax) {
            let mut child_registers = registers;
            child_registers.apply_syscall_return(0, site.next_rip);
            dispatcher
                .subsystems_mut()
                .set_pending_fork_child_regs(gpr_from_registers(child_registers));
        }
        let dispatch_result = dispatcher.dispatch(GuestContext::new(pid, tid, syscall_registers));
        if dispatch_result.result == SyscallReturn::Errno(LinuxErrno::EAGAIN)
            && let Some((fd, write)) = blocking_fd_wait(
                dispatcher.subsystems().files.vfs().fds(),
                syscall_registers.rax,
                syscall_registers.rdi,
            )
        {
            dispatcher
                .subsystems_mut()
                .tasks_mut()
                .block_task_for_fd(tid, fd, write)
                .map_err(|_| GuestExecutionError::MissingTask(tid))?;
            let task = dispatcher
                .subsystems_mut()
                .tasks_mut()
                .task_mut(tid)
                .ok_or(GuestExecutionError::MissingTask(tid))?;
            let blocked_regs = gpr_from_registers(registers);
            task.set_regs(blocked_regs);
            return Ok(GuestExecutionStep::new(
                tid,
                before_rip,
                blocked_regs.rip(),
                blocked_regs.rax(),
                task.state(),
            ));
        }
        if is_nonreturning_exit_syscall(syscall_registers, &dispatch_result) {
            let trap_regs = gpr_from_registers(registers);
            let task = dispatcher
                .subsystems_mut()
                .tasks_mut()
                .task_mut(tid)
                .ok_or(GuestExecutionError::MissingTask(tid))?;
            if task.regs() == gpr {
                task.set_regs(trap_regs);
            }
            return Ok(GuestExecutionStep::new(
                tid,
                before_rip,
                task.regs().rip(),
                dispatch_result.encoded_rax,
                task.state(),
            ));
        }
        registers.apply_syscall_return(dispatch_result.encoded_rax, site.next_rip);

        let task = dispatcher
            .subsystems_mut()
            .tasks_mut()
            .task_mut(tid)
            .ok_or(GuestExecutionError::MissingTask(tid))?;
        let blocked_after_syscall = matches!(
            task.state(),
            TaskState::WaitingForChild { .. }
                | TaskState::WaitingForVfork { .. }
                | TaskState::WaitingForSignalSet { .. }
                | TaskState::WaitingForFutex { .. }
                | TaskState::WaitingForSleep
        );
        let final_regs = if task.regs() == gpr || blocked_after_syscall {
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
}

pub(crate) fn dispatch_native_libc_intrinsic_task<T>(
    dispatcher: &mut SyscallDispatcher<RuntimeSubsystems, T>,
    tid: mcr_sys::GuestTid,
    pid: mcr_sys::GuestPid,
    before_rip: u64,
    mut registers: GuestRegisters,
    intrinsic: GuestLibcIntrinsic,
) -> Result<GuestExecutionStep, GuestExecutionError> {
    let memory = dispatcher
        .subsystems_mut()
        .memory_for_process_mut(pid)
        .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
    let mut return_address = [0; 8];
    memory.read(registers.rsp, &mut return_address)?;
    let return_rip = u64::from_le_bytes(return_address);
    let result = memory
        .dispatch_libc_intrinsic(intrinsic, registers.rdi, registers.rsi, registers.rdx)
        .map_err(guest_libc_intrinsic_execution_error)?;
    registers.rax = result;
    registers.rsp = registers
        .rsp
        .checked_add(8)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    registers.rip = return_rip;
    let gpr = gpr_from_registers(registers);
    let task = dispatcher
        .subsystems_mut()
        .tasks_mut()
        .task_mut(tid)
        .ok_or(GuestExecutionError::MissingTask(tid))?;
    task.set_regs(gpr);
    Ok(GuestExecutionStep::new(
        tid,
        before_rip,
        gpr.rip(),
        gpr.rax(),
        task.state(),
    ))
}

pub(crate) fn guest_libc_intrinsic_execution_error(
    error: GuestLibcIntrinsicError,
) -> GuestExecutionError {
    match error {
        GuestLibcIntrinsicError::Memory(error) => GuestExecutionError::Memory(error),
        GuestLibcIntrinsicError::UnsupportedOverlap
        | GuestLibcIntrinsicError::UnterminatedString => {
            GuestExecutionError::Memory(GuestMemoryError::InvalidAddress)
        }
    }
}

pub(crate) fn guest_execution_errno(error: GuestExecutionError) -> LinuxErrno {
    match error {
        GuestExecutionError::Memory(error) => error.errno(),
        GuestExecutionError::MissingInitialTask
        | GuestExecutionError::MissingTask(_)
        | GuestExecutionError::TaskExited { .. }
        | GuestExecutionError::Execution(_) => LinuxErrno::EINVAL,
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
