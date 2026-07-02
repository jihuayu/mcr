use mcr_elf::GuestMemoryImage;
use mcr_sys::{
    EventSyscalls, FileSyscalls, GuestContext, MemorySyscalls, NetworkSyscalls, NoopSyscallTracer,
    SyscallDispatchResult, SyscallDispatcher, SyscallTracer, TimeSyscalls,
};
use mcr_task::{GuestExecutable, GuestKernel, GuestProgram, TaskError};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

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
    fn dispatch_task(&mut self, request: &mcr_sys::SyscallRequest) -> mcr_sys::SyscallOutcome {
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

#[cfg(test)]
mod tests {
    use mcr_sys::{
        GuestContext, InMemorySyscallTracer, Syscall, SyscallRegisters, SyscallReturn,
        SyscallTraceEvent,
    };
    use mcr_task::{ARCH_SET_FS, ExitState, INITIAL_GUEST_PID, INITIAL_GUEST_TID};
    use mcr_testkit::elf::{Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X};

    use super::*;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-runtime");
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
}
