mod errors;
mod fd;
mod host_worker_pool;
mod kernel;
mod process;
mod program;
mod registers;
mod task;

#[cfg(test)]
mod tests;

pub use errors::TaskError;
pub use fd::{GuestFdEntry, GuestFdTable};
pub use host_worker_pool::{
    HostWorkerPoolBoundary, HostWorkerPoolCompletion, HostWorkerPoolCompletionError,
    HostWorkerPools,
};
pub use kernel::GuestKernel;
pub use mcr_win::{
    DEFAULT_GUEST_TASK_QUEUE_CAPACITY, DEFAULT_GUEST_TASK_WORKERS,
    DEFAULT_IO_COMPLETION_QUEUE_CAPACITY, DEFAULT_IO_COMPLETION_WORKERS,
    HOST_WORKER_POOL_MAX_QUEUED_JOBS, HOST_WORKER_POOL_MAX_WORKERS, HostWorkerPoolConfig,
    HostWorkerPoolConfigError, HostWorkerPoolDiagnostics, HostWorkerPoolExecutor,
    HostWorkerPoolJob, HostWorkerPoolJobError, HostWorkerPoolRole, HostWorkerPoolSubmission,
    HostWorkerPoolSubmitError,
};
pub use process::{
    CompletedWait, ExitState, GuestProcess, GuestSignalAction, SignalState, WaitedChild,
};
pub use program::{GuestExecutable, GuestImageState, GuestProgram};
pub use registers::{GprState, TlsState};
pub use task::{FutexWaitKey, GuestTask, TaskState};

use mcr_sys::{GuestAddress, GuestPid, GuestTid};

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
pub const LINUX_SIGSTOP: u32 = 19;
pub const LINUX_SIGTERM: u32 = 15;
pub const LINUX_SIGNAL_COUNT: u32 = 64;
