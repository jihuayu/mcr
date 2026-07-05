//! Windows host adapters for MCR.
//!
//! This crate exposes narrow host capabilities only. Linux ABI policy and errno
//! conversion live in the owning runtime, VFS, task, syscall, and networking
//! layers above this crate.

pub mod clocks;
pub mod error;
pub mod files;
mod host_worker_pool;
pub mod iocp;
pub mod memory;
pub mod native_exec;
pub mod network;
pub mod overlapped_io;
pub mod pipes;
pub mod random;
pub mod sync;

#[cfg(windows)]
mod windows;

pub use clocks::{monotonic_time, sleep_for, system_time};
pub use error::{HostError, HostErrorCode, HostErrorKind, HostOperation, HostResult};
pub use files::{
    FileAccess, FileCreation, FileOptions, FileShare, HostFile, RenameMode, create_hard_link,
    create_symlink_file, delete_file, rename_file, replace_file,
};
pub use host_worker_pool::{
    DEFAULT_GUEST_TASK_QUEUE_CAPACITY, DEFAULT_GUEST_TASK_WORKERS,
    DEFAULT_IO_COMPLETION_QUEUE_CAPACITY, DEFAULT_IO_COMPLETION_WORKERS,
    HOST_WORKER_POOL_MAX_QUEUED_JOBS, HOST_WORKER_POOL_MAX_WORKERS, HostWorkerPoolConfig,
    HostWorkerPoolConfigError, HostWorkerPoolDiagnostics, HostWorkerPoolExecutor,
    HostWorkerPoolJob, HostWorkerPoolJobError, HostWorkerPoolRole, HostWorkerPoolSubmission,
    HostWorkerPoolSubmitError,
};
pub use iocp::{HostIoCompletionPacket, HostIoCompletionPort};
pub use memory::{HostFileMapping, HostMemory, MemoryProtection};
pub use native_exec::{
    DEFAULT_MXCSR, HostCpuRegisters, HostFloatingPointState, HostXmmRegisters,
    NativeExecutionError, execute_x86_64_until_trap,
};
pub use network::{
    AddressFamily, HostAcceptExSubmission, HostConnectExSubmission, HostRioCapability,
    HostShutdown, HostSocket, HostSocketIoCompletion, HostSocketIoDirection, HostSocketIoFailure,
    HostSocketIoResult, HostSocketIoSubmission, HostSocketOptionName, HostSocketOptionValue,
    NetworkStack, PendingHostAcceptEx, PendingHostConnectEx, PendingHostSocketIo,
    SocketCompletionKind, SocketEvents, SocketFastPathKind, SocketKind, SocketPoll, SocketProtocol,
    poll_sockets,
};
pub use overlapped_io::{
    HostIoCompletion, HostIoDirection, HostIoFailure, HostIoFallback, HostIoFallbackReason,
    HostIoResult, HostIoSubmission, PendingHostIo,
};
pub use pipes::HostPipePair;
pub use random::fill_random;
pub use sync::{
    AddressWaitResult, wait_on_address_u32, wake_by_address_all_u32, wake_by_address_single_u32,
};

/// Stable crate name used by workspace smoke tests.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    use super::CRATE_NAME;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-win");
    }
}
