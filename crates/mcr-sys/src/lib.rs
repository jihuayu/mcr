pub mod abi;
pub mod dispatcher;
pub mod errno;
pub mod return_value;
pub mod syscall;
pub mod trace;

pub use abi::{
    GuestAddress, GuestPid, GuestTid, LINUX_DIRENT64_NAME_OFFSET, LINUX_UTSNAME_FIELD_LEN,
    LinuxDirent64Header, LinuxIovec, LinuxStat, LinuxStatx, LinuxStatxTimestamp, LinuxTimespec,
    LinuxUtsname, SyscallArgs, SyscallRegisters,
};
pub use dispatcher::{
    EventSyscalls, FileSyscalls, GuestContext, InMemorySyscallTracer, MemorySyscalls,
    NetworkSyscalls, NoopSyscallTracer, SYSCALL_DISPATCH_TABLE, SyscallDescriptor,
    SyscallDispatchResult, SyscallDispatcher, SyscallOutcome, SyscallRequest, SyscallSubsystem,
    SyscallSubsystems, SyscallTracer, TaskSyscalls, TimeSyscalls, decode_syscall_fields,
    syscall_descriptor, syscall_descriptor_by_number,
};
pub use errno::LinuxErrno;
pub use return_value::{LINUX_MAX_ERRNO, SyscallReturn};
pub use syscall::{Syscall, SyscallNumber};
pub use trace::{
    HostErrorTrace, SyscallEnterEvent, SyscallExitEvent, SyscallTraceEvent, TraceContext,
    TraceField, UnsupportedSyscallEvent,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    use super::CRATE_NAME;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-sys");
    }
}
