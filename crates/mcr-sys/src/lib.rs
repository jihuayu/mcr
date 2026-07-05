pub mod abi;
pub mod codec;
pub mod dispatcher;
pub mod errno;
pub mod fd;
pub mod memory;
pub mod net;
pub mod return_value;
pub mod syscall;
pub mod task;
pub mod trace;

pub use abi::{
    GuestAddress, GuestPid, GuestTid, LINUX_DIRENT64_NAME_OFFSET, LINUX_UTSNAME_FIELD_LEN,
    LinuxDirent64Header, LinuxIovec, LinuxStat, LinuxStatx, LinuxStatxTimestamp, LinuxTimespec,
    LinuxTms, LinuxUtsname, SyscallArgs, SyscallRegisters,
};
pub use codec::{
    GuestMemoryAccess, GuestMemoryAccessError, LINUX_IOV_MAX, LINUX_MAX_C_STRING_LEN,
    LINUX_MAX_SELECT_FDS, LINUX_MAX_VECTOR_ITEMS, LINUX_SELECT_FD_BITS, LINUX_SOCKADDR_IN_LEN,
    LINUX_SOCKADDR_IN6_LEN, LINUX_SOCKADDR_UN_LEN, LINUX_SOCKADDR_UN_PATH_LEN, LinuxSelectInterest,
    LinuxSocketAddress, encode_socket_address, iovec_output_buffers, memory_errno,
    read_guest_c_bytes, read_guest_i64, read_guest_timespec, read_guest_u32, read_guest_u64,
    read_guest_vector, read_iovec_buffers, read_iovecs, read_msghdr, read_pollfd,
    read_required_timespec_duration, read_select_interests, read_select_timeout,
    read_socket_address, select_fd_set_contains, select_fd_set_len, select_nfds,
    write_guest_timespec, write_guest_u32, write_iovec_buffers, write_msghdr_flags,
    write_msghdr_namelen, write_optional_socket_address, write_pollfd_revents, write_select_fd_set,
    write_socket_address, write_socket_address_to_msghdr_name, write_zeroed,
};
pub use dispatcher::{
    EventSyscalls, FileSyscalls, GuestContext, InMemorySyscallTracer, MemorySyscalls,
    NetworkSyscalls, NoopSyscallTracer, SYSCALL_DISPATCH_TABLE, SyscallDescriptor,
    SyscallDispatchResult, SyscallDispatcher, SyscallOutcome, SyscallRequest, SyscallSubsystem,
    SyscallSubsystems, SyscallTracer, TaskSyscalls, TimeSyscalls, decode_syscall_fields,
    syscall_descriptor, syscall_descriptor_by_number,
};
pub use errno::{LinuxErrno, host_error_errno};
pub use fd::{
    Dup2SyscallArgs, Dup3SyscallArgs, DupSyscallArgs, FcntlSyscallArgs, IoctlSyscallArgs,
    LINUX_F_DUPFD, LINUX_F_DUPFD_CLOEXEC, LINUX_F_GETFD, LINUX_F_GETFL, LINUX_F_GETPIPE_SZ,
    LINUX_F_SETFD, LINUX_F_SETFL, LINUX_F_SETPIPE_SZ, LINUX_FD_CLOEXEC, LINUX_IOCTL_FIONREAD,
    LINUX_IOCTL_TCGETS, LINUX_IOCTL_TCSETS, LINUX_IOCTL_TCSETSF, LINUX_IOCTL_TCSETSW,
    LINUX_IOCTL_TIOCGPGRP, LINUX_IOCTL_TIOCGWINSZ, LINUX_IOCTL_TIOCSPGRP, LINUX_O_CLOEXEC,
    LINUX_O_NONBLOCK, Pipe2SyscallArgs, PipeSyscallArgs,
};
pub use memory::{
    BrkSyscallArgs, LINUX_MAP_32BIT, LINUX_MAP_ANONYMOUS, LINUX_MAP_DENYWRITE,
    LINUX_MAP_EXECUTABLE, LINUX_MAP_FIXED, LINUX_MAP_FIXED_NOREPLACE, LINUX_MAP_GROWSDOWN,
    LINUX_MAP_HUGETLB, LINUX_MAP_LOCKED, LINUX_MAP_NONBLOCK, LINUX_MAP_NORESERVE,
    LINUX_MAP_POPULATE, LINUX_MAP_PRIVATE, LINUX_MAP_SHARED, LINUX_MAP_STACK, LINUX_MAP_SYNC,
    LINUX_MAP_TYPE_MASK, LINUX_MAP_VALID_MASK, LINUX_PROT_EXEC, LINUX_PROT_NONE, LINUX_PROT_READ,
    LINUX_PROT_VALID_MASK, LINUX_PROT_WRITE, MmapSyscallArgs, MprotectSyscallArgs,
    MunmapSyscallArgs,
};
pub use net::{
    Accept4SyscallArgs, LINUX_AF_INET, LINUX_AF_INET6, LINUX_AF_UNIX, LINUX_EPOLL_CLOEXEC,
    LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD, LINUX_EPOLLERR, LINUX_EPOLLET,
    LINUX_EPOLLEXCLUSIVE, LINUX_EPOLLHUP, LINUX_EPOLLIN, LINUX_EPOLLONESHOT, LINUX_EPOLLOUT,
    LINUX_EPOLLPRI, LINUX_IPPROTO_IP, LINUX_IPPROTO_TCP, LINUX_IPPROTO_UDP, LINUX_MSG_CMSG_CLOEXEC,
    LINUX_MSG_CTRUNC, LINUX_MSG_DONTROUTE, LINUX_MSG_DONTWAIT, LINUX_MSG_NOSIGNAL, LINUX_MSG_OOB,
    LINUX_MSG_PEEK, LINUX_MSG_TRUNC, LINUX_POLLERR, LINUX_POLLHUP, LINUX_POLLIN, LINUX_POLLNVAL,
    LINUX_POLLOUT, LINUX_POLLPRI, LINUX_POLLRDBAND, LINUX_POLLRDNORM, LINUX_POLLWRBAND,
    LINUX_POLLWRNORM, LINUX_SHUT_RD, LINUX_SHUT_RDWR, LINUX_SHUT_WR, LINUX_SO_DEBUG,
    LINUX_SO_ERROR, LINUX_SO_KEEPALIVE, LINUX_SO_RCVBUF, LINUX_SO_REUSEADDR, LINUX_SO_REUSEPORT,
    LINUX_SO_SNDBUF, LINUX_SO_TYPE, LINUX_SOCK_CLOEXEC, LINUX_SOCK_DGRAM, LINUX_SOCK_FLAG_MASK,
    LINUX_SOCK_NONBLOCK, LINUX_SOCK_RAW, LINUX_SOCK_STREAM, LINUX_SOCK_TYPE_MASK, LINUX_SOL_SOCKET,
    LINUX_TCP_NODELAY, LinuxCmsghdr, LinuxEpollEvent, LinuxIn6Addr, LinuxMsghdr, LinuxPollfd,
    LinuxSockaddr, LinuxSockaddrIn, LinuxSockaddrIn6, LinuxSockaddrStorage, LinuxSockaddrUn,
    SendRecvFromSyscallArgs, SendRecvMsgSyscallArgs, ShutdownSyscallArgs, SockaddrSyscallArgs,
    SocketSyscallArgs, SockoptSyscallArgs,
};
pub use return_value::{LINUX_MAX_ERRNO, SyscallReturn};
pub use syscall::{Syscall, SyscallNumber};
pub use task::{
    CloneSyscallArgs, FutexSyscallArgs, KillSyscallArgs, LINUX_CLONE_CHILD_CLEARTID,
    LINUX_CLONE_CHILD_SETTID, LINUX_CLONE_DETACHED, LINUX_CLONE_EXIT_SIGNAL_MASK,
    LINUX_CLONE_FILES, LINUX_CLONE_FS, LINUX_CLONE_PARENT_SETTID, LINUX_CLONE_SETTLS,
    LINUX_CLONE_SIGHAND, LINUX_CLONE_SYSVSEM, LINUX_CLONE_THREAD, LINUX_CLONE_VFORK,
    LINUX_CLONE_VM, LINUX_FUTEX_CLOCK_REALTIME, LINUX_FUTEX_CMD_MASK, LINUX_FUTEX_CMP_REQUEUE,
    LINUX_FUTEX_PRIVATE_FLAG, LINUX_FUTEX_REQUEUE, LINUX_FUTEX_WAIT, LINUX_FUTEX_WAKE,
    LINUX_KERNEL_SIGSET_SIZE, LINUX_ROBUST_LIST_HEAD_SIZE, LINUX_SIG_BLOCK, LINUX_SIG_SETMASK,
    LINUX_SIG_UNBLOCK, LINUX_SIGCHLD, LINUX_WAIT_SUPPORTED_OPTIONS, LINUX_WNOHANG,
    RtSigactionSyscallArgs, RtSigprocmaskSyscallArgs, SetRobustListSyscallArgs,
    SetTidAddressSyscallArgs, TgkillSyscallArgs, TkillSyscallArgs, Wait4SyscallArgs,
};
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
