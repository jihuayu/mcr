pub const LINUX_AF_UNIX: u32 = 1;
pub const LINUX_AF_INET: u32 = 2;
pub const LINUX_AF_INET6: u32 = 10;

pub const LINUX_SOCK_STREAM: u32 = 1;
pub const LINUX_SOCK_DGRAM: u32 = 2;
pub const LINUX_SOCK_RAW: u32 = 3;
pub const LINUX_SOCK_NONBLOCK: u32 = 0o4000;
pub const LINUX_SOCK_CLOEXEC: u32 = 0o2000000;
pub const LINUX_SOCK_TYPE_MASK: u32 = 0xf;
pub const LINUX_SOCK_FLAG_MASK: u32 = LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC;

pub const LINUX_IPPROTO_IP: u32 = 0;
pub const LINUX_IPPROTO_TCP: u32 = 6;
pub const LINUX_IPPROTO_UDP: u32 = 17;

pub const LINUX_SOL_SOCKET: u32 = 1;
pub const LINUX_SO_DEBUG: u32 = 1;
pub const LINUX_SO_REUSEADDR: u32 = 2;
pub const LINUX_SO_TYPE: u32 = 3;
pub const LINUX_SO_ERROR: u32 = 4;
pub const LINUX_SO_KEEPALIVE: u32 = 9;
pub const LINUX_SO_SNDBUF: u32 = 7;
pub const LINUX_SO_RCVBUF: u32 = 8;
pub const LINUX_SO_REUSEPORT: u32 = 15;

pub const LINUX_TCP_NODELAY: u32 = 1;

pub const LINUX_SHUT_RD: u32 = 0;
pub const LINUX_SHUT_WR: u32 = 1;
pub const LINUX_SHUT_RDWR: u32 = 2;

pub const LINUX_MSG_OOB: u32 = 0x1;
pub const LINUX_MSG_PEEK: u32 = 0x2;
pub const LINUX_MSG_DONTROUTE: u32 = 0x4;
pub const LINUX_MSG_CTRUNC: u32 = 0x8;
pub const LINUX_MSG_TRUNC: u32 = 0x20;
pub const LINUX_MSG_DONTWAIT: u32 = 0x40;
pub const LINUX_MSG_NOSIGNAL: u32 = 0x4000;
pub const LINUX_MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;

pub const LINUX_POLLIN: i16 = 0x0001;
pub const LINUX_POLLPRI: i16 = 0x0002;
pub const LINUX_POLLOUT: i16 = 0x0004;
pub const LINUX_POLLERR: i16 = 0x0008;
pub const LINUX_POLLHUP: i16 = 0x0010;
pub const LINUX_POLLNVAL: i16 = 0x0020;

pub const LINUX_EPOLL_CTL_ADD: u32 = 1;
pub const LINUX_EPOLL_CTL_DEL: u32 = 2;
pub const LINUX_EPOLL_CTL_MOD: u32 = 3;

pub const LINUX_EPOLLIN: u32 = 0x0000_0001;
pub const LINUX_EPOLLPRI: u32 = 0x0000_0002;
pub const LINUX_EPOLLOUT: u32 = 0x0000_0004;
pub const LINUX_EPOLLERR: u32 = 0x0000_0008;
pub const LINUX_EPOLLHUP: u32 = 0x0000_0010;
pub const LINUX_EPOLLET: u32 = 1 << 31;
pub const LINUX_EPOLL_CLOEXEC: u32 = 0o2000000;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxSockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxSockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxIn6Addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxSockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: LinuxIn6Addr,
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSockaddrUn {
    pub sun_family: u16,
    pub sun_path: [u8; 108],
}

impl Default for LinuxSockaddrUn {
    fn default() -> Self {
        Self {
            sun_family: 0,
            sun_path: [0; 108],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSockaddrStorage {
    pub ss_family: u16,
    pub __data: [u8; 126],
}

impl Default for LinuxSockaddrStorage {
    fn default() -> Self {
        Self {
            ss_family: 0,
            __data: [0; 126],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxMsghdr {
    pub msg_name: u64,
    pub msg_namelen: u32,
    pub __pad1: u32,
    pub msg_iov: u64,
    pub msg_iovlen: u64,
    pub msg_control: u64,
    pub msg_controllen: u64,
    pub msg_flags: u32,
    pub __pad2: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxCmsghdr {
    pub cmsg_len: u64,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxPollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxEpollEvent {
    pub events: u32,
    pub data: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketSyscallArgs {
    pub domain: u32,
    pub kind: u32,
    pub protocol: u32,
}

impl SocketSyscallArgs {
    #[must_use]
    pub const fn new(domain: u32, kind: u32, protocol: u32) -> Self {
        Self {
            domain,
            kind,
            protocol,
        }
    }

    #[must_use]
    pub const fn socket_type(self) -> u32 {
        self.kind & LINUX_SOCK_TYPE_MASK
    }

    #[must_use]
    pub const fn flags(self) -> u32 {
        self.kind & !LINUX_SOCK_TYPE_MASK
    }

    #[must_use]
    pub const fn has_supported_flags(self) -> bool {
        self.flags() & !LINUX_SOCK_FLAG_MASK == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockaddrSyscallArgs {
    pub fd: i32,
    pub sockaddr: u64,
    pub addrlen: u32,
}

impl SockaddrSyscallArgs {
    #[must_use]
    pub const fn new(fd: i32, sockaddr: u64, addrlen: u32) -> Self {
        Self {
            fd,
            sockaddr,
            addrlen,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accept4SyscallArgs {
    pub fd: i32,
    pub sockaddr: u64,
    pub addrlen: u64,
    pub flags: u32,
}

impl Accept4SyscallArgs {
    #[must_use]
    pub const fn new(fd: i32, sockaddr: u64, addrlen: u64, flags: u32) -> Self {
        Self {
            fd,
            sockaddr,
            addrlen,
            flags,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendRecvMsgSyscallArgs {
    pub fd: i32,
    pub msg: u64,
    pub flags: u32,
}

impl SendRecvMsgSyscallArgs {
    #[must_use]
    pub const fn new(fd: i32, msg: u64, flags: u32) -> Self {
        Self { fd, msg, flags }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendRecvFromSyscallArgs {
    pub fd: i32,
    pub buf: u64,
    pub len: u64,
    pub flags: u32,
    pub sockaddr: u64,
    pub addrlen: u64,
}

impl SendRecvFromSyscallArgs {
    #[must_use]
    pub const fn new(fd: i32, buf: u64, len: u64, flags: u32, sockaddr: u64, addrlen: u64) -> Self {
        Self {
            fd,
            buf,
            len,
            flags,
            sockaddr,
            addrlen,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownSyscallArgs {
    pub fd: i32,
    pub how: u32,
}

impl ShutdownSyscallArgs {
    #[must_use]
    pub const fn new(fd: i32, how: u32) -> Self {
        Self { fd, how }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockoptSyscallArgs {
    pub fd: i32,
    pub level: u32,
    pub optname: u32,
    pub optval: u64,
    pub optlen: u64,
}

impl SockoptSyscallArgs {
    #[must_use]
    pub const fn new(fd: i32, level: u32, optname: u32, optval: u64, optlen: u64) -> Self {
        Self {
            fd,
            level,
            optname,
            optval,
            optlen,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::{
        Accept4SyscallArgs, LINUX_AF_INET, LINUX_AF_INET6, LINUX_AF_UNIX, LINUX_EPOLL_CLOEXEC,
        LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD, LINUX_EPOLLERR,
        LINUX_EPOLLET, LINUX_EPOLLHUP, LINUX_EPOLLIN, LINUX_EPOLLOUT, LINUX_EPOLLPRI,
        LINUX_MSG_CMSG_CLOEXEC, LINUX_MSG_DONTWAIT, LINUX_MSG_NOSIGNAL, LINUX_POLLERR,
        LINUX_POLLHUP, LINUX_POLLIN, LINUX_POLLNVAL, LINUX_POLLOUT, LINUX_POLLPRI, LINUX_SHUT_RD,
        LINUX_SHUT_RDWR, LINUX_SHUT_WR, LINUX_SOCK_CLOEXEC, LINUX_SOCK_DGRAM, LINUX_SOCK_NONBLOCK,
        LINUX_SOCK_STREAM, LINUX_SOL_SOCKET, LINUX_TCP_NODELAY, LinuxCmsghdr, LinuxEpollEvent,
        LinuxMsghdr, LinuxPollfd, LinuxSockaddr, LinuxSockaddrIn, LinuxSockaddrIn6,
        LinuxSockaddrStorage, LinuxSockaddrUn, SendRecvFromSyscallArgs, SendRecvMsgSyscallArgs,
        ShutdownSyscallArgs, SockaddrSyscallArgs, SocketSyscallArgs, SockoptSyscallArgs,
    };

    #[test]
    fn socket_constants_match_linux_x86_64_values() {
        assert_eq!(LINUX_AF_UNIX, 1);
        assert_eq!(LINUX_AF_INET, 2);
        assert_eq!(LINUX_AF_INET6, 10);
        assert_eq!(LINUX_SOCK_STREAM, 1);
        assert_eq!(LINUX_SOCK_DGRAM, 2);
        assert_eq!(LINUX_SOCK_NONBLOCK, 0o4000);
        assert_eq!(LINUX_SOCK_CLOEXEC, 0o2000000);
        assert_eq!(LINUX_SOL_SOCKET, 1);
        assert_eq!(LINUX_TCP_NODELAY, 1);
        assert_eq!(LINUX_SHUT_RD, 0);
        assert_eq!(LINUX_SHUT_WR, 1);
        assert_eq!(LINUX_SHUT_RDWR, 2);
        assert_eq!(LINUX_MSG_DONTWAIT, 0x40);
        assert_eq!(LINUX_MSG_NOSIGNAL, 0x4000);
        assert_eq!(LINUX_MSG_CMSG_CLOEXEC, 0x4000_0000);
        assert_eq!(LINUX_POLLIN, 0x0001);
        assert_eq!(LINUX_POLLPRI, 0x0002);
        assert_eq!(LINUX_POLLOUT, 0x0004);
        assert_eq!(LINUX_POLLERR, 0x0008);
        assert_eq!(LINUX_POLLHUP, 0x0010);
        assert_eq!(LINUX_POLLNVAL, 0x0020);
        assert_eq!(LINUX_EPOLL_CTL_ADD, 1);
        assert_eq!(LINUX_EPOLL_CTL_DEL, 2);
        assert_eq!(LINUX_EPOLL_CTL_MOD, 3);
        assert_eq!(LINUX_EPOLLIN, 0x0000_0001);
        assert_eq!(LINUX_EPOLLPRI, 0x0000_0002);
        assert_eq!(LINUX_EPOLLOUT, 0x0000_0004);
        assert_eq!(LINUX_EPOLLERR, 0x0000_0008);
        assert_eq!(LINUX_EPOLLHUP, 0x0000_0010);
        assert_eq!(LINUX_EPOLLET, 1 << 31);
        assert_eq!(LINUX_EPOLL_CLOEXEC, 0o2000000);
    }

    #[test]
    fn socket_abi_struct_sizes_match_linux_x86_64_layouts() {
        assert_eq!(size_of::<LinuxSockaddr>(), 16);
        assert_eq!(size_of::<LinuxSockaddrIn>(), 16);
        assert_eq!(size_of::<LinuxSockaddrIn6>(), 28);
        assert_eq!(size_of::<LinuxSockaddrUn>(), 110);
        assert_eq!(size_of::<LinuxSockaddrStorage>(), 128);
        assert_eq!(size_of::<LinuxMsghdr>(), 56);
        assert_eq!(size_of::<LinuxCmsghdr>(), 16);
        assert_eq!(size_of::<LinuxPollfd>(), 8);
        assert_eq!(size_of::<LinuxEpollEvent>(), 12);
        assert_eq!(align_of::<LinuxMsghdr>(), 8);
        assert_eq!(align_of::<LinuxPollfd>(), 4);
        assert_eq!(align_of::<LinuxEpollEvent>(), 1);
    }

    #[test]
    fn socket_arg_helpers_preserve_linux_shapes() {
        let socket =
            SocketSyscallArgs::new(LINUX_AF_INET, LINUX_SOCK_STREAM | LINUX_SOCK_CLOEXEC, 0);
        assert_eq!(socket.socket_type(), LINUX_SOCK_STREAM);
        assert_eq!(socket.flags(), LINUX_SOCK_CLOEXEC);
        assert!(socket.has_supported_flags());
        assert!(!SocketSyscallArgs::new(LINUX_AF_INET, 0x100, 0).has_supported_flags());

        assert_eq!(SockaddrSyscallArgs::new(3, 0x1000, 16).addrlen, 16);
        assert_eq!(
            Accept4SyscallArgs::new(3, 0x1000, 0x2000, 0).addrlen,
            0x2000
        );
        assert_eq!(
            SendRecvMsgSyscallArgs::new(3, 0x3000, LINUX_MSG_DONTWAIT).flags,
            0x40
        );
        assert_eq!(
            SendRecvFromSyscallArgs::new(3, 0x4000, 5, LINUX_MSG_NOSIGNAL, 0, 0).len,
            5
        );
        assert_eq!(
            ShutdownSyscallArgs::new(3, LINUX_SHUT_RDWR).how,
            LINUX_SHUT_RDWR
        );
        assert_eq!(
            SockoptSyscallArgs::new(3, LINUX_SOL_SOCKET, 4, 0x5000, 4).optname,
            4
        );
    }
}
