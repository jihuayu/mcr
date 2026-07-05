use std::net::SocketAddr;
use std::time::Duration;

use crate::error::{HostError, HostOperation, HostResult};

use super::super::model::{
    AddressFamily, HostShutdown, HostSocketOptionName, HostSocketOptionValue, SocketEvents,
    SocketKind, SocketProtocol,
};

#[cfg(windows)]
pub(in crate::network::platform) fn duration_to_poll_timeout(duration: Duration) -> i32 {
    if duration.is_zero() {
        return 0;
    }

    let millis = duration.as_millis().saturating_add(1);
    millis.min(i32::MAX as u128) as i32
}

#[cfg(windows)]
impl AddressFamily {
    pub(in crate::network::platform) const fn to_winsock(self) -> i32 {
        match self {
            Self::Inet => AF_INET,
            Self::Inet6 => AF_INET6,
            Self::Unix => AF_UNIX,
        }
    }
}

#[cfg(windows)]
impl SocketKind {
    pub(in crate::network::platform) const fn to_winsock(self) -> i32 {
        match self {
            Self::Stream => SOCK_STREAM,
            Self::Datagram => SOCK_DGRAM,
        }
    }
}

#[cfg(windows)]
impl SocketProtocol {
    pub(in crate::network::platform) const fn to_winsock(self) -> i32 {
        match self {
            Self::Default => 0,
            Self::Tcp => IPPROTO_TCP,
            Self::Udp => IPPROTO_UDP,
        }
    }
}

#[cfg(windows)]
impl SocketKind {
    pub(in crate::network::platform) const fn from_winsock(value: i32) -> HostResult<Self> {
        match value {
            SOCK_STREAM => Ok(Self::Stream),
            SOCK_DGRAM => Ok(Self::Datagram),
            _ => Err(HostError::invalid_input(HostOperation::GetSocketOption)),
        }
    }
}

#[cfg(windows)]
impl HostShutdown {
    pub(in crate::network::platform) const fn to_winsock(self) -> i32 {
        match self {
            Self::Read => SD_RECEIVE,
            Self::Write => SD_SEND,
            Self::Both => SD_BOTH,
        }
    }
}

#[cfg(windows)]
impl SocketEvents {
    pub(in crate::network::platform) const fn to_winsock(self) -> i16 {
        let mut events = 0;
        if self.readable {
            events |= POLLIN;
        }
        if self.writable {
            events |= POLLOUT;
        }
        // WSAPoll rejects POLLPRI for ordinary TCP connect checks on Windows. The runtime does
        // not implement Linux OOB/priority-band socket data yet, so keep this interest local.
        events
    }

    pub(in crate::network::platform) const fn from_winsock(events: i16) -> Self {
        Self {
            readable: events & POLLIN != 0,
            writable: events & POLLOUT != 0,
            priority: events & POLLPRI != 0,
            error: events & POLLERR != 0,
            hang_up: events & POLLHUP != 0,
            invalid: events & POLLNVAL != 0,
        }
    }
}

#[cfg(windows)]
pub(in crate::network::platform) const WSA_VERSION_2_2: u16 = 0x0202;
#[cfg(windows)]
pub(in crate::network::platform) const AF_UNIX: i32 = 1;
#[cfg(windows)]
pub(in crate::network::platform) const AF_INET: i32 = 2;
#[cfg(windows)]
pub(in crate::network::platform) const AF_INET6: i32 = 23;
#[cfg(windows)]
pub(in crate::network::platform) const SOCK_STREAM: i32 = 1;
#[cfg(windows)]
pub(in crate::network::platform) const SOCK_DGRAM: i32 = 2;
#[cfg(windows)]
pub(in crate::network::platform) const IPPROTO_TCP: i32 = 6;
#[cfg(windows)]
pub(in crate::network::platform) const IPPROTO_UDP: i32 = 17;
#[cfg(windows)]
pub(in crate::network::platform) const POLLERR: i16 = 0x0001;
#[cfg(windows)]
pub(in crate::network::platform) const POLLHUP: i16 = 0x0002;
#[cfg(windows)]
pub(in crate::network::platform) const POLLNVAL: i16 = 0x0004;
#[cfg(windows)]
pub(in crate::network::platform) const POLLOUT: i16 = 0x0010;
#[cfg(windows)]
pub(in crate::network::platform) const POLLIN: i16 = 0x0300;
#[cfg(windows)]
pub(in crate::network::platform) const POLLPRI: i16 = 0x0400;

#[cfg(windows)]
pub(in crate::network::platform) const WSA_FLAG_OVERLAPPED: u32 = 0x01;
#[cfg(windows)]
pub(in crate::network::platform) const WSA_IO_PENDING: i32 = 997;
#[cfg(windows)]
pub(in crate::network::platform) const TRUE: crate::windows::Bool = 1;
#[cfg(windows)]
pub(in crate::network::platform) const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xc800_0006;
#[cfg(windows)]
pub(in crate::network::platform) const SOL_SOCKET: i32 = 0xffff;
#[cfg(windows)]
pub(in crate::network::platform) const SO_REUSEADDR: i32 = 0x0004;
#[cfg(windows)]
pub(in crate::network::platform) const SO_KEEPALIVE: i32 = 0x0008;
#[cfg(windows)]
pub(in crate::network::platform) const SO_SNDBUF: i32 = 0x1001;
#[cfg(windows)]
pub(in crate::network::platform) const SO_RCVBUF: i32 = 0x1002;
#[cfg(windows)]
pub(in crate::network::platform) const SO_ERROR: i32 = 0x1007;
#[cfg(windows)]
pub(in crate::network::platform) const SO_TYPE: i32 = 0x1008;
#[cfg(windows)]
pub(in crate::network::platform) const SO_UPDATE_ACCEPT_CONTEXT: i32 = 0x700b;
#[cfg(windows)]
pub(in crate::network::platform) const SO_UPDATE_CONNECT_CONTEXT: i32 = 0x7010;
#[cfg(windows)]
pub(in crate::network::platform) const TCP_NODELAY: i32 = 0x0001;
#[cfg(windows)]
pub(in crate::network::platform) const FIONBIO: i32 = 0x8004_667e_u32 as i32;
#[cfg(windows)]
pub(in crate::network::platform) const SD_RECEIVE: i32 = 0;
#[cfg(windows)]
pub(in crate::network::platform) const SD_SEND: i32 = 1;
#[cfg(windows)]
pub(in crate::network::platform) const SD_BOTH: i32 = 2;

#[cfg(windows)]
#[repr(C)]
pub(in crate::network::platform) struct WsaData {
    pub(in crate::network::platform) version: u16,
    pub(in crate::network::platform) high_version: u16,
    pub(in crate::network::platform) description: [u8; 257],
    pub(in crate::network::platform) system_status: [u8; 129],
    pub(in crate::network::platform) max_sockets: u16,
    pub(in crate::network::platform) max_udp_datagram: u16,
    pub(in crate::network::platform) vendor_info: *mut u8,
}

#[cfg(windows)]
impl Default for WsaData {
    fn default() -> Self {
        Self {
            version: 0,
            high_version: 0,
            description: [0; 257],
            system_status: [0; 129],
            max_sockets: 0,
            max_udp_datagram: 0,
            vendor_info: std::ptr::null_mut(),
        }
    }
}

#[cfg(windows)]
#[repr(C)]
pub(in crate::network::platform) struct WsaPollFd {
    pub(in crate::network::platform) fd: crate::windows::Socket,
    pub(in crate::network::platform) events: i16,
    pub(in crate::network::platform) revents: i16,
}

#[cfg(windows)]
#[repr(C)]
pub(in crate::network::platform) struct WsaBuf {
    pub(in crate::network::platform) len: u32,
    pub(in crate::network::platform) buf: *mut std::ffi::c_char,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::network) struct Guid {
    pub(in crate::network::platform) data1: u32,
    pub(in crate::network::platform) data2: u16,
    pub(in crate::network::platform) data3: u16,
    pub(in crate::network::platform) data4: [u8; 8],
}

#[cfg(windows)]
pub(in crate::network) const WSAID_ACCEPTEX: Guid = Guid {
    data1: 0xb536_7df1,
    data2: 0xcbac,
    data3: 0x11cf,
    data4: [0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92],
};

#[cfg(windows)]
pub(in crate::network) const WSAID_CONNECTEX: Guid = Guid {
    data1: 0x25a2_07b9,
    data2: 0xddf3,
    data3: 0x4660,
    data4: [0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e],
};

#[cfg(windows)]
pub(in crate::network::platform) const WSAID_MULTIPLE_RIO: Guid = Guid {
    data1: 0x8509_e081,
    data2: 0x96dd,
    data3: 0x4005,
    data4: [0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f],
};

#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(in crate::network::platform) struct RioExtensionFunctionTable {
    pub(in crate::network::platform) cb_size: u32,
    pub(in crate::network::platform) functions: [usize; RIO_FUNCTION_COUNT],
}

#[cfg(windows)]
impl Default for RioExtensionFunctionTable {
    fn default() -> Self {
        Self {
            cb_size: std::mem::size_of::<Self>() as u32,
            functions: [0; RIO_FUNCTION_COUNT],
        }
    }
}

#[cfg(windows)]
pub(in crate::network::platform) const RIO_FUNCTION_COUNT: usize = 13;

#[cfg(windows)]
pub(in crate::network::platform) type AcceptExFn =
    unsafe extern "system" fn(
        listen_socket: crate::windows::Socket,
        accept_socket: crate::windows::Socket,
        output_buffer: *mut std::ffi::c_void,
        receive_data_len: u32,
        local_address_len: u32,
        remote_address_len: u32,
        bytes_received: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;

#[cfg(windows)]
pub(in crate::network::platform) type ConnectExFn =
    unsafe extern "system" fn(
        socket: crate::windows::Socket,
        name: *const Sockaddr,
        name_len: i32,
        send_buffer: *mut std::ffi::c_void,
        send_data_len: u32,
        bytes_sent: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;

#[cfg(windows)]
#[repr(C)]
#[derive(Debug)]
pub(in crate::network::platform) struct WsaOverlapped {
    pub(in crate::network::platform) internal: usize,
    pub(in crate::network::platform) internal_high: usize,
    pub(in crate::network::platform) offset: u32,
    pub(in crate::network::platform) offset_high: u32,
    pub(in crate::network::platform) event: crate::windows::Handle,
}

#[cfg(windows)]
// SAFETY: `WsaOverlapped` owns a Windows event handle and plain OVERLAPPED
// fields. Pending socket operations move this owner to a worker thread without
// sharing mutable access to the same OVERLAPPED allocation.
unsafe impl Send for WsaOverlapped {}

#[cfg(windows)]
impl WsaOverlapped {
    pub(in crate::network::platform) const fn new(event: crate::windows::Handle) -> Self {
        Self {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event,
        }
    }
}

#[cfg(windows)]
#[repr(C)]
pub(in crate::network::platform) struct Sockaddr {
    pub(in crate::network::platform) family: u16,
    pub(in crate::network::platform) data: [u8; 14],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
pub(in crate::network::platform) struct SockaddrIn {
    pub(in crate::network::platform) family: u16,
    pub(in crate::network::platform) port: u16,
    pub(in crate::network::platform) addr: u32,
    pub(in crate::network::platform) zero: [u8; 8],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
pub(in crate::network::platform) struct In6Addr {
    pub(in crate::network::platform) bytes: [u8; 16],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
pub(in crate::network::platform) struct SockaddrIn6 {
    pub(in crate::network::platform) family: u16,
    pub(in crate::network::platform) port: u16,
    pub(in crate::network::platform) flowinfo: u32,
    pub(in crate::network::platform) addr: In6Addr,
    pub(in crate::network::platform) scope_id: u32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
pub(in crate::network::platform) struct SockaddrStorage {
    pub(in crate::network::platform) family: u16,
    pub(in crate::network::platform) data: [u8; 126],
}

#[cfg(windows)]
impl Default for SockaddrStorage {
    fn default() -> Self {
        Self {
            family: 0,
            data: [0; 126],
        }
    }
}

#[cfg(windows)]
impl SockaddrStorage {
    pub(in crate::network::platform) fn as_mut_sockaddr(&mut self) -> *mut Sockaddr {
        std::ptr::from_mut(self).cast()
    }
}

#[cfg(windows)]
pub(in crate::network::platform) union SocketAddressStorage {
    pub(in crate::network::platform) inet: SockaddrIn,
    pub(in crate::network::platform) inet6: SockaddrIn6,
    pub(in crate::network::platform) storage: SockaddrStorage,
}

#[cfg(windows)]
impl SocketAddressStorage {
    pub(in crate::network::platform) fn from_socket_addr(address: SocketAddr) -> Self {
        match address {
            SocketAddr::V4(address) => Self {
                inet: SockaddrIn {
                    family: AF_INET as u16,
                    port: address.port().to_be(),
                    addr: u32::from_ne_bytes(address.ip().octets()),
                    zero: [0; 8],
                },
            },
            SocketAddr::V6(address) => Self {
                inet6: SockaddrIn6 {
                    family: AF_INET6 as u16,
                    port: address.port().to_be(),
                    flowinfo: address.flowinfo(),
                    addr: In6Addr {
                        bytes: address.ip().octets(),
                    },
                    scope_id: address.scope_id(),
                },
            },
        }
    }

    pub(in crate::network::platform) fn as_sockaddr(&self) -> *const Sockaddr {
        std::ptr::from_ref(self).cast()
    }

    pub(in crate::network::platform) fn len(&self) -> i32 {
        // SAFETY: The active union field's first member is the address family.
        let family = unsafe { self.storage.family };
        match i32::from(family) {
            AF_INET => size_of_i32::<SockaddrIn>().expect("sockaddr_in size fits i32"),
            AF_INET6 => size_of_i32::<SockaddrIn6>().expect("sockaddr_in6 size fits i32"),
            _ => size_of_i32::<SockaddrStorage>().expect("sockaddr_storage size fits i32"),
        }
    }
}

#[cfg(windows)]
pub(in crate::network::platform) fn socket_addr_from_storage(
    storage: &SockaddrStorage,
) -> HostResult<SocketAddr> {
    match i32::from(storage.family) {
        AF_INET => {
            // SAFETY: Caller populated storage through Winsock for an AF_INET address.
            let inet = unsafe {
                std::ptr::from_ref(storage)
                    .cast::<SockaddrIn>()
                    .read_unaligned()
            };
            Ok(SocketAddr::from((
                std::net::Ipv4Addr::from(inet.addr.to_ne_bytes()),
                u16::from_be(inet.port),
            )))
        }
        AF_INET6 => {
            // SAFETY: Caller populated storage through Winsock for an AF_INET6 address.
            let inet6 = unsafe {
                std::ptr::from_ref(storage)
                    .cast::<SockaddrIn6>()
                    .read_unaligned()
            };
            Ok(SocketAddr::from(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(inet6.addr.bytes),
                u16::from_be(inet6.port),
                inet6.flowinfo,
                inet6.scope_id,
            )))
        }
        _ => Err(HostError::invalid_input(HostOperation::QuerySocketAddress)),
    }
}

#[cfg(windows)]
pub(in crate::network::platform) fn socket_option_name_to_winsock(
    name: HostSocketOptionName,
) -> (i32, i32) {
    match name {
        HostSocketOptionName::ReuseAddress => (SOL_SOCKET, SO_REUSEADDR),
        HostSocketOptionName::KeepAlive => (SOL_SOCKET, SO_KEEPALIVE),
        HostSocketOptionName::SendBufferSize => (SOL_SOCKET, SO_SNDBUF),
        HostSocketOptionName::ReceiveBufferSize => (SOL_SOCKET, SO_RCVBUF),
        HostSocketOptionName::SocketError => (SOL_SOCKET, SO_ERROR),
        HostSocketOptionName::SocketType => (SOL_SOCKET, SO_TYPE),
        HostSocketOptionName::TcpNoDelay => (IPPROTO_TCP, TCP_NODELAY),
    }
}

#[cfg(windows)]
pub(in crate::network::platform) fn socket_option_to_winsock(
    name: HostSocketOptionName,
    value: HostSocketOptionValue,
) -> HostResult<(i32, i32, i32)> {
    let (level, option) = socket_option_name_to_winsock(name);
    let raw = match (name, value) {
        (
            HostSocketOptionName::ReuseAddress
            | HostSocketOptionName::KeepAlive
            | HostSocketOptionName::TcpNoDelay,
            HostSocketOptionValue::Bool(value),
        ) => i32::from(value),
        (
            HostSocketOptionName::SendBufferSize | HostSocketOptionName::ReceiveBufferSize,
            HostSocketOptionValue::Int(value),
        ) => value,
        (HostSocketOptionName::SocketError | HostSocketOptionName::SocketType, _) => {
            return Err(HostError::invalid_input(HostOperation::SetSocketOption));
        }
        _ => return Err(HostError::invalid_input(HostOperation::SetSocketOption)),
    };
    Ok((level, option, raw))
}

#[cfg(windows)]
pub(in crate::network::platform) fn socket_option_from_winsock(
    name: HostSocketOptionName,
    raw: i32,
) -> HostResult<HostSocketOptionValue> {
    match name {
        HostSocketOptionName::ReuseAddress
        | HostSocketOptionName::KeepAlive
        | HostSocketOptionName::TcpNoDelay => Ok(HostSocketOptionValue::Bool(raw != 0)),
        HostSocketOptionName::SendBufferSize
        | HostSocketOptionName::ReceiveBufferSize
        | HostSocketOptionName::SocketError => Ok(HostSocketOptionValue::Int(raw)),
        HostSocketOptionName::SocketType => {
            Ok(HostSocketOptionValue::Kind(SocketKind::from_winsock(raw)?))
        }
    }
}

#[cfg(windows)]
pub(in crate::network::platform) fn size_of_i32<T>() -> HostResult<i32> {
    i32::try_from(std::mem::size_of::<T>())
        .map_err(|_| HostError::invalid_input(HostOperation::QuerySocketAddress))
}

#[cfg(windows)]
#[link(name = "ws2_32")]
unsafe extern "system" {
    pub(in crate::network::platform) fn WSAStartup(
        version_requested: u16,
        data: *mut WsaData,
    ) -> i32;
    pub(in crate::network::platform) fn WSACleanup() -> i32;
    pub(in crate::network::platform) fn socket(
        af: i32,
        socket_type: i32,
        protocol: i32,
    ) -> crate::windows::Socket;
    pub(in crate::network::platform) fn WSASocketW(
        af: i32,
        socket_type: i32,
        protocol: i32,
        protocol_info: *mut std::ffi::c_void,
        group: u32,
        flags: u32,
    ) -> crate::windows::Socket;
    pub(in crate::network::platform) fn closesocket(socket: crate::windows::Socket) -> i32;
    pub(in crate::network::platform) fn WSAGetOverlappedResult(
        socket: crate::windows::Socket,
        overlapped: *mut std::ffi::c_void,
        bytes_transferred: *mut u32,
        wait: crate::windows::Bool,
        flags: *mut u32,
    ) -> crate::windows::Bool;
    pub(in crate::network::platform) fn WSAPoll(
        fd_array: *mut WsaPollFd,
        fds: u32,
        timeout: i32,
    ) -> i32;
    pub(in crate::network::platform) fn connect(
        socket: crate::windows::Socket,
        name: *const Sockaddr,
        name_len: i32,
    ) -> i32;
    pub(in crate::network::platform) fn bind(
        socket: crate::windows::Socket,
        name: *const Sockaddr,
        name_len: i32,
    ) -> i32;
    pub(in crate::network::platform) fn listen(socket: crate::windows::Socket, backlog: i32)
    -> i32;
    pub(in crate::network::platform) fn accept(
        socket: crate::windows::Socket,
        address: *mut Sockaddr,
        address_len: *mut i32,
    ) -> crate::windows::Socket;
    pub(in crate::network::platform) fn send(
        socket: crate::windows::Socket,
        buffer: *const std::ffi::c_char,
        len: i32,
        flags: i32,
    ) -> i32;
    pub(in crate::network::platform) fn WSASend(
        socket: crate::windows::Socket,
        buffers: *mut WsaBuf,
        buffer_count: u32,
        bytes_sent: *mut u32,
        flags: u32,
        overlapped: *mut std::ffi::c_void,
        completion_routine: *mut std::ffi::c_void,
    ) -> i32;
    pub(in crate::network::platform) fn sendto(
        socket: crate::windows::Socket,
        buffer: *const std::ffi::c_char,
        len: i32,
        flags: i32,
        to: *const Sockaddr,
        tolen: i32,
    ) -> i32;
    pub(in crate::network::platform) fn WSASendTo(
        socket: crate::windows::Socket,
        buffers: *mut WsaBuf,
        buffer_count: u32,
        bytes_sent: *mut u32,
        flags: u32,
        to: *const Sockaddr,
        tolen: i32,
        overlapped: *mut std::ffi::c_void,
        completion_routine: *mut std::ffi::c_void,
    ) -> i32;
    pub(in crate::network::platform) fn recv(
        socket: crate::windows::Socket,
        buffer: *mut std::ffi::c_char,
        len: i32,
        flags: i32,
    ) -> i32;
    pub(in crate::network::platform) fn WSARecv(
        socket: crate::windows::Socket,
        buffers: *mut WsaBuf,
        buffer_count: u32,
        bytes_received: *mut u32,
        flags: *mut u32,
        overlapped: *mut std::ffi::c_void,
        completion_routine: *mut std::ffi::c_void,
    ) -> i32;
    pub(in crate::network::platform) fn recvfrom(
        socket: crate::windows::Socket,
        buffer: *mut std::ffi::c_char,
        len: i32,
        flags: i32,
        from: *mut Sockaddr,
        fromlen: *mut i32,
    ) -> i32;
    pub(in crate::network::platform) fn WSARecvFrom(
        socket: crate::windows::Socket,
        buffers: *mut WsaBuf,
        buffer_count: u32,
        bytes_received: *mut u32,
        flags: *mut u32,
        from: *mut Sockaddr,
        fromlen: *mut i32,
        overlapped: *mut std::ffi::c_void,
        completion_routine: *mut std::ffi::c_void,
    ) -> i32;
    pub(in crate::network::platform) fn WSAIoctl(
        socket: crate::windows::Socket,
        io_control_code: u32,
        in_buffer: *mut std::ffi::c_void,
        in_buffer_size: u32,
        out_buffer: *mut std::ffi::c_void,
        out_buffer_size: u32,
        bytes_returned: *mut u32,
        overlapped: *mut std::ffi::c_void,
        completion_routine: *mut std::ffi::c_void,
    ) -> i32;
    pub(in crate::network::platform) fn ioctlsocket(
        socket: crate::windows::Socket,
        cmd: i32,
        argp: *mut u32,
    ) -> i32;
    pub(in crate::network::platform) fn setsockopt(
        socket: crate::windows::Socket,
        level: i32,
        option_name: i32,
        option_value: *const std::ffi::c_char,
        option_len: i32,
    ) -> i32;
    pub(in crate::network::platform) fn getsockopt(
        socket: crate::windows::Socket,
        level: i32,
        option_name: i32,
        option_value: *mut std::ffi::c_char,
        option_len: *mut i32,
    ) -> i32;
    pub(in crate::network::platform) fn shutdown(socket: crate::windows::Socket, how: i32) -> i32;
    pub(in crate::network::platform) fn getsockname(
        socket: crate::windows::Socket,
        name: *mut Sockaddr,
        name_len: *mut i32,
    ) -> i32;
    pub(in crate::network::platform) fn getpeername(
        socket: crate::windows::Socket,
        name: *mut Sockaddr,
        name_len: *mut i32,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    pub(in crate::network::platform) fn CreateEventW(
        security_attributes: crate::windows::Handle,
        manual_reset: crate::windows::Bool,
        initial_state: crate::windows::Bool,
        name: *const u16,
    ) -> crate::windows::Handle;
    pub(in crate::network::platform) fn CancelIoEx(
        file: crate::windows::Handle,
        overlapped: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;
}
