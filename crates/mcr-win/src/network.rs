use std::time::Duration;

use crate::error::{HostError, HostOperation, HostResult};

/// Host address family for socket creation.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AddressFamily {
    Inet,
    Inet6,
    Unix,
}

/// Host socket type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketKind {
    Stream,
    Datagram,
}

/// Host socket protocol.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketProtocol {
    Default,
    Tcp,
    Udp,
}

/// Socket readiness events used by the host networking adapter.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct SocketEvents {
    pub readable: bool,
    pub writable: bool,
    pub priority: bool,
    pub error: bool,
    pub hang_up: bool,
    pub invalid: bool,
}

impl SocketEvents {
    /// Read readiness interest.
    pub const fn read() -> Self {
        Self {
            readable: true,
            writable: false,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        }
    }

    /// Write readiness interest.
    pub const fn write() -> Self {
        Self {
            readable: false,
            writable: true,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        }
    }

    /// Read and write readiness interest.
    pub const fn read_write() -> Self {
        Self {
            readable: true,
            writable: true,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        }
    }

    /// Returns whether no readiness flags are set.
    pub const fn is_empty(self) -> bool {
        !self.readable
            && !self.writable
            && !self.priority
            && !self.error
            && !self.hang_up
            && !self.invalid
    }
}

/// Socket poll entry.
#[derive(Debug)]
pub struct SocketPoll<'a> {
    pub socket: &'a HostSocket,
    pub interest: SocketEvents,
    pub readiness: SocketEvents,
}

impl<'a> SocketPoll<'a> {
    /// Creates a socket poll entry with no readiness set.
    pub const fn new(socket: &'a HostSocket, interest: SocketEvents) -> Self {
        Self {
            socket,
            interest,
            readiness: SocketEvents {
                readable: false,
                writable: false,
                priority: false,
                error: false,
                hang_up: false,
                invalid: false,
            },
        }
    }
}

/// Winsock runtime lifetime guard.
#[derive(Debug)]
pub struct NetworkStack {
    #[cfg(windows)]
    _private: (),
}

impl NetworkStack {
    /// Initializes host networking.
    pub fn start() -> HostResult<Self> {
        start_platform()
    }

    /// Opens a host socket.
    pub fn open_socket(
        &self,
        family: AddressFamily,
        kind: SocketKind,
        protocol: SocketProtocol,
    ) -> HostResult<HostSocket> {
        open_socket_platform(family, kind, protocol)
    }

    /// Polls host sockets for readiness.
    pub fn poll(
        &self,
        entries: &mut [SocketPoll<'_>],
        timeout: Option<Duration>,
    ) -> HostResult<usize> {
        poll_platform(entries, timeout)
    }
}

#[cfg(windows)]
impl Drop for NetworkStack {
    fn drop(&mut self) {
        // SAFETY: This balances a successful `WSAStartup` in `start_platform`.
        unsafe {
            WSACleanup();
        }
    }
}

/// Owned host socket.
#[derive(Debug)]
pub struct HostSocket {
    #[cfg(windows)]
    raw: crate::windows::Socket,
    #[cfg(not(windows))]
    _private: (),
}

#[cfg(windows)]
impl Drop for HostSocket {
    fn drop(&mut self) {
        // SAFETY: `raw` is an owned SOCKET created by `socket`.
        unsafe {
            let _ = closesocket(self.raw);
        }
    }
}

#[cfg(not(windows))]
fn start_platform() -> HostResult<NetworkStack> {
    Ok(NetworkStack {})
}

#[cfg(not(windows))]
fn open_socket_platform(
    _family: AddressFamily,
    _kind: SocketKind,
    _protocol: SocketProtocol,
) -> HostResult<HostSocket> {
    Err(HostError::unsupported(HostOperation::OpenSocket))
}

#[cfg(not(windows))]
fn poll_platform(entries: &mut [SocketPoll<'_>], _timeout: Option<Duration>) -> HostResult<usize> {
    if entries.is_empty() {
        Ok(0)
    } else {
        Err(HostError::unsupported(HostOperation::PollSockets))
    }
}

#[cfg(windows)]
fn start_platform() -> HostResult<NetworkStack> {
    let mut data = WsaData::default();
    // SAFETY: `data` points to writable WSADATA storage.
    let status = unsafe { WSAStartup(WSA_VERSION_2_2, &mut data) };
    if status != 0 {
        return Err(HostError::with_code(
            HostOperation::StartNetwork,
            crate::error::winsock_kind(status),
            crate::HostErrorCode::Winsock(status),
        ));
    }
    Ok(NetworkStack { _private: () })
}

#[cfg(windows)]
fn open_socket_platform(
    family: AddressFamily,
    kind: SocketKind,
    protocol: SocketProtocol,
) -> HostResult<HostSocket> {
    // SAFETY: Arguments are plain Winsock constants.
    let raw = unsafe {
        socket(
            family.to_winsock(),
            kind.to_winsock(),
            protocol.to_winsock(),
        )
    };
    if raw == crate::windows::INVALID_SOCKET {
        return Err(crate::error::last_winsock_error(HostOperation::OpenSocket));
    }
    Ok(HostSocket { raw })
}

#[cfg(windows)]
fn poll_platform(entries: &mut [SocketPoll<'_>], timeout: Option<Duration>) -> HostResult<usize> {
    if entries.len() > u32::MAX as usize {
        return Err(HostError::invalid_input(HostOperation::PollSockets));
    }

    let mut poll_fds = entries
        .iter()
        .map(|entry| WsaPollFd {
            fd: entry.socket.raw,
            events: entry.interest.to_winsock(),
            revents: 0,
        })
        .collect::<Vec<_>>();
    let timeout = timeout.map_or(-1, duration_to_poll_timeout);

    // SAFETY: `poll_fds` points to `entries.len()` initialized WSAPOLLFD values.
    let ready = unsafe { WSAPoll(poll_fds.as_mut_ptr(), poll_fds.len() as u32, timeout) };
    if ready == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::PollSockets));
    }

    for (entry, poll_fd) in entries.iter_mut().zip(poll_fds.iter()) {
        entry.readiness = SocketEvents::from_winsock(poll_fd.revents);
    }

    Ok(ready as usize)
}

#[cfg(windows)]
fn duration_to_poll_timeout(duration: Duration) -> i32 {
    if duration.is_zero() {
        return 0;
    }

    let millis = duration.as_millis().saturating_add(1);
    millis.min(i32::MAX as u128) as i32
}

#[cfg(windows)]
impl AddressFamily {
    const fn to_winsock(self) -> i32 {
        match self {
            Self::Inet => AF_INET,
            Self::Inet6 => AF_INET6,
            Self::Unix => AF_UNIX,
        }
    }
}

#[cfg(windows)]
impl SocketKind {
    const fn to_winsock(self) -> i32 {
        match self {
            Self::Stream => SOCK_STREAM,
            Self::Datagram => SOCK_DGRAM,
        }
    }
}

#[cfg(windows)]
impl SocketProtocol {
    const fn to_winsock(self) -> i32 {
        match self {
            Self::Default => 0,
            Self::Tcp => IPPROTO_TCP,
            Self::Udp => IPPROTO_UDP,
        }
    }
}

#[cfg(windows)]
impl SocketEvents {
    const fn to_winsock(self) -> i16 {
        let mut events = 0;
        if self.readable {
            events |= POLLIN;
        }
        if self.writable {
            events |= POLLOUT;
        }
        if self.priority {
            events |= POLLPRI;
        }
        events
    }

    const fn from_winsock(events: i16) -> Self {
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
const WSA_VERSION_2_2: u16 = 0x0202;
#[cfg(windows)]
const AF_UNIX: i32 = 1;
#[cfg(windows)]
const AF_INET: i32 = 2;
#[cfg(windows)]
const AF_INET6: i32 = 23;
#[cfg(windows)]
const SOCK_STREAM: i32 = 1;
#[cfg(windows)]
const SOCK_DGRAM: i32 = 2;
#[cfg(windows)]
const IPPROTO_TCP: i32 = 6;
#[cfg(windows)]
const IPPROTO_UDP: i32 = 17;
#[cfg(windows)]
const POLLERR: i16 = 0x0001;
#[cfg(windows)]
const POLLHUP: i16 = 0x0002;
#[cfg(windows)]
const POLLNVAL: i16 = 0x0004;
#[cfg(windows)]
const POLLOUT: i16 = 0x0010;
#[cfg(windows)]
const POLLIN: i16 = 0x0300;
#[cfg(windows)]
const POLLPRI: i16 = 0x0400;

#[cfg(windows)]
#[repr(C)]
struct WsaData {
    version: u16,
    high_version: u16,
    description: [u8; 257],
    system_status: [u8; 129],
    max_sockets: u16,
    max_udp_datagram: u16,
    vendor_info: *mut u8,
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
struct WsaPollFd {
    fd: crate::windows::Socket,
    events: i16,
    revents: i16,
}

#[cfg(windows)]
#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version_requested: u16, data: *mut WsaData) -> i32;
    fn WSACleanup() -> i32;
    fn socket(af: i32, socket_type: i32, protocol: i32) -> crate::windows::Socket;
    fn closesocket(socket: crate::windows::Socket) -> i32;
    fn WSAPoll(fd_array: *mut WsaPollFd, fds: u32, timeout: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::{NetworkStack, SocketEvents};

    #[test]
    fn socket_events_empty_detects_flags() {
        assert!(SocketEvents::default().is_empty());
    }

    #[test]
    fn network_stack_polls_empty_set() {
        let stack = NetworkStack::start().unwrap();
        let mut entries = [];

        let ready = stack
            .poll(&mut entries, Some(std::time::Duration::ZERO))
            .unwrap();

        assert_eq!(ready, 0);
    }
}
