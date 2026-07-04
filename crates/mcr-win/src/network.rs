use std::io::{IoSlice, IoSliceMut};
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::{HostError, HostErrorCode, HostOperation, HostResult};

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

/// Host socket shutdown direction.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostShutdown {
    Read,
    Write,
    Both,
}

/// Supported socket options surfaced by the host adapter.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostSocketOptionName {
    ReuseAddress,
    KeepAlive,
    SendBufferSize,
    ReceiveBufferSize,
    SocketError,
    SocketType,
    TcpNoDelay,
}

/// Supported socket option values.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostSocketOptionValue {
    Bool(bool),
    Int(i32),
    Kind(SocketKind),
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

/// Host socket completion classes that can wake guest readiness waiters.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketCompletionKind {
    Accept,
    Connect,
    Receive,
    Send,
    PeerClosed,
    Closed,
    Error,
}

impl SocketCompletionKind {
    /// Maps a host completion into the level-trigger readiness bits visible to
    /// `select`, `poll`, and `epoll`.
    pub const fn readiness(self) -> SocketEvents {
        match self {
            Self::Accept | Self::Receive => SocketEvents {
                readable: true,
                writable: false,
                priority: false,
                error: false,
                hang_up: false,
                invalid: false,
            },
            Self::Connect | Self::Send => SocketEvents {
                readable: false,
                writable: true,
                priority: false,
                error: false,
                hang_up: false,
                invalid: false,
            },
            Self::PeerClosed => SocketEvents {
                readable: true,
                writable: false,
                priority: false,
                error: false,
                hang_up: true,
                invalid: false,
            },
            Self::Closed => SocketEvents {
                readable: false,
                writable: false,
                priority: false,
                error: true,
                hang_up: true,
                invalid: false,
            },
            Self::Error => SocketEvents {
                readable: false,
                writable: false,
                priority: false,
                error: true,
                hang_up: false,
                invalid: false,
            },
        }
    }
}

/// Winsock extension fast paths that can feed the socket readiness seam.
///
/// The host adapter owns extension-function lookup, overlapped operation
/// lifetime, context update, and cancellation. Higher layers only observe the
/// corresponding completion class and keep Linux socket state unchanged.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketFastPathKind {
    AcceptEx,
    ConnectEx,
}

impl SocketFastPathKind {
    /// Completion kind emitted when this fast path has progressed enough to
    /// wake guest readiness waiters.
    pub const fn completion_kind(self) -> SocketCompletionKind {
        match self {
            Self::AcceptEx => SocketCompletionKind::Accept,
            Self::ConnectEx => SocketCompletionKind::Connect,
        }
    }
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

impl HostSocket {
    /// Connects this socket to a remote address.
    pub fn connect(&self, address: SocketAddr) -> HostResult<()> {
        connect_platform(self, address)
    }

    /// Binds this socket to a local address.
    pub fn bind(&self, address: SocketAddr) -> HostResult<()> {
        bind_platform(self, address)
    }

    /// Marks this socket as a listening socket.
    pub fn listen(&self, backlog: i32) -> HostResult<()> {
        listen_platform(self, backlog)
    }

    /// Accepts a pending connection.
    pub fn accept(&self) -> HostResult<(Self, SocketAddr)> {
        accept_platform(self)
    }

    /// Sends bytes on this socket.
    pub fn send(&self, buffer: &[u8]) -> HostResult<usize> {
        send_platform(self, buffer)
    }

    /// Sends scattered bytes on this socket.
    pub fn send_vectored(&self, buffers: &[IoSlice<'_>]) -> HostResult<usize> {
        send_vectored_platform(self, buffers)
    }

    /// Sends bytes to a remote datagram address.
    pub fn send_to(&self, buffer: &[u8], address: SocketAddr) -> HostResult<usize> {
        send_to_platform(self, buffer, address)
    }

    /// Sends scattered bytes to a remote datagram address.
    pub fn send_to_vectored(
        &self,
        buffers: &[IoSlice<'_>],
        address: SocketAddr,
    ) -> HostResult<usize> {
        send_to_vectored_platform(self, buffers, address)
    }

    /// Receives bytes from this socket.
    pub fn recv(&self, buffer: &mut [u8]) -> HostResult<usize> {
        recv_platform(self, buffer)
    }

    /// Receives bytes into scattered buffers.
    pub fn recv_vectored(&self, buffers: &mut [IoSliceMut<'_>]) -> HostResult<usize> {
        recv_vectored_platform(self, buffers)
    }

    /// Receives bytes and the remote datagram address.
    pub fn recv_from(&self, buffer: &mut [u8]) -> HostResult<(usize, SocketAddr)> {
        recv_from_platform(self, buffer)
    }

    /// Receives bytes into scattered buffers and reports the remote datagram address.
    pub fn recv_from_vectored(
        &self,
        buffers: &mut [IoSliceMut<'_>],
    ) -> HostResult<(usize, SocketAddr)> {
        recv_from_vectored_platform(self, buffers)
    }

    /// Polls this socket for readiness.
    pub fn poll(
        &self,
        interest: SocketEvents,
        timeout: Option<Duration>,
    ) -> HostResult<SocketEvents> {
        let mut entry = [SocketPoll::new(self, interest)];
        let _ = poll_platform(&mut entry, timeout)?;
        Ok(entry[0].readiness)
    }

    /// Sets host nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> HostResult<()> {
        set_nonblocking_platform(self, nonblocking)
    }

    /// Sets a supported socket option.
    pub fn set_option(
        &self,
        name: HostSocketOptionName,
        value: HostSocketOptionValue,
    ) -> HostResult<()> {
        set_socket_option_platform(self, name, value)
    }

    /// Reads a supported socket option.
    pub fn get_option(&self, name: HostSocketOptionName) -> HostResult<HostSocketOptionValue> {
        get_socket_option_platform(self, name)
    }

    /// Reads and clears the pending socket error when the host exposes one.
    pub fn take_error(&self) -> HostResult<Option<HostError>> {
        take_error_platform(self)
    }

    /// Shuts down one or both directions of this socket.
    pub fn shutdown(&self, how: HostShutdown) -> HostResult<()> {
        shutdown_platform(self, how)
    }

    /// Returns this socket's local address.
    pub fn local_addr(&self) -> HostResult<SocketAddr> {
        socket_addr_platform(self, SocketAddressKind::Local)
    }

    /// Returns this socket's peer address.
    pub fn peer_addr(&self) -> HostResult<SocketAddr> {
        socket_addr_platform(self, SocketAddressKind::Peer)
    }
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

#[cfg(not(windows))]
fn connect_platform(_socket: &HostSocket, _address: SocketAddr) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::ConnectSocket))
}

#[cfg(not(windows))]
fn bind_platform(_socket: &HostSocket, _address: SocketAddr) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::BindSocket))
}

#[cfg(not(windows))]
fn listen_platform(_socket: &HostSocket, _backlog: i32) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::ListenSocket))
}

#[cfg(not(windows))]
fn accept_platform(_socket: &HostSocket) -> HostResult<(HostSocket, SocketAddr)> {
    Err(HostError::unsupported(HostOperation::AcceptSocket))
}

#[cfg(not(windows))]
fn send_platform(_socket: &HostSocket, _buffer: &[u8]) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::SendSocket))
}

#[cfg(not(windows))]
fn send_vectored_platform(_socket: &HostSocket, _buffers: &[IoSlice<'_>]) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::SendSocket))
}

#[cfg(not(windows))]
fn send_to_platform(
    _socket: &HostSocket,
    _buffer: &[u8],
    _address: SocketAddr,
) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::SendSocket))
}

#[cfg(not(windows))]
fn send_to_vectored_platform(
    _socket: &HostSocket,
    _buffers: &[IoSlice<'_>],
    _address: SocketAddr,
) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::SendSocket))
}

#[cfg(not(windows))]
fn recv_platform(_socket: &HostSocket, _buffer: &mut [u8]) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::RecvSocket))
}

#[cfg(not(windows))]
fn recv_vectored_platform(
    _socket: &HostSocket,
    _buffers: &mut [IoSliceMut<'_>],
) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::RecvSocket))
}

#[cfg(not(windows))]
fn recv_from_platform(_socket: &HostSocket, _buffer: &mut [u8]) -> HostResult<(usize, SocketAddr)> {
    Err(HostError::unsupported(HostOperation::RecvSocket))
}

#[cfg(not(windows))]
fn recv_from_vectored_platform(
    _socket: &HostSocket,
    _buffers: &mut [IoSliceMut<'_>],
) -> HostResult<(usize, SocketAddr)> {
    Err(HostError::unsupported(HostOperation::RecvSocket))
}

#[cfg(not(windows))]
fn set_nonblocking_platform(_socket: &HostSocket, _nonblocking: bool) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::SetSocketNonblocking))
}

#[cfg(not(windows))]
fn set_socket_option_platform(
    _socket: &HostSocket,
    _name: HostSocketOptionName,
    _value: HostSocketOptionValue,
) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::SetSocketOption))
}

#[cfg(not(windows))]
fn get_socket_option_platform(
    _socket: &HostSocket,
    _name: HostSocketOptionName,
) -> HostResult<HostSocketOptionValue> {
    Err(HostError::unsupported(HostOperation::GetSocketOption))
}

#[cfg(not(windows))]
fn take_error_platform(_socket: &HostSocket) -> HostResult<Option<HostError>> {
    Err(HostError::unsupported(HostOperation::GetSocketOption))
}

#[cfg(not(windows))]
fn shutdown_platform(_socket: &HostSocket, _how: HostShutdown) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::ShutdownSocket))
}

#[cfg(not(windows))]
fn socket_addr_platform(_socket: &HostSocket, _kind: SocketAddressKind) -> HostResult<SocketAddr> {
    Err(HostError::unsupported(HostOperation::QuerySocketAddress))
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum SocketAddressKind {
    Local,
    Peer,
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
    if entries.is_empty() {
        return Ok(0);
    }
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
fn connect_platform(socket: &HostSocket, address: SocketAddr) -> HostResult<()> {
    let storage = SocketAddressStorage::from_socket_addr(address);
    // SAFETY: `storage` points to a valid sockaddr for the supplied address.
    let status = unsafe { connect(socket.raw, storage.as_sockaddr(), storage.len()) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::ConnectSocket,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn bind_platform(socket: &HostSocket, address: SocketAddr) -> HostResult<()> {
    let storage = SocketAddressStorage::from_socket_addr(address);
    // SAFETY: `storage` points to a valid sockaddr for the supplied address.
    let status = unsafe { bind(socket.raw, storage.as_sockaddr(), storage.len()) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::BindSocket));
    }
    Ok(())
}

#[cfg(windows)]
fn listen_platform(socket: &HostSocket, backlog: i32) -> HostResult<()> {
    // SAFETY: Arguments are plain Winsock values.
    let status = unsafe { listen(socket.raw, backlog) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::ListenSocket,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn accept_platform(socket: &HostSocket) -> HostResult<(HostSocket, SocketAddr)> {
    let mut storage = SockaddrStorage::default();
    let mut len = size_of_i32::<SockaddrStorage>()?;
    // SAFETY: `storage` and `len` point to writable sockaddr storage.
    let accepted = unsafe { accept(socket.raw, storage.as_mut_sockaddr(), &mut len) };
    if accepted == crate::windows::INVALID_SOCKET {
        return Err(crate::error::last_winsock_error(
            HostOperation::AcceptSocket,
        ));
    }
    Ok((
        HostSocket { raw: accepted },
        socket_addr_from_storage(&storage)?,
    ))
}

#[cfg(windows)]
fn send_platform(socket: &HostSocket, buffer: &[u8]) -> HostResult<usize> {
    let len = i32::try_from(buffer.len())
        .map_err(|_| HostError::invalid_input(HostOperation::SendSocket))?;
    // SAFETY: `buffer` points to `len` readable bytes for the duration of the call.
    let sent = unsafe { send(socket.raw, buffer.as_ptr().cast(), len, 0) };
    if sent == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::SendSocket));
    }
    Ok(sent as usize)
}

#[cfg(windows)]
fn send_vectored_platform(socket: &HostSocket, buffers: &[IoSlice<'_>]) -> HostResult<usize> {
    if buffers.is_empty() {
        return Ok(0);
    }

    let mut wsa_buffers = wsa_send_buffers(buffers)?;
    let mut sent = 0u32;
    // SAFETY: Each `WSABUF` points to readable slice storage for this synchronous call.
    let status = unsafe {
        WSASend(
            socket.raw,
            wsa_buffers.as_mut_ptr(),
            wsa_buffer_count(wsa_buffers.len(), HostOperation::SendSocket)?,
            &mut sent,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::SendSocket));
    }
    Ok(sent as usize)
}

#[cfg(windows)]
fn send_to_platform(socket: &HostSocket, buffer: &[u8], address: SocketAddr) -> HostResult<usize> {
    let len = i32::try_from(buffer.len())
        .map_err(|_| HostError::invalid_input(HostOperation::SendSocket))?;
    let storage = SocketAddressStorage::from_socket_addr(address);
    // SAFETY: `buffer` points to `len` readable bytes and `storage` is a valid sockaddr.
    let sent = unsafe {
        sendto(
            socket.raw,
            buffer.as_ptr().cast(),
            len,
            0,
            storage.as_sockaddr(),
            storage.len(),
        )
    };
    if sent == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::SendSocket));
    }
    Ok(sent as usize)
}

#[cfg(windows)]
fn send_to_vectored_platform(
    socket: &HostSocket,
    buffers: &[IoSlice<'_>],
    address: SocketAddr,
) -> HostResult<usize> {
    if buffers.is_empty() {
        return Ok(0);
    }

    let mut wsa_buffers = wsa_send_buffers(buffers)?;
    let storage = SocketAddressStorage::from_socket_addr(address);
    let mut sent = 0u32;
    // SAFETY: `WSABUF` entries and `storage` remain valid for this synchronous call.
    let status = unsafe {
        WSASendTo(
            socket.raw,
            wsa_buffers.as_mut_ptr(),
            wsa_buffer_count(wsa_buffers.len(), HostOperation::SendSocket)?,
            &mut sent,
            0,
            storage.as_sockaddr(),
            storage.len(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::SendSocket));
    }
    Ok(sent as usize)
}

#[cfg(windows)]
fn recv_platform(socket: &HostSocket, buffer: &mut [u8]) -> HostResult<usize> {
    let len = i32::try_from(buffer.len())
        .map_err(|_| HostError::invalid_input(HostOperation::RecvSocket))?;
    // SAFETY: `buffer` points to `len` writable bytes for the duration of the call.
    let received = unsafe { recv(socket.raw, buffer.as_mut_ptr().cast(), len, 0) };
    if received == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::RecvSocket));
    }
    Ok(received as usize)
}

#[cfg(windows)]
fn recv_vectored_platform(
    socket: &HostSocket,
    buffers: &mut [IoSliceMut<'_>],
) -> HostResult<usize> {
    if buffers.is_empty() {
        return Ok(0);
    }

    let mut wsa_buffers = wsa_recv_buffers(buffers)?;
    let mut received = 0u32;
    let mut flags = 0u32;
    // SAFETY: Each `WSABUF` points to writable slice storage for this synchronous call.
    let status = unsafe {
        WSARecv(
            socket.raw,
            wsa_buffers.as_mut_ptr(),
            wsa_buffer_count(wsa_buffers.len(), HostOperation::RecvSocket)?,
            &mut received,
            &mut flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::RecvSocket));
    }
    Ok(received as usize)
}

#[cfg(windows)]
fn recv_from_platform(socket: &HostSocket, buffer: &mut [u8]) -> HostResult<(usize, SocketAddr)> {
    let len = i32::try_from(buffer.len())
        .map_err(|_| HostError::invalid_input(HostOperation::RecvSocket))?;
    let mut storage = SockaddrStorage::default();
    let mut address_len = size_of_i32::<SockaddrStorage>()?;
    // SAFETY: `buffer`, `storage`, and `address_len` point to writable storage.
    let received = unsafe {
        recvfrom(
            socket.raw,
            buffer.as_mut_ptr().cast(),
            len,
            0,
            storage.as_mut_sockaddr(),
            &mut address_len,
        )
    };
    if received == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::RecvSocket));
    }
    Ok((received as usize, socket_addr_from_storage(&storage)?))
}

#[cfg(windows)]
fn recv_from_vectored_platform(
    socket: &HostSocket,
    buffers: &mut [IoSliceMut<'_>],
) -> HostResult<(usize, SocketAddr)> {
    if buffers.is_empty() {
        return Ok((0, socket_addr_platform(socket, SocketAddressKind::Peer)?));
    }

    let mut wsa_buffers = wsa_recv_buffers(buffers)?;
    let mut storage = SockaddrStorage::default();
    let mut address_len = size_of_i32::<SockaddrStorage>()?;
    let mut received = 0u32;
    let mut flags = 0u32;
    // SAFETY: `WSABUF`, `storage`, and length pointers remain valid for this synchronous call.
    let status = unsafe {
        WSARecvFrom(
            socket.raw,
            wsa_buffers.as_mut_ptr(),
            wsa_buffer_count(wsa_buffers.len(), HostOperation::RecvSocket)?,
            &mut received,
            &mut flags,
            storage.as_mut_sockaddr(),
            &mut address_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::RecvSocket));
    }
    Ok((received as usize, socket_addr_from_storage(&storage)?))
}

#[cfg(windows)]
fn wsa_send_buffers(buffers: &[IoSlice<'_>]) -> HostResult<Vec<WsaBuf>> {
    buffers
        .iter()
        .map(|buffer| {
            let len = u32::try_from(buffer.len())
                .map_err(|_| HostError::invalid_input(HostOperation::SendSocket))?;
            Ok(WsaBuf {
                len,
                buf: buffer.as_ptr().cast_mut().cast(),
            })
        })
        .collect()
}

#[cfg(windows)]
fn wsa_recv_buffers(buffers: &mut [IoSliceMut<'_>]) -> HostResult<Vec<WsaBuf>> {
    buffers
        .iter_mut()
        .map(|buffer| {
            let len = u32::try_from(buffer.len())
                .map_err(|_| HostError::invalid_input(HostOperation::RecvSocket))?;
            Ok(WsaBuf {
                len,
                buf: buffer.as_mut_ptr().cast(),
            })
        })
        .collect()
}

#[cfg(windows)]
fn wsa_buffer_count(count: usize, operation: HostOperation) -> HostResult<u32> {
    u32::try_from(count).map_err(|_| HostError::invalid_input(operation))
}

#[cfg(windows)]
fn set_nonblocking_platform(socket: &HostSocket, nonblocking: bool) -> HostResult<()> {
    let mut mode = u32::from(nonblocking);
    // SAFETY: `mode` points to writable u_long storage as required by ioctlsocket.
    let status = unsafe { ioctlsocket(socket.raw, FIONBIO, &mut mode) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::SetSocketNonblocking,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn set_socket_option_platform(
    socket: &HostSocket,
    name: HostSocketOptionName,
    value: HostSocketOptionValue,
) -> HostResult<()> {
    let (level, option, raw) = socket_option_to_winsock(name, value)?;
    // SAFETY: `raw` points to an initialized i32 option value.
    let status = unsafe {
        setsockopt(
            socket.raw,
            level,
            option,
            std::ptr::from_ref(&raw).cast(),
            size_of_i32::<i32>()?,
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::SetSocketOption,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn get_socket_option_platform(
    socket: &HostSocket,
    name: HostSocketOptionName,
) -> HostResult<HostSocketOptionValue> {
    let (level, option) = socket_option_name_to_winsock(name);
    let mut raw = 0i32;
    let mut len = size_of_i32::<i32>()?;
    // SAFETY: `raw` and `len` point to writable option storage.
    let status = unsafe {
        getsockopt(
            socket.raw,
            level,
            option,
            std::ptr::from_mut(&mut raw).cast(),
            &mut len,
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::GetSocketOption,
        ));
    }
    socket_option_from_winsock(name, raw)
}

#[cfg(windows)]
fn take_error_platform(socket: &HostSocket) -> HostResult<Option<HostError>> {
    match socket.get_option(HostSocketOptionName::SocketError)? {
        HostSocketOptionValue::Int(0) => Ok(None),
        HostSocketOptionValue::Int(code) => Ok(Some(HostError::with_code(
            HostOperation::ConnectSocket,
            crate::error::winsock_kind(code),
            HostErrorCode::Winsock(code),
        ))),
        _ => Err(HostError::invalid_input(HostOperation::GetSocketOption)),
    }
}

#[cfg(windows)]
fn shutdown_platform(socket: &HostSocket, how: HostShutdown) -> HostResult<()> {
    // SAFETY: Arguments are plain Winsock values.
    let status = unsafe { shutdown(socket.raw, how.to_winsock()) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::ShutdownSocket,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn socket_addr_platform(socket: &HostSocket, kind: SocketAddressKind) -> HostResult<SocketAddr> {
    let mut storage = SockaddrStorage::default();
    let mut len = size_of_i32::<SockaddrStorage>()?;
    let status = match kind {
        SocketAddressKind::Local => {
            // SAFETY: `storage` and `len` point to writable sockaddr storage.
            unsafe { getsockname(socket.raw, storage.as_mut_sockaddr(), &mut len) }
        }
        SocketAddressKind::Peer => {
            // SAFETY: `storage` and `len` point to writable sockaddr storage.
            unsafe { getpeername(socket.raw, storage.as_mut_sockaddr(), &mut len) }
        }
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::QuerySocketAddress,
        ));
    }
    socket_addr_from_storage(&storage)
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
impl SocketKind {
    const fn from_winsock(value: i32) -> HostResult<Self> {
        match value {
            SOCK_STREAM => Ok(Self::Stream),
            SOCK_DGRAM => Ok(Self::Datagram),
            _ => Err(HostError::invalid_input(HostOperation::GetSocketOption)),
        }
    }
}

#[cfg(windows)]
impl HostShutdown {
    const fn to_winsock(self) -> i32 {
        match self {
            Self::Read => SD_RECEIVE,
            Self::Write => SD_SEND,
            Self::Both => SD_BOTH,
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
        // WSAPoll rejects POLLPRI for ordinary TCP connect checks on Windows. The runtime does
        // not implement Linux OOB/priority-band socket data yet, so keep this interest local.
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
const SOL_SOCKET: i32 = 0xffff;
#[cfg(windows)]
const SO_REUSEADDR: i32 = 0x0004;
#[cfg(windows)]
const SO_KEEPALIVE: i32 = 0x0008;
#[cfg(windows)]
const SO_SNDBUF: i32 = 0x1001;
#[cfg(windows)]
const SO_RCVBUF: i32 = 0x1002;
#[cfg(windows)]
const SO_ERROR: i32 = 0x1007;
#[cfg(windows)]
const SO_TYPE: i32 = 0x1008;
#[cfg(windows)]
const TCP_NODELAY: i32 = 0x0001;
#[cfg(windows)]
const FIONBIO: i32 = 0x8004_667e_u32 as i32;
#[cfg(windows)]
const SD_RECEIVE: i32 = 0;
#[cfg(windows)]
const SD_SEND: i32 = 1;
#[cfg(windows)]
const SD_BOTH: i32 = 2;

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
#[repr(C)]
struct WsaBuf {
    len: u32,
    buf: *mut std::ffi::c_char,
}

#[cfg(windows)]
#[repr(C)]
struct Sockaddr {
    family: u16,
    data: [u8; 14],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    family: u16,
    port: u16,
    addr: u32,
    zero: [u8; 8],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct In6Addr {
    bytes: [u8; 16],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: In6Addr,
    scope_id: u32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrStorage {
    family: u16,
    data: [u8; 126],
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
    fn as_mut_sockaddr(&mut self) -> *mut Sockaddr {
        std::ptr::from_mut(self).cast()
    }
}

#[cfg(windows)]
union SocketAddressStorage {
    inet: SockaddrIn,
    inet6: SockaddrIn6,
    storage: SockaddrStorage,
}

#[cfg(windows)]
impl SocketAddressStorage {
    fn from_socket_addr(address: SocketAddr) -> Self {
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

    fn as_sockaddr(&self) -> *const Sockaddr {
        std::ptr::from_ref(self).cast()
    }

    fn len(&self) -> i32 {
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
fn socket_addr_from_storage(storage: &SockaddrStorage) -> HostResult<SocketAddr> {
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
fn socket_option_name_to_winsock(name: HostSocketOptionName) -> (i32, i32) {
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
fn socket_option_to_winsock(
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
fn socket_option_from_winsock(
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
fn size_of_i32<T>() -> HostResult<i32> {
    i32::try_from(std::mem::size_of::<T>())
        .map_err(|_| HostError::invalid_input(HostOperation::QuerySocketAddress))
}

#[cfg(windows)]
#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version_requested: u16, data: *mut WsaData) -> i32;
    fn WSACleanup() -> i32;
    fn socket(af: i32, socket_type: i32, protocol: i32) -> crate::windows::Socket;
    fn closesocket(socket: crate::windows::Socket) -> i32;
    fn WSAPoll(fd_array: *mut WsaPollFd, fds: u32, timeout: i32) -> i32;
    fn connect(socket: crate::windows::Socket, name: *const Sockaddr, name_len: i32) -> i32;
    fn bind(socket: crate::windows::Socket, name: *const Sockaddr, name_len: i32) -> i32;
    fn listen(socket: crate::windows::Socket, backlog: i32) -> i32;
    fn accept(
        socket: crate::windows::Socket,
        address: *mut Sockaddr,
        address_len: *mut i32,
    ) -> crate::windows::Socket;
    fn send(
        socket: crate::windows::Socket,
        buffer: *const std::ffi::c_char,
        len: i32,
        flags: i32,
    ) -> i32;
    fn WSASend(
        socket: crate::windows::Socket,
        buffers: *mut WsaBuf,
        buffer_count: u32,
        bytes_sent: *mut u32,
        flags: u32,
        overlapped: *mut std::ffi::c_void,
        completion_routine: *mut std::ffi::c_void,
    ) -> i32;
    fn sendto(
        socket: crate::windows::Socket,
        buffer: *const std::ffi::c_char,
        len: i32,
        flags: i32,
        to: *const Sockaddr,
        tolen: i32,
    ) -> i32;
    fn WSASendTo(
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
    fn recv(
        socket: crate::windows::Socket,
        buffer: *mut std::ffi::c_char,
        len: i32,
        flags: i32,
    ) -> i32;
    fn WSARecv(
        socket: crate::windows::Socket,
        buffers: *mut WsaBuf,
        buffer_count: u32,
        bytes_received: *mut u32,
        flags: *mut u32,
        overlapped: *mut std::ffi::c_void,
        completion_routine: *mut std::ffi::c_void,
    ) -> i32;
    fn recvfrom(
        socket: crate::windows::Socket,
        buffer: *mut std::ffi::c_char,
        len: i32,
        flags: i32,
        from: *mut Sockaddr,
        fromlen: *mut i32,
    ) -> i32;
    fn WSARecvFrom(
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
    fn ioctlsocket(socket: crate::windows::Socket, cmd: i32, argp: *mut u32) -> i32;
    fn setsockopt(
        socket: crate::windows::Socket,
        level: i32,
        option_name: i32,
        option_value: *const std::ffi::c_char,
        option_len: i32,
    ) -> i32;
    fn getsockopt(
        socket: crate::windows::Socket,
        level: i32,
        option_name: i32,
        option_value: *mut std::ffi::c_char,
        option_len: *mut i32,
    ) -> i32;
    fn shutdown(socket: crate::windows::Socket, how: i32) -> i32;
    fn getsockname(socket: crate::windows::Socket, name: *mut Sockaddr, name_len: *mut i32) -> i32;
    fn getpeername(socket: crate::windows::Socket, name: *mut Sockaddr, name_len: *mut i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::{NetworkStack, SocketCompletionKind, SocketEvents};

    #[cfg(windows)]
    use std::io::{IoSlice, IoSliceMut};

    #[cfg(windows)]
    use super::{
        AddressFamily, HostShutdown, HostSocketOptionName, HostSocketOptionValue, SocketKind,
        SocketPoll, SocketProtocol,
    };

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

    #[test]
    fn socket_completion_kind_maps_to_readiness_bits() {
        assert_eq!(
            SocketCompletionKind::Accept.readiness(),
            SocketEvents::read()
        );
        assert_eq!(
            SocketCompletionKind::Receive.readiness(),
            SocketEvents::read()
        );
        assert_eq!(
            SocketCompletionKind::Connect.readiness(),
            SocketEvents::write()
        );
        assert_eq!(
            SocketCompletionKind::Send.readiness(),
            SocketEvents::write()
        );

        let peer_closed = SocketCompletionKind::PeerClosed.readiness();
        assert!(peer_closed.readable);
        assert!(peer_closed.hang_up);
        assert!(!peer_closed.error);

        let closed = SocketCompletionKind::Closed.readiness();
        assert!(closed.hang_up);
        assert!(closed.error);

        let error = SocketCompletionKind::Error.readiness();
        assert!(error.error);
        assert!(!error.hang_up);
    }

    #[test]
    fn socket_fast_path_kinds_map_to_completion_classes() {
        assert_eq!(
            super::SocketFastPathKind::AcceptEx.completion_kind(),
            SocketCompletionKind::Accept
        );
        assert_eq!(
            super::SocketFastPathKind::ConnectEx.completion_kind(),
            SocketCompletionKind::Connect
        );
    }

    #[cfg(windows)]
    #[test]
    fn udp_socket_accepts_nonblocking_mode() {
        let stack = NetworkStack::start().unwrap();
        let socket = stack
            .open_socket(
                AddressFamily::Inet,
                SocketKind::Datagram,
                SocketProtocol::Udp,
            )
            .unwrap();

        socket.set_nonblocking(true).unwrap();
        socket.set_nonblocking(false).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn tcp_loopback_socket_round_trip_uses_host_adapter() {
        let stack = NetworkStack::start().unwrap();
        let listener = stack
            .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
            .unwrap();
        listener
            .set_option(
                HostSocketOptionName::ReuseAddress,
                HostSocketOptionValue::Bool(true),
            )
            .unwrap();
        listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        listener.listen(1).unwrap();
        let local = listener.local_addr().unwrap();

        let client = stack
            .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
            .unwrap();
        client
            .set_option(
                HostSocketOptionName::TcpNoDelay,
                HostSocketOptionValue::Bool(true),
            )
            .unwrap();
        client.connect(local).unwrap();

        let (server, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip(), client.local_addr().unwrap().ip());
        assert_eq!(client.peer_addr().unwrap(), server.local_addr().unwrap());
        assert_eq!(
            client.get_option(HostSocketOptionName::TcpNoDelay).unwrap(),
            HostSocketOptionValue::Bool(true)
        );
        assert_eq!(
            client.get_option(HostSocketOptionName::SocketType).unwrap(),
            HostSocketOptionValue::Kind(SocketKind::Stream)
        );

        let mut poll = [SocketPoll::new(&client, SocketEvents::write())];
        assert_eq!(
            stack
                .poll(&mut poll, Some(std::time::Duration::from_millis(50)))
                .unwrap(),
            1
        );
        assert!(poll[0].readiness.writable);

        assert_eq!(client.send(b"ping").unwrap(), 4);
        let mut buffer = [0; 4];
        assert_eq!(server.recv(&mut buffer).unwrap(), 4);
        assert_eq!(&buffer, b"ping");

        let chunks = [IoSlice::new(b"ve"), IoSlice::new(b"c!")];
        assert_eq!(client.send_vectored(&chunks).unwrap(), 4);
        let mut first = [0; 2];
        let mut second = [0; 2];
        let mut buffers = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        assert_eq!(server.recv_vectored(&mut buffers).unwrap(), 4);
        assert_eq!(&first, b"ve");
        assert_eq!(&second, b"c!");

        server.shutdown(HostShutdown::Both).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn tcp_poll_ignores_priority_interest_for_write_readiness() {
        let stack = NetworkStack::start().unwrap();
        let listener = stack
            .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
            .unwrap();
        listener
            .set_option(
                HostSocketOptionName::ReuseAddress,
                HostSocketOptionValue::Bool(true),
            )
            .unwrap();
        listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        listener.listen(1).unwrap();
        let local = listener.local_addr().unwrap();

        let client = stack
            .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
            .unwrap();
        client.connect(local).unwrap();
        let (server, _) = listener.accept().unwrap();

        let mut poll = [SocketPoll::new(
            &client,
            SocketEvents {
                writable: true,
                priority: true,
                ..SocketEvents::default()
            },
        )];

        assert_eq!(
            stack
                .poll(&mut poll, Some(std::time::Duration::from_millis(50)))
                .unwrap(),
            1
        );
        assert!(poll[0].readiness.writable);
        assert!(!poll[0].readiness.priority);

        server.shutdown(HostShutdown::Both).unwrap();
    }
}
