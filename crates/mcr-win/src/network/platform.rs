use std::io::{IoSlice, IoSliceMut};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{HostError, HostOperation, HostResult};
use crate::iocp::{HostIoCompletionPacket, HostIoCompletionPort};

use super::model::{
    AddressFamily, HostAcceptExSubmission, HostConnectExSubmission, HostShutdown,
    HostSocketIoCompletion, HostSocketIoDirection, HostSocketIoFailure, HostSocketIoSubmission,
    HostSocketOptionName, HostSocketOptionValue, SocketEvents, SocketFastPathKind, SocketKind,
    SocketPoll, SocketProtocol,
};

mod pending;
mod windows;
mod winsock;

use self::pending::{WindowsPendingAcceptEx, WindowsPendingConnectEx, WindowsPendingSocketIo};
use self::windows::*;
pub(super) use self::winsock::{Guid, WSAID_ACCEPTEX, WSAID_CONNECTEX};
use self::winsock::{WSACleanup, closesocket};

/// Pending `AcceptEx` operation.
#[derive(Debug)]
pub struct PendingHostAcceptEx {
    platform: Option<WindowsPendingAcceptEx>,
}

impl PendingHostAcceptEx {
    fn from_windows_pending(platform: WindowsPendingAcceptEx) -> Self {
        Self {
            platform: Some(platform),
        }
    }

    #[must_use]
    pub fn overlapped_token(&self) -> usize {
        if let Some(platform) = self.platform.as_ref() {
            return platform.overlapped_token();
        }
        0
    }

    #[must_use]
    pub fn matches_completion(&self, packet: HostIoCompletionPacket) -> bool {
        self.overlapped_token() == packet.overlapped()
    }

    pub fn complete_from_packet(
        mut self,
        packet: HostIoCompletionPacket,
    ) -> Result<(HostSocket, SocketAddr), HostError> {
        if !self.matches_completion(packet) {
            return Err(HostError::invalid_input(HostOperation::AcceptSocket));
        }
        if let Some(error) = packet.error_code() {
            self.mark_completed_without_context_update();
            return Err(crate::error::windows_error(
                HostOperation::AcceptSocket,
                error,
            ));
        }
        self.mark_completed_platform()
    }

    fn mark_completed_platform(&mut self) -> Result<(HostSocket, SocketAddr), HostError> {
        let Some(platform) = self.platform.as_mut() else {
            return Err(HostError::invalid_input(HostOperation::AcceptSocket));
        };
        platform.completed = true;
        let accepted_ref = platform
            .accepted
            .as_ref()
            .ok_or_else(|| HostError::invalid_input(HostOperation::AcceptSocket))?;
        update_accept_context(accepted_ref.raw(), platform.listener.raw)?;
        let peer = accepted_ref.peer_addr()?;
        let accepted = platform
            .accepted
            .take()
            .ok_or_else(|| HostError::invalid_input(HostOperation::AcceptSocket))?;
        self.platform.take();
        Ok((accepted, peer))
    }

    fn mark_completed_without_context_update(&mut self) {
        if let Some(platform) = self.platform.as_mut() {
            platform.completed = true;
        }
        self.platform.take();
    }
}

/// Pending `ConnectEx` operation.
#[derive(Debug)]
pub struct PendingHostConnectEx {
    platform: Option<WindowsPendingConnectEx>,
}

impl PendingHostConnectEx {
    fn from_windows_pending(platform: WindowsPendingConnectEx) -> Self {
        Self {
            platform: Some(platform),
        }
    }

    #[must_use]
    pub fn overlapped_token(&self) -> usize {
        if let Some(platform) = self.platform.as_ref() {
            return platform.overlapped_token();
        }
        0
    }

    #[must_use]
    pub fn matches_completion(&self, packet: HostIoCompletionPacket) -> bool {
        self.overlapped_token() == packet.overlapped()
    }

    pub fn complete_from_packet(mut self, packet: HostIoCompletionPacket) -> Result<(), HostError> {
        if !self.matches_completion(packet) {
            return Err(HostError::invalid_input(HostOperation::ConnectSocket));
        }
        let Some(error) = packet.error_code() else {
            return self.mark_completed_platform();
        };
        self.mark_completed_without_context_update();
        Err(crate::error::windows_error(
            HostOperation::ConnectSocket,
            error,
        ))
    }

    fn mark_completed_platform(&mut self) -> Result<(), HostError> {
        let Some(platform) = self.platform.as_mut() else {
            return Err(HostError::invalid_input(HostOperation::ConnectSocket));
        };
        platform.completed = true;
        update_connect_context(platform.socket.raw)?;
        self.platform.take();
        Ok(())
    }

    fn mark_completed_without_context_update(&mut self) {
        if let Some(platform) = self.platform.as_mut() {
            platform.completed = true;
        }
        self.platform.take();
    }
}

/// Pending overlapped host socket operation.
#[derive(Debug)]
pub struct PendingHostSocketIo {
    direction: HostSocketIoDirection,
    buffer: Option<Vec<u8>>,
    platform: Option<WindowsPendingSocketIo>,
}

impl PendingHostSocketIo {
    fn from_windows_pending(
        direction: HostSocketIoDirection,
        platform: WindowsPendingSocketIo,
        buffer: Vec<u8>,
    ) -> Self {
        Self {
            direction,
            buffer: Some(buffer),
            platform: Some(platform),
        }
    }

    #[must_use]
    pub const fn direction(&self) -> HostSocketIoDirection {
        self.direction
    }

    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_deref().unwrap_or(&[])
    }

    #[must_use]
    pub fn overlapped_token(&self) -> usize {
        if let Some(platform) = self.platform.as_ref() {
            return platform.overlapped_token();
        }
        0
    }

    #[must_use]
    pub fn matches_completion(&self, packet: HostIoCompletionPacket) -> bool {
        self.overlapped_token() == packet.overlapped()
    }

    #[must_use]
    pub fn complete_from_packet(
        mut self,
        packet: HostIoCompletionPacket,
    ) -> HostSocketIoSubmission {
        if !self.matches_completion(packet) {
            return HostSocketIoSubmission::Pending(self);
        }
        let buffer = self.buffer.take().unwrap_or_default();
        if let Some(error) = packet.error_code() {
            self.mark_completed_platform();
            return HostSocketIoSubmission::Failed(HostSocketIoFailure::new(
                self.direction,
                crate::error::windows_error(self.direction.operation(), error),
                buffer,
            ));
        }
        if packet.bytes_transferred() as usize > buffer.len() {
            self.mark_completed_platform();
            return HostSocketIoSubmission::Failed(HostSocketIoFailure::new(
                self.direction,
                HostError::invalid_input(self.direction.operation()),
                buffer,
            ));
        }
        self.mark_completed_platform();
        HostSocketIoSubmission::Completed(HostSocketIoCompletion::new(
            self.direction,
            packet.bytes_transferred() as usize,
            buffer,
        ))
    }

    fn mark_completed_platform(&mut self) {
        if let Some(platform) = self.platform.as_mut() {
            platform.completed = true;
        }
        self.platform.take();
    }
}

/// Registered I/O capability reported by the host for a socket.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct HostRioCapability {
    supported: bool,
    error_code: Option<i32>,
    function_count: usize,
}

impl HostRioCapability {
    const fn supported(function_count: usize) -> Self {
        Self {
            supported: true,
            error_code: None,
            function_count,
        }
    }

    pub const fn unsupported(error_code: Option<i32>) -> Self {
        Self {
            supported: false,
            error_code,
            function_count: 0,
        }
    }

    #[must_use]
    pub const fn is_supported(self) -> bool {
        self.supported
    }

    #[must_use]
    pub const fn error_code(self) -> Option<i32> {
        self.error_code
    }

    #[must_use]
    pub const fn function_count(self) -> usize {
        self.function_count
    }
}

/// Winsock runtime lifetime guard.
#[derive(Debug)]
pub struct NetworkStack {
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

    /// Opens a host socket in overlapped mode and associates it with an IOCP.
    pub fn open_socket_with_iocp(
        &self,
        family: AddressFamily,
        kind: SocketKind,
        protocol: SocketProtocol,
        port: &HostIoCompletionPort,
        completion_key: usize,
    ) -> HostResult<HostSocket> {
        open_socket_with_iocp_platform(family, kind, protocol, port, completion_key)
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
    inner: Arc<HostSocketInner>,
}

#[derive(Debug)]
struct HostSocketInner {
    raw: crate::windows::Socket,
}

impl HostSocket {
    fn from_raw(raw: crate::windows::Socket) -> Self {
        Self {
            inner: Arc::new(HostSocketInner { raw }),
        }
    }

    fn raw(&self) -> crate::windows::Socket {
        self.inner.raw
    }

    fn clone_inner(&self) -> Arc<HostSocketInner> {
        Arc::clone(&self.inner)
    }

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

    /// Looks up a Winsock extension function pointer for this socket.
    pub fn extension_function(&self, kind: SocketFastPathKind) -> HostResult<usize> {
        extension_function_platform(self, kind)
    }

    /// Queries whether Registered I/O is available for this socket.
    pub fn rio_capability(&self) -> HostResult<HostRioCapability> {
        rio_capability_platform(self)
    }

    /// Submits a `ConnectEx` operation. The socket must be bound and associated with an IOCP.
    pub fn submit_connect_ex(&self, address: SocketAddr) -> HostConnectExSubmission {
        submit_connect_ex_platform(self, address)
    }

    /// Submits an `AcceptEx` operation. The listener must be associated with an IOCP.
    pub fn submit_accept_ex(&self) -> HostAcceptExSubmission {
        submit_accept_ex_platform(self)
    }

    /// Submits an overlapped receive. The socket must be associated with an IOCP.
    pub fn submit_overlapped_recv(&self, buffer: Vec<u8>) -> HostSocketIoSubmission {
        submit_overlapped_socket_io_platform(self, HostSocketIoDirection::Receive, buffer)
    }

    /// Submits an overlapped send. The socket must be associated with an IOCP.
    pub fn submit_overlapped_send(&self, buffer: Vec<u8>) -> HostSocketIoSubmission {
        submit_overlapped_socket_io_platform(self, HostSocketIoDirection::Send, buffer)
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

impl Drop for HostSocketInner {
    fn drop(&mut self) {
        // SAFETY: `raw` is an owned SOCKET created by `socket`.
        unsafe {
            let _ = closesocket(self.raw);
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum SocketAddressKind {
    Local,
    Peer,
}
