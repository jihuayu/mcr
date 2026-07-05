use super::*;

#[cfg(not(windows))]
pub(super) fn start_platform() -> HostResult<NetworkStack> {
    Ok(NetworkStack {})
}

#[cfg(not(windows))]
pub(super) fn open_socket_platform(
    _family: AddressFamily,
    _kind: SocketKind,
    _protocol: SocketProtocol,
) -> HostResult<HostSocket> {
    Err(HostError::unsupported(HostOperation::OpenSocket))
}

#[cfg(not(windows))]
pub(super) fn open_socket_with_iocp_platform(
    _family: AddressFamily,
    _kind: SocketKind,
    _protocol: SocketProtocol,
    _port: &HostIoCompletionPort,
    _completion_key: usize,
) -> HostResult<HostSocket> {
    Err(HostError::unsupported(HostOperation::OpenSocket))
}

#[cfg(not(windows))]
pub(super) fn poll_platform(
    entries: &mut [SocketPoll<'_>],
    _timeout: Option<Duration>,
) -> HostResult<usize> {
    if entries.is_empty() {
        Ok(0)
    } else {
        Err(HostError::unsupported(HostOperation::PollSockets))
    }
}

#[cfg(not(windows))]
pub(super) fn connect_platform(_socket: &HostSocket, _address: SocketAddr) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::ConnectSocket))
}

#[cfg(not(windows))]
pub(super) fn bind_platform(_socket: &HostSocket, _address: SocketAddr) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::BindSocket))
}

#[cfg(not(windows))]
pub(super) fn listen_platform(_socket: &HostSocket, _backlog: i32) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::ListenSocket))
}

#[cfg(not(windows))]
pub(super) fn accept_platform(_socket: &HostSocket) -> HostResult<(HostSocket, SocketAddr)> {
    Err(HostError::unsupported(HostOperation::AcceptSocket))
}

#[cfg(not(windows))]
pub(super) fn send_platform(_socket: &HostSocket, _buffer: &[u8]) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::SendSocket))
}

#[cfg(not(windows))]
pub(super) fn send_vectored_platform(
    _socket: &HostSocket,
    _buffers: &[IoSlice<'_>],
) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::SendSocket))
}

#[cfg(not(windows))]
pub(super) fn send_to_platform(
    _socket: &HostSocket,
    _buffer: &[u8],
    _address: SocketAddr,
) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::SendSocket))
}

#[cfg(not(windows))]
pub(super) fn send_to_vectored_platform(
    _socket: &HostSocket,
    _buffers: &[IoSlice<'_>],
    _address: SocketAddr,
) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::SendSocket))
}

#[cfg(not(windows))]
pub(super) fn recv_platform(_socket: &HostSocket, _buffer: &mut [u8]) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::RecvSocket))
}

#[cfg(not(windows))]
pub(super) fn recv_vectored_platform(
    _socket: &HostSocket,
    _buffers: &mut [IoSliceMut<'_>],
) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::RecvSocket))
}

#[cfg(not(windows))]
pub(super) fn recv_from_platform(
    _socket: &HostSocket,
    _buffer: &mut [u8],
) -> HostResult<(usize, SocketAddr)> {
    Err(HostError::unsupported(HostOperation::RecvSocket))
}

#[cfg(not(windows))]
pub(super) fn recv_from_vectored_platform(
    _socket: &HostSocket,
    _buffers: &mut [IoSliceMut<'_>],
) -> HostResult<(usize, SocketAddr)> {
    Err(HostError::unsupported(HostOperation::RecvSocket))
}

#[cfg(not(windows))]
pub(super) fn extension_function_platform(
    _socket: &HostSocket,
    _kind: SocketFastPathKind,
) -> HostResult<usize> {
    Err(HostError::unsupported(HostOperation::GetSocketOption))
}

#[cfg(not(windows))]
pub(super) fn rio_capability_platform(_socket: &HostSocket) -> HostResult<HostRioCapability> {
    Ok(HostRioCapability::unsupported(None))
}

#[cfg(not(windows))]
pub(super) fn submit_connect_ex_platform(
    _socket: &HostSocket,
    _address: SocketAddr,
) -> HostConnectExSubmission {
    HostConnectExSubmission::Failed(HostError::unsupported(HostOperation::ConnectSocket))
}

#[cfg(not(windows))]
pub(super) fn submit_accept_ex_platform(_socket: &HostSocket) -> HostAcceptExSubmission {
    HostAcceptExSubmission::Failed(HostError::unsupported(HostOperation::AcceptSocket))
}

#[cfg(not(windows))]
pub(super) fn submit_overlapped_socket_io_platform(
    _socket: &HostSocket,
    direction: HostSocketIoDirection,
    buffer: Vec<u8>,
) -> HostSocketIoSubmission {
    HostSocketIoSubmission::Failed(HostSocketIoFailure::new(
        direction,
        HostError::unsupported(direction.operation()),
        buffer,
    ))
}

#[cfg(not(windows))]
pub(super) fn set_nonblocking_platform(_socket: &HostSocket, _nonblocking: bool) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::SetSocketNonblocking))
}

#[cfg(not(windows))]
pub(super) fn set_socket_option_platform(
    _socket: &HostSocket,
    _name: HostSocketOptionName,
    _value: HostSocketOptionValue,
) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::SetSocketOption))
}

#[cfg(not(windows))]
pub(super) fn get_socket_option_platform(
    _socket: &HostSocket,
    _name: HostSocketOptionName,
) -> HostResult<HostSocketOptionValue> {
    Err(HostError::unsupported(HostOperation::GetSocketOption))
}

#[cfg(not(windows))]
pub(super) fn take_error_platform(_socket: &HostSocket) -> HostResult<Option<HostError>> {
    Err(HostError::unsupported(HostOperation::GetSocketOption))
}

#[cfg(not(windows))]
pub(super) fn shutdown_platform(_socket: &HostSocket, _how: HostShutdown) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::ShutdownSocket))
}

#[cfg(not(windows))]
pub(super) fn socket_addr_platform(
    _socket: &HostSocket,
    _kind: SocketAddressKind,
) -> HostResult<SocketAddr> {
    Err(HostError::unsupported(HostOperation::QuerySocketAddress))
}
