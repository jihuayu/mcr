use std::io::{IoSlice, IoSliceMut};
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::{HostError, HostErrorCode, HostOperation, HostResult};
use crate::iocp::HostIoCompletionPort;

use super::super::model::{
    AddressFamily, HostAcceptExSubmission, HostConnectExSubmission, HostShutdown,
    HostSocketIoCompletion, HostSocketIoDirection, HostSocketIoFailure, HostSocketIoSubmission,
    HostSocketOptionName, HostSocketOptionValue, SocketEvents, SocketFastPathKind, SocketKind,
    SocketPoll, SocketProtocol,
};
use super::pending::{
    ACCEPTEX_ADDRESS_BUFFER_LEN, WindowsPendingAcceptEx, WindowsPendingConnectEx,
    WindowsPendingSocketIo,
};
use super::winsock::*;
use super::{
    HostRioCapability, HostSocket, NetworkStack, PendingHostAcceptEx, PendingHostConnectEx,
    PendingHostSocketIo, SocketAddressKind,
};

#[cfg(windows)]
pub(super) fn start_platform() -> HostResult<NetworkStack> {
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
pub(super) fn open_socket_platform(
    family: AddressFamily,
    kind: SocketKind,
    protocol: SocketProtocol,
) -> HostResult<HostSocket> {
    open_socket_raw_platform(family, kind, protocol, false)
}

#[cfg(windows)]
pub(super) fn open_socket_with_iocp_platform(
    family: AddressFamily,
    kind: SocketKind,
    protocol: SocketProtocol,
    port: &HostIoCompletionPort,
    completion_key: usize,
) -> HostResult<HostSocket> {
    let socket = open_socket_raw_platform(family, kind, protocol, true)?;
    // SAFETY: `socket` owns a valid overlapped Winsock SOCKET and keeps it alive
    // for at least as long as any operations submitted through this adapter.
    unsafe {
        port.associate_raw_handle(socket.raw(), completion_key)?;
    }
    Ok(socket)
}

#[cfg(windows)]
pub(super) fn open_socket_raw_platform(
    family: AddressFamily,
    kind: SocketKind,
    protocol: SocketProtocol,
    overlapped: bool,
) -> HostResult<HostSocket> {
    let raw = if overlapped {
        // SAFETY: Arguments are plain Winsock constants; protocol info is not supplied.
        unsafe {
            WSASocketW(
                family.to_winsock(),
                kind.to_winsock(),
                protocol.to_winsock(),
                std::ptr::null_mut(),
                0,
                WSA_FLAG_OVERLAPPED,
            )
        }
    } else {
        // SAFETY: Arguments are plain Winsock constants.
        unsafe {
            socket(
                family.to_winsock(),
                kind.to_winsock(),
                protocol.to_winsock(),
            )
        }
    };
    if raw == crate::windows::INVALID_SOCKET {
        return Err(crate::error::last_winsock_error(HostOperation::OpenSocket));
    }
    Ok(HostSocket::from_raw(raw))
}

#[cfg(windows)]
pub(super) fn poll_platform(
    entries: &mut [SocketPoll<'_>],
    timeout: Option<Duration>,
) -> HostResult<usize> {
    if entries.is_empty() {
        return Ok(0);
    }
    if entries.len() > u32::MAX as usize {
        return Err(HostError::invalid_input(HostOperation::PollSockets));
    }

    let mut poll_fds = entries
        .iter()
        .map(|entry| WsaPollFd {
            fd: entry.socket.raw(),
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
pub(super) fn connect_platform(socket: &HostSocket, address: SocketAddr) -> HostResult<()> {
    let storage = SocketAddressStorage::from_socket_addr(address);
    // SAFETY: `storage` points to a valid sockaddr for the supplied address.
    let status = unsafe { connect(socket.raw(), storage.as_sockaddr(), storage.len()) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::ConnectSocket,
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn bind_platform(socket: &HostSocket, address: SocketAddr) -> HostResult<()> {
    let storage = SocketAddressStorage::from_socket_addr(address);
    // SAFETY: `storage` points to a valid sockaddr for the supplied address.
    let status = unsafe { bind(socket.raw(), storage.as_sockaddr(), storage.len()) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::BindSocket));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn listen_platform(socket: &HostSocket, backlog: i32) -> HostResult<()> {
    // SAFETY: Arguments are plain Winsock values.
    let status = unsafe { listen(socket.raw(), backlog) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::ListenSocket,
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn accept_platform(socket: &HostSocket) -> HostResult<(HostSocket, SocketAddr)> {
    let mut storage = SockaddrStorage::default();
    let mut len = size_of_i32::<SockaddrStorage>()?;
    // SAFETY: `storage` and `len` point to writable sockaddr storage.
    let accepted = unsafe { accept(socket.raw(), storage.as_mut_sockaddr(), &mut len) };
    if accepted == crate::windows::INVALID_SOCKET {
        return Err(crate::error::last_winsock_error(
            HostOperation::AcceptSocket,
        ));
    }
    Ok((
        HostSocket::from_raw(accepted),
        socket_addr_from_storage(&storage)?,
    ))
}

#[cfg(windows)]
pub(super) fn send_platform(socket: &HostSocket, buffer: &[u8]) -> HostResult<usize> {
    let len = i32::try_from(buffer.len())
        .map_err(|_| HostError::invalid_input(HostOperation::SendSocket))?;
    // SAFETY: `buffer` points to `len` readable bytes for the duration of the call.
    let sent = unsafe { send(socket.raw(), buffer.as_ptr().cast(), len, 0) };
    if sent == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::SendSocket));
    }
    Ok(sent as usize)
}

#[cfg(windows)]
pub(super) fn send_vectored_platform(
    socket: &HostSocket,
    buffers: &[IoSlice<'_>],
) -> HostResult<usize> {
    if buffers.is_empty() {
        return Ok(0);
    }

    let mut wsa_buffers = wsa_send_buffers(buffers)?;
    let mut sent = 0u32;
    // SAFETY: Each `WSABUF` points to readable slice storage for this synchronous call.
    let status = unsafe {
        WSASend(
            socket.raw(),
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
pub(super) fn send_to_platform(
    socket: &HostSocket,
    buffer: &[u8],
    address: SocketAddr,
) -> HostResult<usize> {
    let len = i32::try_from(buffer.len())
        .map_err(|_| HostError::invalid_input(HostOperation::SendSocket))?;
    let storage = SocketAddressStorage::from_socket_addr(address);
    // SAFETY: `buffer` points to `len` readable bytes and `storage` is a valid sockaddr.
    let sent = unsafe {
        sendto(
            socket.raw(),
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
pub(super) fn send_to_vectored_platform(
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
            socket.raw(),
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
pub(super) fn recv_platform(socket: &HostSocket, buffer: &mut [u8]) -> HostResult<usize> {
    let len = i32::try_from(buffer.len())
        .map_err(|_| HostError::invalid_input(HostOperation::RecvSocket))?;
    // SAFETY: `buffer` points to `len` writable bytes for the duration of the call.
    let received = unsafe { recv(socket.raw(), buffer.as_mut_ptr().cast(), len, 0) };
    if received == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(HostOperation::RecvSocket));
    }
    Ok(received as usize)
}

#[cfg(windows)]
pub(super) fn recv_vectored_platform(
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
            socket.raw(),
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
pub(super) fn recv_from_platform(
    socket: &HostSocket,
    buffer: &mut [u8],
) -> HostResult<(usize, SocketAddr)> {
    let len = i32::try_from(buffer.len())
        .map_err(|_| HostError::invalid_input(HostOperation::RecvSocket))?;
    let mut storage = SockaddrStorage::default();
    let mut address_len = size_of_i32::<SockaddrStorage>()?;
    // SAFETY: `buffer`, `storage`, and `address_len` point to writable storage.
    let received = unsafe {
        recvfrom(
            socket.raw(),
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
pub(super) fn recv_from_vectored_platform(
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
            socket.raw(),
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
pub(super) fn extension_function_platform(
    socket: &HostSocket,
    kind: SocketFastPathKind,
) -> HostResult<usize> {
    let mut guid = kind.extension_guid();
    let mut function = 0usize;
    let mut bytes_returned = 0u32;
    let status = unsafe {
        // SAFETY: Input and output buffers point to initialized stack storage for this call.
        WSAIoctl(
            socket.raw(),
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            std::ptr::from_mut(&mut guid).cast(),
            std::mem::size_of::<Guid>() as u32,
            std::ptr::from_mut(&mut function).cast(),
            std::mem::size_of::<usize>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::GetSocketOption,
        ));
    }
    if function == 0 || bytes_returned < std::mem::size_of::<usize>() as u32 {
        return Err(HostError::invalid_input(HostOperation::GetSocketOption));
    }
    Ok(function)
}

#[cfg(windows)]
pub(super) fn rio_capability_platform(socket: &HostSocket) -> HostResult<HostRioCapability> {
    let mut guid = WSAID_MULTIPLE_RIO;
    let mut table = RioExtensionFunctionTable::default();
    let mut bytes_returned = 0u32;
    let status = unsafe {
        // SAFETY: Input and output buffers point to initialized stack storage for this call.
        WSAIoctl(
            socket.raw(),
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            std::ptr::from_mut(&mut guid).cast(),
            std::mem::size_of::<Guid>() as u32,
            std::ptr::from_mut(&mut table).cast(),
            std::mem::size_of::<RioExtensionFunctionTable>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Ok(HostRioCapability::unsupported(Some(
            crate::windows::wsa_last_error(),
        )));
    }
    if bytes_returned < std::mem::size_of::<u32>() as u32 || table.cb_size == 0 {
        return Ok(HostRioCapability::unsupported(None));
    }
    let function_count = table
        .functions
        .iter()
        .filter(|function| **function != 0)
        .count();
    Ok(HostRioCapability::supported(function_count))
}

#[cfg(windows)]
pub(super) fn submit_connect_ex_platform(
    socket: &HostSocket,
    address: SocketAddr,
) -> HostConnectExSubmission {
    let function = match socket.extension_function(SocketFastPathKind::ConnectEx) {
        Ok(function) => function,
        Err(error) => return HostConnectExSubmission::Failed(error),
    };
    let event = unsafe {
        // SAFETY: Creating an unnamed manual-reset event with no security descriptor.
        CreateEventW(
            std::ptr::null_mut(),
            TRUE,
            crate::windows::FALSE,
            std::ptr::null(),
        )
    };
    if event.is_null() {
        return HostConnectExSubmission::Failed(crate::error::last_windows_error(
            HostOperation::ConnectSocket,
        ));
    }

    let storage = SocketAddressStorage::from_socket_addr(address);
    let overlapped = WsaOverlapped::new(event);
    let mut platform = WindowsPendingConnectEx::new(socket.clone_inner(), overlapped);
    let mut bytes_sent = 0u32;
    let connect_ex = unsafe {
        // SAFETY: The pointer was returned by WSAIoctl for WSAID_CONNECTEX on this socket.
        std::mem::transmute::<usize, ConnectExFn>(function)
    };
    let ok = unsafe {
        // SAFETY: Socket, sockaddr, and OVERLAPPED live for the duration of the submitted op.
        connect_ex(
            socket.raw(),
            storage.as_sockaddr(),
            storage.len(),
            std::ptr::null_mut(),
            0,
            &mut bytes_sent,
            platform.overlapped_mut_ptr(),
        )
    };
    if ok == crate::windows::FALSE {
        let error = crate::windows::wsa_last_error();
        if error != WSA_IO_PENDING {
            return HostConnectExSubmission::Failed(HostError::with_code(
                HostOperation::ConnectSocket,
                crate::error::winsock_kind(error),
                HostErrorCode::Winsock(error),
            ));
        }
    }

    platform.submitted = true;
    HostConnectExSubmission::Pending(PendingHostConnectEx::from_windows_pending(platform))
}

#[cfg(windows)]
pub(super) fn submit_accept_ex_platform(listener: &HostSocket) -> HostAcceptExSubmission {
    let function = match listener.extension_function(SocketFastPathKind::AcceptEx) {
        Ok(function) => function,
        Err(error) => return HostAcceptExSubmission::Failed(error),
    };
    let listener_addr = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => return HostAcceptExSubmission::Failed(error),
    };
    let family = if listener_addr.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    let accepted =
        match open_socket_raw_platform(family, SocketKind::Stream, SocketProtocol::Tcp, true) {
            Ok(socket) => socket,
            Err(error) => return HostAcceptExSubmission::Failed(error),
        };
    let event = unsafe {
        // SAFETY: Creating an unnamed manual-reset event with no security descriptor.
        CreateEventW(
            std::ptr::null_mut(),
            TRUE,
            crate::windows::FALSE,
            std::ptr::null(),
        )
    };
    if event.is_null() {
        return HostAcceptExSubmission::Failed(crate::error::last_windows_error(
            HostOperation::AcceptSocket,
        ));
    }

    let overlapped = WsaOverlapped::new(event);
    let mut platform = WindowsPendingAcceptEx::new(listener.clone_inner(), accepted, overlapped);
    let accept_ex = unsafe {
        // SAFETY: The pointer was returned by WSAIoctl for WSAID_ACCEPTEX on this socket.
        std::mem::transmute::<usize, AcceptExFn>(function)
    };
    let mut bytes_received = 0u32;
    let output_buffer = platform.output_buffer.as_mut_ptr().cast();
    let overlapped = platform.overlapped_mut_ptr();
    let ok = unsafe {
        // SAFETY: Listener, accepted socket, output buffer, and OVERLAPPED outlive the operation.
        accept_ex(
            listener.raw(),
            platform.accepted_raw(),
            output_buffer,
            0,
            ACCEPTEX_ADDRESS_BUFFER_LEN,
            ACCEPTEX_ADDRESS_BUFFER_LEN,
            &mut bytes_received,
            overlapped,
        )
    };
    if ok == crate::windows::FALSE {
        let error = crate::windows::wsa_last_error();
        if error != WSA_IO_PENDING {
            return HostAcceptExSubmission::Failed(HostError::with_code(
                HostOperation::AcceptSocket,
                crate::error::winsock_kind(error),
                HostErrorCode::Winsock(error),
            ));
        }
    }

    platform.submitted = true;
    HostAcceptExSubmission::Pending(PendingHostAcceptEx::from_windows_pending(platform))
}

#[cfg(windows)]
pub(super) fn submit_overlapped_socket_io_platform(
    socket: &HostSocket,
    direction: HostSocketIoDirection,
    mut buffer: Vec<u8>,
) -> HostSocketIoSubmission {
    if buffer.is_empty() {
        return HostSocketIoSubmission::Completed(HostSocketIoCompletion::new(
            direction, 0, buffer,
        ));
    }

    let event = unsafe {
        // SAFETY: Creating an unnamed manual-reset event with no security descriptor.
        CreateEventW(
            std::ptr::null_mut(),
            TRUE,
            crate::windows::FALSE,
            std::ptr::null(),
        )
    };
    if event.is_null() {
        return HostSocketIoSubmission::Failed(HostSocketIoFailure::new(
            direction,
            crate::error::last_windows_error(direction.operation()),
            buffer,
        ));
    }

    let overlapped = WsaOverlapped::new(event);
    let mut platform = WindowsPendingSocketIo::new(socket.clone_inner(), overlapped);
    let mut bytes_transferred = 0u32;
    let mut wsa_buffer = WsaBuf {
        len: buffer.len().min(u32::MAX as usize) as u32,
        buf: buffer.as_mut_ptr().cast(),
    };
    let status = match direction {
        HostSocketIoDirection::Receive => {
            let mut flags = 0u32;
            unsafe {
                // SAFETY: The socket, buffer, and OVERLAPPED are kept alive by the pending object.
                WSARecv(
                    socket.raw(),
                    &mut wsa_buffer,
                    1,
                    &mut bytes_transferred,
                    &mut flags,
                    platform.overlapped_mut_ptr(),
                    std::ptr::null_mut(),
                )
            }
        }
        HostSocketIoDirection::Send => unsafe {
            // SAFETY: The socket, buffer, and OVERLAPPED are kept alive by the pending object.
            WSASend(
                socket.raw(),
                &mut wsa_buffer,
                1,
                &mut bytes_transferred,
                0,
                platform.overlapped_mut_ptr(),
                std::ptr::null_mut(),
            )
        },
    };

    if status == crate::windows::SOCKET_ERROR {
        let error = crate::windows::wsa_last_error();
        if error != WSA_IO_PENDING {
            return HostSocketIoSubmission::Failed(HostSocketIoFailure::new(
                direction,
                HostError::with_code(
                    direction.operation(),
                    crate::error::winsock_kind(error),
                    HostErrorCode::Winsock(error),
                ),
                buffer,
            ));
        }
    }

    platform.submitted = true;
    HostSocketIoSubmission::Pending(PendingHostSocketIo::from_windows_pending(
        direction, platform, buffer,
    ))
}

#[cfg(windows)]
pub(super) fn wsa_send_buffers(buffers: &[IoSlice<'_>]) -> HostResult<Vec<WsaBuf>> {
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
pub(super) fn wsa_recv_buffers(buffers: &mut [IoSliceMut<'_>]) -> HostResult<Vec<WsaBuf>> {
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
pub(super) fn wsa_buffer_count(count: usize, operation: HostOperation) -> HostResult<u32> {
    u32::try_from(count).map_err(|_| HostError::invalid_input(operation))
}

#[cfg(windows)]
pub(super) fn set_nonblocking_platform(socket: &HostSocket, nonblocking: bool) -> HostResult<()> {
    let mut mode = u32::from(nonblocking);
    // SAFETY: `mode` points to writable u_long storage as required by ioctlsocket.
    let status = unsafe { ioctlsocket(socket.raw(), FIONBIO, &mut mode) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::SetSocketNonblocking,
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn set_socket_option_platform(
    socket: &HostSocket,
    name: HostSocketOptionName,
    value: HostSocketOptionValue,
) -> HostResult<()> {
    let (level, option, raw) = socket_option_to_winsock(name, value)?;
    // SAFETY: `raw` points to an initialized i32 option value.
    let status = unsafe {
        setsockopt(
            socket.raw(),
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
pub(super) fn get_socket_option_platform(
    socket: &HostSocket,
    name: HostSocketOptionName,
) -> HostResult<HostSocketOptionValue> {
    let (level, option) = socket_option_name_to_winsock(name);
    let mut raw = 0i32;
    let mut len = size_of_i32::<i32>()?;
    // SAFETY: `raw` and `len` point to writable option storage.
    let status = unsafe {
        getsockopt(
            socket.raw(),
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
pub(super) fn take_error_platform(socket: &HostSocket) -> HostResult<Option<HostError>> {
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
pub(super) fn shutdown_platform(socket: &HostSocket, how: HostShutdown) -> HostResult<()> {
    // SAFETY: Arguments are plain Winsock values.
    let status = unsafe { shutdown(socket.raw(), how.to_winsock()) };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::ShutdownSocket,
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn socket_addr_platform(
    socket: &HostSocket,
    kind: SocketAddressKind,
) -> HostResult<SocketAddr> {
    let mut storage = SockaddrStorage::default();
    let mut len = size_of_i32::<SockaddrStorage>()?;
    let status = match kind {
        SocketAddressKind::Local => {
            // SAFETY: `storage` and `len` point to writable sockaddr storage.
            unsafe { getsockname(socket.raw(), storage.as_mut_sockaddr(), &mut len) }
        }
        SocketAddressKind::Peer => {
            // SAFETY: `storage` and `len` point to writable sockaddr storage.
            unsafe { getpeername(socket.raw(), storage.as_mut_sockaddr(), &mut len) }
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
pub(super) fn update_connect_context(socket: crate::windows::Socket) -> HostResult<()> {
    let status = unsafe {
        // SAFETY: The socket completed ConnectEx; null option payload is required by Winsock.
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_UPDATE_CONNECT_CONTEXT,
            std::ptr::null(),
            0,
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::ConnectSocket,
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn update_accept_context(
    accepted: crate::windows::Socket,
    listener: crate::windows::Socket,
) -> HostResult<()> {
    let status = unsafe {
        // SAFETY: `listener` is the listening socket that produced `accepted` through AcceptEx.
        setsockopt(
            accepted,
            SOL_SOCKET,
            SO_UPDATE_ACCEPT_CONTEXT,
            std::ptr::from_ref(&listener).cast(),
            std::mem::size_of::<crate::windows::Socket>() as i32,
        )
    };
    if status == crate::windows::SOCKET_ERROR {
        return Err(crate::error::last_winsock_error(
            HostOperation::AcceptSocket,
        ));
    }
    Ok(())
}
