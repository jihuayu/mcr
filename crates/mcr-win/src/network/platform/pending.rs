use std::sync::Arc;

use super::winsock::{CancelIoEx, SockaddrStorage, TRUE, WSAGetOverlappedResult, WsaOverlapped};
use super::{HostSocket, HostSocketInner};

#[cfg(windows)]
#[derive(Debug)]
pub(in crate::network::platform) struct WindowsPendingAcceptEx {
    pub(in crate::network::platform) listener: Arc<HostSocketInner>,
    pub(in crate::network::platform) accepted: Option<HostSocket>,
    pub(in crate::network::platform) overlapped: Box<WsaOverlapped>,
    pub(in crate::network::platform) output_buffer: Vec<u8>,
    pub(in crate::network::platform) submitted: bool,
    pub(in crate::network::platform) completed: bool,
}

#[cfg(windows)]
impl WindowsPendingAcceptEx {
    pub(in crate::network::platform) fn new(
        listener: Arc<HostSocketInner>,
        accepted: HostSocket,
        overlapped: WsaOverlapped,
    ) -> Self {
        Self {
            listener,
            accepted: Some(accepted),
            overlapped: Box::new(overlapped),
            output_buffer: vec![0; (ACCEPTEX_ADDRESS_BUFFER_LEN * 2) as usize],
            submitted: false,
            completed: false,
        }
    }

    pub(in crate::network::platform) fn accepted_raw(&self) -> crate::windows::Socket {
        self.accepted
            .as_ref()
            .expect("accepted socket present while AcceptEx is pending")
            .raw()
    }

    pub(in crate::network::platform) fn overlapped_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        (&mut *self.overlapped as *mut WsaOverlapped).cast()
    }

    pub(in crate::network::platform) fn overlapped_token(&self) -> usize {
        (&*self.overlapped as *const WsaOverlapped) as usize
    }
}

#[cfg(windows)]
impl Drop for WindowsPendingAcceptEx {
    fn drop(&mut self) {
        if self.submitted && !self.completed {
            let overlapped = self.overlapped_mut_ptr();
            unsafe {
                // SAFETY: The listener and OVERLAPPED are owned by this pending operation.
                let _ = CancelIoEx(self.listener.raw as crate::windows::Handle, overlapped);
                let mut bytes_transferred = 0u32;
                let mut flags = 0u32;
                let _ = WSAGetOverlappedResult(
                    self.listener.raw,
                    overlapped,
                    &mut bytes_transferred,
                    TRUE,
                    &mut flags,
                );
            }
        }
        crate::windows::close_handle(self.overlapped.event);
    }
}

#[cfg(windows)]
pub(in crate::network::platform) const ACCEPTEX_ADDRESS_BUFFER_LEN: u32 =
    std::mem::size_of::<SockaddrStorage>() as u32 + 16;

#[cfg(windows)]
#[derive(Debug)]
pub(in crate::network::platform) struct WindowsPendingConnectEx {
    pub(in crate::network::platform) socket: Arc<HostSocketInner>,
    pub(in crate::network::platform) overlapped: Box<WsaOverlapped>,
    pub(in crate::network::platform) submitted: bool,
    pub(in crate::network::platform) completed: bool,
}

#[cfg(windows)]
impl WindowsPendingConnectEx {
    pub(in crate::network::platform) fn new(
        socket: Arc<HostSocketInner>,
        overlapped: WsaOverlapped,
    ) -> Self {
        Self {
            socket,
            overlapped: Box::new(overlapped),
            submitted: false,
            completed: false,
        }
    }

    pub(in crate::network::platform) fn overlapped_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        (&mut *self.overlapped as *mut WsaOverlapped).cast()
    }

    pub(in crate::network::platform) fn overlapped_token(&self) -> usize {
        (&*self.overlapped as *const WsaOverlapped) as usize
    }
}

#[cfg(windows)]
impl Drop for WindowsPendingConnectEx {
    fn drop(&mut self) {
        if self.submitted && !self.completed {
            let overlapped = self.overlapped_mut_ptr();
            unsafe {
                // SAFETY: The socket and OVERLAPPED are owned by this pending operation.
                let _ = CancelIoEx(self.socket.raw as crate::windows::Handle, overlapped);
                let mut bytes_transferred = 0u32;
                let mut flags = 0u32;
                let _ = WSAGetOverlappedResult(
                    self.socket.raw,
                    overlapped,
                    &mut bytes_transferred,
                    TRUE,
                    &mut flags,
                );
            }
        }
        crate::windows::close_handle(self.overlapped.event);
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub(in crate::network::platform) struct WindowsPendingSocketIo {
    socket: Arc<HostSocketInner>,
    pub(in crate::network::platform) overlapped: Box<WsaOverlapped>,
    pub(in crate::network::platform) submitted: bool,
    pub(in crate::network::platform) completed: bool,
}

#[cfg(windows)]
impl WindowsPendingSocketIo {
    pub(in crate::network::platform) fn new(
        socket: Arc<HostSocketInner>,
        overlapped: WsaOverlapped,
    ) -> Self {
        Self {
            socket,
            overlapped: Box::new(overlapped),
            submitted: false,
            completed: false,
        }
    }

    pub(in crate::network::platform) fn overlapped_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        (&mut *self.overlapped as *mut WsaOverlapped).cast()
    }

    pub(in crate::network::platform) fn overlapped_token(&self) -> usize {
        (&*self.overlapped as *const WsaOverlapped) as usize
    }
}

#[cfg(windows)]
impl Drop for WindowsPendingSocketIo {
    fn drop(&mut self) {
        if self.submitted && !self.completed {
            let overlapped = self.overlapped_mut_ptr();
            unsafe {
                // SAFETY: The socket and OVERLAPPED are owned by this pending operation.
                let _ = CancelIoEx(self.socket.raw as crate::windows::Handle, overlapped);
                let mut bytes_transferred = 0u32;
                let mut flags = 0u32;
                let _ = WSAGetOverlappedResult(
                    self.socket.raw,
                    overlapped,
                    &mut bytes_transferred,
                    TRUE,
                    &mut flags,
                );
            }
        }
        crate::windows::close_handle(self.overlapped.event);
    }
}
