use std::time::Duration;

use crate::error::{HostOperation, HostResult};

/// Completion packet returned by a Windows I/O completion port.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HostIoCompletionPacket {
    bytes_transferred: u32,
    completion_key: usize,
    overlapped: usize,
    error_code: Option<u32>,
}

impl HostIoCompletionPacket {
    #[must_use]
    pub const fn bytes_transferred(self) -> u32 {
        self.bytes_transferred
    }

    #[must_use]
    pub const fn completion_key(self) -> usize {
        self.completion_key
    }

    #[must_use]
    pub const fn overlapped(self) -> usize {
        self.overlapped
    }

    #[must_use]
    pub const fn error_code(self) -> Option<u32> {
        self.error_code
    }
}

/// Host-owned Windows I/O completion port.
#[derive(Debug)]
pub struct HostIoCompletionPort {
    handle: crate::windows::Handle,
}

impl HostIoCompletionPort {
    /// Creates a standalone I/O completion port.
    pub fn new() -> HostResult<Self> {
        create_iocp_platform()
    }

    /// Associates a file-like raw Windows handle with this completion port.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid Windows handle that supports IOCP association,
    /// and it must remain valid according to the operation lifetime rules of
    /// the host API that owns it.
    pub unsafe fn associate_raw_handle(
        &self,
        handle: usize,
        completion_key: usize,
    ) -> HostResult<()> {
        associate_iocp_handle_platform(self, handle, completion_key)
    }

    /// Posts a synthetic completion packet.
    pub fn post(
        &self,
        bytes_transferred: u32,
        completion_key: usize,
        overlapped: usize,
    ) -> HostResult<()> {
        post_iocp_platform(self, bytes_transferred, completion_key, overlapped)
    }

    /// Waits for a completion packet, returning `None` on timeout.
    pub fn get(&self, timeout: Option<Duration>) -> HostResult<Option<HostIoCompletionPacket>> {
        get_iocp_platform(self, timeout)
    }
}

impl Drop for HostIoCompletionPort {
    fn drop(&mut self) {
        crate::windows::close_handle(self.handle);
    }
}

unsafe impl Send for HostIoCompletionPort {}

unsafe impl Sync for HostIoCompletionPort {}

fn create_iocp_platform() -> HostResult<HostIoCompletionPort> {
    let handle = unsafe {
        // SAFETY: INVALID_HANDLE_VALUE creates a new completion port; existing port is null.
        CreateIoCompletionPort(
            crate::windows::INVALID_HANDLE_VALUE,
            std::ptr::null_mut(),
            0,
            0,
        )
    };
    if handle.is_null() {
        return Err(crate::error::last_windows_error(
            HostOperation::CreateIoCompletionPort,
        ));
    }
    Ok(HostIoCompletionPort { handle })
}

fn associate_iocp_handle_platform(
    port: &HostIoCompletionPort,
    handle: usize,
    completion_key: usize,
) -> HostResult<()> {
    let associated = unsafe {
        // SAFETY: `port` owns a valid IOCP handle, and `handle` is a host handle supplied by mcr-win.
        CreateIoCompletionPort(
            handle as crate::windows::Handle,
            port.handle,
            completion_key,
            0,
        )
    };
    if associated.is_null() {
        return Err(crate::error::last_windows_error(
            HostOperation::CreateIoCompletionPort,
        ));
    }
    Ok(())
}

fn post_iocp_platform(
    port: &HostIoCompletionPort,
    bytes_transferred: u32,
    completion_key: usize,
    overlapped: usize,
) -> HostResult<()> {
    let ok = unsafe {
        // SAFETY: The completion port handle is valid; the overlapped value is an opaque token.
        PostQueuedCompletionStatus(
            port.handle,
            bytes_transferred,
            completion_key,
            overlapped as *mut std::ffi::c_void,
        )
    };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(
            HostOperation::PostIoCompletionPort,
        ));
    }
    Ok(())
}

fn get_iocp_platform(
    port: &HostIoCompletionPort,
    timeout: Option<Duration>,
) -> HostResult<Option<HostIoCompletionPacket>> {
    let mut bytes_transferred = 0;
    let mut completion_key = 0usize;
    let mut overlapped = std::ptr::null_mut();
    let ok = unsafe {
        // SAFETY: Output pointers reference initialized stack storage for this call.
        GetQueuedCompletionStatus(
            port.handle,
            &mut bytes_transferred,
            &mut completion_key,
            &mut overlapped,
            timeout_millis(timeout),
        )
    };
    if ok == crate::windows::FALSE {
        let error = crate::windows::last_error();
        if overlapped.is_null() {
            if error == WAIT_TIMEOUT {
                return Ok(None);
            }
            return Err(crate::error::windows_error(
                HostOperation::GetIoCompletionPort,
                error,
            ));
        }
        return Ok(Some(HostIoCompletionPacket {
            bytes_transferred,
            completion_key,
            overlapped: overlapped as usize,
            error_code: Some(error),
        }));
    }

    Ok(Some(HostIoCompletionPacket {
        bytes_transferred,
        completion_key,
        overlapped: overlapped as usize,
        error_code: None,
    }))
}

fn timeout_millis(timeout: Option<Duration>) -> u32 {
    match timeout {
        Some(timeout) => timeout.as_millis().min(u128::from(INFINITE - 1)) as u32,
        None => INFINITE,
    }
}

const INFINITE: u32 = 0xffff_ffff;
const WAIT_TIMEOUT: u32 = 258;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateIoCompletionPort(
        file_handle: crate::windows::Handle,
        existing_completion_port: crate::windows::Handle,
        completion_key: usize,
        number_of_concurrent_threads: u32,
    ) -> crate::windows::Handle;
    fn PostQueuedCompletionStatus(
        completion_port: crate::windows::Handle,
        bytes_transferred: u32,
        completion_key: usize,
        overlapped: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;
    fn GetQueuedCompletionStatus(
        completion_port: crate::windows::Handle,
        bytes_transferred: *mut u32,
        completion_key: *mut usize,
        overlapped: *mut *mut std::ffi::c_void,
        milliseconds: u32,
    ) -> crate::windows::Bool;
}

#[cfg(test)]
mod tests {
    use super::HostIoCompletionPort;
    use std::time::Duration;

    #[test]
    fn iocp_post_and_poll_round_trip() {
        let port = HostIoCompletionPort::new().unwrap();

        assert_eq!(port.get(Some(Duration::ZERO)).unwrap(), None);
        port.post(7, 11, 0x1234).unwrap();

        let packet = port.get(Some(Duration::from_secs(1))).unwrap().unwrap();
        assert_eq!(packet.bytes_transferred(), 7);
        assert_eq!(packet.completion_key(), 11);
        assert_eq!(packet.overlapped(), 0x1234);
        assert_eq!(packet.error_code(), None);
    }
}
