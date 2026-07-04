use std::ffi::c_void;

pub(crate) type Bool = i32;
pub(crate) type Dword = u32;
pub(crate) type Handle = *mut c_void;
pub(crate) type Socket = usize;

pub(crate) const FALSE: Bool = 0;
pub(crate) const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
pub(crate) const INVALID_SOCKET: Socket = !0usize;
pub(crate) const SOCKET_ERROR: i32 = -1;

#[link(name = "kernel32")]
unsafe extern "system" {
    pub(crate) fn GetLastError() -> Dword;
    pub(crate) fn CloseHandle(handle: Handle) -> Bool;
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    pub(crate) fn WSAGetLastError() -> i32;
}

pub(crate) fn last_error() -> u32 {
    // SAFETY: `GetLastError` has no preconditions and returns the calling thread's error code.
    unsafe { GetLastError() }
}

pub(crate) fn wsa_last_error() -> i32 {
    // SAFETY: `WSAGetLastError` has no preconditions and returns the calling thread's WSA code.
    unsafe { WSAGetLastError() }
}

pub(crate) fn close_handle(handle: Handle) {
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        // SAFETY: The caller passes an owned Windows HANDLE and this function consumes it.
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}
