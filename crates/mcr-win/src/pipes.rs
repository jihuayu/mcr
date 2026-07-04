use crate::error::{HostOperation, HostResult};
use crate::files::HostFile;

/// Host-owned overlapped byte pipe pair.
#[derive(Debug)]
pub struct HostPipePair {
    reader: HostFile,
    writer: HostFile,
}

impl HostPipePair {
    /// Creates a byte pipe pair whose handles support overlapped I/O.
    pub fn create_overlapped() -> HostResult<Self> {
        create_overlapped_pipe_pair_platform()
    }

    #[must_use]
    pub const fn reader(&self) -> &HostFile {
        &self.reader
    }

    #[must_use]
    pub const fn writer(&self) -> &HostFile {
        &self.writer
    }
}

#[cfg(not(windows))]
fn create_overlapped_pipe_pair_platform() -> HostResult<HostPipePair> {
    Err(crate::error::HostError::unsupported(
        HostOperation::OpenFile,
    ))
}

#[cfg(windows)]
fn create_overlapped_pipe_pair_platform() -> HostResult<HostPipePair> {
    let name = unique_pipe_name();
    let name_wide = path_to_wide(&name);
    let reader = unsafe {
        // SAFETY: `name_wide` is a null-terminated UTF-16 pipe name.
        CreateNamedPipeW(
            name_wide.as_ptr(),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            DEFAULT_PIPE_BUFFER_SIZE,
            DEFAULT_PIPE_BUFFER_SIZE,
            0,
            std::ptr::null_mut(),
        )
    };
    if reader == crate::windows::INVALID_HANDLE_VALUE {
        return Err(crate::error::last_windows_error(HostOperation::OpenFile));
    }

    let writer = unsafe {
        // SAFETY: `name_wide` is a null-terminated UTF-16 pipe name.
        CreateFileW(
            name_wide.as_ptr(),
            GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if writer == crate::windows::INVALID_HANDLE_VALUE {
        crate::windows::close_handle(reader);
        return Err(crate::error::last_windows_error(HostOperation::OpenFile));
    }

    let connected = unsafe {
        // SAFETY: `reader` is a named-pipe server handle.
        ConnectNamedPipe(reader, std::ptr::null_mut())
    };
    if connected == crate::windows::FALSE {
        let error = crate::windows::last_error();
        if error != ERROR_PIPE_CONNECTED {
            crate::windows::close_handle(writer);
            crate::windows::close_handle(reader);
            return Err(crate::error::windows_error(HostOperation::OpenFile, error));
        }
    }

    Ok(HostPipePair {
        reader: HostFile::from_windows_handle(reader, true),
        writer: HostFile::from_windows_handle(writer, true),
    })
}

#[cfg(windows)]
fn unique_pipe_name() -> String {
    static NEXT_PIPE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT_PIPE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(r"\\.\pipe\mcr-{}-{id}", std::process::id())
}

#[cfg(windows)]
fn path_to_wide(path: &str) -> Vec<u16> {
    path.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
const DEFAULT_PIPE_BUFFER_SIZE: u32 = 64 * 1024;
#[cfg(windows)]
const GENERIC_WRITE: u32 = 0x4000_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
#[cfg(windows)]
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
#[cfg(windows)]
const OPEN_EXISTING: u32 = 3;
#[cfg(windows)]
const PIPE_ACCESS_INBOUND: u32 = 0x0000_0001;
#[cfg(windows)]
const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
#[cfg(windows)]
const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
#[cfg(windows)]
const PIPE_WAIT: u32 = 0x0000_0000;
#[cfg(windows)]
const ERROR_PIPE_CONNECTED: u32 = 535;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buffer_size: u32,
        in_buffer_size: u32,
        default_timeout: u32,
        security_attributes: crate::windows::Handle,
    ) -> crate::windows::Handle;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: crate::windows::Handle,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: crate::windows::Handle,
    ) -> crate::windows::Handle;
    fn ConnectNamedPipe(
        named_pipe: crate::windows::Handle,
        overlapped: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;
}

#[cfg(test)]
mod tests {
    use super::HostPipePair;
    #[cfg(windows)]
    use crate::HostIoDirection;

    #[cfg(windows)]
    #[test]
    fn overlapped_pipe_pair_round_trips_bytes() {
        let pipe = HostPipePair::create_overlapped().unwrap();
        let write = pipe
            .writer()
            .submit_overlapped_write_at(0, b"pipe".to_vec());
        let write = match write.complete_or_fallback(pipe.writer()) {
            Ok(completion) => completion,
            Err(failure) => panic!("pipe write failed: {failure:?}"),
        };

        let read = pipe.reader().submit_overlapped_read_at(0, vec![0; 4]);
        let read = match read.complete_or_fallback(pipe.reader()) {
            Ok(completion) => completion,
            Err(failure) => panic!("pipe read failed: {failure:?}"),
        };

        assert_eq!(write.direction(), HostIoDirection::Write);
        assert_eq!(write.bytes_transferred(), 4);
        assert_eq!(read.direction(), HostIoDirection::Read);
        assert_eq!(read.bytes_transferred(), 4);
        assert_eq!(read.buffer(), b"pipe");
    }

    #[cfg(not(windows))]
    #[test]
    fn overlapped_pipe_pair_reports_unsupported_off_windows() {
        assert!(HostPipePair::create_overlapped().is_err());
    }
}
