use crate::error::{HostError, HostErrorKind, HostOperation};
use crate::files::HostFile;

/// Direction for a host file-like I/O operation.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostIoDirection {
    Read,
    Write,
}

impl HostIoDirection {
    /// Returns the adapter operation used for host error reporting.
    pub const fn operation(self) -> HostOperation {
        match self {
            Self::Read => HostOperation::ReadFile,
            Self::Write => HostOperation::WriteFile,
        }
    }
}

/// Reason an operation stayed on the synchronous backend.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostIoFallbackReason {
    /// The current host handle was opened for the existing synchronous backend.
    SynchronousBackend,
}

/// Result type for host I/O submissions that must return their owned buffer.
pub type HostIoResult = Result<HostIoCompletion, HostIoFailure>;

/// Completion of a host file-like I/O operation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostIoCompletion {
    direction: HostIoDirection,
    bytes_transferred: usize,
    buffer: Vec<u8>,
}

impl HostIoCompletion {
    pub(crate) fn new(
        direction: HostIoDirection,
        bytes_transferred: usize,
        buffer: Vec<u8>,
    ) -> Self {
        Self {
            direction,
            bytes_transferred,
            buffer,
        }
    }

    /// Returns whether this was a read or write operation.
    pub const fn direction(&self) -> HostIoDirection {
        self.direction
    }

    /// Returns the host-reported byte count.
    pub const fn bytes_transferred(&self) -> usize {
        self.bytes_transferred
    }

    /// Returns the operation buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Consumes the completion and returns the operation buffer.
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }
}

/// Failed host file-like I/O operation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostIoFailure {
    direction: HostIoDirection,
    error: HostError,
    buffer: Vec<u8>,
}

impl HostIoFailure {
    pub(crate) fn new(direction: HostIoDirection, error: HostError, buffer: Vec<u8>) -> Self {
        Self {
            direction,
            error,
            buffer,
        }
    }

    /// Returns whether this was a read or write operation.
    pub const fn direction(&self) -> HostIoDirection {
        self.direction
    }

    /// Returns the host adapter error without assigning Linux errno.
    pub const fn error(&self) -> &HostError {
        &self.error
    }

    /// Returns the operation buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Consumes the failure and returns its error plus operation buffer.
    pub fn into_parts(self) -> (HostError, Vec<u8>) {
        (self.error, self.buffer)
    }
}

/// Submission returned by the host file-like I/O adapter.
#[derive(Debug)]
pub enum HostIoSubmission {
    Completed(HostIoCompletion),
    Failed(HostIoFailure),
    Pending(PendingHostIo),
    Fallback(HostIoFallback),
}

impl HostIoSubmission {
    /// Completes an immediate operation or runs the synchronous fallback.
    pub fn complete_or_fallback(self, file: &HostFile) -> HostIoResult {
        match self {
            Self::Completed(completion) => Ok(completion),
            Self::Failed(failure) => Err(failure),
            Self::Fallback(fallback) => fallback.complete(file),
            Self::Pending(pending) => pending.wait_complete(),
        }
    }
}

/// Synchronous fallback for a host file-like I/O operation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostIoFallback {
    direction: HostIoDirection,
    reason: HostIoFallbackReason,
    buffer: Vec<u8>,
}

impl HostIoFallback {
    pub(crate) fn new(
        direction: HostIoDirection,
        reason: HostIoFallbackReason,
        buffer: Vec<u8>,
    ) -> Self {
        Self {
            direction,
            reason,
            buffer,
        }
    }

    /// Returns whether this was a read or write operation.
    pub const fn direction(&self) -> HostIoDirection {
        self.direction
    }

    /// Returns why the operation stayed on the synchronous backend.
    pub const fn reason(&self) -> HostIoFallbackReason {
        self.reason
    }

    /// Returns the fallback-owned buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Executes this operation against the synchronous file adapter.
    pub fn complete(self, file: &HostFile) -> HostIoResult {
        let Self {
            direction, buffer, ..
        } = self;
        match direction {
            HostIoDirection::Read => {
                let mut buffer = buffer;
                match file.read(&mut buffer) {
                    Ok(bytes_transferred) => {
                        Ok(HostIoCompletion::new(direction, bytes_transferred, buffer))
                    }
                    Err(error) => Err(HostIoFailure::new(direction, error, buffer)),
                }
            }
            HostIoDirection::Write => match file.write(&buffer) {
                Ok(bytes_transferred) => {
                    Ok(HostIoCompletion::new(direction, bytes_transferred, buffer))
                }
                Err(error) => Err(HostIoFailure::new(direction, error, buffer)),
            },
        }
    }
}

/// Pending host file-like I/O operation.
#[derive(Debug)]
pub struct PendingHostIo {
    direction: HostIoDirection,
    cancel_requested: bool,
    buffer: Option<Vec<u8>>,
    platform: Option<PendingHostIoPlatform>,
}

impl PendingHostIo {
    #[cfg(test)]
    fn new(direction: HostIoDirection, buffer: Vec<u8>) -> Self {
        Self {
            direction,
            cancel_requested: false,
            buffer: Some(buffer),
            platform: None,
        }
    }

    #[cfg(windows)]
    pub(crate) fn from_windows_pending(
        direction: HostIoDirection,
        platform: WindowsPendingHostIo,
        buffer: Vec<u8>,
    ) -> Self {
        Self {
            direction,
            cancel_requested: false,
            buffer: Some(buffer),
            platform: Some(platform),
        }
    }

    /// Returns whether this was a read or write operation.
    pub const fn direction(&self) -> HostIoDirection {
        self.direction
    }

    /// Returns whether cancellation has been requested.
    pub const fn cancel_requested(&self) -> bool {
        self.cancel_requested
    }

    /// Returns the pending operation buffer.
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_deref().unwrap_or(&[])
    }

    /// Requests cancellation without releasing the completion record or buffer.
    pub fn request_cancel(&mut self) -> bool {
        if self.cancel_requested {
            return false;
        }
        self.cancel_requested = true;
        self.request_cancel_platform();
        true
    }

    /// Polls the host completion source without blocking.
    pub fn poll_complete(mut self) -> HostIoSubmission {
        match self.try_complete_platform() {
            PendingPoll::Pending => HostIoSubmission::Pending(self),
            PendingPoll::Ready(result) => result.into(),
        }
    }

    /// Waits for the host completion source and returns the owned buffer.
    pub fn wait_complete(mut self) -> HostIoResult {
        match self.wait_complete_platform() {
            PendingPoll::Ready(result) => result,
            PendingPoll::Pending => self.unsupported_completion(),
        }
    }

    /// Drains a host-aborted operation after cancellation or close.
    pub fn drain_cancelled(self) -> HostIoResult {
        if self.platform.is_some() {
            return self.wait_complete();
        }

        Err(HostIoFailure::new(
            self.direction,
            HostError::new(self.direction.operation(), HostErrorKind::Interrupted),
            self.into_buffer(),
        ))
    }

    fn unsupported_completion(mut self) -> HostIoResult {
        Err(HostIoFailure::new(
            self.direction,
            HostError::unsupported(self.direction.operation()),
            self.buffer.take().unwrap_or_default(),
        ))
    }

    #[cfg(test)]
    fn complete(mut self, bytes_transferred: usize) -> HostIoResult {
        let buffer = self.buffer.take().unwrap_or_default();
        if bytes_transferred > buffer.len() {
            return Err(HostIoFailure::new(
                self.direction,
                HostError::invalid_input(self.direction.operation()),
                buffer,
            ));
        }
        Ok(HostIoCompletion::new(
            self.direction,
            bytes_transferred,
            buffer,
        ))
    }

    fn into_buffer(mut self) -> Vec<u8> {
        self.buffer.take().unwrap_or_default()
    }

    fn request_cancel_platform(&self) {
        if let Some(platform) = self.platform.as_ref() {
            platform.request_cancel();
        }
    }

    fn try_complete_platform(&mut self) -> PendingPoll {
        self.complete_platform(crate::windows::FALSE)
    }

    fn wait_complete_platform(&mut self) -> PendingPoll {
        self.complete_platform(TRUE)
    }

    fn take_unsupported_completion(&mut self) -> HostIoResult {
        Err(HostIoFailure::new(
            self.direction,
            HostError::unsupported(self.direction.operation()),
            self.buffer.take().unwrap_or_default(),
        ))
    }

    fn complete_platform(&mut self, wait: crate::windows::Bool) -> PendingPoll {
        let Some(platform) = self.platform.as_mut() else {
            return PendingPoll::Ready(self.take_unsupported_completion());
        };

        let mut bytes_transferred = 0;
        let completed = unsafe {
            // SAFETY: `platform` owns both the duplicated handle and the OVERLAPPED record.
            GetOverlappedResult(
                platform.handle(),
                platform.overlapped_mut_ptr(),
                &mut bytes_transferred,
                wait,
            )
        };

        if completed == crate::windows::FALSE {
            let error = crate::windows::last_error();
            if error == ERROR_IO_INCOMPLETE {
                return PendingPoll::Pending;
            }
            let buffer = self.buffer.take().unwrap_or_default();
            self.platform.take();
            if self.direction == HostIoDirection::Read && error == ERROR_HANDLE_EOF {
                return PendingPoll::Ready(Ok(HostIoCompletion::new(self.direction, 0, buffer)));
            }
            return PendingPoll::Ready(Err(HostIoFailure::new(
                self.direction,
                crate::error::windows_error(self.direction.operation(), error),
                buffer,
            )));
        }

        let buffer = self.buffer.take().unwrap_or_default();
        self.platform.take();
        PendingPoll::Ready(Ok(HostIoCompletion::new(
            self.direction,
            bytes_transferred as usize,
            buffer,
        )))
    }
}

impl From<HostIoResult> for HostIoSubmission {
    fn from(value: HostIoResult) -> Self {
        match value {
            Ok(completion) => Self::Completed(completion),
            Err(failure) => Self::Failed(failure),
        }
    }
}

impl Drop for PendingHostIo {
    fn drop(&mut self) {
        if let Some(mut platform) = self.platform.take() {
            platform.request_cancel();
            let mut bytes_transferred = 0;
            let _ = unsafe {
                // SAFETY: `platform` is still alive and owns the completion record.
                GetOverlappedResult(
                    platform.handle(),
                    platform.overlapped_mut_ptr(),
                    &mut bytes_transferred,
                    TRUE,
                )
            };
        }
    }
}

enum PendingPoll {
    Pending,
    Ready(HostIoResult),
}

type PendingHostIoPlatform = WindowsPendingHostIo;

#[derive(Debug)]
pub(crate) struct WindowsPendingHostIo {
    handle: crate::windows::Handle,
    overlapped: Box<WindowsOverlapped>,
}

impl WindowsPendingHostIo {
    pub(crate) fn new(handle: crate::windows::Handle, overlapped: WindowsOverlapped) -> Self {
        Self {
            handle,
            overlapped: Box::new(overlapped),
        }
    }

    pub(crate) const fn handle(&self) -> crate::windows::Handle {
        self.handle
    }

    pub(crate) fn overlapped_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        (&mut *self.overlapped as *mut WindowsOverlapped).cast()
    }

    fn request_cancel(&self) {
        let overlapped = (&*self.overlapped as *const WindowsOverlapped).cast_mut();
        unsafe {
            // SAFETY: The duplicated handle and OVERLAPPED record are owned by this pending op.
            let _ = CancelIoEx(self.handle, overlapped.cast());
        }
    }
}

impl Drop for WindowsPendingHostIo {
    fn drop(&mut self) {
        crate::windows::close_handle(self.overlapped.event);
        crate::windows::close_handle(self.handle);
    }
}

#[repr(C)]
#[derive(Debug)]
pub(crate) struct WindowsOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: crate::windows::Handle,
}

impl WindowsOverlapped {
    pub(crate) const fn new(offset: u64, event: crate::windows::Handle) -> Self {
        Self {
            internal: 0,
            internal_high: 0,
            offset: offset as u32,
            offset_high: (offset >> 32) as u32,
            event,
        }
    }
}

const TRUE: crate::windows::Bool = 1;
const ERROR_IO_INCOMPLETE: u32 = 996;
const ERROR_HANDLE_EOF: u32 = 38;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetOverlappedResult(
        file: crate::windows::Handle,
        overlapped: *mut std::ffi::c_void,
        number_of_bytes_transferred: *mut u32,
        wait: crate::windows::Bool,
    ) -> crate::windows::Bool;
    fn CancelIoEx(
        file: crate::windows::Handle,
        overlapped: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{HostIoDirection, HostIoFallbackReason, HostIoSubmission, PendingHostIo};
    use crate::{FileAccess, FileCreation, FileOptions, HostErrorKind, HostFile, HostOperation};

    #[test]
    fn overlapped_submission_uses_synchronous_fallback_without_replacing_backend() {
        let path = temp_path("overlapped-fallback");
        let _ = std::fs::remove_file(&path);

        let file = HostFile::open(
            &path,
            FileOptions::new(FileAccess::ReadWrite, FileCreation::CreateNew),
        )
        .unwrap();
        let write = expect_fallback(file.submit_overlapped_write(b"abc".to_vec()));
        assert_eq!(write.direction(), HostIoDirection::Write);
        assert_eq!(write.reason(), HostIoFallbackReason::SynchronousBackend);
        let completion = write.complete(&file).unwrap();
        assert_eq!(completion.bytes_transferred(), 3);
        assert_eq!(completion.buffer(), b"abc");
        file.flush().unwrap();
        drop(file);

        let file = HostFile::open(
            &path,
            FileOptions::new(FileAccess::Read, FileCreation::OpenExisting),
        )
        .unwrap();
        let read = expect_fallback(file.submit_overlapped_read(vec![0; 3]));
        assert_eq!(read.direction(), HostIoDirection::Read);
        let completion = read.complete(&file).unwrap();
        assert_eq!(completion.bytes_transferred(), 3);
        assert_eq!(completion.buffer(), b"abc");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn synchronous_fallback_failure_preserves_buffer_and_host_error_shape() {
        let path = temp_path("overlapped-fallback-error");
        let _ = std::fs::remove_file(&path);

        let file = HostFile::open(
            &path,
            FileOptions::new(FileAccess::ReadWrite, FileCreation::CreateNew),
        )
        .unwrap();
        file.write(b"seed").unwrap();
        drop(file);

        let file = HostFile::open(
            &path,
            FileOptions::new(FileAccess::Read, FileCreation::OpenExisting),
        )
        .unwrap();
        let failure = file
            .submit_overlapped_write(b"kept".to_vec())
            .complete_or_fallback(&file)
            .unwrap_err();
        assert_eq!(failure.direction(), HostIoDirection::Write);
        assert_eq!(failure.error().operation(), HostOperation::WriteFile);
        assert_ne!(failure.error().kind(), HostErrorKind::Unsupported);
        assert_eq!(failure.buffer(), b"kept");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn pending_cancel_keeps_buffer_until_drained_and_maps_interrupted() {
        let mut pending = PendingHostIo::new(HostIoDirection::Read, vec![1, 2, 3]);

        assert_eq!(pending.buffer(), &[1, 2, 3]);
        assert!(pending.request_cancel());
        assert!(!pending.request_cancel());
        assert!(pending.cancel_requested());
        assert_eq!(pending.buffer(), &[1, 2, 3]);

        let failure = pending.drain_cancelled().unwrap_err();
        assert_eq!(failure.direction(), HostIoDirection::Read);
        assert_eq!(failure.error().operation(), HostOperation::ReadFile);
        assert_eq!(failure.error().kind(), HostErrorKind::Interrupted);
        let (_error, buffer) = failure.into_parts();
        assert_eq!(buffer, vec![1, 2, 3]);
    }

    #[test]
    fn pending_completion_can_win_after_cancel_request() {
        let mut pending = PendingHostIo::new(HostIoDirection::Write, b"abcd".to_vec());

        assert!(pending.request_cancel());
        let completion = pending.complete(2).unwrap();

        assert_eq!(completion.direction(), HostIoDirection::Write);
        assert_eq!(completion.bytes_transferred(), 2);
        assert_eq!(completion.buffer(), b"abcd");
    }

    fn expect_fallback(submission: HostIoSubmission) -> super::HostIoFallback {
        match submission {
            HostIoSubmission::Fallback(fallback) => fallback,
            other => panic!("expected synchronous fallback, got {other:?}"),
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mcr-win-{label}-{}-{nanos}", std::process::id()))
    }
}
