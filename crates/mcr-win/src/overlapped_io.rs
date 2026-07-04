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
    fn new(direction: HostIoDirection, bytes_transferred: usize, buffer: Vec<u8>) -> Self {
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
    fn new(direction: HostIoDirection, error: HostError, buffer: Vec<u8>) -> Self {
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
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HostIoSubmission {
    Completed(HostIoCompletion),
    Pending(PendingHostIo),
    Fallback(HostIoFallback),
}

impl HostIoSubmission {
    /// Completes an immediate operation or runs the synchronous fallback.
    ///
    /// Pending operations must be completed by the future overlapped backend.
    pub fn complete_or_fallback(self, file: &HostFile) -> HostIoResult {
        match self {
            Self::Completed(completion) => Ok(completion),
            Self::Fallback(fallback) => fallback.complete(file),
            Self::Pending(pending) => pending.unsupported_completion(),
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
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PendingHostIo {
    direction: HostIoDirection,
    cancel_requested: bool,
    buffer: Vec<u8>,
}

impl PendingHostIo {
    #[cfg(test)]
    fn new(direction: HostIoDirection, buffer: Vec<u8>) -> Self {
        Self {
            direction,
            cancel_requested: false,
            buffer,
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
        &self.buffer
    }

    /// Requests cancellation without releasing the completion record or buffer.
    pub fn request_cancel(&mut self) -> bool {
        if self.cancel_requested {
            return false;
        }
        self.cancel_requested = true;
        true
    }

    /// Drains a host-aborted operation after cancellation or close.
    pub fn drain_cancelled(self) -> HostIoResult {
        Err(HostIoFailure::new(
            self.direction,
            HostError::new(self.direction.operation(), HostErrorKind::Interrupted),
            self.buffer,
        ))
    }

    fn unsupported_completion(self) -> HostIoResult {
        Err(HostIoFailure::new(
            self.direction,
            HostError::unsupported(self.direction.operation()),
            self.buffer,
        ))
    }

    #[cfg(test)]
    fn complete(self, bytes_transferred: usize) -> HostIoResult {
        if bytes_transferred > self.buffer.len() {
            return Err(HostIoFailure::new(
                self.direction,
                HostError::invalid_input(self.direction.operation()),
                self.buffer,
            ));
        }
        Ok(HostIoCompletion::new(
            self.direction,
            bytes_transferred,
            self.buffer,
        ))
    }
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
