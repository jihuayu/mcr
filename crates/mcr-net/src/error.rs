use std::fmt;

use mcr_win::{HostError, HostErrorKind};

use crate::types::SocketId;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostIoError {
    errno: LinuxErrno,
    reason: String,
}

impl HostIoError {
    #[must_use]
    pub fn new(errno: LinuxErrno, reason: impl Into<String>) -> Self {
        Self {
            errno,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn unsupported() -> Self {
        Self {
            errno: LinuxErrno::FunctionNotImplemented,
            reason: "host socket transport is not supported".to_owned(),
        }
    }

    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        self.errno
    }
}

impl fmt::Display for HostIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.errno, self.reason)
    }
}

impl std::error::Error for HostIoError {}

impl From<HostError> for HostIoError {
    fn from(error: HostError) -> Self {
        Self {
            errno: host_error_errno(error.kind()),
            reason: error.to_string(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketOperation {
    Accept,
    AllocateSocketId,
    Bind,
    Close,
    Connect,
    CreateSocket,
    GetSocketOption,
    Listen,
    Poll,
    Recv,
    RecvMsg,
    Send,
    SendMsg,
    SetSocketOption,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxErrno {
    AlreadyConnected,
    BadFileDescriptor,
    BrokenPipe,
    ConnectionRefused,
    ConnectionReset,
    FunctionNotImplemented,
    InvalidArgument,
    NotConnected,
    OperationAlreadyInProgress,
    OperationInProgress,
    OperationWouldBlock,
    OperationNotSupported,
    AddressFamilyNotSupported,
    ProtocolNotAvailable,
    ProtocolNotSupported,
    ProtocolWrongTypeForSocket,
    Shutdown,
    SocketTypeNotSupported,
    TimedOut,
}

impl LinuxErrno {
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::AlreadyConnected => 106,
            Self::BadFileDescriptor => 9,
            Self::BrokenPipe => 32,
            Self::ConnectionRefused => 111,
            Self::ConnectionReset => 104,
            Self::FunctionNotImplemented => 38,
            Self::InvalidArgument => 22,
            Self::OperationNotSupported => 95,
            Self::NotConnected => 107,
            Self::OperationAlreadyInProgress => 114,
            Self::OperationInProgress => 115,
            Self::OperationWouldBlock => 11,
            Self::ProtocolWrongTypeForSocket => 91,
            Self::ProtocolNotAvailable => 92,
            Self::ProtocolNotSupported => 93,
            Self::SocketTypeNotSupported => 94,
            Self::AddressFamilyNotSupported => 97,
            Self::Shutdown => 108,
            Self::TimedOut => 110,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocketError {
    InvalidInput {
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    },
    Unsupported {
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    },
    InvalidState {
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    },
    WouldBlock {
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    },
    HostIo {
        errno: LinuxErrno,
        reason: String,
    },
    BadSocket {
        id: SocketId,
    },
}

impl SocketError {
    pub(crate) fn invalid_input(
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    ) -> Self {
        Self::InvalidInput {
            operation,
            errno,
            reason,
        }
    }

    pub(crate) fn unsupported(
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    ) -> Self {
        Self::Unsupported {
            operation,
            errno,
            reason,
        }
    }

    pub(crate) fn invalid_state(
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    ) -> Self {
        Self::InvalidState {
            operation,
            errno,
            reason,
        }
    }

    pub(crate) fn would_block(operation: SocketOperation, reason: &'static str) -> Self {
        Self::WouldBlock {
            operation,
            errno: LinuxErrno::OperationWouldBlock,
            reason,
        }
    }

    pub(crate) fn with_errno(mut self, errno: LinuxErrno) -> Self {
        match &mut self {
            Self::InvalidInput { errno: current, .. }
            | Self::Unsupported { errno: current, .. }
            | Self::InvalidState { errno: current, .. }
            | Self::WouldBlock { errno: current, .. }
            | Self::HostIo { errno: current, .. } => *current = errno,
            Self::BadSocket { .. } => {}
        }
        self
    }

    pub(crate) fn from_host(error: HostIoError) -> Self {
        Self::HostIo {
            errno: error.linux_errno(),
            reason: error.to_string(),
        }
    }

    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        match self {
            Self::InvalidInput { errno, .. }
            | Self::Unsupported { errno, .. }
            | Self::InvalidState { errno, .. }
            | Self::WouldBlock { errno, .. }
            | Self::HostIo { errno, .. } => *errno,
            Self::BadSocket { .. } => LinuxErrno::BadFileDescriptor,
        }
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput {
                operation, reason, ..
            } => write!(f, "{operation:?}: invalid input: {reason}"),
            Self::Unsupported {
                operation, reason, ..
            } => write!(f, "{operation:?}: unsupported: {reason}"),
            Self::InvalidState {
                operation, reason, ..
            } => write!(f, "{operation:?}: invalid state: {reason}"),
            Self::WouldBlock {
                operation, reason, ..
            } => write!(f, "{operation:?}: would block: {reason}"),
            Self::HostIo { reason, .. } => write!(f, "host socket I/O failed: {reason}"),
            Self::BadSocket { id } => write!(f, "bad socket id {id}"),
        }
    }
}

impl std::error::Error for SocketError {}
const fn host_error_errno(kind: HostErrorKind) -> LinuxErrno {
    match kind {
        HostErrorKind::InvalidInput => LinuxErrno::InvalidArgument,
        HostErrorKind::Interrupted | HostErrorKind::WouldBlock => LinuxErrno::OperationWouldBlock,
        HostErrorKind::TimedOut => LinuxErrno::TimedOut,
        HostErrorKind::BrokenPipe => LinuxErrno::BrokenPipe,
        HostErrorKind::Unsupported => LinuxErrno::FunctionNotImplemented,
        HostErrorKind::Unavailable => LinuxErrno::ConnectionRefused,
        HostErrorKind::AccessDenied
        | HostErrorKind::NotFound
        | HostErrorKind::AlreadyExists
        | HostErrorKind::OutOfMemory
        | HostErrorKind::Poisoned
        | HostErrorKind::Other => LinuxErrno::ConnectionReset,
    }
}
