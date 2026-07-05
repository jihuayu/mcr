use crate::error::{HostError, HostOperation};

#[cfg(windows)]
use super::platform::{Guid, WSAID_ACCEPTEX, WSAID_CONNECTEX};
use super::platform::{HostSocket, PendingHostAcceptEx, PendingHostConnectEx, PendingHostSocketIo};

/// Host address family for socket creation.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AddressFamily {
    Inet,
    Inet6,
    Unix,
}

/// Host socket type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketKind {
    Stream,
    Datagram,
}

/// Host socket protocol.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketProtocol {
    Default,
    Tcp,
    Udp,
}

/// Host socket shutdown direction.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostShutdown {
    Read,
    Write,
    Both,
}

/// Supported socket options surfaced by the host adapter.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostSocketOptionName {
    ReuseAddress,
    KeepAlive,
    SendBufferSize,
    ReceiveBufferSize,
    SocketError,
    SocketType,
    TcpNoDelay,
}

/// Supported socket option values.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostSocketOptionValue {
    Bool(bool),
    Int(i32),
    Kind(SocketKind),
}

/// Socket readiness events used by the host networking adapter.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct SocketEvents {
    pub readable: bool,
    pub writable: bool,
    pub priority: bool,
    pub error: bool,
    pub hang_up: bool,
    pub invalid: bool,
}

/// Host socket completion classes that can wake guest readiness waiters.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketCompletionKind {
    Accept,
    Connect,
    Receive,
    Send,
    PeerClosed,
    Closed,
    Error,
}

impl SocketCompletionKind {
    /// Maps a host completion into the level-trigger readiness bits visible to
    /// `select`, `poll`, and `epoll`.
    pub const fn readiness(self) -> SocketEvents {
        match self {
            Self::Accept | Self::Receive => SocketEvents {
                readable: true,
                writable: false,
                priority: false,
                error: false,
                hang_up: false,
                invalid: false,
            },
            Self::Connect | Self::Send => SocketEvents {
                readable: false,
                writable: true,
                priority: false,
                error: false,
                hang_up: false,
                invalid: false,
            },
            Self::PeerClosed => SocketEvents {
                readable: true,
                writable: false,
                priority: false,
                error: false,
                hang_up: true,
                invalid: false,
            },
            Self::Closed => SocketEvents {
                readable: false,
                writable: false,
                priority: false,
                error: true,
                hang_up: true,
                invalid: false,
            },
            Self::Error => SocketEvents {
                readable: false,
                writable: false,
                priority: false,
                error: true,
                hang_up: false,
                invalid: false,
            },
        }
    }
}

/// Winsock extension fast paths that can feed the socket readiness seam.
///
/// The host adapter owns extension-function lookup, overlapped operation
/// lifetime, context update, and cancellation. Higher layers only observe the
/// corresponding completion class and keep Linux socket state unchanged.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketFastPathKind {
    AcceptEx,
    ConnectEx,
}

impl SocketFastPathKind {
    /// Completion kind emitted when this fast path has progressed enough to
    /// wake guest readiness waiters.
    pub const fn completion_kind(self) -> SocketCompletionKind {
        match self {
            Self::AcceptEx => SocketCompletionKind::Accept,
            Self::ConnectEx => SocketCompletionKind::Connect,
        }
    }

    #[cfg(windows)]
    pub(super) const fn extension_guid(self) -> Guid {
        match self {
            Self::AcceptEx => WSAID_ACCEPTEX,
            Self::ConnectEx => WSAID_CONNECTEX,
        }
    }
}

impl SocketEvents {
    /// Read readiness interest.
    pub const fn read() -> Self {
        Self {
            readable: true,
            writable: false,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        }
    }

    /// Write readiness interest.
    pub const fn write() -> Self {
        Self {
            readable: false,
            writable: true,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        }
    }

    /// Read and write readiness interest.
    pub const fn read_write() -> Self {
        Self {
            readable: true,
            writable: true,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        }
    }

    /// Returns whether no readiness flags are set.
    pub const fn is_empty(self) -> bool {
        !self.readable
            && !self.writable
            && !self.priority
            && !self.error
            && !self.hang_up
            && !self.invalid
    }
}

/// Socket poll entry.
#[derive(Debug)]
pub struct SocketPoll<'a> {
    pub socket: &'a HostSocket,
    pub interest: SocketEvents,
    pub readiness: SocketEvents,
}

impl<'a> SocketPoll<'a> {
    /// Creates a socket poll entry with no readiness set.
    pub const fn new(socket: &'a HostSocket, interest: SocketEvents) -> Self {
        Self {
            socket,
            interest,
            readiness: SocketEvents {
                readable: false,
                writable: false,
                priority: false,
                error: false,
                hang_up: false,
                invalid: false,
            },
        }
    }
}

/// Direction for an overlapped host socket buffer operation.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostSocketIoDirection {
    Receive,
    Send,
}

impl HostSocketIoDirection {
    pub(super) const fn operation(self) -> HostOperation {
        match self {
            Self::Receive => HostOperation::RecvSocket,
            Self::Send => HostOperation::SendSocket,
        }
    }
}

/// Completion of an overlapped host socket buffer operation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostSocketIoCompletion {
    direction: HostSocketIoDirection,
    bytes_transferred: usize,
    buffer: Vec<u8>,
}

impl HostSocketIoCompletion {
    pub(super) fn new(
        direction: HostSocketIoDirection,
        bytes_transferred: usize,
        buffer: Vec<u8>,
    ) -> Self {
        Self {
            direction,
            bytes_transferred,
            buffer,
        }
    }

    #[must_use]
    pub const fn direction(&self) -> HostSocketIoDirection {
        self.direction
    }

    #[must_use]
    pub const fn bytes_transferred(&self) -> usize {
        self.bytes_transferred
    }

    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    #[must_use]
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }
}

/// Failed overlapped host socket buffer operation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostSocketIoFailure {
    direction: HostSocketIoDirection,
    error: HostError,
    buffer: Vec<u8>,
}

impl HostSocketIoFailure {
    pub(super) fn new(direction: HostSocketIoDirection, error: HostError, buffer: Vec<u8>) -> Self {
        Self {
            direction,
            error,
            buffer,
        }
    }

    #[must_use]
    pub const fn direction(&self) -> HostSocketIoDirection {
        self.direction
    }

    #[must_use]
    pub const fn error(&self) -> &HostError {
        &self.error
    }

    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    #[must_use]
    pub fn into_parts(self) -> (HostError, Vec<u8>) {
        (self.error, self.buffer)
    }
}

pub type HostSocketIoResult = Result<HostSocketIoCompletion, HostSocketIoFailure>;

/// Submission returned by the overlapped host socket adapter.
#[derive(Debug)]
pub enum HostSocketIoSubmission {
    Completed(HostSocketIoCompletion),
    Failed(HostSocketIoFailure),
    Pending(PendingHostSocketIo),
}

impl From<HostSocketIoResult> for HostSocketIoSubmission {
    fn from(value: HostSocketIoResult) -> Self {
        match value {
            Ok(completion) => Self::Completed(completion),
            Err(failure) => Self::Failed(failure),
        }
    }
}

/// Submission returned by the host `ConnectEx` adapter.
#[derive(Debug)]
pub enum HostConnectExSubmission {
    Failed(HostError),
    Pending(PendingHostConnectEx),
}

/// Submission returned by the host `AcceptEx` adapter.
#[derive(Debug)]
pub enum HostAcceptExSubmission {
    Failed(HostError),
    Pending(PendingHostAcceptEx),
}
