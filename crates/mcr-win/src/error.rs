use std::error::Error;
use std::fmt;
use std::io;

/// Result type used by host adapters.
pub type HostResult<T> = Result<T, HostError>;

/// Host operation that produced an adapter error.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostOperation {
    AllocateMemory,
    ProtectMemory,
    FreeMemory,
    OpenFile,
    ReadFile,
    WriteFile,
    FlushFile,
    MapFile,
    UnmapFile,
    DeleteFile,
    RenameFile,
    ReplaceFile,
    CreateHardLink,
    CreateSymlink,
    QueryClock,
    Sleep,
    FillRandom,
    WaitOnAddress,
    WakeByAddress,
    CreateIoCompletionPort,
    PostIoCompletionPort,
    GetIoCompletionPort,
    StartNetwork,
    OpenSocket,
    PollSockets,
    CloseSocket,
    ConnectSocket,
    BindSocket,
    ListenSocket,
    AcceptSocket,
    SendSocket,
    RecvSocket,
    SetSocketNonblocking,
    SetSocketOption,
    GetSocketOption,
    ShutdownSocket,
    QuerySocketAddress,
}

impl fmt::Display for HostOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operation = match self {
            Self::AllocateMemory => "allocate memory",
            Self::ProtectMemory => "protect memory",
            Self::FreeMemory => "free memory",
            Self::OpenFile => "open file",
            Self::ReadFile => "read file",
            Self::WriteFile => "write file",
            Self::FlushFile => "flush file",
            Self::MapFile => "map file",
            Self::UnmapFile => "unmap file",
            Self::DeleteFile => "delete file",
            Self::RenameFile => "rename file",
            Self::ReplaceFile => "replace file",
            Self::CreateHardLink => "create hard link",
            Self::CreateSymlink => "create symlink",
            Self::QueryClock => "query clock",
            Self::Sleep => "sleep",
            Self::FillRandom => "fill random bytes",
            Self::WaitOnAddress => "wait on address",
            Self::WakeByAddress => "wake by address",
            Self::CreateIoCompletionPort => "create I/O completion port",
            Self::PostIoCompletionPort => "post I/O completion",
            Self::GetIoCompletionPort => "get I/O completion",
            Self::StartNetwork => "start networking",
            Self::OpenSocket => "open socket",
            Self::PollSockets => "poll sockets",
            Self::CloseSocket => "close socket",
            Self::ConnectSocket => "connect socket",
            Self::BindSocket => "bind socket",
            Self::ListenSocket => "listen socket",
            Self::AcceptSocket => "accept socket",
            Self::SendSocket => "send socket",
            Self::RecvSocket => "receive socket",
            Self::SetSocketNonblocking => "set socket nonblocking mode",
            Self::SetSocketOption => "set socket option",
            Self::GetSocketOption => "get socket option",
            Self::ShutdownSocket => "shutdown socket",
            Self::QuerySocketAddress => "query socket address",
        };
        f.write_str(operation)
    }
}

/// Platform-neutral shape of a host failure.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostErrorKind {
    AccessDenied,
    NotFound,
    AlreadyExists,
    InvalidInput,
    Interrupted,
    TimedOut,
    WouldBlock,
    BrokenPipe,
    OutOfMemory,
    Unsupported,
    Poisoned,
    Unavailable,
    Other,
}

impl fmt::Display for HostErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::AccessDenied => "access denied",
            Self::NotFound => "not found",
            Self::AlreadyExists => "already exists",
            Self::InvalidInput => "invalid input",
            Self::Interrupted => "interrupted",
            Self::TimedOut => "timed out",
            Self::WouldBlock => "would block",
            Self::BrokenPipe => "broken pipe",
            Self::OutOfMemory => "out of memory",
            Self::Unsupported => "unsupported",
            Self::Poisoned => "poisoned synchronization primitive",
            Self::Unavailable => "unavailable",
            Self::Other => "other host error",
        };
        f.write_str(kind)
    }
}

/// Native code attached to a host failure.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HostErrorCode {
    Windows(u32),
    Winsock(i32),
    Os(i32),
}

impl fmt::Display for HostErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows(code) => write!(f, "windows:{code}"),
            Self::Winsock(code) => write!(f, "winsock:{code}"),
            Self::Os(code) => write!(f, "os:{code}"),
        }
    }
}

/// Typed host adapter error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostError {
    operation: HostOperation,
    kind: HostErrorKind,
    code: Option<HostErrorCode>,
}

impl HostError {
    /// Creates a host error with no native platform code.
    pub const fn new(operation: HostOperation, kind: HostErrorKind) -> Self {
        Self {
            operation,
            kind,
            code: None,
        }
    }

    /// Creates a host error with a native platform code.
    pub const fn with_code(
        operation: HostOperation,
        kind: HostErrorKind,
        code: HostErrorCode,
    ) -> Self {
        Self {
            operation,
            kind,
            code: Some(code),
        }
    }

    /// Creates an unsupported-operation host error.
    pub const fn unsupported(operation: HostOperation) -> Self {
        Self::new(operation, HostErrorKind::Unsupported)
    }

    /// Creates an invalid-input host error.
    pub const fn invalid_input(operation: HostOperation) -> Self {
        Self::new(operation, HostErrorKind::InvalidInput)
    }

    /// Maps a Rust I/O error into a host adapter error without assigning Linux errno.
    pub fn from_io(operation: HostOperation, error: io::Error) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::NotFound => HostErrorKind::NotFound,
            io::ErrorKind::PermissionDenied => HostErrorKind::AccessDenied,
            io::ErrorKind::AlreadyExists => HostErrorKind::AlreadyExists,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => HostErrorKind::InvalidInput,
            io::ErrorKind::Interrupted => HostErrorKind::Interrupted,
            io::ErrorKind::TimedOut => HostErrorKind::TimedOut,
            io::ErrorKind::WouldBlock => HostErrorKind::WouldBlock,
            io::ErrorKind::BrokenPipe => HostErrorKind::BrokenPipe,
            io::ErrorKind::OutOfMemory => HostErrorKind::OutOfMemory,
            io::ErrorKind::Unsupported => HostErrorKind::Unsupported,
            _ => HostErrorKind::Other,
        };

        let code = error.raw_os_error().map(HostErrorCode::Os);
        Self {
            operation,
            kind,
            code,
        }
    }

    /// Returns the operation that failed.
    pub const fn operation(&self) -> HostOperation {
        self.operation
    }

    /// Returns the typed host error kind.
    pub const fn kind(&self) -> HostErrorKind {
        self.kind
    }

    /// Returns the native host error code when one is available.
    pub const fn code(&self) -> Option<HostErrorCode> {
        self.code
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(f, "{} failed: {} ({code})", self.operation, self.kind),
            None => write!(f, "{} failed: {}", self.operation, self.kind),
        }
    }
}

impl Error for HostError {}

#[cfg(windows)]
pub(crate) fn windows_kind(code: u32) -> HostErrorKind {
    match code {
        windows_codes::ERROR_ACCESS_DENIED => HostErrorKind::AccessDenied,
        windows_codes::ERROR_FILE_NOT_FOUND | windows_codes::ERROR_PATH_NOT_FOUND => {
            HostErrorKind::NotFound
        }
        windows_codes::ERROR_ALREADY_EXISTS | windows_codes::ERROR_FILE_EXISTS => {
            HostErrorKind::AlreadyExists
        }
        windows_codes::ERROR_INVALID_PARAMETER | windows_codes::ERROR_INVALID_NAME => {
            HostErrorKind::InvalidInput
        }
        windows_codes::ERROR_NOT_ENOUGH_MEMORY | windows_codes::ERROR_OUTOFMEMORY => {
            HostErrorKind::OutOfMemory
        }
        windows_codes::ERROR_TIMEOUT | windows_codes::WAIT_TIMEOUT => HostErrorKind::TimedOut,
        windows_codes::ERROR_BROKEN_PIPE => HostErrorKind::BrokenPipe,
        windows_codes::ERROR_OPERATION_ABORTED => HostErrorKind::Interrupted,
        _ => HostErrorKind::Other,
    }
}

#[cfg(windows)]
pub(crate) fn winsock_kind(code: i32) -> HostErrorKind {
    match code {
        winsock_codes::WSAEACCES => HostErrorKind::AccessDenied,
        winsock_codes::WSAEADDRINUSE => HostErrorKind::AlreadyExists,
        winsock_codes::WSAEAFNOSUPPORT
        | winsock_codes::WSAEPROTONOSUPPORT
        | winsock_codes::WSAESOCKTNOSUPPORT => HostErrorKind::Unsupported,
        winsock_codes::WSAEINVAL | winsock_codes::WSAENOTSOCK => HostErrorKind::InvalidInput,
        winsock_codes::WSAEINTR => HostErrorKind::Interrupted,
        winsock_codes::WSAETIMEDOUT => HostErrorKind::TimedOut,
        winsock_codes::WSAEWOULDBLOCK
        | winsock_codes::WSAEINPROGRESS
        | winsock_codes::WSAEALREADY => HostErrorKind::WouldBlock,
        winsock_codes::WSAECONNREFUSED
        | winsock_codes::WSAENETUNREACH
        | winsock_codes::WSAEHOSTUNREACH => HostErrorKind::Unavailable,
        winsock_codes::WSAECONNRESET | winsock_codes::WSAESHUTDOWN => HostErrorKind::BrokenPipe,
        _ => HostErrorKind::Other,
    }
}

#[cfg(windows)]
pub(crate) fn last_windows_error(operation: HostOperation) -> HostError {
    let code = crate::windows::last_error();
    HostError::with_code(operation, windows_kind(code), HostErrorCode::Windows(code))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn last_os_error(operation: HostOperation) -> HostError {
    HostError::from_io(operation, io::Error::last_os_error())
}

#[cfg(windows)]
pub(crate) fn windows_error(operation: HostOperation, code: u32) -> HostError {
    HostError::with_code(operation, windows_kind(code), HostErrorCode::Windows(code))
}

#[cfg(windows)]
pub(crate) fn last_winsock_error(operation: HostOperation) -> HostError {
    let code = crate::windows::wsa_last_error();
    HostError::with_code(operation, winsock_kind(code), HostErrorCode::Winsock(code))
}

#[cfg(windows)]
mod windows_codes {
    pub const ERROR_FILE_NOT_FOUND: u32 = 2;
    pub const ERROR_PATH_NOT_FOUND: u32 = 3;
    pub const ERROR_ACCESS_DENIED: u32 = 5;
    pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
    pub const ERROR_OUTOFMEMORY: u32 = 14;
    pub const ERROR_FILE_EXISTS: u32 = 80;
    pub const ERROR_INVALID_PARAMETER: u32 = 87;
    pub const ERROR_INVALID_NAME: u32 = 123;
    pub const ERROR_ALREADY_EXISTS: u32 = 183;
    pub const WAIT_TIMEOUT: u32 = 258;
    pub const ERROR_OPERATION_ABORTED: u32 = 995;
    pub const ERROR_BROKEN_PIPE: u32 = 109;
    pub const ERROR_TIMEOUT: u32 = 1460;
}

#[cfg(windows)]
mod winsock_codes {
    pub const WSAEINTR: i32 = 10004;
    pub const WSAEACCES: i32 = 10013;
    pub const WSAEFAULT: i32 = 10014;
    pub const WSAEINVAL: i32 = 10022;
    pub const WSAEMFILE: i32 = 10024;
    pub const WSAEWOULDBLOCK: i32 = 10035;
    pub const WSAEINPROGRESS: i32 = 10036;
    pub const WSAEALREADY: i32 = 10037;
    pub const WSAENOTSOCK: i32 = 10038;
    pub const WSAESHUTDOWN: i32 = 10058;
    pub const WSAETIMEDOUT: i32 = 10060;
    pub const WSAECONNREFUSED: i32 = 10061;
    pub const WSAECONNRESET: i32 = 10054;
    pub const WSAEADDRINUSE: i32 = 10048;
    pub const WSAEAFNOSUPPORT: i32 = 10047;
    pub const WSAENETUNREACH: i32 = 10051;
    pub const WSAEHOSTUNREACH: i32 = 10065;
    pub const WSAEPROTONOSUPPORT: i32 = 10043;
    pub const WSAESOCKTNOSUPPORT: i32 = 10044;

    const _: () = {
        let _ = WSAEFAULT;
        let _ = WSAEMFILE;
    };
}

#[cfg(test)]
mod tests {
    use super::{HostError, HostErrorKind, HostOperation};

    #[test]
    fn display_includes_operation_and_kind() {
        let error = HostError::new(HostOperation::OpenFile, HostErrorKind::NotFound);

        assert_eq!(error.to_string(), "open file failed: not found");
    }
}
