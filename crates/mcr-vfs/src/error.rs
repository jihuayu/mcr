use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsError {
    AlreadyExists,
    BadFd,
    BrokenPipe,
    Busy,
    InvalidPath,
    IsDirectory,
    Loop,
    NameTooLong,
    NoEntry,
    NotEmpty,
    NoSpace,
    NotSeekable,
    NotSocket,
    NotTerminal,
    NotDirectory,
    NotPermitted,
    PermissionDenied,
    WouldBlock,
}

impl VfsError {
    pub fn linux_errno(self) -> u16 {
        match self {
            Self::AlreadyExists => 17,
            Self::BadFd => 9,
            Self::BrokenPipe => 32,
            Self::Busy => 16,
            Self::InvalidPath => 22,
            Self::IsDirectory => 21,
            Self::Loop => 40,
            Self::NameTooLong => 36,
            Self::NoEntry => 2,
            Self::NotEmpty => 39,
            Self::NoSpace => 28,
            Self::NotSeekable => 29,
            Self::NotSocket => 88,
            Self::NotTerminal => 25,
            Self::NotDirectory => 20,
            Self::NotPermitted => 1,
            Self::PermissionDenied => 13,
            Self::WouldBlock => 11,
        }
    }
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AlreadyExists => "file exists",
            Self::BadFd => "bad file descriptor",
            Self::BrokenPipe => "broken pipe",
            Self::Busy => "device or resource busy",
            Self::InvalidPath => "invalid path",
            Self::IsDirectory => "is a directory",
            Self::Loop => "too many symbolic links",
            Self::NameTooLong => "path name is too long",
            Self::NoEntry => "no such file or directory",
            Self::NotEmpty => "directory not empty",
            Self::NoSpace => "no space left on device",
            Self::NotSeekable => "illegal seek",
            Self::NotSocket => "socket operation on non-socket",
            Self::NotTerminal => "inappropriate ioctl for device",
            Self::NotDirectory => "not a directory",
            Self::NotPermitted => "operation not permitted",
            Self::PermissionDenied => "permission denied",
            Self::WouldBlock => "resource temporarily unavailable",
        };
        f.write_str(message)
    }
}

impl std::error::Error for VfsError {}

pub type VfsResult<T> = Result<T, VfsError>;
