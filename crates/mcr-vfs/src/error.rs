use std::fmt;

use mcr_sys::LinuxErrno;

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
    pub const fn linux_errno(self) -> u16 {
        self.linux_errno_value().raw()
    }

    pub const fn linux_errno_value(self) -> LinuxErrno {
        match self {
            Self::AlreadyExists => LinuxErrno::EEXIST,
            Self::BadFd => LinuxErrno::EBADF,
            Self::BrokenPipe => LinuxErrno::EPIPE,
            Self::Busy => LinuxErrno::EBUSY,
            Self::InvalidPath => LinuxErrno::EINVAL,
            Self::IsDirectory => LinuxErrno::EISDIR,
            Self::Loop => LinuxErrno::ELOOP,
            Self::NameTooLong => LinuxErrno::ENAMETOOLONG,
            Self::NoEntry => LinuxErrno::ENOENT,
            Self::NotEmpty => LinuxErrno::ENOTEMPTY,
            Self::NoSpace => LinuxErrno::ENOSPC,
            Self::NotSeekable => LinuxErrno::ESPIPE,
            Self::NotSocket => LinuxErrno::ENOTSOCK,
            Self::NotTerminal => LinuxErrno::ENOTTY,
            Self::NotDirectory => LinuxErrno::ENOTDIR,
            Self::NotPermitted => LinuxErrno::EPERM,
            Self::PermissionDenied => LinuxErrno::EACCES,
            Self::WouldBlock => LinuxErrno::EWOULDBLOCK,
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
