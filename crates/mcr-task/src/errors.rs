use std::fmt;

use mcr_elf::GuestImageError;
use mcr_sys::{GuestPid, GuestTid, LinuxErrno, SyscallOutcome};

#[derive(Debug)]
pub enum TaskError {
    BadFd(i32),
    InvalidCloneFlags(u64),
    InvalidRobustListLength(u64),
    InvalidSignal(u32),
    InvalidSignalMaskHow(u32),
    InvalidSigsetSize(u64),
    InvalidWaitOptions(u32),
    NoChild,
    PidExhausted,
    TidExhausted,
    UnknownPid(GuestPid),
    UnknownTid(GuestTid),
    UnsupportedSignalTarget(i32),
    WouldBlock,
    Elf(mcr_elf::ElfValidationError),
    Image(GuestImageError),
}

impl TaskError {
    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        match self {
            Self::BadFd(_) => LinuxErrno::EBADF,
            Self::InvalidCloneFlags(_)
            | Self::InvalidRobustListLength(_)
            | Self::InvalidSignal(_)
            | Self::InvalidSignalMaskHow(_)
            | Self::InvalidSigsetSize(_)
            | Self::InvalidWaitOptions(_)
            | Self::UnsupportedSignalTarget(_) => LinuxErrno::EINVAL,
            Self::NoChild => LinuxErrno::ECHILD,
            Self::PidExhausted | Self::TidExhausted => LinuxErrno::EAGAIN,
            Self::UnknownPid(_) | Self::UnknownTid(_) => LinuxErrno::ESRCH,
            Self::WouldBlock => LinuxErrno::EAGAIN,
            Self::Elf(_) | Self::Image(_) => LinuxErrno::ENOEXEC,
        }
    }

    #[must_use]
    pub fn into_outcome(self) -> SyscallOutcome {
        SyscallOutcome::errno(self.linux_errno()).with_decoded_field("task_error", self.to_string())
    }
}

impl fmt::Display for TaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFd(fd) => write!(formatter, "bad guest fd {fd}"),
            Self::InvalidCloneFlags(flags) => {
                write!(formatter, "unsupported clone flags {flags:#x}")
            }
            Self::InvalidRobustListLength(length) => {
                write!(formatter, "invalid robust list length {length}")
            }
            Self::InvalidSignal(signal) => write!(formatter, "invalid signal {signal}"),
            Self::InvalidSignalMaskHow(how) => write!(formatter, "invalid signal mask how {how}"),
            Self::InvalidSigsetSize(size) => write!(formatter, "invalid sigset size {size}"),
            Self::InvalidWaitOptions(options) => {
                write!(formatter, "unsupported wait4 options {options:#x}")
            }
            Self::NoChild => write!(formatter, "no waitable child process"),
            Self::PidExhausted => write!(formatter, "guest PID namespace exhausted"),
            Self::TidExhausted => write!(formatter, "guest TID namespace exhausted"),
            Self::UnknownPid(pid) => write!(formatter, "unknown guest pid {pid}"),
            Self::UnknownTid(tid) => write!(formatter, "unknown guest tid {tid}"),
            Self::UnsupportedSignalTarget(pid) => {
                write!(formatter, "unsupported signal target {pid}")
            }
            Self::WouldBlock => write!(formatter, "waitable child has not exited"),
            Self::Elf(error) => write!(formatter, "{error}"),
            Self::Image(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for TaskError {}

impl From<mcr_elf::ElfValidationError> for TaskError {
    fn from(value: mcr_elf::ElfValidationError) -> Self {
        Self::Elf(value)
    }
}

impl From<GuestImageError> for TaskError {
    fn from(value: GuestImageError) -> Self {
        Self::Image(value)
    }
}
