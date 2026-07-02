use crate::errno::LinuxErrno;

pub const LINUX_MAX_ERRNO: u16 = LinuxErrno::MAX;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SyscallReturn {
    Success(u64),
    Errno(LinuxErrno),
}

impl SyscallReturn {
    #[must_use]
    pub const fn success(value: u64) -> Self {
        Self::Success(value)
    }

    #[must_use]
    pub const fn errno(errno: LinuxErrno) -> Self {
        Self::Errno(errno)
    }

    #[must_use]
    pub const fn unsupported() -> Self {
        Self::Errno(LinuxErrno::ENOSYS)
    }

    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success(_))
    }

    #[must_use]
    pub const fn errno_value(self) -> Option<LinuxErrno> {
        match self {
            Self::Success(_) => None,
            Self::Errno(errno) => Some(errno),
        }
    }

    #[must_use]
    pub const fn encode_i64(self) -> i64 {
        match self {
            Self::Success(value) => value as i64,
            Self::Errno(errno) => -(errno.raw() as i64),
        }
    }

    #[must_use]
    pub const fn encode_u64(self) -> u64 {
        self.encode_i64() as u64
    }

    #[must_use]
    pub const fn decode_rax(raw: u64) -> Self {
        let signed = raw as i64;
        if signed < 0 && signed >= -(LinuxErrno::MAX as i64) {
            match LinuxErrno::new((-signed) as u16) {
                Some(errno) => Self::Errno(errno),
                None => Self::Success(raw),
            }
        } else {
            Self::Success(raw)
        }
    }
}

impl From<u64> for SyscallReturn {
    fn from(value: u64) -> Self {
        Self::Success(value)
    }
}

impl From<LinuxErrno> for SyscallReturn {
    fn from(errno: LinuxErrno) -> Self {
        Self::Errno(errno)
    }
}

#[cfg(test)]
mod tests {
    use super::{LinuxErrno, SyscallReturn};

    #[test]
    fn success_values_encode_without_changes() {
        assert_eq!(SyscallReturn::success(0).encode_i64(), 0);
        assert_eq!(SyscallReturn::success(42).encode_u64(), 42);
        assert_eq!(SyscallReturn::decode_rax(42), SyscallReturn::Success(42));
    }

    #[test]
    fn errno_values_encode_as_negative_linux_returns() {
        let encoded = SyscallReturn::errno(LinuxErrno::ENOENT).encode_u64();

        assert_eq!(encoded as i64, -2);
        assert_eq!(
            SyscallReturn::decode_rax(encoded),
            SyscallReturn::Errno(LinuxErrno::ENOENT)
        );
    }

    #[test]
    fn unsupported_syscalls_encode_as_enosys() {
        assert_eq!(
            SyscallReturn::unsupported(),
            SyscallReturn::Errno(LinuxErrno::ENOSYS)
        );
        assert_eq!(SyscallReturn::unsupported().encode_i64(), -38);
    }
}
