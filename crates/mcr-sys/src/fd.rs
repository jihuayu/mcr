pub const LINUX_F_DUPFD: u32 = 0;
pub const LINUX_F_GETFD: u32 = 1;
pub const LINUX_F_SETFD: u32 = 2;
pub const LINUX_F_GETFL: u32 = 3;
pub const LINUX_F_SETFL: u32 = 4;
pub const LINUX_F_DUPFD_CLOEXEC: u32 = 1030;
pub const LINUX_F_SETPIPE_SZ: u32 = 1031;
pub const LINUX_F_GETPIPE_SZ: u32 = 1032;

pub const LINUX_FD_CLOEXEC: u32 = 1;

pub const LINUX_O_NONBLOCK: u32 = 0o4000;
pub const LINUX_O_CLOEXEC: u32 = 0o2000000;

pub const LINUX_IOCTL_TCGETS: u64 = 0x5401;
pub const LINUX_IOCTL_TCSETS: u64 = 0x5402;
pub const LINUX_IOCTL_TCSETSW: u64 = 0x5403;
pub const LINUX_IOCTL_TCSETSF: u64 = 0x5404;
pub const LINUX_IOCTL_TIOCGPGRP: u64 = 0x540f;
pub const LINUX_IOCTL_TIOCSPGRP: u64 = 0x5410;
pub const LINUX_IOCTL_TIOCGWINSZ: u64 = 0x5413;
pub const LINUX_IOCTL_FIONREAD: u64 = 0x541b;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipeSyscallArgs {
    pub pipefd: u64,
}

impl PipeSyscallArgs {
    #[must_use]
    pub const fn new(pipefd: u64) -> Self {
        Self { pipefd }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pipe2SyscallArgs {
    pub pipefd: u64,
    pub flags: u32,
}

impl Pipe2SyscallArgs {
    #[must_use]
    pub const fn new(pipefd: u64, flags: u32) -> Self {
        Self { pipefd, flags }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DupSyscallArgs {
    pub oldfd: i32,
}

impl DupSyscallArgs {
    #[must_use]
    pub const fn new(oldfd: i32) -> Self {
        Self { oldfd }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dup2SyscallArgs {
    pub oldfd: i32,
    pub newfd: i32,
}

impl Dup2SyscallArgs {
    #[must_use]
    pub const fn new(oldfd: i32, newfd: i32) -> Self {
        Self { oldfd, newfd }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dup3SyscallArgs {
    pub oldfd: i32,
    pub newfd: i32,
    pub flags: u32,
}

impl Dup3SyscallArgs {
    #[must_use]
    pub const fn new(oldfd: i32, newfd: i32, flags: u32) -> Self {
        Self {
            oldfd,
            newfd,
            flags,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FcntlSyscallArgs {
    pub fd: i32,
    pub cmd: u32,
    pub arg: u64,
}

impl FcntlSyscallArgs {
    #[must_use]
    pub const fn new(fd: i32, cmd: u32, arg: u64) -> Self {
        Self { fd, cmd, arg }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoctlSyscallArgs {
    pub fd: i32,
    pub request: u64,
    pub argp: u64,
}

impl IoctlSyscallArgs {
    #[must_use]
    pub const fn new(fd: i32, request: u64, argp: u64) -> Self {
        Self { fd, request, argp }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Dup2SyscallArgs, Dup3SyscallArgs, DupSyscallArgs, FcntlSyscallArgs, IoctlSyscallArgs,
        LINUX_F_DUPFD, LINUX_F_DUPFD_CLOEXEC, LINUX_F_GETFD, LINUX_F_GETFL, LINUX_F_GETPIPE_SZ,
        LINUX_F_SETFD, LINUX_F_SETFL, LINUX_F_SETPIPE_SZ, LINUX_FD_CLOEXEC, LINUX_IOCTL_FIONREAD,
        LINUX_IOCTL_TCGETS, LINUX_IOCTL_TIOCGWINSZ, LINUX_O_CLOEXEC, LINUX_O_NONBLOCK,
        Pipe2SyscallArgs, PipeSyscallArgs,
    };

    #[test]
    fn fd_syscall_arg_constants_match_linux_x86_64_values() {
        assert_eq!(LINUX_F_DUPFD, 0);
        assert_eq!(LINUX_F_GETFD, 1);
        assert_eq!(LINUX_F_SETFD, 2);
        assert_eq!(LINUX_F_GETFL, 3);
        assert_eq!(LINUX_F_SETFL, 4);
        assert_eq!(LINUX_F_DUPFD_CLOEXEC, 1030);
        assert_eq!(LINUX_F_SETPIPE_SZ, 1031);
        assert_eq!(LINUX_F_GETPIPE_SZ, 1032);

        assert_eq!(LINUX_FD_CLOEXEC, 1);
        assert_eq!(LINUX_O_NONBLOCK, 0o4000);
        assert_eq!(LINUX_O_CLOEXEC, 0o2000000);

        assert_eq!(LINUX_IOCTL_TCGETS, 0x5401);
        assert_eq!(LINUX_IOCTL_TIOCGWINSZ, 0x5413);
        assert_eq!(LINUX_IOCTL_FIONREAD, 0x541b);
    }

    #[test]
    fn fd_syscall_arg_helpers_preserve_linux_shapes() {
        assert_eq!(PipeSyscallArgs::new(0x1000).pipefd, 0x1000);
        assert_eq!(
            Pipe2SyscallArgs::new(0x1000, LINUX_O_CLOEXEC).flags,
            LINUX_O_CLOEXEC
        );
        assert_eq!(DupSyscallArgs::new(3).oldfd, 3);
        assert_eq!(Dup2SyscallArgs::new(3, 4).newfd, 4);
        assert_eq!(
            Dup3SyscallArgs::new(3, 4, LINUX_O_CLOEXEC).flags,
            LINUX_O_CLOEXEC
        );
        assert_eq!(
            FcntlSyscallArgs::new(3, LINUX_F_GETFL, 0).cmd,
            LINUX_F_GETFL
        );
        assert_eq!(
            IoctlSyscallArgs::new(1, LINUX_IOCTL_FIONREAD, 0x2000).argp,
            0x2000
        );
    }
}
