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

#[cfg(test)]
mod tests {
    use super::{
        LINUX_F_DUPFD, LINUX_F_DUPFD_CLOEXEC, LINUX_F_GETFD, LINUX_F_GETFL,
        LINUX_F_GETPIPE_SZ, LINUX_F_SETFD, LINUX_F_SETFL, LINUX_F_SETPIPE_SZ, LINUX_FD_CLOEXEC,
        LINUX_IOCTL_FIONREAD, LINUX_IOCTL_TCGETS, LINUX_IOCTL_TIOCGWINSZ, LINUX_O_CLOEXEC,
        LINUX_O_NONBLOCK,
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
}
