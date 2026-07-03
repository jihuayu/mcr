use core::fmt;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SyscallNumber(u64);

impl SyscallNumber {
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl From<u64> for SyscallNumber {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<SyscallNumber> for u64 {
    fn from(value: SyscallNumber) -> Self {
        value.raw()
    }
}

impl fmt::Display for SyscallNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Syscall {
    Read,
    Write,
    Open,
    Close,
    Stat,
    Fstat,
    Lstat,
    Poll,
    Lseek,
    Mmap,
    Mprotect,
    Munmap,
    Brk,
    RtSigaction,
    RtSigprocmask,
    RtSigreturn,
    Ioctl,
    Readv,
    Writev,
    Access,
    Pipe,
    Getuid,
    Getgid,
    Setuid,
    Setgid,
    Geteuid,
    Getegid,
    Setpgid,
    Getppid,
    Getpgrp,
    Setsid,
    Setreuid,
    Setregid,
    Nanosleep,
    Dup,
    Dup2,
    Getpid,
    Socket,
    Connect,
    Accept,
    Sendto,
    Recvfrom,
    Sendmsg,
    Recvmsg,
    Shutdown,
    Bind,
    Listen,
    Getsockname,
    Getpeername,
    Setsockopt,
    Getsockopt,
    Clone,
    Fork,
    Vfork,
    Execve,
    Exit,
    Wait4,
    Kill,
    Uname,
    Fcntl,
    Ftruncate,
    Getdents,
    Getcwd,
    Chdir,
    Mkdir,
    Rmdir,
    Link,
    Unlink,
    Rename,
    Readlink,
    Symlink,
    Umask,
    ArchPrctl,
    Gettid,
    Futex,
    Getdents64,
    SetTidAddress,
    ClockGettime,
    ExitGroup,
    EpollWait,
    EpollCtl,
    Tgkill,
    Openat,
    Mkdirat,
    Newfstatat,
    Unlinkat,
    Linkat,
    Symlinkat,
    Readlinkat,
    Ppoll,
    SetRobustList,
    EpollCreate1,
    Accept4,
    Dup3,
    Pipe2,
    Renameat2,
    Getrandom,
    Statx,
    Unknown(SyscallNumber),
}

impl Syscall {
    pub const READ: SyscallNumber = SyscallNumber::new(0);
    pub const WRITE: SyscallNumber = SyscallNumber::new(1);
    pub const OPEN: SyscallNumber = SyscallNumber::new(2);
    pub const CLOSE: SyscallNumber = SyscallNumber::new(3);
    pub const STAT: SyscallNumber = SyscallNumber::new(4);
    pub const FSTAT: SyscallNumber = SyscallNumber::new(5);
    pub const LSTAT: SyscallNumber = SyscallNumber::new(6);
    pub const POLL: SyscallNumber = SyscallNumber::new(7);
    pub const LSEEK: SyscallNumber = SyscallNumber::new(8);
    pub const MMAP: SyscallNumber = SyscallNumber::new(9);
    pub const MPROTECT: SyscallNumber = SyscallNumber::new(10);
    pub const MUNMAP: SyscallNumber = SyscallNumber::new(11);
    pub const BRK: SyscallNumber = SyscallNumber::new(12);
    pub const RT_SIGACTION: SyscallNumber = SyscallNumber::new(13);
    pub const RT_SIGPROCMASK: SyscallNumber = SyscallNumber::new(14);
    pub const RT_SIGRETURN: SyscallNumber = SyscallNumber::new(15);
    pub const IOCTL: SyscallNumber = SyscallNumber::new(16);
    pub const READV: SyscallNumber = SyscallNumber::new(19);
    pub const WRITEV: SyscallNumber = SyscallNumber::new(20);
    pub const ACCESS: SyscallNumber = SyscallNumber::new(21);
    pub const PIPE: SyscallNumber = SyscallNumber::new(22);
    pub const GETUID: SyscallNumber = SyscallNumber::new(102);
    pub const GETGID: SyscallNumber = SyscallNumber::new(104);
    pub const SETUID: SyscallNumber = SyscallNumber::new(105);
    pub const SETGID: SyscallNumber = SyscallNumber::new(106);
    pub const GETEUID: SyscallNumber = SyscallNumber::new(107);
    pub const GETEGID: SyscallNumber = SyscallNumber::new(108);
    pub const SETPGID: SyscallNumber = SyscallNumber::new(109);
    pub const GETPPID: SyscallNumber = SyscallNumber::new(110);
    pub const GETPGRP: SyscallNumber = SyscallNumber::new(111);
    pub const SETSID: SyscallNumber = SyscallNumber::new(112);
    pub const SETREUID: SyscallNumber = SyscallNumber::new(113);
    pub const SETREGID: SyscallNumber = SyscallNumber::new(114);
    pub const NANOSLEEP: SyscallNumber = SyscallNumber::new(35);
    pub const DUP: SyscallNumber = SyscallNumber::new(32);
    pub const DUP2: SyscallNumber = SyscallNumber::new(33);
    pub const GETPID: SyscallNumber = SyscallNumber::new(39);
    pub const SOCKET: SyscallNumber = SyscallNumber::new(41);
    pub const CONNECT: SyscallNumber = SyscallNumber::new(42);
    pub const ACCEPT: SyscallNumber = SyscallNumber::new(43);
    pub const SENDTO: SyscallNumber = SyscallNumber::new(44);
    pub const RECVFROM: SyscallNumber = SyscallNumber::new(45);
    pub const SENDMSG: SyscallNumber = SyscallNumber::new(46);
    pub const RECVMSG: SyscallNumber = SyscallNumber::new(47);
    pub const SHUTDOWN: SyscallNumber = SyscallNumber::new(48);
    pub const BIND: SyscallNumber = SyscallNumber::new(49);
    pub const LISTEN: SyscallNumber = SyscallNumber::new(50);
    pub const GETSOCKNAME: SyscallNumber = SyscallNumber::new(51);
    pub const GETPEERNAME: SyscallNumber = SyscallNumber::new(52);
    pub const SETSOCKOPT: SyscallNumber = SyscallNumber::new(54);
    pub const GETSOCKOPT: SyscallNumber = SyscallNumber::new(55);
    pub const CLONE: SyscallNumber = SyscallNumber::new(56);
    pub const FORK: SyscallNumber = SyscallNumber::new(57);
    pub const VFORK: SyscallNumber = SyscallNumber::new(58);
    pub const EXECVE: SyscallNumber = SyscallNumber::new(59);
    pub const EXIT: SyscallNumber = SyscallNumber::new(60);
    pub const WAIT4: SyscallNumber = SyscallNumber::new(61);
    pub const KILL: SyscallNumber = SyscallNumber::new(62);
    pub const UNAME: SyscallNumber = SyscallNumber::new(63);
    pub const FCNTL: SyscallNumber = SyscallNumber::new(72);
    pub const FTRUNCATE: SyscallNumber = SyscallNumber::new(77);
    pub const GETDENTS: SyscallNumber = SyscallNumber::new(78);
    pub const GETCWD: SyscallNumber = SyscallNumber::new(79);
    pub const CHDIR: SyscallNumber = SyscallNumber::new(80);
    pub const MKDIR: SyscallNumber = SyscallNumber::new(83);
    pub const RMDIR: SyscallNumber = SyscallNumber::new(84);
    pub const RENAME: SyscallNumber = SyscallNumber::new(82);
    pub const READLINK: SyscallNumber = SyscallNumber::new(89);
    pub const SYMLINK: SyscallNumber = SyscallNumber::new(88);
    pub const LINK: SyscallNumber = SyscallNumber::new(86);
    pub const UNLINK: SyscallNumber = SyscallNumber::new(87);
    pub const UMASK: SyscallNumber = SyscallNumber::new(95);
    pub const ARCH_PRCTL: SyscallNumber = SyscallNumber::new(158);
    pub const GETTID: SyscallNumber = SyscallNumber::new(186);
    pub const FUTEX: SyscallNumber = SyscallNumber::new(202);
    pub const GETDENTS64: SyscallNumber = SyscallNumber::new(217);
    pub const SET_TID_ADDRESS: SyscallNumber = SyscallNumber::new(218);
    pub const CLOCK_GETTIME: SyscallNumber = SyscallNumber::new(228);
    pub const EXIT_GROUP: SyscallNumber = SyscallNumber::new(231);
    pub const EPOLL_WAIT: SyscallNumber = SyscallNumber::new(232);
    pub const EPOLL_CTL: SyscallNumber = SyscallNumber::new(233);
    pub const TGKILL: SyscallNumber = SyscallNumber::new(234);
    pub const OPENAT: SyscallNumber = SyscallNumber::new(257);
    pub const MKDIRAT: SyscallNumber = SyscallNumber::new(258);
    pub const NEWFSTATAT: SyscallNumber = SyscallNumber::new(262);
    pub const UNLINKAT: SyscallNumber = SyscallNumber::new(263);
    pub const LINKAT: SyscallNumber = SyscallNumber::new(265);
    pub const SYMLINKAT: SyscallNumber = SyscallNumber::new(266);
    pub const READLINKAT: SyscallNumber = SyscallNumber::new(267);
    pub const PPOLL: SyscallNumber = SyscallNumber::new(271);
    pub const SET_ROBUST_LIST: SyscallNumber = SyscallNumber::new(273);
    pub const EPOLL_CREATE1: SyscallNumber = SyscallNumber::new(291);
    pub const ACCEPT4: SyscallNumber = SyscallNumber::new(288);
    pub const DUP3: SyscallNumber = SyscallNumber::new(292);
    pub const PIPE2: SyscallNumber = SyscallNumber::new(293);
    pub const RENAMEAT2: SyscallNumber = SyscallNumber::new(316);
    pub const GETRANDOM: SyscallNumber = SyscallNumber::new(318);
    pub const STATX: SyscallNumber = SyscallNumber::new(332);

    #[must_use]
    pub const fn from_number(number: SyscallNumber) -> Self {
        match number.raw() {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::Open,
            3 => Self::Close,
            4 => Self::Stat,
            5 => Self::Fstat,
            6 => Self::Lstat,
            7 => Self::Poll,
            8 => Self::Lseek,
            9 => Self::Mmap,
            10 => Self::Mprotect,
            11 => Self::Munmap,
            12 => Self::Brk,
            13 => Self::RtSigaction,
            14 => Self::RtSigprocmask,
            15 => Self::RtSigreturn,
            16 => Self::Ioctl,
            19 => Self::Readv,
            20 => Self::Writev,
            21 => Self::Access,
            22 => Self::Pipe,
            32 => Self::Dup,
            33 => Self::Dup2,
            35 => Self::Nanosleep,
            39 => Self::Getpid,
            41 => Self::Socket,
            42 => Self::Connect,
            43 => Self::Accept,
            44 => Self::Sendto,
            45 => Self::Recvfrom,
            46 => Self::Sendmsg,
            47 => Self::Recvmsg,
            48 => Self::Shutdown,
            49 => Self::Bind,
            50 => Self::Listen,
            51 => Self::Getsockname,
            52 => Self::Getpeername,
            54 => Self::Setsockopt,
            55 => Self::Getsockopt,
            56 => Self::Clone,
            57 => Self::Fork,
            58 => Self::Vfork,
            59 => Self::Execve,
            60 => Self::Exit,
            61 => Self::Wait4,
            62 => Self::Kill,
            63 => Self::Uname,
            72 => Self::Fcntl,
            77 => Self::Ftruncate,
            78 => Self::Getdents,
            79 => Self::Getcwd,
            80 => Self::Chdir,
            82 => Self::Rename,
            83 => Self::Mkdir,
            84 => Self::Rmdir,
            86 => Self::Link,
            87 => Self::Unlink,
            88 => Self::Symlink,
            89 => Self::Readlink,
            95 => Self::Umask,
            102 => Self::Getuid,
            104 => Self::Getgid,
            105 => Self::Setuid,
            106 => Self::Setgid,
            107 => Self::Geteuid,
            108 => Self::Getegid,
            109 => Self::Setpgid,
            110 => Self::Getppid,
            111 => Self::Getpgrp,
            112 => Self::Setsid,
            113 => Self::Setreuid,
            114 => Self::Setregid,
            158 => Self::ArchPrctl,
            186 => Self::Gettid,
            202 => Self::Futex,
            217 => Self::Getdents64,
            218 => Self::SetTidAddress,
            228 => Self::ClockGettime,
            231 => Self::ExitGroup,
            232 => Self::EpollWait,
            233 => Self::EpollCtl,
            234 => Self::Tgkill,
            257 => Self::Openat,
            258 => Self::Mkdirat,
            262 => Self::Newfstatat,
            263 => Self::Unlinkat,
            265 => Self::Linkat,
            266 => Self::Symlinkat,
            267 => Self::Readlinkat,
            271 => Self::Ppoll,
            273 => Self::SetRobustList,
            288 => Self::Accept4,
            291 => Self::EpollCreate1,
            292 => Self::Dup3,
            293 => Self::Pipe2,
            316 => Self::Renameat2,
            318 => Self::Getrandom,
            332 => Self::Statx,
            _ => Self::Unknown(number),
        }
    }

    #[must_use]
    pub const fn number(self) -> SyscallNumber {
        match self {
            Self::Read => Self::READ,
            Self::Write => Self::WRITE,
            Self::Open => Self::OPEN,
            Self::Close => Self::CLOSE,
            Self::Stat => Self::STAT,
            Self::Fstat => Self::FSTAT,
            Self::Lstat => Self::LSTAT,
            Self::Poll => Self::POLL,
            Self::Lseek => Self::LSEEK,
            Self::Mmap => Self::MMAP,
            Self::Mprotect => Self::MPROTECT,
            Self::Munmap => Self::MUNMAP,
            Self::Brk => Self::BRK,
            Self::RtSigaction => Self::RT_SIGACTION,
            Self::RtSigprocmask => Self::RT_SIGPROCMASK,
            Self::RtSigreturn => Self::RT_SIGRETURN,
            Self::Ioctl => Self::IOCTL,
            Self::Readv => Self::READV,
            Self::Writev => Self::WRITEV,
            Self::Access => Self::ACCESS,
            Self::Pipe => Self::PIPE,
            Self::Getuid => Self::GETUID,
            Self::Getgid => Self::GETGID,
            Self::Setuid => Self::SETUID,
            Self::Setgid => Self::SETGID,
            Self::Geteuid => Self::GETEUID,
            Self::Getegid => Self::GETEGID,
            Self::Setpgid => Self::SETPGID,
            Self::Getppid => Self::GETPPID,
            Self::Getpgrp => Self::GETPGRP,
            Self::Setsid => Self::SETSID,
            Self::Setreuid => Self::SETREUID,
            Self::Setregid => Self::SETREGID,
            Self::Nanosleep => Self::NANOSLEEP,
            Self::Dup => Self::DUP,
            Self::Dup2 => Self::DUP2,
            Self::Getpid => Self::GETPID,
            Self::Socket => Self::SOCKET,
            Self::Connect => Self::CONNECT,
            Self::Accept => Self::ACCEPT,
            Self::Sendto => Self::SENDTO,
            Self::Recvfrom => Self::RECVFROM,
            Self::Sendmsg => Self::SENDMSG,
            Self::Recvmsg => Self::RECVMSG,
            Self::Shutdown => Self::SHUTDOWN,
            Self::Bind => Self::BIND,
            Self::Listen => Self::LISTEN,
            Self::Getsockname => Self::GETSOCKNAME,
            Self::Getpeername => Self::GETPEERNAME,
            Self::Setsockopt => Self::SETSOCKOPT,
            Self::Getsockopt => Self::GETSOCKOPT,
            Self::Clone => Self::CLONE,
            Self::Fork => Self::FORK,
            Self::Vfork => Self::VFORK,
            Self::Execve => Self::EXECVE,
            Self::Exit => Self::EXIT,
            Self::Wait4 => Self::WAIT4,
            Self::Kill => Self::KILL,
            Self::Uname => Self::UNAME,
            Self::Fcntl => Self::FCNTL,
            Self::Ftruncate => Self::FTRUNCATE,
            Self::Getdents => Self::GETDENTS,
            Self::Getcwd => Self::GETCWD,
            Self::Chdir => Self::CHDIR,
            Self::Mkdir => Self::MKDIR,
            Self::Rmdir => Self::RMDIR,
            Self::Link => Self::LINK,
            Self::Unlink => Self::UNLINK,
            Self::Rename => Self::RENAME,
            Self::Readlink => Self::READLINK,
            Self::Symlink => Self::SYMLINK,
            Self::Umask => Self::UMASK,
            Self::ArchPrctl => Self::ARCH_PRCTL,
            Self::Gettid => Self::GETTID,
            Self::Futex => Self::FUTEX,
            Self::Getdents64 => Self::GETDENTS64,
            Self::SetTidAddress => Self::SET_TID_ADDRESS,
            Self::ClockGettime => Self::CLOCK_GETTIME,
            Self::ExitGroup => Self::EXIT_GROUP,
            Self::EpollWait => Self::EPOLL_WAIT,
            Self::EpollCtl => Self::EPOLL_CTL,
            Self::Tgkill => Self::TGKILL,
            Self::Openat => Self::OPENAT,
            Self::Mkdirat => Self::MKDIRAT,
            Self::Newfstatat => Self::NEWFSTATAT,
            Self::Unlinkat => Self::UNLINKAT,
            Self::Linkat => Self::LINKAT,
            Self::Symlinkat => Self::SYMLINKAT,
            Self::Readlinkat => Self::READLINKAT,
            Self::Ppoll => Self::PPOLL,
            Self::SetRobustList => Self::SET_ROBUST_LIST,
            Self::Accept4 => Self::ACCEPT4,
            Self::EpollCreate1 => Self::EPOLL_CREATE1,
            Self::Dup3 => Self::DUP3,
            Self::Pipe2 => Self::PIPE2,
            Self::Renameat2 => Self::RENAMEAT2,
            Self::Getrandom => Self::GETRANDOM,
            Self::Statx => Self::STATX,
            Self::Unknown(number) => number,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Open => "open",
            Self::Close => "close",
            Self::Stat => "stat",
            Self::Fstat => "fstat",
            Self::Lstat => "lstat",
            Self::Poll => "poll",
            Self::Lseek => "lseek",
            Self::Mmap => "mmap",
            Self::Mprotect => "mprotect",
            Self::Munmap => "munmap",
            Self::Brk => "brk",
            Self::RtSigaction => "rt_sigaction",
            Self::RtSigprocmask => "rt_sigprocmask",
            Self::RtSigreturn => "rt_sigreturn",
            Self::Ioctl => "ioctl",
            Self::Readv => "readv",
            Self::Writev => "writev",
            Self::Access => "access",
            Self::Pipe => "pipe",
            Self::Getuid => "getuid",
            Self::Getgid => "getgid",
            Self::Setuid => "setuid",
            Self::Setgid => "setgid",
            Self::Geteuid => "geteuid",
            Self::Getegid => "getegid",
            Self::Setpgid => "setpgid",
            Self::Getppid => "getppid",
            Self::Getpgrp => "getpgrp",
            Self::Setsid => "setsid",
            Self::Setreuid => "setreuid",
            Self::Setregid => "setregid",
            Self::Nanosleep => "nanosleep",
            Self::Dup => "dup",
            Self::Dup2 => "dup2",
            Self::Getpid => "getpid",
            Self::Socket => "socket",
            Self::Connect => "connect",
            Self::Accept => "accept",
            Self::Sendto => "sendto",
            Self::Recvfrom => "recvfrom",
            Self::Sendmsg => "sendmsg",
            Self::Recvmsg => "recvmsg",
            Self::Shutdown => "shutdown",
            Self::Bind => "bind",
            Self::Listen => "listen",
            Self::Getsockname => "getsockname",
            Self::Getpeername => "getpeername",
            Self::Setsockopt => "setsockopt",
            Self::Getsockopt => "getsockopt",
            Self::Clone => "clone",
            Self::Fork => "fork",
            Self::Vfork => "vfork",
            Self::Execve => "execve",
            Self::Exit => "exit",
            Self::Wait4 => "wait4",
            Self::Kill => "kill",
            Self::Uname => "uname",
            Self::Fcntl => "fcntl",
            Self::Ftruncate => "ftruncate",
            Self::Getdents => "getdents",
            Self::Getcwd => "getcwd",
            Self::Chdir => "chdir",
            Self::Mkdir => "mkdir",
            Self::Rmdir => "rmdir",
            Self::Link => "link",
            Self::Unlink => "unlink",
            Self::Rename => "rename",
            Self::Readlink => "readlink",
            Self::Symlink => "symlink",
            Self::Umask => "umask",
            Self::ArchPrctl => "arch_prctl",
            Self::Gettid => "gettid",
            Self::Futex => "futex",
            Self::Getdents64 => "getdents64",
            Self::SetTidAddress => "set_tid_address",
            Self::ClockGettime => "clock_gettime",
            Self::ExitGroup => "exit_group",
            Self::EpollWait => "epoll_wait",
            Self::EpollCtl => "epoll_ctl",
            Self::Tgkill => "tgkill",
            Self::Openat => "openat",
            Self::Mkdirat => "mkdirat",
            Self::Newfstatat => "newfstatat",
            Self::Unlinkat => "unlinkat",
            Self::Linkat => "linkat",
            Self::Symlinkat => "symlinkat",
            Self::Readlinkat => "readlinkat",
            Self::Ppoll => "ppoll",
            Self::SetRobustList => "set_robust_list",
            Self::Accept4 => "accept4",
            Self::EpollCreate1 => "epoll_create1",
            Self::Dup3 => "dup3",
            Self::Pipe2 => "pipe2",
            Self::Renameat2 => "renameat2",
            Self::Getrandom => "getrandom",
            Self::Statx => "statx",
            Self::Unknown(_) => "unknown",
        }
    }

    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_known() {
            write!(f, "{}({})", self.name(), self.number().raw())
        } else {
            write!(f, "unknown({})", self.number().raw())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Syscall, SyscallNumber};

    #[test]
    fn maps_linux_x86_64_syscall_numbers() {
        assert_eq!(Syscall::from_number(Syscall::READ), Syscall::Read);
        assert_eq!(Syscall::from_number(Syscall::OPENAT), Syscall::Openat);
        assert_eq!(Syscall::from_number(Syscall::SENDTO), Syscall::Sendto);
        assert_eq!(Syscall::from_number(Syscall::ACCEPT4), Syscall::Accept4);
        assert_eq!(Syscall::from_number(Syscall::STATX), Syscall::Statx);
        assert_eq!(Syscall::ExitGroup.number().raw(), 231);
        assert_eq!(Syscall::ClockGettime.name(), "clock_gettime");
    }

    #[test]
    fn unsupported_syscalls_keep_their_raw_number() {
        let number = SyscallNumber::new(9999);
        let syscall = Syscall::from_number(number);

        assert_eq!(syscall, Syscall::Unknown(number));
        assert_eq!(syscall.number(), number);
        assert!(!syscall.is_known());
        assert_eq!(syscall.to_string(), "unknown(9999)");
    }
}
