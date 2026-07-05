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
    Fsync,
    Fdatasync,
    Poll,
    Lseek,
    Mmap,
    Mprotect,
    Munmap,
    Brk,
    RtSigaction,
    RtSigprocmask,
    RtSigreturn,
    RtSigsuspend,
    Ioctl,
    Pread64,
    Pwrite64,
    Readv,
    Writev,
    Access,
    Pipe,
    Select,
    SchedYield,
    Madvise,
    Gettimeofday,
    Times,
    Getrlimit,
    Getrusage,
    Sysinfo,
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
    Getpgid,
    Getsid,
    Sigaltstack,
    Statfs,
    Fstatfs,
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
    Tkill,
    Uname,
    Fcntl,
    Flock,
    Ftruncate,
    Fallocate,
    Getdents,
    Getcwd,
    Chdir,
    Fchdir,
    Mkdir,
    Rmdir,
    Link,
    Unlink,
    Rename,
    Readlink,
    Symlink,
    Chmod,
    Chown,
    Umask,
    Prctl,
    ArchPrctl,
    Gettid,
    Futex,
    SchedGetaffinity,
    Getdents64,
    SetTidAddress,
    ClockGettime,
    ClockGetres,
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
    Utimensat,
    Ppoll,
    SetRobustList,
    Eventfd2,
    EpollCreate1,
    Accept4,
    Dup3,
    Pipe2,
    Prlimit64,
    Getcpu,
    Renameat2,
    Getrandom,
    Membarrier,
    Statx,
    Rseq,
    Clone3,
    CloseRange,
    Openat2,
    Faccessat2,
    EpollPwait2,
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
    pub const FSYNC: SyscallNumber = SyscallNumber::new(74);
    pub const FDATASYNC: SyscallNumber = SyscallNumber::new(75);
    pub const POLL: SyscallNumber = SyscallNumber::new(7);
    pub const LSEEK: SyscallNumber = SyscallNumber::new(8);
    pub const MMAP: SyscallNumber = SyscallNumber::new(9);
    pub const MPROTECT: SyscallNumber = SyscallNumber::new(10);
    pub const MUNMAP: SyscallNumber = SyscallNumber::new(11);
    pub const BRK: SyscallNumber = SyscallNumber::new(12);
    pub const RT_SIGACTION: SyscallNumber = SyscallNumber::new(13);
    pub const RT_SIGPROCMASK: SyscallNumber = SyscallNumber::new(14);
    pub const RT_SIGRETURN: SyscallNumber = SyscallNumber::new(15);
    pub const RT_SIGSUSPEND: SyscallNumber = SyscallNumber::new(130);
    pub const IOCTL: SyscallNumber = SyscallNumber::new(16);
    pub const PREAD64: SyscallNumber = SyscallNumber::new(17);
    pub const PWRITE64: SyscallNumber = SyscallNumber::new(18);
    pub const READV: SyscallNumber = SyscallNumber::new(19);
    pub const WRITEV: SyscallNumber = SyscallNumber::new(20);
    pub const ACCESS: SyscallNumber = SyscallNumber::new(21);
    pub const PIPE: SyscallNumber = SyscallNumber::new(22);
    pub const SELECT: SyscallNumber = SyscallNumber::new(23);
    pub const SCHED_YIELD: SyscallNumber = SyscallNumber::new(24);
    pub const MADVISE: SyscallNumber = SyscallNumber::new(28);
    pub const GETTIMEOFDAY: SyscallNumber = SyscallNumber::new(96);
    pub const TIMES: SyscallNumber = SyscallNumber::new(100);
    pub const GETRLIMIT: SyscallNumber = SyscallNumber::new(97);
    pub const GETRUSAGE: SyscallNumber = SyscallNumber::new(98);
    pub const SYSINFO: SyscallNumber = SyscallNumber::new(99);
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
    pub const GETPGID: SyscallNumber = SyscallNumber::new(121);
    pub const GETSID: SyscallNumber = SyscallNumber::new(124);
    pub const SIGALTSTACK: SyscallNumber = SyscallNumber::new(131);
    pub const STATFS: SyscallNumber = SyscallNumber::new(137);
    pub const FSTATFS: SyscallNumber = SyscallNumber::new(138);
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
    pub const FLOCK: SyscallNumber = SyscallNumber::new(73);
    pub const FTRUNCATE: SyscallNumber = SyscallNumber::new(77);
    pub const FALLOCATE: SyscallNumber = SyscallNumber::new(285);
    pub const GETDENTS: SyscallNumber = SyscallNumber::new(78);
    pub const GETCWD: SyscallNumber = SyscallNumber::new(79);
    pub const CHDIR: SyscallNumber = SyscallNumber::new(80);
    pub const FCHDIR: SyscallNumber = SyscallNumber::new(81);
    pub const MKDIR: SyscallNumber = SyscallNumber::new(83);
    pub const RMDIR: SyscallNumber = SyscallNumber::new(84);
    pub const RENAME: SyscallNumber = SyscallNumber::new(82);
    pub const READLINK: SyscallNumber = SyscallNumber::new(89);
    pub const SYMLINK: SyscallNumber = SyscallNumber::new(88);
    pub const LINK: SyscallNumber = SyscallNumber::new(86);
    pub const UNLINK: SyscallNumber = SyscallNumber::new(87);
    pub const CHMOD: SyscallNumber = SyscallNumber::new(90);
    pub const CHOWN: SyscallNumber = SyscallNumber::new(92);
    pub const UMASK: SyscallNumber = SyscallNumber::new(95);
    pub const PRCTL: SyscallNumber = SyscallNumber::new(157);
    pub const ARCH_PRCTL: SyscallNumber = SyscallNumber::new(158);
    pub const GETTID: SyscallNumber = SyscallNumber::new(186);
    pub const TKILL: SyscallNumber = SyscallNumber::new(200);
    pub const FUTEX: SyscallNumber = SyscallNumber::new(202);
    pub const SCHED_GETAFFINITY: SyscallNumber = SyscallNumber::new(204);
    pub const GETDENTS64: SyscallNumber = SyscallNumber::new(217);
    pub const SET_TID_ADDRESS: SyscallNumber = SyscallNumber::new(218);
    pub const CLOCK_GETTIME: SyscallNumber = SyscallNumber::new(228);
    pub const CLOCK_GETRES: SyscallNumber = SyscallNumber::new(229);
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
    pub const UTIMENSAT: SyscallNumber = SyscallNumber::new(280);
    pub const PPOLL: SyscallNumber = SyscallNumber::new(271);
    pub const SET_ROBUST_LIST: SyscallNumber = SyscallNumber::new(273);
    pub const EVENTFD2: SyscallNumber = SyscallNumber::new(290);
    pub const EPOLL_CREATE1: SyscallNumber = SyscallNumber::new(291);
    pub const ACCEPT4: SyscallNumber = SyscallNumber::new(288);
    pub const DUP3: SyscallNumber = SyscallNumber::new(292);
    pub const PIPE2: SyscallNumber = SyscallNumber::new(293);
    pub const PRLIMIT64: SyscallNumber = SyscallNumber::new(302);
    pub const GETCPU: SyscallNumber = SyscallNumber::new(309);
    pub const RENAMEAT2: SyscallNumber = SyscallNumber::new(316);
    pub const GETRANDOM: SyscallNumber = SyscallNumber::new(318);
    pub const MEMBARRIER: SyscallNumber = SyscallNumber::new(324);
    pub const STATX: SyscallNumber = SyscallNumber::new(332);
    pub const RSEQ: SyscallNumber = SyscallNumber::new(334);
    pub const CLONE3: SyscallNumber = SyscallNumber::new(435);
    pub const CLOSE_RANGE: SyscallNumber = SyscallNumber::new(436);
    pub const OPENAT2: SyscallNumber = SyscallNumber::new(437);
    pub const FACCESSAT2: SyscallNumber = SyscallNumber::new(439);
    pub const EPOLL_PWAIT2: SyscallNumber = SyscallNumber::new(441);

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
            130 => Self::RtSigsuspend,
            16 => Self::Ioctl,
            17 => Self::Pread64,
            18 => Self::Pwrite64,
            19 => Self::Readv,
            20 => Self::Writev,
            21 => Self::Access,
            22 => Self::Pipe,
            23 => Self::Select,
            24 => Self::SchedYield,
            28 => Self::Madvise,
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
            73 => Self::Flock,
            74 => Self::Fsync,
            75 => Self::Fdatasync,
            77 => Self::Ftruncate,
            285 => Self::Fallocate,
            78 => Self::Getdents,
            79 => Self::Getcwd,
            80 => Self::Chdir,
            81 => Self::Fchdir,
            82 => Self::Rename,
            83 => Self::Mkdir,
            84 => Self::Rmdir,
            86 => Self::Link,
            87 => Self::Unlink,
            88 => Self::Symlink,
            89 => Self::Readlink,
            90 => Self::Chmod,
            92 => Self::Chown,
            95 => Self::Umask,
            96 => Self::Gettimeofday,
            97 => Self::Getrlimit,
            98 => Self::Getrusage,
            99 => Self::Sysinfo,
            100 => Self::Times,
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
            121 => Self::Getpgid,
            124 => Self::Getsid,
            131 => Self::Sigaltstack,
            137 => Self::Statfs,
            138 => Self::Fstatfs,
            157 => Self::Prctl,
            158 => Self::ArchPrctl,
            186 => Self::Gettid,
            200 => Self::Tkill,
            202 => Self::Futex,
            204 => Self::SchedGetaffinity,
            217 => Self::Getdents64,
            218 => Self::SetTidAddress,
            228 => Self::ClockGettime,
            229 => Self::ClockGetres,
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
            280 => Self::Utimensat,
            288 => Self::Accept4,
            290 => Self::Eventfd2,
            291 => Self::EpollCreate1,
            292 => Self::Dup3,
            293 => Self::Pipe2,
            302 => Self::Prlimit64,
            309 => Self::Getcpu,
            316 => Self::Renameat2,
            318 => Self::Getrandom,
            324 => Self::Membarrier,
            332 => Self::Statx,
            334 => Self::Rseq,
            435 => Self::Clone3,
            436 => Self::CloseRange,
            437 => Self::Openat2,
            439 => Self::Faccessat2,
            441 => Self::EpollPwait2,
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
            Self::Fsync => Self::FSYNC,
            Self::Fdatasync => Self::FDATASYNC,
            Self::Poll => Self::POLL,
            Self::Lseek => Self::LSEEK,
            Self::Mmap => Self::MMAP,
            Self::Mprotect => Self::MPROTECT,
            Self::Munmap => Self::MUNMAP,
            Self::Brk => Self::BRK,
            Self::RtSigaction => Self::RT_SIGACTION,
            Self::RtSigprocmask => Self::RT_SIGPROCMASK,
            Self::RtSigreturn => Self::RT_SIGRETURN,
            Self::RtSigsuspend => Self::RT_SIGSUSPEND,
            Self::Ioctl => Self::IOCTL,
            Self::Pread64 => Self::PREAD64,
            Self::Pwrite64 => Self::PWRITE64,
            Self::Readv => Self::READV,
            Self::Writev => Self::WRITEV,
            Self::Access => Self::ACCESS,
            Self::Pipe => Self::PIPE,
            Self::Select => Self::SELECT,
            Self::SchedYield => Self::SCHED_YIELD,
            Self::Madvise => Self::MADVISE,
            Self::Gettimeofday => Self::GETTIMEOFDAY,
            Self::Times => Self::TIMES,
            Self::Getrlimit => Self::GETRLIMIT,
            Self::Getrusage => Self::GETRUSAGE,
            Self::Sysinfo => Self::SYSINFO,
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
            Self::Getpgid => Self::GETPGID,
            Self::Getsid => Self::GETSID,
            Self::Sigaltstack => Self::SIGALTSTACK,
            Self::Statfs => Self::STATFS,
            Self::Fstatfs => Self::FSTATFS,
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
            Self::Flock => Self::FLOCK,
            Self::Ftruncate => Self::FTRUNCATE,
            Self::Fallocate => Self::FALLOCATE,
            Self::Getdents => Self::GETDENTS,
            Self::Getcwd => Self::GETCWD,
            Self::Chdir => Self::CHDIR,
            Self::Fchdir => Self::FCHDIR,
            Self::Mkdir => Self::MKDIR,
            Self::Rmdir => Self::RMDIR,
            Self::Link => Self::LINK,
            Self::Unlink => Self::UNLINK,
            Self::Rename => Self::RENAME,
            Self::Readlink => Self::READLINK,
            Self::Symlink => Self::SYMLINK,
            Self::Chmod => Self::CHMOD,
            Self::Chown => Self::CHOWN,
            Self::Umask => Self::UMASK,
            Self::Prctl => Self::PRCTL,
            Self::ArchPrctl => Self::ARCH_PRCTL,
            Self::Gettid => Self::GETTID,
            Self::Tkill => Self::TKILL,
            Self::Futex => Self::FUTEX,
            Self::SchedGetaffinity => Self::SCHED_GETAFFINITY,
            Self::Getdents64 => Self::GETDENTS64,
            Self::SetTidAddress => Self::SET_TID_ADDRESS,
            Self::ClockGettime => Self::CLOCK_GETTIME,
            Self::ClockGetres => Self::CLOCK_GETRES,
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
            Self::Utimensat => Self::UTIMENSAT,
            Self::Ppoll => Self::PPOLL,
            Self::SetRobustList => Self::SET_ROBUST_LIST,
            Self::Eventfd2 => Self::EVENTFD2,
            Self::Accept4 => Self::ACCEPT4,
            Self::EpollCreate1 => Self::EPOLL_CREATE1,
            Self::Dup3 => Self::DUP3,
            Self::Pipe2 => Self::PIPE2,
            Self::Prlimit64 => Self::PRLIMIT64,
            Self::Getcpu => Self::GETCPU,
            Self::Renameat2 => Self::RENAMEAT2,
            Self::Getrandom => Self::GETRANDOM,
            Self::Membarrier => Self::MEMBARRIER,
            Self::Statx => Self::STATX,
            Self::Rseq => Self::RSEQ,
            Self::Clone3 => Self::CLONE3,
            Self::CloseRange => Self::CLOSE_RANGE,
            Self::Openat2 => Self::OPENAT2,
            Self::Faccessat2 => Self::FACCESSAT2,
            Self::EpollPwait2 => Self::EPOLL_PWAIT2,
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
            Self::Fsync => "fsync",
            Self::Fdatasync => "fdatasync",
            Self::Poll => "poll",
            Self::Lseek => "lseek",
            Self::Mmap => "mmap",
            Self::Mprotect => "mprotect",
            Self::Munmap => "munmap",
            Self::Brk => "brk",
            Self::RtSigaction => "rt_sigaction",
            Self::RtSigprocmask => "rt_sigprocmask",
            Self::RtSigreturn => "rt_sigreturn",
            Self::RtSigsuspend => "rt_sigsuspend",
            Self::Ioctl => "ioctl",
            Self::Pread64 => "pread64",
            Self::Pwrite64 => "pwrite64",
            Self::Readv => "readv",
            Self::Writev => "writev",
            Self::Access => "access",
            Self::Pipe => "pipe",
            Self::Select => "select",
            Self::SchedYield => "sched_yield",
            Self::Madvise => "madvise",
            Self::Gettimeofday => "gettimeofday",
            Self::Times => "times",
            Self::Getrlimit => "getrlimit",
            Self::Getrusage => "getrusage",
            Self::Sysinfo => "sysinfo",
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
            Self::Getpgid => "getpgid",
            Self::Getsid => "getsid",
            Self::Sigaltstack => "sigaltstack",
            Self::Statfs => "statfs",
            Self::Fstatfs => "fstatfs",
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
            Self::Flock => "flock",
            Self::Ftruncate => "ftruncate",
            Self::Fallocate => "fallocate",
            Self::Getdents => "getdents",
            Self::Getcwd => "getcwd",
            Self::Chdir => "chdir",
            Self::Fchdir => "fchdir",
            Self::Mkdir => "mkdir",
            Self::Rmdir => "rmdir",
            Self::Link => "link",
            Self::Unlink => "unlink",
            Self::Rename => "rename",
            Self::Readlink => "readlink",
            Self::Symlink => "symlink",
            Self::Chmod => "chmod",
            Self::Chown => "chown",
            Self::Umask => "umask",
            Self::Prctl => "prctl",
            Self::ArchPrctl => "arch_prctl",
            Self::Gettid => "gettid",
            Self::Tkill => "tkill",
            Self::Futex => "futex",
            Self::SchedGetaffinity => "sched_getaffinity",
            Self::Getdents64 => "getdents64",
            Self::SetTidAddress => "set_tid_address",
            Self::ClockGettime => "clock_gettime",
            Self::ClockGetres => "clock_getres",
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
            Self::Utimensat => "utimensat",
            Self::Ppoll => "ppoll",
            Self::SetRobustList => "set_robust_list",
            Self::Eventfd2 => "eventfd2",
            Self::Accept4 => "accept4",
            Self::EpollCreate1 => "epoll_create1",
            Self::Dup3 => "dup3",
            Self::Pipe2 => "pipe2",
            Self::Prlimit64 => "prlimit64",
            Self::Getcpu => "getcpu",
            Self::Renameat2 => "renameat2",
            Self::Getrandom => "getrandom",
            Self::Membarrier => "membarrier",
            Self::Statx => "statx",
            Self::Rseq => "rseq",
            Self::Clone3 => "clone3",
            Self::CloseRange => "close_range",
            Self::Openat2 => "openat2",
            Self::Faccessat2 => "faccessat2",
            Self::EpollPwait2 => "epoll_pwait2",
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
        assert_eq!(Syscall::from_number(Syscall::EVENTFD2), Syscall::Eventfd2);
        assert_eq!(Syscall::from_number(Syscall::STATX), Syscall::Statx);
        assert_eq!(Syscall::ExitGroup.number().raw(), 231);
        assert_eq!(Syscall::ClockGettime.name(), "clock_gettime");

        for (number, syscall, name) in [
            (Syscall::PREAD64, Syscall::Pread64, "pread64"),
            (Syscall::PWRITE64, Syscall::Pwrite64, "pwrite64"),
            (Syscall::FSYNC, Syscall::Fsync, "fsync"),
            (Syscall::FDATASYNC, Syscall::Fdatasync, "fdatasync"),
            (Syscall::SELECT, Syscall::Select, "select"),
            (Syscall::SCHED_YIELD, Syscall::SchedYield, "sched_yield"),
            (Syscall::MADVISE, Syscall::Madvise, "madvise"),
            (Syscall::GETTIMEOFDAY, Syscall::Gettimeofday, "gettimeofday"),
            (Syscall::TIMES, Syscall::Times, "times"),
            (Syscall::GETRLIMIT, Syscall::Getrlimit, "getrlimit"),
            (Syscall::GETRUSAGE, Syscall::Getrusage, "getrusage"),
            (Syscall::SYSINFO, Syscall::Sysinfo, "sysinfo"),
            (Syscall::GETPGID, Syscall::Getpgid, "getpgid"),
            (Syscall::GETSID, Syscall::Getsid, "getsid"),
            (
                Syscall::RT_SIGSUSPEND,
                Syscall::RtSigsuspend,
                "rt_sigsuspend",
            ),
            (Syscall::SIGALTSTACK, Syscall::Sigaltstack, "sigaltstack"),
            (Syscall::STATFS, Syscall::Statfs, "statfs"),
            (Syscall::FSTATFS, Syscall::Fstatfs, "fstatfs"),
            (Syscall::FCHDIR, Syscall::Fchdir, "fchdir"),
            (Syscall::FLOCK, Syscall::Flock, "flock"),
            (Syscall::FALLOCATE, Syscall::Fallocate, "fallocate"),
            (Syscall::PRCTL, Syscall::Prctl, "prctl"),
            (Syscall::TKILL, Syscall::Tkill, "tkill"),
            (
                Syscall::SCHED_GETAFFINITY,
                Syscall::SchedGetaffinity,
                "sched_getaffinity",
            ),
            (Syscall::CLOCK_GETRES, Syscall::ClockGetres, "clock_getres"),
            (Syscall::PRLIMIT64, Syscall::Prlimit64, "prlimit64"),
            (Syscall::GETCPU, Syscall::Getcpu, "getcpu"),
            (Syscall::MEMBARRIER, Syscall::Membarrier, "membarrier"),
            (Syscall::RSEQ, Syscall::Rseq, "rseq"),
            (Syscall::CLONE3, Syscall::Clone3, "clone3"),
            (Syscall::CLOSE_RANGE, Syscall::CloseRange, "close_range"),
            (Syscall::OPENAT2, Syscall::Openat2, "openat2"),
            (Syscall::FACCESSAT2, Syscall::Faccessat2, "faccessat2"),
            (Syscall::EPOLL_PWAIT2, Syscall::EpollPwait2, "epoll_pwait2"),
        ] {
            assert_eq!(Syscall::from_number(number), syscall);
            assert_eq!(syscall.number(), number);
            assert_eq!(syscall.name(), name);
        }
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
