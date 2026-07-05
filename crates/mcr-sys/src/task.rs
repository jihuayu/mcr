use crate::abi::GuestAddress;

pub const LINUX_SIGCHLD: u64 = 17;
pub const LINUX_KERNEL_SIGSET_SIZE: u64 = 8;
pub const LINUX_SIG_BLOCK: u32 = 0;
pub const LINUX_SIG_UNBLOCK: u32 = 1;
pub const LINUX_SIG_SETMASK: u32 = 2;
pub const LINUX_CLONE_VM: u64 = 0x0000_0100;
pub const LINUX_CLONE_FS: u64 = 0x0000_0200;
pub const LINUX_CLONE_FILES: u64 = 0x0000_0400;
pub const LINUX_CLONE_SIGHAND: u64 = 0x0000_0800;
pub const LINUX_CLONE_VFORK: u64 = 0x0000_4000;
pub const LINUX_CLONE_THREAD: u64 = 0x0001_0000;
pub const LINUX_CLONE_SYSVSEM: u64 = 0x0004_0000;
pub const LINUX_CLONE_SETTLS: u64 = 0x0008_0000;
pub const LINUX_CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const LINUX_CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const LINUX_CLONE_DETACHED: u64 = 0x0040_0000;
pub const LINUX_CLONE_CHILD_SETTID: u64 = 0x0100_0000;
pub const LINUX_CLONE_EXIT_SIGNAL_MASK: u64 = 0x0000_00ff;
pub const LINUX_FUTEX_WAIT: u32 = 0;
pub const LINUX_FUTEX_WAKE: u32 = 1;
pub const LINUX_FUTEX_REQUEUE: u32 = 3;
pub const LINUX_FUTEX_CMP_REQUEUE: u32 = 4;
pub const LINUX_FUTEX_CMD_MASK: u32 = 0x7f;
pub const LINUX_FUTEX_PRIVATE_FLAG: u32 = 0x80;
pub const LINUX_FUTEX_CLOCK_REALTIME: u32 = 0x100;
pub const LINUX_ROBUST_LIST_HEAD_SIZE: u64 = 24;
pub const LINUX_WNOHANG: u32 = 0x0000_0001;
pub const LINUX_WAIT_SUPPORTED_OPTIONS: u32 = LINUX_WNOHANG;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloneSyscallArgs {
    pub flags: u64,
    pub child_stack: GuestAddress,
    pub parent_tid: GuestAddress,
    pub child_tid: GuestAddress,
    pub tls: GuestAddress,
}

impl CloneSyscallArgs {
    #[must_use]
    pub const fn new(
        flags: u64,
        child_stack: GuestAddress,
        parent_tid: GuestAddress,
        child_tid: GuestAddress,
        tls: GuestAddress,
    ) -> Self {
        Self {
            flags,
            child_stack,
            parent_tid,
            child_tid,
            tls,
        }
    }

    #[must_use]
    pub const fn exit_signal(self) -> u64 {
        self.flags & LINUX_CLONE_EXIT_SIGNAL_MASK
    }

    #[must_use]
    pub const fn has_clone_vm(self) -> bool {
        self.flags & LINUX_CLONE_VM != 0
    }

    #[must_use]
    pub const fn has_clone_vfork(self) -> bool {
        self.flags & LINUX_CLONE_VFORK != 0
    }

    #[must_use]
    pub const fn has_clone_thread(self) -> bool {
        self.flags & LINUX_CLONE_THREAD != 0
    }

    #[must_use]
    pub const fn has_clone_settls(self) -> bool {
        self.flags & LINUX_CLONE_SETTLS != 0
    }

    #[must_use]
    pub const fn has_clone_parent_settid(self) -> bool {
        self.flags & LINUX_CLONE_PARENT_SETTID != 0
    }

    #[must_use]
    pub const fn has_clone_child_cleartid(self) -> bool {
        self.flags & LINUX_CLONE_CHILD_CLEARTID != 0
    }

    #[must_use]
    pub const fn has_clone_child_settid(self) -> bool {
        self.flags & LINUX_CLONE_CHILD_SETTID != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtSigactionSyscallArgs {
    pub sig: u32,
    pub act: GuestAddress,
    pub oldact: GuestAddress,
    pub sigsetsize: u64,
}

impl RtSigactionSyscallArgs {
    #[must_use]
    pub const fn new(sig: u32, act: GuestAddress, oldact: GuestAddress, sigsetsize: u64) -> Self {
        Self {
            sig,
            act,
            oldact,
            sigsetsize,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtSigprocmaskSyscallArgs {
    pub how: u32,
    pub set: GuestAddress,
    pub oldset: GuestAddress,
    pub sigsetsize: u64,
}

impl RtSigprocmaskSyscallArgs {
    #[must_use]
    pub const fn new(how: u32, set: GuestAddress, oldset: GuestAddress, sigsetsize: u64) -> Self {
        Self {
            how,
            set,
            oldset,
            sigsetsize,
        }
    }

    #[must_use]
    pub const fn supported_how(self) -> bool {
        matches!(
            self.how,
            LINUX_SIG_BLOCK | LINUX_SIG_UNBLOCK | LINUX_SIG_SETMASK
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KillSyscallArgs {
    pub pid: i32,
    pub sig: u32,
}

impl KillSyscallArgs {
    #[must_use]
    pub const fn new(pid: i32, sig: u32) -> Self {
        Self { pid, sig }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TgkillSyscallArgs {
    pub tgid: i32,
    pub tid: i32,
    pub sig: u32,
}

impl TgkillSyscallArgs {
    #[must_use]
    pub const fn new(tgid: i32, tid: i32, sig: u32) -> Self {
        Self { tgid, tid, sig }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TkillSyscallArgs {
    pub tid: i32,
    pub sig: u32,
}

impl TkillSyscallArgs {
    #[must_use]
    pub const fn new(tid: i32, sig: u32) -> Self {
        Self { tid, sig }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexSyscallArgs {
    pub uaddr: GuestAddress,
    pub op: u32,
    pub val: u32,
    pub timeout: GuestAddress,
    pub uaddr2: GuestAddress,
    pub val3: u32,
}

impl FutexSyscallArgs {
    #[must_use]
    pub const fn new(
        uaddr: GuestAddress,
        op: u32,
        val: u32,
        timeout: GuestAddress,
        uaddr2: GuestAddress,
        val3: u32,
    ) -> Self {
        Self {
            uaddr,
            op,
            val,
            timeout,
            uaddr2,
            val3,
        }
    }

    #[must_use]
    pub const fn command(self) -> u32 {
        self.op & LINUX_FUTEX_CMD_MASK
    }

    #[must_use]
    pub const fn is_private(self) -> bool {
        self.op & LINUX_FUTEX_PRIVATE_FLAG != 0
    }

    #[must_use]
    pub const fn has_unsupported_flags(self) -> bool {
        self.op & !(LINUX_FUTEX_CMD_MASK | LINUX_FUTEX_PRIVATE_FLAG | LINUX_FUTEX_CLOCK_REALTIME)
            != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetTidAddressSyscallArgs {
    pub tidptr: GuestAddress,
}

impl SetTidAddressSyscallArgs {
    #[must_use]
    pub const fn new(tidptr: GuestAddress) -> Self {
        Self { tidptr }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetRobustListSyscallArgs {
    pub head: GuestAddress,
    pub len: u64,
}

impl SetRobustListSyscallArgs {
    #[must_use]
    pub const fn new(head: GuestAddress, len: u64) -> Self {
        Self { head, len }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wait4SyscallArgs {
    pub pid: i32,
    pub wstatus: GuestAddress,
    pub options: u32,
    pub rusage: GuestAddress,
}

impl Wait4SyscallArgs {
    #[must_use]
    pub const fn new(pid: i32, wstatus: GuestAddress, options: u32, rusage: GuestAddress) -> Self {
        Self {
            pid,
            wstatus,
            options,
            rusage,
        }
    }

    #[must_use]
    pub const fn no_hang(self) -> bool {
        self.options & LINUX_WNOHANG != 0
    }

    #[must_use]
    pub const fn has_unsupported_options(self) -> bool {
        self.options & !LINUX_WAIT_SUPPORTED_OPTIONS != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_syscall_args_decode_common_flags() {
        let args = CloneSyscallArgs::new(
            LINUX_CLONE_VM | LINUX_CLONE_VFORK | LINUX_SIGCHLD,
            0x7000,
            0x7100,
            0x7200,
            0x7300,
        );

        assert_eq!(args.exit_signal(), LINUX_SIGCHLD);
        assert!(args.has_clone_vm());
        assert!(args.has_clone_vfork());
        assert_eq!(args.child_stack, 0x7000);
        assert_eq!(args.parent_tid, 0x7100);
        assert_eq!(args.child_tid, 0x7200);
        assert_eq!(args.tls, 0x7300);
    }

    #[test]
    fn wait4_syscall_args_decode_options() {
        let args = Wait4SyscallArgs::new(-1, 0x8000, LINUX_WNOHANG, 0);

        assert!(args.no_hang());
        assert!(!args.has_unsupported_options());
        assert_eq!(args.pid, -1);
        assert_eq!(args.wstatus, 0x8000);
    }

    #[test]
    fn signal_syscall_args_decode_common_shapes() {
        let action = RtSigactionSyscallArgs::new(2, 0x1000, 0x2000, LINUX_KERNEL_SIGSET_SIZE);
        let mask = RtSigprocmaskSyscallArgs::new(LINUX_SIG_SETMASK, 0x3000, 0x4000, 8);
        let kill = KillSyscallArgs::new(-1, 15);
        let tgkill = TgkillSyscallArgs::new(7, 8, 9);
        let tkill = TkillSyscallArgs::new(8, 9);

        assert_eq!(action.sig, 2);
        assert_eq!(action.act, 0x1000);
        assert_eq!(action.oldact, 0x2000);
        assert_eq!(action.sigsetsize, 8);
        assert!(mask.supported_how());
        assert_eq!(kill.pid, -1);
        assert_eq!(kill.sig, 15);
        assert_eq!(tgkill.tgid, 7);
        assert_eq!(tgkill.tid, 8);
        assert_eq!(tgkill.sig, 9);
        assert_eq!(tkill.tid, 8);
        assert_eq!(tkill.sig, 9);
    }

    #[test]
    fn futex_syscall_args_decode_private_wait_wake() {
        let wait = FutexSyscallArgs::new(
            0x1000,
            LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG,
            7,
            0x2000,
            0,
            0,
        );

        assert_eq!(wait.command(), LINUX_FUTEX_WAIT);
        assert!(wait.is_private());
        assert!(!wait.has_unsupported_flags());
        assert_eq!(wait.val, 7);
        assert_eq!(SetTidAddressSyscallArgs::new(0x3000).tidptr, 0x3000);
        assert_eq!(
            SetRobustListSyscallArgs::new(0x4000, LINUX_ROBUST_LIST_HEAD_SIZE).len,
            24
        );
    }
}
