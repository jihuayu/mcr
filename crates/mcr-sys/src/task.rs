use crate::abi::GuestAddress;

pub const LINUX_SIGCHLD: u64 = 17;
pub const LINUX_CLONE_VM: u64 = 0x0000_0100;
pub const LINUX_CLONE_VFORK: u64 = 0x0000_4000;
pub const LINUX_CLONE_EXIT_SIGNAL_MASK: u64 = 0x0000_00ff;
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
}
