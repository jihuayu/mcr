use std::collections::BTreeSet;

use mcr_elf::GuestMemoryImage;
use mcr_sys::{GuestAddress, GuestPid, GuestTid, Wait4SyscallArgs};

use crate::{GprState, TlsState};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FutexWaitKey {
    pid: Option<GuestPid>,
    uaddr: GuestAddress,
}

impl FutexWaitKey {
    #[must_use]
    pub const fn new(pid: GuestPid, uaddr: GuestAddress, private: bool) -> Self {
        Self {
            pid: if private { Some(pid) } else { None },
            uaddr,
        }
    }

    #[must_use]
    pub const fn uaddr(self) -> GuestAddress {
        self.uaddr
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    Runnable,
    WaitingForChild { args: Wait4SyscallArgs },
    WaitingForVfork { child_pid: GuestPid },
    WaitingForSignalSet { mask: u64 },
    WaitingForSignalSuspend { mask: u64 },
    WaitingForFd { fd: i32, write: bool },
    WaitingForFutex { key: FutexWaitKey },
    WaitingForSleep,
    Exited { status: i32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestTask {
    pub(crate) tid: GuestTid,
    pub(crate) pid: GuestPid,
    pub(crate) regs: GprState,
    pub(crate) tls: TlsState,
    pub(crate) state: TaskState,
    pub(crate) robust_list: Option<GuestAddress>,
    pub(crate) clear_child_tid: Option<GuestAddress>,
    pub(crate) signal_mask: u64,
    pub(crate) pending_signals: BTreeSet<u32>,
    pub(crate) pending_signal_delivery: Option<u32>,
}

impl GuestTask {
    pub(crate) fn initial(tid: GuestTid, pid: GuestPid, image: &GuestMemoryImage) -> Self {
        Self {
            tid,
            pid,
            regs: GprState::new(image.entrypoint(), image.initial_stack_pointer()),
            tls: TlsState::new(),
            state: TaskState::Runnable,
            robust_list: None,
            clear_child_tid: None,
            signal_mask: 0,
            pending_signals: BTreeSet::new(),
            pending_signal_delivery: None,
        }
    }

    #[must_use]
    pub const fn tid(&self) -> GuestTid {
        self.tid
    }

    #[must_use]
    pub const fn pid(&self) -> GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn regs(&self) -> GprState {
        self.regs
    }

    pub fn set_regs(&mut self, regs: GprState) {
        self.regs = regs;
    }

    #[must_use]
    pub const fn tls(&self) -> TlsState {
        self.tls
    }

    #[must_use]
    pub const fn state(&self) -> TaskState {
        self.state
    }

    #[must_use]
    pub const fn robust_list(&self) -> Option<GuestAddress> {
        self.robust_list
    }

    #[must_use]
    pub const fn clear_child_tid(&self) -> Option<GuestAddress> {
        self.clear_child_tid
    }

    #[must_use]
    pub const fn signal_mask(&self) -> u64 {
        self.signal_mask
    }

    pub fn set_signal_mask(&mut self, signal_mask: u64) {
        self.signal_mask = signal_mask;
    }

    pub fn take_clear_child_tid(&mut self) -> Option<GuestAddress> {
        self.clear_child_tid.take()
    }

    pub fn take_pending_signal_delivery(&mut self) -> Option<u32> {
        self.pending_signal_delivery.take()
    }
}
