use std::collections::{BTreeMap, BTreeSet};

use mcr_sys::{
    GuestAddress, GuestPid, GuestTid, LINUX_SIG_BLOCK, LINUX_SIG_SETMASK, LINUX_SIG_UNBLOCK,
    Wait4SyscallArgs,
};

use crate::{GuestFdTable, GuestImageState, TaskError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitState {
    Running,
    Exited { status: i32 },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestSignalAction {
    action: GuestAddress,
    flags: u64,
    restorer: GuestAddress,
    mask: u64,
}

impl GuestSignalAction {
    #[must_use]
    pub const fn new(action: GuestAddress) -> Self {
        Self {
            action,
            flags: 0,
            restorer: 0,
            mask: 0,
        }
    }

    #[must_use]
    pub const fn from_kernel_sigaction(
        action: GuestAddress,
        flags: u64,
        restorer: GuestAddress,
        mask: u64,
    ) -> Self {
        Self {
            action,
            flags,
            restorer,
            mask,
        }
    }

    #[must_use]
    pub const fn action(self) -> GuestAddress {
        self.action
    }

    #[must_use]
    pub const fn flags(self) -> u64 {
        self.flags
    }

    #[must_use]
    pub const fn restorer(self) -> GuestAddress {
        self.restorer
    }

    #[must_use]
    pub const fn mask(self) -> u64 {
        self.mask
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignalState {
    actions: BTreeMap<u32, GuestSignalAction>,
    blocked: u64,
}

impl SignalState {
    #[must_use]
    pub fn action(&self, signal: u32) -> Option<GuestSignalAction> {
        self.actions.get(&signal).copied()
    }

    #[must_use]
    pub const fn blocked(&self) -> u64 {
        self.blocked
    }

    pub(crate) fn set_action(&mut self, signal: u32, action: GuestSignalAction) {
        self.actions.insert(signal, action);
    }

    pub(crate) fn apply_mask(&mut self, how: u32, mask: u64) -> Result<(), TaskError> {
        match how {
            LINUX_SIG_BLOCK => {
                self.blocked |= mask;
                Ok(())
            }
            LINUX_SIG_UNBLOCK => {
                self.blocked &= !mask;
                Ok(())
            }
            LINUX_SIG_SETMASK => {
                self.blocked = mask;
                Ok(())
            }
            _ => Err(TaskError::InvalidSignalMaskHow(how)),
        }
    }

    pub fn set_blocked(&mut self, mask: u64) {
        self.blocked = mask;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitedChild {
    pid: GuestPid,
    status: i32,
    wait_status: u32,
}

impl WaitedChild {
    #[must_use]
    pub const fn new(pid: GuestPid, status: i32) -> Self {
        Self {
            pid,
            status,
            wait_status: linux_wait_exit_status(status),
        }
    }

    #[must_use]
    pub const fn pid(self) -> GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn status(self) -> i32 {
        self.status
    }

    #[must_use]
    pub const fn wait_status(self) -> u32 {
        self.wait_status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletedWait {
    tid: GuestTid,
    pid: GuestPid,
    args: Wait4SyscallArgs,
    waited: WaitedChild,
}

impl CompletedWait {
    #[must_use]
    pub const fn new(
        tid: GuestTid,
        pid: GuestPid,
        args: Wait4SyscallArgs,
        waited: WaitedChild,
    ) -> Self {
        Self {
            tid,
            pid,
            args,
            waited,
        }
    }

    #[must_use]
    pub const fn tid(self) -> GuestTid {
        self.tid
    }

    #[must_use]
    pub const fn pid(self) -> GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn args(self) -> Wait4SyscallArgs {
        self.args
    }

    #[must_use]
    pub const fn waited(self) -> WaitedChild {
        self.waited
    }
}

const fn linux_wait_exit_status(status: i32) -> u32 {
    ((status as u32) & 0xff) << 8
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestProcess {
    pub(crate) pid: GuestPid,
    pub(crate) parent: Option<GuestPid>,
    pub(crate) pgid: GuestPid,
    pub(crate) sid: GuestPid,
    pub(crate) image: GuestImageState,
    pub(crate) files: GuestFdTable,
    pub(crate) signals: SignalState,
    pub(crate) pending_signals: BTreeSet<u32>,
    pub(crate) children: BTreeSet<GuestPid>,
    pub(crate) exit_state: ExitState,
}

impl GuestProcess {
    #[must_use]
    pub const fn pid(&self) -> GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn parent(&self) -> Option<GuestPid> {
        self.parent
    }

    #[must_use]
    pub const fn pgid(&self) -> GuestPid {
        self.pgid
    }

    #[must_use]
    pub const fn sid(&self) -> GuestPid {
        self.sid
    }

    #[must_use]
    pub fn image(&self) -> &GuestImageState {
        &self.image
    }

    #[must_use]
    pub const fn files(&self) -> &GuestFdTable {
        &self.files
    }

    #[must_use]
    pub const fn files_mut(&mut self) -> &mut GuestFdTable {
        &mut self.files
    }

    #[must_use]
    pub const fn signals(&self) -> &SignalState {
        &self.signals
    }

    #[must_use]
    pub const fn signals_mut(&mut self) -> &mut SignalState {
        &mut self.signals
    }

    #[must_use]
    pub fn pending_signals(&self) -> &BTreeSet<u32> {
        &self.pending_signals
    }

    #[must_use]
    pub fn children(&self) -> &BTreeSet<GuestPid> {
        &self.children
    }

    #[must_use]
    pub const fn exit_state(&self) -> ExitState {
        self.exit_state
    }
}
