use std::collections::BTreeSet;

use mcr_sys::{
    CloneSyscallArgs, GuestAddress, GuestPid, GuestTid, LINUX_CLONE_CHILD_CLEARTID,
    LINUX_CLONE_CHILD_SETTID, LINUX_CLONE_DETACHED, LINUX_CLONE_EXIT_SIGNAL_MASK,
    LINUX_CLONE_FILES, LINUX_CLONE_FS, LINUX_CLONE_PARENT_SETTID, LINUX_CLONE_SETTLS,
    LINUX_CLONE_SIGHAND, LINUX_CLONE_SYSVSEM, LINUX_CLONE_THREAD, LINUX_CLONE_VFORK,
    LINUX_CLONE_VM, LINUX_SIGCHLD, LinuxErrno, SyscallOutcome,
};

use super::{GuestKernel, current_syscall_return_rip};
use crate::{ExitState, GprState, GuestProcess, TaskError, TaskState};

impl GuestKernel {
    pub fn fork_current(&mut self, tid: GuestTid) -> SyscallOutcome {
        self.fork_like_current(tid, "fork", current_syscall_return_rip(self, tid))
    }

    pub fn vfork_current(&mut self, tid: GuestTid) -> SyscallOutcome {
        self.fork_like_current_and_maybe_block_parent(
            tid,
            "vfork",
            current_syscall_return_rip(self, tid),
            true,
        )
    }

    pub fn clone_current(&mut self, tid: GuestTid, args: CloneSyscallArgs) -> SyscallOutcome {
        self.clone_current_with_return(tid, args, current_syscall_return_rip(self, tid))
    }

    pub fn fork_current_with_child_regs(
        &mut self,
        tid: GuestTid,
        child_regs: GprState,
    ) -> SyscallOutcome {
        self.fork_like_current_with_child_regs(tid, "fork", child_regs)
    }

    pub fn vfork_current_with_child_regs(
        &mut self,
        tid: GuestTid,
        child_regs: GprState,
    ) -> SyscallOutcome {
        self.fork_like_current_with_child_regs_and_maybe_block_parent(
            tid, "vfork", child_regs, true,
        )
    }

    pub fn clone_current_with_child_regs(
        &mut self,
        tid: GuestTid,
        args: CloneSyscallArgs,
        child_regs: GprState,
    ) -> SyscallOutcome {
        if args.has_clone_thread() {
            return self.thread_current_with_child_regs(tid, args, child_regs);
        }
        if !is_supported_fork_like_clone(args.flags) {
            return TaskError::InvalidCloneFlags(args.flags).into_outcome();
        }

        let child_regs = clone_fork_like_child_regs(args, child_regs);
        self.fork_like_current_with_child_regs_and_maybe_block_parent(
            tid,
            "clone",
            child_regs,
            args.has_clone_vfork(),
        )
        .with_decoded_field("clone_flags", format!("{:#x}", args.flags))
    }

    pub(super) fn clone_current_with_return(
        &mut self,
        tid: GuestTid,
        args: CloneSyscallArgs,
        child_return_rip: GuestAddress,
    ) -> SyscallOutcome {
        if args.has_clone_thread() {
            let Some(parent_regs) = self.task(tid).map(|task| task.regs) else {
                return SyscallOutcome::errno(LinuxErrno::ESRCH);
            };
            return self.thread_current_with_child_regs(
                tid,
                args,
                parent_regs.with_syscall_return(child_return_rip, 0),
            );
        }
        if !is_supported_fork_like_clone(args.flags) {
            return TaskError::InvalidCloneFlags(args.flags).into_outcome();
        }

        self.clone_fork_like_current(tid, args, child_return_rip)
            .with_decoded_field("clone_flags", format!("{:#x}", args.flags))
    }

    pub fn fork_child(&mut self, tid: GuestTid) -> Result<GuestPid, TaskError> {
        let (child_pid, _) = self.fork_child_task(tid)?;

        Ok(child_pid)
    }

    fn fork_child_task(&mut self, tid: GuestTid) -> Result<(GuestPid, GuestTid), TaskError> {
        let parent_task = self.task(tid).cloned().ok_or(TaskError::UnknownTid(tid))?;
        let parent_pid = parent_task.pid;
        let parent = self
            .process(parent_pid)
            .cloned()
            .ok_or(TaskError::UnknownPid(parent_pid))?;
        if !matches!(parent.exit_state, ExitState::Running) {
            return Err(TaskError::UnknownPid(parent_pid));
        }

        let child_pid = self.allocate_pid()?;
        let child_tid = self.allocate_tid()?;
        let mut child_task = parent_task;
        child_task.pid = child_pid;
        child_task.tid = child_tid;
        child_task.state = TaskState::Runnable;

        self.processes.insert(
            child_pid,
            GuestProcess {
                pid: child_pid,
                parent: Some(parent_pid),
                pgid: parent.pgid,
                sid: parent.sid,
                image: parent.image,
                files: parent.files,
                signals: parent.signals,
                children: BTreeSet::new(),
                exit_state: ExitState::Running,
            },
        );
        self.insert_task(child_task);
        self.process_mut(parent_pid)
            .ok_or(TaskError::UnknownPid(parent_pid))?
            .children
            .insert(child_pid);

        Ok((child_pid, child_tid))
    }

    pub(super) fn fork_like_current(
        &mut self,
        tid: GuestTid,
        syscall: &'static str,
        child_return_rip: GuestAddress,
    ) -> SyscallOutcome {
        self.fork_like_current_and_maybe_block_parent(tid, syscall, child_return_rip, false)
    }

    fn fork_like_current_and_maybe_block_parent(
        &mut self,
        tid: GuestTid,
        syscall: &'static str,
        child_return_rip: GuestAddress,
        block_parent_for_vfork: bool,
    ) -> SyscallOutcome {
        match self.fork_child_task(tid) {
            Ok((child_pid, child_tid)) => {
                if let Some(child_task) = self.task_mut(child_tid) {
                    child_task.regs = child_task.regs.with_syscall_return(child_return_rip, 0);
                }
                if block_parent_for_vfork {
                    self.set_task_state(tid, TaskState::WaitingForVfork { child_pid });
                }
                SyscallOutcome::success(u64::from(child_pid))
                    .with_decoded_field("guest_pid", child_pid.to_string())
                    .with_decoded_field("fork_kind", syscall)
            }
            Err(error) => error.into_outcome(),
        }
    }

    fn fork_like_current_with_child_regs(
        &mut self,
        tid: GuestTid,
        syscall: &'static str,
        child_regs: GprState,
    ) -> SyscallOutcome {
        self.fork_like_current_with_child_regs_and_maybe_block_parent(
            tid, syscall, child_regs, false,
        )
    }

    fn fork_like_current_with_child_regs_and_maybe_block_parent(
        &mut self,
        tid: GuestTid,
        syscall: &'static str,
        child_regs: GprState,
        block_parent_for_vfork: bool,
    ) -> SyscallOutcome {
        match self.fork_child_task(tid) {
            Ok((child_pid, child_tid)) => {
                if let Some(child_task) = self.task_mut(child_tid) {
                    child_task.regs = child_regs;
                }
                if block_parent_for_vfork {
                    self.set_task_state(tid, TaskState::WaitingForVfork { child_pid });
                }
                SyscallOutcome::success(u64::from(child_pid))
                    .with_decoded_field("guest_pid", child_pid.to_string())
                    .with_decoded_field("fork_kind", syscall)
            }
            Err(error) => error.into_outcome(),
        }
    }

    fn clone_fork_like_current(
        &mut self,
        tid: GuestTid,
        args: CloneSyscallArgs,
        child_return_rip: GuestAddress,
    ) -> SyscallOutcome {
        let Some(parent_regs) = self.task(tid).map(|task| task.regs) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        let child_regs =
            clone_fork_like_child_regs(args, parent_regs.with_syscall_return(child_return_rip, 0));
        self.fork_like_current_with_child_regs_and_maybe_block_parent(
            tid,
            "clone",
            child_regs,
            args.has_clone_vfork(),
        )
    }

    pub(super) fn resume_vfork_parent(&mut self, child_pid: GuestPid) {
        let Some(parent_pid) = self.process(child_pid).and_then(GuestProcess::parent) else {
            return;
        };
        let waiting_tids = self
            .tasks
            .values()
            .filter_map(|task| {
                (task.pid == parent_pid
                    && matches!(task.state, TaskState::WaitingForVfork { child_pid: waiting_pid } if waiting_pid == child_pid))
                .then_some(task.tid)
            })
            .collect::<Vec<_>>();
        for tid in waiting_tids {
            self.set_task_state(tid, TaskState::Runnable);
        }
    }

    fn thread_current_with_child_regs(
        &mut self,
        tid: GuestTid,
        args: CloneSyscallArgs,
        mut child_regs: GprState,
    ) -> SyscallOutcome {
        if !is_supported_thread_clone(args.flags) {
            return TaskError::InvalidCloneFlags(args.flags).into_outcome();
        }

        let Some(parent_task) = self.task(tid).cloned() else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if !self.processes.contains_key(&parent_task.pid) {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }

        let child_tid = match self.allocate_tid() {
            Ok(tid) => tid,
            Err(error) => return error.into_outcome(),
        };

        if args.child_stack != 0 {
            child_regs.rsp = args.child_stack;
        }

        let mut child_task = parent_task;
        child_task.tid = child_tid;
        child_task.regs = child_regs;
        child_task.state = TaskState::Runnable;
        child_task.robust_list = None;
        child_task.clear_child_tid =
            (args.has_clone_child_cleartid() && args.child_tid != 0).then_some(args.child_tid);
        if args.has_clone_settls() {
            child_task.tls.fs_base = args.tls;
        }

        self.insert_task(child_task);

        SyscallOutcome::success(u64::from(child_tid))
            .with_decoded_field("guest_tid", child_tid.to_string())
            .with_decoded_field("clone_kind", "thread")
            .with_decoded_field("clone_flags", format!("{:#x}", args.flags))
    }
}

const fn is_supported_fork_like_clone(flags: u64) -> bool {
    let semantic_flags = flags & !LINUX_CLONE_EXIT_SIGNAL_MASK;
    let exit_signal = flags & LINUX_CLONE_EXIT_SIGNAL_MASK;
    (exit_signal == 0 || exit_signal == LINUX_SIGCHLD)
        && (semantic_flags == 0 || semantic_flags == (LINUX_CLONE_VM | LINUX_CLONE_VFORK))
        && flags & !(LINUX_CLONE_EXIT_SIGNAL_MASK | LINUX_CLONE_VM | LINUX_CLONE_VFORK) == 0
}

fn clone_fork_like_child_regs(args: CloneSyscallArgs, mut child_regs: GprState) -> GprState {
    if args.child_stack != 0 {
        child_regs.rsp = args.child_stack;
    }
    child_regs
}

const fn is_supported_thread_clone(flags: u64) -> bool {
    const REQUIRED: u64 = LINUX_CLONE_VM
        | LINUX_CLONE_FS
        | LINUX_CLONE_FILES
        | LINUX_CLONE_SIGHAND
        | LINUX_CLONE_THREAD;
    const OPTIONAL: u64 = LINUX_CLONE_SYSVSEM
        | LINUX_CLONE_SETTLS
        | LINUX_CLONE_PARENT_SETTID
        | LINUX_CLONE_CHILD_CLEARTID
        | LINUX_CLONE_CHILD_SETTID
        | LINUX_CLONE_DETACHED;
    let exit_signal = flags & LINUX_CLONE_EXIT_SIGNAL_MASK;
    exit_signal == 0 && flags & REQUIRED == REQUIRED && flags & !(REQUIRED | OPTIONAL) == 0
}
