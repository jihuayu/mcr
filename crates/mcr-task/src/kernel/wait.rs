use mcr_sys::{GuestAddress, GuestPid, GuestTid, LinuxErrno, SyscallOutcome, Wait4SyscallArgs};

use super::{GuestKernel, current_syscall_return_rip};
use crate::{
    CompletedWait, ExitState, FutexWaitKey, GuestProcess, TaskError, TaskState, WaitedChild,
};

impl GuestKernel {
    pub fn wait4_child(
        &mut self,
        parent_pid: GuestPid,
        args: Wait4SyscallArgs,
    ) -> Result<Option<WaitedChild>, TaskError> {
        if args.has_unsupported_options() {
            return Err(TaskError::InvalidWaitOptions(args.options));
        }

        let child_pid = self.exited_waitable_child(parent_pid, args.pid)?;
        match child_pid {
            Some(child_pid) => self.reap_child(parent_pid, child_pid).map(Some),
            None if self.has_waitable_child(parent_pid, args.pid)? && args.no_hang() => Ok(None),
            None if self.has_waitable_child(parent_pid, args.pid)? => Err(TaskError::WouldBlock),
            None => Err(TaskError::NoChild),
        }
    }

    pub fn wait4_current(&mut self, tid: GuestTid, args: Wait4SyscallArgs) -> SyscallOutcome {
        self.wait4_current_with_return(tid, args, current_syscall_return_rip(self, tid))
    }

    pub(super) fn wait4_current_with_return(
        &mut self,
        tid: GuestTid,
        args: Wait4SyscallArgs,
        return_rip: GuestAddress,
    ) -> SyscallOutcome {
        let Some(parent_pid) = self.task(tid).map(|task| task.pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };

        match self.wait4_child(parent_pid, args) {
            Ok(Some(waited)) => SyscallOutcome::success(u64::from(waited.pid()))
                .with_decoded_field("guest_pid", waited.pid().to_string())
                .with_decoded_field("exit_status", waited.status().to_string())
                .with_decoded_field("wait_status", format!("{:#x}", waited.wait_status())),
            Ok(None) => SyscallOutcome::success(0),
            Err(TaskError::WouldBlock) => {
                let Some(task) = self.task_mut(tid) else {
                    return SyscallOutcome::errno(LinuxErrno::ESRCH);
                };
                task.regs = task.regs.with_syscall_return(return_rip, task.regs.rax());
                task.state = TaskState::WaitingForChild { args };
                SyscallOutcome::success(0).with_decoded_field("task_blocked", "wait4")
            }
            Err(error) => error.into_outcome(),
        }
    }

    #[must_use]
    pub fn runnable_tids(&self) -> Vec<GuestTid> {
        self.tasks
            .values()
            .filter(|task| matches!(task.state, TaskState::Runnable))
            .map(|task| task.tid)
            .collect()
    }

    pub fn resume_waiting_tasks(&mut self) -> Vec<CompletedWait> {
        let waiting_tasks: Vec<(GuestTid, GuestPid, Wait4SyscallArgs)> = self
            .tasks
            .values()
            .filter_map(|task| match task.state {
                TaskState::WaitingForChild { args } => Some((task.tid, task.pid, args)),
                TaskState::Runnable
                | TaskState::WaitingForVfork { .. }
                | TaskState::WaitingForFd { .. }
                | TaskState::WaitingForFutex { .. }
                | TaskState::Exited { .. } => None,
            })
            .collect();
        let mut completed = Vec::new();

        for (tid, parent_pid, args) in waiting_tasks {
            let Ok(Some(waited)) = self.wait4_child(parent_pid, args) else {
                continue;
            };
            if let Some(task) = self.task_mut(tid) {
                task.regs = task
                    .regs
                    .with_syscall_return(task.regs.rip(), u64::from(waited.pid()));
                task.state = TaskState::Runnable;
            }
            completed.push(CompletedWait::new(tid, parent_pid, args, waited));
        }
        completed
    }

    pub fn block_task_for_fd(
        &mut self,
        tid: GuestTid,
        fd: i32,
        write: bool,
    ) -> Result<(), TaskError> {
        let task = self.task_mut(tid).ok_or(TaskError::UnknownTid(tid))?;
        task.state = TaskState::WaitingForFd { fd, write };
        Ok(())
    }

    pub fn resume_fd_waiters<F>(&mut self, mut ready: F) -> usize
    where
        F: FnMut(GuestPid, i32, bool) -> bool,
    {
        let mut resumed = 0;
        for task in self.tasks.values_mut() {
            if let TaskState::WaitingForFd { fd, write } = task.state
                && ready(task.pid, fd, write)
            {
                task.state = TaskState::Runnable;
                resumed += 1;
            }
        }
        resumed
    }

    pub fn block_task_for_futex(
        &mut self,
        tid: GuestTid,
        key: FutexWaitKey,
    ) -> Result<(), TaskError> {
        let task = self.task_mut(tid).ok_or(TaskError::UnknownTid(tid))?;
        task.state = TaskState::WaitingForFutex { key };
        Ok(())
    }

    pub fn wake_futex_waiters(&mut self, key: FutexWaitKey, limit: u32) -> usize {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        if limit == 0 {
            return 0;
        }

        let mut resumed = 0;
        for task in self.tasks.values_mut() {
            if matches!(task.state, TaskState::WaitingForFutex { key: wait_key } if wait_key == key)
            {
                task.state = TaskState::Runnable;
                resumed += 1;
                if resumed == limit {
                    break;
                }
            }
        }
        resumed
    }

    fn exited_waitable_child(
        &self,
        parent_pid: GuestPid,
        selector: i32,
    ) -> Result<Option<GuestPid>, TaskError> {
        Ok(self
            .matching_children(parent_pid, selector)?
            .into_iter()
            .find(|pid| {
                matches!(
                    self.process(*pid).map(GuestProcess::exit_state),
                    Some(ExitState::Exited { .. })
                )
            }))
    }

    fn has_waitable_child(&self, parent_pid: GuestPid, selector: i32) -> Result<bool, TaskError> {
        Ok(!self.matching_children(parent_pid, selector)?.is_empty())
    }

    fn matching_children(
        &self,
        parent_pid: GuestPid,
        selector: i32,
    ) -> Result<Vec<GuestPid>, TaskError> {
        let parent = self
            .process(parent_pid)
            .ok_or(TaskError::UnknownPid(parent_pid))?;
        let children = parent
            .children
            .iter()
            .copied()
            .filter(|child_pid| self.child_matches(parent, *child_pid, selector))
            .collect();
        Ok(children)
    }

    fn child_matches(&self, parent: &GuestProcess, child_pid: GuestPid, selector: i32) -> bool {
        let Some(child) = self.process(child_pid) else {
            return false;
        };

        match selector {
            -1 => true,
            0 => child.pgid == parent.pgid,
            value if value > 0 => child_pid == value as GuestPid,
            value => child.pgid == value.unsigned_abs(),
        }
    }

    fn reap_child(
        &mut self,
        parent_pid: GuestPid,
        child_pid: GuestPid,
    ) -> Result<WaitedChild, TaskError> {
        let status = match self
            .process(child_pid)
            .ok_or(TaskError::UnknownPid(child_pid))?
            .exit_state()
        {
            ExitState::Exited { status } => status,
            ExitState::Running => return Err(TaskError::WouldBlock),
        };

        self.tasks.retain(|_, task| task.pid != child_pid);
        self.processes.remove(&child_pid);
        self.process_mut(parent_pid)
            .ok_or(TaskError::UnknownPid(parent_pid))?
            .children
            .remove(&child_pid);

        Ok(WaitedChild::new(child_pid, status))
    }
}
