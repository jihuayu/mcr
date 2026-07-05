use mcr_sys::{
    GuestPid, GuestTid, KillSyscallArgs, LINUX_KERNEL_SIGSET_SIZE, LINUX_ROBUST_LIST_HEAD_SIZE,
    LinuxErrno, RtSigactionSyscallArgs, RtSigprocmaskSyscallArgs, SetRobustListSyscallArgs,
    SetTidAddressSyscallArgs, SyscallOutcome, TgkillSyscallArgs, TkillSyscallArgs,
};

use super::{GuestKernel, current_syscall_return_rip};
use crate::{
    ExitState, GuestSignalAction, LINUX_SIGKILL, LINUX_SIGNAL_COUNT, LINUX_SIGTERM, TaskError,
    TaskState,
};

impl GuestKernel {
    pub fn exit_task(&mut self, tid: GuestTid, status: i32) -> SyscallOutcome {
        let Some(task) = self.tasks.get_mut(&tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };

        let pid = task.pid;
        let _ = task;
        self.set_task_state(tid, TaskState::Exited { status });

        let all_exited = self
            .tasks
            .values()
            .filter(|candidate| candidate.pid == pid)
            .all(|candidate| matches!(candidate.state, TaskState::Exited { .. }));
        if all_exited {
            if let Some(process) = self.processes.get_mut(&pid) {
                process.exit_state = ExitState::Exited { status };
            }
            self.resume_vfork_parent(pid);
        }

        SyscallOutcome::success(0)
            .with_decoded_field("guest_tid", tid.to_string())
            .with_decoded_field("exit_status", status.to_string())
    }

    pub fn exit_group(&mut self, pid: GuestPid, status: i32) -> SyscallOutcome {
        if !self.processes.contains_key(&pid) {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }

        let tids = self
            .tasks
            .values()
            .filter_map(|task| (task.pid == pid).then_some(task.tid))
            .collect::<Vec<_>>();
        for tid in tids {
            self.set_task_state(tid, TaskState::Exited { status });
        }
        if let Some(process) = self.processes.get_mut(&pid) {
            process.exit_state = ExitState::Exited { status };
        }
        self.resume_vfork_parent(pid);

        SyscallOutcome::success(0)
            .with_decoded_field("guest_pid", pid.to_string())
            .with_decoded_field("exit_status", status.to_string())
    }

    pub fn rt_sigaction_current(
        &mut self,
        tid: GuestTid,
        args: RtSigactionSyscallArgs,
    ) -> SyscallOutcome {
        let Some(pid) = self.task(tid).map(|task| task.pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if let Err(error) = validate_signal(args.sig) {
            return error.into_outcome();
        }
        if args.sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
            return TaskError::InvalidSigsetSize(args.sigsetsize).into_outcome();
        }
        if args.act != 0 {
            let Some(process) = self.process_mut(pid) else {
                return SyscallOutcome::errno(LinuxErrno::ESRCH);
            };
            process
                .signals
                .set_action(args.sig, GuestSignalAction::new(args.act));
        }
        SyscallOutcome::success(0).with_decoded_field("signal", args.sig.to_string())
    }

    pub fn rt_sigprocmask_current(
        &mut self,
        tid: GuestTid,
        args: RtSigprocmaskSyscallArgs,
    ) -> SyscallOutcome {
        let Some(pid) = self.task(tid).map(|task| task.pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if args.sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
            return TaskError::InvalidSigsetSize(args.sigsetsize).into_outcome();
        }
        if !args.supported_how() {
            return TaskError::InvalidSignalMaskHow(args.how).into_outcome();
        }
        if args.set != 0 {
            let Some(process) = self.process_mut(pid) else {
                return SyscallOutcome::errno(LinuxErrno::ESRCH);
            };
            if let Err(error) = process.signals.apply_mask(args.how, args.set) {
                return error.into_outcome();
            }
        }
        SyscallOutcome::success(0).with_decoded_field("signal_mask", format!("{:#x}", args.set))
    }

    fn queue_process_signal(&mut self, pid: GuestPid, signal: u32) {
        if let Some(process) = self.process_mut(pid) {
            process.pending_signals.insert(signal);
        }
        self.wake_signal_waiters(pid);
    }

    fn queue_task_signal(&mut self, tid: GuestTid, signal: u32) {
        let Some(pid) = self.task_mut(tid).map(|task| {
            task.pending_signals.insert(signal);
            task.pid
        }) else {
            return;
        };
        self.wake_signal_waiters(pid);
    }

    fn take_pending_signal_for_task(
        &mut self,
        tid: GuestTid,
        pid: GuestPid,
        signal_mask: u64,
    ) -> Option<u32> {
        if let Some(signal) = self
            .task_mut(tid)
            .and_then(|task| take_pending_signal(&mut task.pending_signals, signal_mask))
        {
            return Some(signal);
        }
        self.process_mut(pid)
            .and_then(|process| take_pending_signal(&mut process.pending_signals, signal_mask))
    }

    pub fn rt_sigtimedwait_current(
        &mut self,
        tid: GuestTid,
        signal_mask: u64,
        sigsetsize: u64,
        wait_indefinitely: bool,
    ) -> SyscallOutcome {
        if sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
            return TaskError::InvalidSigsetSize(sigsetsize).into_outcome();
        }
        let Some(pid) = self.task(tid).map(|task| task.pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if let Some(signal) = self.take_pending_signal_for_task(tid, pid, signal_mask) {
            return SyscallOutcome::success(u64::from(signal))
                .with_decoded_field("signal", signal.to_string());
        }
        if wait_indefinitely {
            let return_rip = current_syscall_return_rip(self, tid);
            let Some(task) = self.task_mut(tid) else {
                return SyscallOutcome::errno(LinuxErrno::ESRCH);
            };
            task.regs = task.regs.with_syscall_return(return_rip, task.regs.rax());
            self.set_task_state(tid, TaskState::WaitingForSignalSet { mask: signal_mask });
            return SyscallOutcome::success(0)
                .with_decoded_field("task_blocked", "rt_sigtimedwait");
        }
        SyscallOutcome::errno(LinuxErrno::EAGAIN)
            .with_decoded_field("signal_wait", "no_pending_signal")
    }

    pub fn wake_signal_waiters(&mut self, pid: GuestPid) -> usize {
        let waiters = self
            .tasks
            .values()
            .filter_map(|task| match task.state {
                TaskState::WaitingForSignalSet { mask } if task.pid == pid => {
                    Some((task.tid, mask))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut woken = 0usize;
        for (tid, mask) in waiters {
            let Some(signal) = self.take_pending_signal_for_task(tid, pid, mask) else {
                continue;
            };
            if let Some(task) = self.task_mut(tid) {
                task.regs = task
                    .regs
                    .with_syscall_return(task.regs.rip(), u64::from(signal));
                self.set_task_state(tid, TaskState::Runnable);
                woken += 1;
            }
        }
        woken
    }

    pub fn kill_current(&mut self, args: KillSyscallArgs) -> SyscallOutcome {
        if args.pid <= 0 {
            return TaskError::UnsupportedSignalTarget(args.pid).into_outcome();
        }
        let pid = args.pid as GuestPid;
        if !self.processes.contains_key(&pid) {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }
        if let Err(error) = validate_signal_or_probe(args.sig) {
            return error.into_outcome();
        }
        if args.sig == 0 {
            return SyscallOutcome::success(0);
        }
        if self.should_terminate_for_process_signal(pid, args.sig) {
            return self.exit_group(pid, signal_exit_status(args.sig));
        }
        self.queue_process_signal(pid, args.sig);
        SyscallOutcome::success(0).with_decoded_field("queued_signal", args.sig.to_string())
    }

    pub fn tkill_current(&mut self, args: TkillSyscallArgs) -> SyscallOutcome {
        if args.tid <= 0 {
            return TaskError::UnsupportedSignalTarget(args.tid).into_outcome();
        }
        let tid = args.tid as GuestTid;
        let Some(task) = self.task(tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if let Err(error) = validate_signal_or_probe(args.sig) {
            return error.into_outcome();
        }
        if args.sig == 0 {
            return SyscallOutcome::success(0);
        }
        if self.should_terminate_for_process_signal(task.pid, args.sig) {
            return self.exit_group(task.pid, signal_exit_status(args.sig));
        }
        self.queue_task_signal(tid, args.sig);
        SyscallOutcome::success(0).with_decoded_field("queued_signal", args.sig.to_string())
    }

    pub fn tgkill_current(&mut self, args: TgkillSyscallArgs) -> SyscallOutcome {
        if args.tgid <= 0 || args.tid <= 0 {
            return TaskError::UnsupportedSignalTarget(args.tid).into_outcome();
        }
        let pid = args.tgid as GuestPid;
        let tid = args.tid as GuestTid;
        let Some(task) = self.task(tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if task.pid != pid {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }
        if let Err(error) = validate_signal_or_probe(args.sig) {
            return error.into_outcome();
        }
        if args.sig == 0 {
            return SyscallOutcome::success(0);
        }
        if self.should_terminate_for_process_signal(pid, args.sig) {
            return self.exit_group(pid, signal_exit_status(args.sig));
        }
        self.queue_task_signal(tid, args.sig);
        SyscallOutcome::success(0).with_decoded_field("queued_signal", args.sig.to_string())
    }

    fn should_terminate_for_process_signal(&self, pid: GuestPid, signal: u32) -> bool {
        if !is_terminating_signal(signal) {
            return false;
        }
        if signal == LINUX_SIGKILL {
            return true;
        }
        let Some(process) = self.process(pid) else {
            return true;
        };
        !signal_matches_mask(signal, process.signals.blocked())
            && process.signals.action(signal).is_none()
    }

    pub fn set_tid_address_current(
        &mut self,
        tid: GuestTid,
        args: SetTidAddressSyscallArgs,
    ) -> SyscallOutcome {
        let Some(task) = self.task_mut(tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        task.clear_child_tid = (args.tidptr != 0).then_some(args.tidptr);
        SyscallOutcome::success(u64::from(tid))
            .with_decoded_field("clear_child_tid", format!("{:#x}", args.tidptr))
    }

    pub fn set_robust_list_current(
        &mut self,
        tid: GuestTid,
        args: SetRobustListSyscallArgs,
    ) -> SyscallOutcome {
        if args.len != LINUX_ROBUST_LIST_HEAD_SIZE {
            return TaskError::InvalidRobustListLength(args.len).into_outcome();
        }
        let Some(task) = self.task_mut(tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        task.robust_list = (args.head != 0).then_some(args.head);
        SyscallOutcome::success(0).with_decoded_field("robust_list", format!("{:#x}", args.head))
    }
}

const fn validate_signal(signal: u32) -> Result<(), TaskError> {
    if signal > 0 && signal <= LINUX_SIGNAL_COUNT {
        Ok(())
    } else {
        Err(TaskError::InvalidSignal(signal))
    }
}

const fn validate_signal_or_probe(signal: u32) -> Result<(), TaskError> {
    if signal <= LINUX_SIGNAL_COUNT {
        Ok(())
    } else {
        Err(TaskError::InvalidSignal(signal))
    }
}

fn take_pending_signal(
    pending: &mut std::collections::BTreeSet<u32>,
    signal_mask: u64,
) -> Option<u32> {
    let signal = pending
        .iter()
        .copied()
        .find(|signal| signal_matches_mask(*signal, signal_mask))?;
    pending.remove(&signal);
    Some(signal)
}

fn signal_matches_mask(signal: u32, signal_mask: u64) -> bool {
    signal > 0 && signal <= LINUX_SIGNAL_COUNT && signal_mask & (1u64 << (signal - 1)) != 0
}

const fn is_terminating_signal(signal: u32) -> bool {
    matches!(signal, LINUX_SIGKILL | LINUX_SIGTERM)
}

const fn signal_exit_status(signal: u32) -> i32 {
    128 + (signal as i32)
}
