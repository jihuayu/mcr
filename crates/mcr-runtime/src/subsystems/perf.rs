#[allow(unused_imports)]
use super::*;

impl RuntimeSubsystems {
    pub(crate) fn perf_begin_run(&mut self) {
        self.perf_summary.begin_run();
    }

    pub(crate) fn perf_finish_run(&mut self) {
        self.perf_summary.finish_run();
    }

    pub(crate) fn perf_record_scheduler_enter(&mut self) {
        self.perf_summary.record_scheduler_enter();
    }

    pub(crate) fn perf_record_no_runnable(&mut self) {
        self.perf_summary.record_no_runnable();
    }

    pub(crate) fn perf_record_dispatch(&mut self, tid: mcr_sys::GuestTid, pid: mcr_sys::GuestPid) {
        let previous_still_runnable =
            self.perf_summary
                .last_dispatched
                .is_some_and(|(last_tid, _)| {
                    self.process
                        .tasks
                        .task(last_tid)
                        .is_some_and(|task| matches!(task.state(), TaskState::Runnable))
                });
        self.perf_summary
            .record_dispatch(tid, pid, previous_still_runnable);
    }

    pub(crate) fn perf_record_syscall(&mut self, syscall: mcr_sys::Syscall) {
        self.perf_summary.record_syscall(syscall);
    }

    pub(crate) fn perf_record_fork_like(
        &mut self,
        syscall: mcr_sys::Syscall,
        clone_args: Option<CloneSyscallArgs>,
    ) {
        self.perf_summary.record_fork_like(syscall, clone_args);
    }

    pub(crate) fn perf_record_remap(&mut self, elapsed: Duration) {
        self.perf_summary.record_remap(elapsed);
    }

    pub(crate) fn perf_record_clone_to_exec(&mut self, elapsed: Duration) {
        self.perf_summary.record_clone_to_exec(elapsed);
    }

    pub(crate) fn perf_record_fd_wakeups(&mut self, count: usize) {
        self.perf_summary.record_fd_wakeups(count);
    }

    pub(crate) fn perf_record_interpreted_block_fallback(
        &mut self,
        bytes_read: usize,
        blocks_decoded: u64,
    ) {
        self.perf_summary
            .record_interpreted_block_fallback(bytes_read, blocks_decoded);
    }

    pub(crate) const fn perf_diagnostics(&self) -> RuntimePerfDiagnostics {
        self.perf_summary.diagnostics()
    }

    pub(crate) fn perf_record_pipe_io(
        &mut self,
        syscall: mcr_sys::Syscall,
        fd: Fd,
        result: &SyscallReturn,
    ) {
        if !matches!(
            syscall,
            mcr_sys::Syscall::Read
                | mcr_sys::Syscall::Readv
                | mcr_sys::Syscall::Write
                | mcr_sys::Syscall::Writev
        ) {
            return;
        }
        let Ok(entry) = self.files.vfs().fds().get(fd) else {
            return;
        };
        self.perf_summary
            .record_pipe_io(syscall, entry.file().kind(), result);
    }
}
