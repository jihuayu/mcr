#[allow(unused_imports)]
use super::*;

#[derive(Debug, Default)]
pub(crate) struct RuntimePerfSummary {
    enabled: bool,
    run_started_at: Option<Instant>,
    guest_syscall_count: u64,
    scheduler_enter_count: u64,
    scheduler_no_runnable_count: u64,
    scheduler_runnable_but_switched_count: u64,
    scheduler_sleep_count: u64,
    scheduler_sleep_total_us: u128,
    pub(crate) last_dispatched: Option<(mcr_sys::GuestTid, mcr_sys::GuestPid)>,
    pid_switch_count: u64,
    same_pid_switch_count: u64,
    cross_pid_switch_count: u64,
    remap_samples_us: Vec<u128>,
    clone_count: u64,
    vfork_clone_count: u64,
    fork_clone_count: u64,
    execve_count: u64,
    clone_to_exec_samples_us: Vec<u128>,
    pipe_read_count: u64,
    pipe_read_empty_count: u64,
    pipe_write_count: u64,
    pipe_wakeup_count: u64,
    fd_wakeup_count: u64,
    poll_count: u64,
    select_count: u64,
    wait4_count: u64,
    futex_count: u64,
    interpreted_block_fallback_count: u64,
    interpreted_block_bytes_read: u64,
    interpreted_blocks_decoded: u64,
}

impl RuntimePerfSummary {
    pub(crate) fn begin_run(&mut self) {
        let enabled = std::env::var_os(PERF_SUMMARY_TRACE_ENV).is_some();
        *self = Self {
            enabled,
            run_started_at: enabled.then(Instant::now),
            ..Self::default()
        };
    }

    pub(crate) fn record_scheduler_enter(&mut self) {
        if self.enabled {
            self.scheduler_enter_count = self.scheduler_enter_count.saturating_add(1);
        }
    }

    pub(crate) fn record_no_runnable(&mut self) {
        if self.enabled {
            self.scheduler_no_runnable_count = self.scheduler_no_runnable_count.saturating_add(1);
        }
    }

    pub(crate) fn record_dispatch(
        &mut self,
        tid: mcr_sys::GuestTid,
        pid: mcr_sys::GuestPid,
        previous_still_runnable: bool,
    ) {
        if !self.enabled {
            return;
        }
        if let Some((last_tid, last_pid)) = self.last_dispatched
            && last_tid != tid
        {
            if previous_still_runnable {
                self.scheduler_runnable_but_switched_count =
                    self.scheduler_runnable_but_switched_count.saturating_add(1);
            }
            if last_pid == pid {
                self.same_pid_switch_count = self.same_pid_switch_count.saturating_add(1);
            } else {
                self.pid_switch_count = self.pid_switch_count.saturating_add(1);
                self.cross_pid_switch_count = self.cross_pid_switch_count.saturating_add(1);
            }
        }
        self.last_dispatched = Some((tid, pid));
    }

    pub(crate) fn record_syscall(&mut self, syscall: mcr_sys::Syscall) {
        if !self.enabled {
            return;
        }
        self.guest_syscall_count = self.guest_syscall_count.saturating_add(1);
        match syscall {
            mcr_sys::Syscall::Poll | mcr_sys::Syscall::Ppoll => {
                self.poll_count = self.poll_count.saturating_add(1);
            }
            mcr_sys::Syscall::Select => {
                self.select_count = self.select_count.saturating_add(1);
            }
            mcr_sys::Syscall::Wait4 => {
                self.wait4_count = self.wait4_count.saturating_add(1);
            }
            mcr_sys::Syscall::Futex => {
                self.futex_count = self.futex_count.saturating_add(1);
            }
            mcr_sys::Syscall::Execve => {
                self.execve_count = self.execve_count.saturating_add(1);
            }
            _ => {}
        }
    }

    pub(crate) fn record_fork_like(
        &mut self,
        syscall: mcr_sys::Syscall,
        clone_args: Option<CloneSyscallArgs>,
    ) {
        if !self.enabled {
            return;
        }
        match syscall {
            mcr_sys::Syscall::Clone => {
                self.clone_count = self.clone_count.saturating_add(1);
                if clone_args.is_some_and(|args| args.has_clone_vfork()) {
                    self.vfork_clone_count = self.vfork_clone_count.saturating_add(1);
                } else {
                    self.fork_clone_count = self.fork_clone_count.saturating_add(1);
                }
            }
            mcr_sys::Syscall::Vfork => {
                self.vfork_clone_count = self.vfork_clone_count.saturating_add(1);
            }
            mcr_sys::Syscall::Fork => {
                self.fork_clone_count = self.fork_clone_count.saturating_add(1);
            }
            _ => {}
        }
    }

    pub(crate) fn record_remap(&mut self, elapsed: Duration) {
        if self.enabled {
            self.remap_samples_us.push(elapsed.as_micros());
        }
    }

    pub(crate) fn record_clone_to_exec(&mut self, elapsed: Duration) {
        if self.enabled {
            self.clone_to_exec_samples_us.push(elapsed.as_micros());
        }
    }

    pub(crate) fn record_pipe_io(
        &mut self,
        syscall: mcr_sys::Syscall,
        kind: FileKind,
        result: &SyscallReturn,
    ) {
        if !self.enabled {
            return;
        }
        match (syscall, kind) {
            (mcr_sys::Syscall::Read | mcr_sys::Syscall::Readv, FileKind::PipeRead) => {
                self.pipe_read_count = self.pipe_read_count.saturating_add(1);
                if matches!(result, SyscallReturn::Errno(LinuxErrno::EAGAIN)) {
                    self.pipe_read_empty_count = self.pipe_read_empty_count.saturating_add(1);
                }
            }
            (mcr_sys::Syscall::Write | mcr_sys::Syscall::Writev, FileKind::PipeWrite) => {
                self.pipe_write_count = self.pipe_write_count.saturating_add(1);
            }
            _ => {}
        }
    }

    pub(crate) fn record_fd_wakeups(&mut self, count: usize) {
        if !self.enabled || count == 0 {
            return;
        }
        let count = count as u64;
        self.fd_wakeup_count = self.fd_wakeup_count.saturating_add(count);
        self.pipe_wakeup_count = self.pipe_wakeup_count.saturating_add(count);
    }

    pub(crate) fn record_interpreted_block_fallback(
        &mut self,
        bytes_read: usize,
        blocks_decoded: u64,
    ) {
        self.interpreted_block_fallback_count =
            self.interpreted_block_fallback_count.saturating_add(1);
        self.interpreted_block_bytes_read = self
            .interpreted_block_bytes_read
            .saturating_add(bytes_read as u64);
        self.interpreted_blocks_decoded = self
            .interpreted_blocks_decoded
            .saturating_add(blocks_decoded);
    }

    pub(crate) const fn diagnostics(&self) -> RuntimePerfDiagnostics {
        RuntimePerfDiagnostics {
            interpreted_block_fallback_count: self.interpreted_block_fallback_count,
            interpreted_block_bytes_read: self.interpreted_block_bytes_read,
            interpreted_blocks_decoded: self.interpreted_blocks_decoded,
        }
    }

    pub(crate) fn finish_run(&mut self) {
        if !self.enabled {
            return;
        }
        let wall_ms = self
            .run_started_at
            .map(|start| start.elapsed().as_millis())
            .unwrap_or_default();
        let remap = sample_summary(&mut self.remap_samples_us);
        let clone_to_exec = sample_summary(&mut self.clone_to_exec_samples_us);
        eprintln!(
            "mcr perf-summary: wall_ms={wall_ms} guest_syscall_count={} scheduler_enter_count={} scheduler_sleep_count={} scheduler_sleep_total_us={} scheduler_no_runnable_count={} scheduler_runnable_but_switched_count={}",
            self.guest_syscall_count,
            self.scheduler_enter_count,
            self.scheduler_sleep_count,
            self.scheduler_sleep_total_us,
            self.scheduler_no_runnable_count,
            self.scheduler_runnable_but_switched_count
        );
        eprintln!(
            "mcr perf-summary: pid_switch_count={} same_pid_switch_count={} cross_pid_switch_count={}",
            self.pid_switch_count, self.same_pid_switch_count, self.cross_pid_switch_count
        );
        eprintln!(
            "mcr perf-summary: remap_count={} remap_total_us={} remap_avg_us={} remap_p50_us={} remap_p95_us={}",
            remap.count, remap.total_us, remap.avg_us, remap.p50_us, remap.p95_us
        );
        eprintln!(
            "mcr perf-summary: clone_count={} vfork_clone_count={} fork_clone_count={} execve_count={} clone_to_exec_count={} clone_to_exec_total_us={} clone_to_exec_avg_us={}",
            self.clone_count,
            self.vfork_clone_count,
            self.fork_clone_count,
            self.execve_count,
            clone_to_exec.count,
            clone_to_exec.total_us,
            clone_to_exec.avg_us
        );
        eprintln!(
            "mcr perf-summary: pipe_read_count={} pipe_read_empty_count={} pipe_write_count={} pipe_wakeup_count={} fd_wakeup_count={} poll_count={} select_count={} wait4_count={} futex_count={}",
            self.pipe_read_count,
            self.pipe_read_empty_count,
            self.pipe_write_count,
            self.pipe_wakeup_count,
            self.fd_wakeup_count,
            self.poll_count,
            self.select_count,
            self.wait4_count,
            self.futex_count
        );
        eprintln!(
            "mcr perf-summary: interpreted_block_fallback_count={} interpreted_block_bytes_read={} interpreted_blocks_decoded={}",
            self.interpreted_block_fallback_count,
            self.interpreted_block_bytes_read,
            self.interpreted_blocks_decoded
        );
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimePerfDiagnostics {
    interpreted_block_fallback_count: u64,
    interpreted_block_bytes_read: u64,
    interpreted_blocks_decoded: u64,
}

impl RuntimePerfDiagnostics {
    #[must_use]
    pub const fn interpreted_block_fallback_count(self) -> u64 {
        self.interpreted_block_fallback_count
    }

    #[must_use]
    pub const fn interpreted_block_bytes_read(self) -> u64 {
        self.interpreted_block_bytes_read
    }

    #[must_use]
    pub const fn interpreted_blocks_decoded(self) -> u64 {
        self.interpreted_blocks_decoded
    }
}

#[derive(Default)]
struct SampleSummary {
    count: usize,
    total_us: u128,
    avg_us: u128,
    p50_us: u128,
    p95_us: u128,
}

fn sample_summary(samples: &mut [u128]) -> SampleSummary {
    if samples.is_empty() {
        return SampleSummary::default();
    }
    samples.sort_unstable();
    let total_us = samples.iter().sum::<u128>();
    let count = samples.len();
    SampleSummary {
        count,
        total_us,
        avg_us: total_us / count as u128,
        p50_us: percentile_us(samples, 50),
        p95_us: percentile_us(samples, 95),
    }
}

fn percentile_us(samples: &[u128], percentile: usize) -> u128 {
    let index = samples.len().saturating_sub(1) * percentile / 100;
    samples[index]
}
