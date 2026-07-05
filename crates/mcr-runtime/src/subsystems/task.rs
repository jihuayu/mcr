#[allow(unused_imports)]
use super::*;

impl mcr_sys::TaskSyscalls for RuntimeSubsystems {
    fn supports_fast_task(&self, request: &SyscallRequest) -> bool {
        if self.pending_fork_exec.contains_key(&request.context.pid) {
            return false;
        }
        matches!(
            request.syscall,
            mcr_sys::Syscall::Getpid | mcr_sys::Syscall::Gettid
        )
    }

    fn dispatch_fast_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let Some(task) = self.tasks.task(request.context.tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if task.pid() != request.context.pid {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }

        match request.syscall {
            mcr_sys::Syscall::Getpid => SyscallOutcome::success(u64::from(task.pid())),
            mcr_sys::Syscall::Gettid => SyscallOutcome::success(u64::from(task.tid())),
            _ => SyscallOutcome::unsupported(),
        }
    }

    fn dispatch_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        if !matches!(
            request.syscall,
            mcr_sys::Syscall::Execve | mcr_sys::Syscall::Wait4
        ) && let Err(errno) = self
            .materialize_pending_fork_exec_children(request.context.pid)
            .map_err(|error| error.errno())
        {
            return SyscallOutcome::errno(errno);
        }
        match request.syscall {
            mcr_sys::Syscall::Futex => self.dispatch_futex(request),
            mcr_sys::Syscall::Execve => self.dispatch_execve(request),
            mcr_sys::Syscall::RtSigprocmask => self.dispatch_rt_sigprocmask(request),
            mcr_sys::Syscall::Sigaltstack => self.dispatch_sigaltstack(request),
            mcr_sys::Syscall::SchedYield => self.dispatch_sched_yield(),
            mcr_sys::Syscall::Getrlimit => self.dispatch_getrlimit(request),
            mcr_sys::Syscall::Getrusage => self.dispatch_getrusage(request),
            mcr_sys::Syscall::Sysinfo => self.dispatch_sysinfo(request),
            mcr_sys::Syscall::Prctl => self.dispatch_prctl(request),
            mcr_sys::Syscall::Prlimit64 => self.dispatch_prlimit64(request),
            mcr_sys::Syscall::Getcpu => self.dispatch_getcpu(request),
            mcr_sys::Syscall::Membarrier => self.dispatch_membarrier(request),
            mcr_sys::Syscall::Rseq => SyscallOutcome::errno(LinuxErrno::ENOSYS),
            mcr_sys::Syscall::Fork
            | mcr_sys::Syscall::Vfork
            | mcr_sys::Syscall::Clone
            | mcr_sys::Syscall::Clone3 => self.dispatch_fork_like(request),
            _ => self.dispatch_kernel_task(request),
        }
    }
}
