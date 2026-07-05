#[allow(unused_imports)]
use super::*;

impl TimeSyscalls for RuntimeSubsystems {
    fn dispatch_time(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self
            .materialize_pending_fork_exec_children(pid)
            .map_err(|error| error.errno())
        {
            return SyscallOutcome::errno(errno);
        }
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = match request.syscall {
            mcr_sys::Syscall::ClockGettime => {
                outcome(self.clock_gettime(arg(request, 0), arg(request, 1)))
            }
            mcr_sys::Syscall::ClockGetres => {
                outcome(self.clock_getres(arg(request, 0), arg(request, 1)))
            }
            mcr_sys::Syscall::Gettimeofday => {
                outcome(self.gettimeofday(arg(request, 0), arg(request, 1)))
            }
            mcr_sys::Syscall::Nanosleep => {
                outcome(self.nanosleep(arg(request, 0), arg(request, 1)))
            }
            mcr_sys::Syscall::Getrandom => {
                outcome(self.getrandom(arg(request, 0), arg(request, 1), arg(request, 2)))
            }
            _ => SyscallOutcome::unsupported(),
        };
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_memory(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }
}
