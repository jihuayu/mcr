#[allow(unused_imports)]
use super::*;

impl NetworkSyscalls for RuntimeSubsystems {
    fn dispatch_network(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self
            .materialize_pending_fork_exec_children(pid)
            .map_err(|error| error.errno())
        {
            return SyscallOutcome::errno(errno);
        }
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = self.files.dispatch_network(request);
        if matches!(outcome.result, SyscallReturn::Success(_)) {
            if let Err(errno) = self.store_selected_process_fds(pid) {
                return SyscallOutcome::errno(errno);
            }
            if let Err(errno) = self.store_selected_process_memory(pid) {
                return SyscallOutcome::errno(errno);
            }
        }
        outcome
    }
}
