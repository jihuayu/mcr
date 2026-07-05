#[allow(unused_imports)]
use super::*;

impl FileSyscalls for RuntimeSubsystems {
    fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
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
        let outcome = match request.syscall {
            mcr_sys::Syscall::Close => outcome(self.close_process_fd(arg_i32(request, 0))),
            mcr_sys::Syscall::CloseRange => outcome(self.close_process_fd_range(
                arg_u32(request, 0),
                arg_u32(request, 1),
                arg_u32(request, 2),
            )),
            _ => self.files.dispatch_file(request),
        };
        self.perf_record_pipe_io(request.syscall, arg_i32(request, 0), &outcome.result);
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
