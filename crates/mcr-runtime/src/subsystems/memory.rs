#[allow(unused_imports)]
use super::*;

impl MemorySyscalls for RuntimeSubsystems {
    fn dispatch_memory(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self
            .materialize_pending_fork_exec_children(pid)
            .map_err(|error| error.errno())
        {
            return SyscallOutcome::errno(errno);
        }
        if matches!(request.syscall, mcr_sys::Syscall::Mmap) {
            if let Err(errno) = self.select_process_context(pid) {
                return SyscallOutcome::errno(errno);
            }
        } else if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = if matches!(request.syscall, mcr_sys::Syscall::Mmap) {
            outcome(self.mmap(
                pid,
                mcr_sys::MmapSyscallArgs {
                    addr: arg(request, 0),
                    length: arg(request, 1),
                    prot: arg_u32(request, 2),
                    flags: arg_u32(request, 3),
                    fd: arg_i32(request, 4),
                    offset: arg(request, 5) as i64,
                },
            ))
        } else {
            self.files.memory_mut().dispatch_memory(request)
        };
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_memory(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        if let SyscallReturn::Success(result) = outcome.result {
            match request.syscall {
                mcr_sys::Syscall::Mmap if arg_u32(request, 2) & mcr_sys::LINUX_PROT_EXEC != 0 => {
                    self.invalidate_native_patch_cache_range(pid, result, arg(request, 1));
                }
                mcr_sys::Syscall::Munmap => {
                    self.invalidate_native_patch_cache_range(pid, arg(request, 0), arg(request, 1));
                }
                mcr_sys::Syscall::Mprotect
                    if arg_u32(request, 2) & mcr_sys::LINUX_PROT_EXEC != 0 =>
                {
                    self.invalidate_native_patch_cache_range(pid, arg(request, 0), arg(request, 1));
                }
                _ => {}
            }
        }
        outcome
    }
}
