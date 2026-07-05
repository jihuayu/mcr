use mcr_sys::{
    BrkSyscallArgs, MemorySyscalls, MmapSyscallArgs, MprotectSyscallArgs, MunmapSyscallArgs,
    Syscall, SyscallOutcome, SyscallRequest,
};

use super::ranges::{checked_raw_range, is_page_aligned, is_supported_madvise};
use super::{GuestMemory, GuestMemoryError, host_error_trace, syscall_result};

impl MemorySyscalls for GuestMemory {
    fn dispatch_memory(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        match request.syscall {
            Syscall::Mmap => syscall_result(self.mmap(MmapSyscallArgs::from_args(request.args))),
            Syscall::Munmap => syscall_result(
                self.munmap(MunmapSyscallArgs::from_args(request.args))
                    .map(|()| 0),
            ),
            Syscall::Mprotect => syscall_result(
                self.mprotect(MprotectSyscallArgs::from_args(request.args))
                    .map(|()| 0),
            ),
            Syscall::Madvise => syscall_result(self.madvise(
                request.args.get(0).unwrap_or_default(),
                request.args.get(1).unwrap_or_default(),
                request.args.get(2).unwrap_or_default() as u32,
            )),
            Syscall::Brk => {
                let outcome = self.set_brk(BrkSyscallArgs::from_args(request.args).addr);
                let mut syscall_outcome = SyscallOutcome::success(outcome.current);
                if let Some(error) = outcome.error.and_then(|error| error.host_error().cloned()) {
                    syscall_outcome = syscall_outcome.with_host_error(host_error_trace(&error));
                }
                syscall_outcome
            }
            _ => SyscallOutcome::unsupported(),
        }
    }
}

impl GuestMemory {
    pub fn madvise(&self, addr: u64, length: u64, advice: u32) -> Result<u64, GuestMemoryError> {
        if !is_page_aligned(addr) {
            return Err(GuestMemoryError::InvalidAddress);
        }
        if !is_supported_madvise(advice) {
            return Err(GuestMemoryError::InvalidFlags);
        }
        if length == 0 {
            return Ok(0);
        }
        checked_raw_range(addr, length)?;
        Ok(0)
    }
}
