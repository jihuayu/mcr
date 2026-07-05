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

impl RuntimeSubsystems {
    pub(crate) fn clock_gettime(
        &mut self,
        clock_id: u64,
        timespec_addr: u64,
    ) -> Result<u64, LinuxErrno> {
        if timespec_addr == 0 {
            return Err(LinuxErrno::EFAULT);
        }

        let timespec = match clock_id {
            LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_COARSE => {
                linux_timespec_from_system_time(mcr_win::system_time().map_err(time_errno)?)
            }
            LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_MONOTONIC_RAW
            | LINUX_CLOCK_MONOTONIC_COARSE
            | LINUX_CLOCK_BOOTTIME => {
                linux_timespec_from_duration(mcr_win::monotonic_time().map_err(time_errno)?)?
            }
            _ => return Err(LinuxErrno::EINVAL),
        };
        write_guest_timespec(self.files.memory_mut(), timespec_addr, timespec)?;
        Ok(0)
    }

    pub(crate) fn clock_getres(
        &mut self,
        clock_id: u64,
        timespec_addr: u64,
    ) -> Result<u64, LinuxErrno> {
        validate_clock_id(clock_id)?;
        if timespec_addr != 0 {
            write_guest_timespec(
                self.files.memory_mut(),
                timespec_addr,
                LinuxTimespec {
                    tv_sec: 0,
                    tv_nsec: 1_000_000,
                },
            )?;
        }
        Ok(0)
    }

    pub(crate) fn gettimeofday(
        &mut self,
        timeval_addr: u64,
        timezone_addr: u64,
    ) -> Result<u64, LinuxErrno> {
        if timeval_addr != 0 {
            let now = linux_timespec_from_system_time(mcr_win::system_time().map_err(time_errno)?);
            write_guest_timeval(self.files.memory_mut(), timeval_addr, now)?;
        }
        if timezone_addr != 0 {
            write_guest_timezone_utc(self.files.memory_mut(), timezone_addr)?;
        }
        Ok(0)
    }

    pub(crate) fn nanosleep(&mut self, req_addr: u64, _rem_addr: u64) -> Result<u64, LinuxErrno> {
        if req_addr == 0 {
            return Err(LinuxErrno::EFAULT);
        }

        let duration = read_required_timespec_duration(self.files.memory(), req_addr)?;
        mcr_win::sleep_for(duration).map_err(time_errno)?;
        Ok(0)
    }

    pub(crate) fn getrandom(
        &mut self,
        buf_addr: u64,
        buflen: u64,
        flags: u64,
    ) -> Result<u64, LinuxErrno> {
        if flags & !LINUX_GRND_SUPPORTED_FLAGS != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let buflen = usize::try_from(buflen).map_err(|_| LinuxErrno::EINVAL)?;
        if buflen == 0 {
            return Ok(0);
        }
        if buf_addr == 0 {
            return Err(LinuxErrno::EFAULT);
        }

        let mut bytes = vec![0; buflen];
        mcr_win::fill_random(&mut bytes).map_err(time_errno)?;
        self.files
            .memory_mut()
            .write_bytes(buf_addr, &bytes)
            .map_err(memory_errno)?;
        Ok(buflen as u64)
    }
}
