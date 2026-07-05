#[allow(unused_imports)]
use super::*;

impl EventSyscalls for RuntimeSubsystems {
    fn dispatch_event(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self
            .materialize_pending_fork_exec_children(pid)
            .map_err(|error| error.errno())
        {
            return SyscallOutcome::errno(errno);
        }
        match request.syscall {
            mcr_sys::Syscall::Poll => self.dispatch_poll(request),
            mcr_sys::Syscall::Select => self.dispatch_select(request),
            mcr_sys::Syscall::Ppoll => self.dispatch_ppoll(request),
            mcr_sys::Syscall::Eventfd2 => self.dispatch_eventfd2(request),
            mcr_sys::Syscall::EpollCreate1 => self.dispatch_epoll_create1(request),
            mcr_sys::Syscall::EpollCtl => self.dispatch_epoll_ctl(request),
            mcr_sys::Syscall::EpollWait => self.dispatch_epoll_wait(request),
            mcr_sys::Syscall::EpollPwait2 => self.dispatch_epoll_pwait2(request),
            _ => SyscallOutcome::unsupported(),
        }
    }
}
