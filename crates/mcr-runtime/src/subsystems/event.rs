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

impl RuntimeSubsystems {
    pub(crate) fn dispatch_futex(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        self.futex(
            request.context.pid,
            request.context.tid,
            FutexSyscallArgs::new(
                arg(request, 0),
                arg_u32(request, 1),
                arg_u32(request, 2),
                arg(request, 3),
                arg(request, 4),
                arg_u32(request, 5),
            ),
        )
    }

    pub(crate) fn futex(
        &mut self,
        pid: mcr_sys::GuestPid,
        tid: mcr_sys::GuestTid,
        args: FutexSyscallArgs,
    ) -> SyscallOutcome {
        if args.op & !(LINUX_FUTEX_CMD_MASK | LINUX_FUTEX_PRIVATE_FLAG) != 0 {
            return SyscallOutcome::errno(LinuxErrno::EINVAL);
        }
        if args.uaddr % 4 != 0 {
            return SyscallOutcome::errno(LinuxErrno::EINVAL);
        }

        match args.command() {
            LINUX_FUTEX_WAIT => self.futex_wait(pid, tid, args),
            LINUX_FUTEX_WAKE => SyscallOutcome::success(self.futex_wake(pid, args)),
            _ => SyscallOutcome::errno(LinuxErrno::EINVAL),
        }
    }

    pub(crate) fn futex_wait(
        &mut self,
        pid: mcr_sys::GuestPid,
        tid: mcr_sys::GuestTid,
        args: FutexSyscallArgs,
    ) -> SyscallOutcome {
        let value = match read_guest_u32(self.files.memory(), args.uaddr) {
            Ok(value) => value,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        if value != args.val {
            return SyscallOutcome::errno(LinuxErrno::EAGAIN);
        }
        let timeout = match read_futex_timeout(self.files.memory(), args.timeout) {
            Ok(timeout) => timeout,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        if timeout.is_some() {
            return SyscallOutcome::errno(LinuxErrno::ETIMEDOUT);
        }

        let key = FutexWaitKey::new(pid, args.uaddr, args.is_private());
        match self.process.tasks.block_task_for_futex(tid, key) {
            Ok(()) => SyscallOutcome::success(0).with_decoded_field("task_blocked", "futex"),
            Err(error) => error.into_outcome(),
        }
    }

    pub(crate) fn futex_wake(&mut self, pid: mcr_sys::GuestPid, args: FutexSyscallArgs) -> u64 {
        let key = FutexWaitKey::new(pid, args.uaddr, args.is_private());
        self.process.tasks.wake_futex_waiters(key, args.val) as u64
    }

    pub(crate) fn dispatch_poll(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let nfds = match usize_arg(request, 1) {
            Ok(nfds) => nfds,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let timeout = match poll_timeout(arg(request, 2)) {
            Ok(timeout) => timeout,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let outcome = outcome(self.poll_fds(arg(request, 0), nfds, timeout));
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

    pub(crate) fn dispatch_ppoll(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        if arg(request, 3) != 0 || arg(request, 4) != 0 {
            return SyscallOutcome::errno(LinuxErrno::EINVAL);
        }
        let nfds = match usize_arg(request, 1) {
            Ok(nfds) => nfds,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let timeout = match read_futex_timeout(self.files.memory(), arg(request, 2)) {
            Ok(timeout) => timeout,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let outcome = outcome(self.poll_fds(arg(request, 0), nfds, timeout));
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

    pub(crate) fn dispatch_select(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let nfds = match select_nfds(arg(request, 0)) {
            Ok(nfds) => nfds,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let timeout = match read_select_timeout(self.files.memory(), arg(request, 4)) {
            Ok(timeout) => timeout,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let outcome = outcome(self.select_fds(
            nfds,
            arg(request, 1),
            arg(request, 2),
            arg(request, 3),
            timeout,
        ));
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

    pub(crate) fn poll_fds(
        &mut self,
        fds_addr: u64,
        nfds: usize,
        timeout: Option<Duration>,
    ) -> Result<u64, LinuxErrno> {
        const MAX_POLL_FDS: usize = 4096;
        if nfds > MAX_POLL_FDS {
            return Err(LinuxErrno::EINVAL);
        }

        let mut ready = 0u64;
        for index in 0..nfds {
            let pollfd_addr = fds_addr
                .checked_add((index * POLLFD_SIZE) as u64)
                .ok_or(LinuxErrno::EFAULT)?;
            let mut pollfd = read_pollfd(self.files.memory(), pollfd_addr)?;
            pollfd.revents = self.poll_fd_revents(pollfd.fd, pollfd.events, timeout)?;
            write_pollfd_revents(self.files.memory_mut(), pollfd_addr, pollfd.revents)?;
            if pollfd.revents != 0 {
                ready = ready.checked_add(1).ok_or(LinuxErrno::EINVAL)?;
            }
        }
        Ok(ready)
    }

    pub(crate) fn select_fds(
        &mut self,
        nfds: usize,
        readfds_addr: u64,
        writefds_addr: u64,
        exceptfds_addr: u64,
        timeout: Option<Duration>,
    ) -> Result<u64, LinuxErrno> {
        let interests = read_select_interests(
            self.files.memory(),
            nfds,
            readfds_addr,
            writefds_addr,
            exceptfds_addr,
        )?;
        let mut ready = self.select_ready_fds(&interests, Some(Duration::ZERO))?;
        if ready.is_empty() && !matches!(timeout, Some(duration) if duration.is_zero()) {
            ready = self.select_ready_fds(&interests, timeout)?;
        }

        write_select_fd_set(self.files.memory_mut(), readfds_addr, nfds, &ready.read)?;
        write_select_fd_set(self.files.memory_mut(), writefds_addr, nfds, &ready.write)?;
        write_select_fd_set(
            self.files.memory_mut(),
            exceptfds_addr,
            nfds,
            &ready.exceptional,
        )?;
        Ok(ready.count() as u64)
    }

    pub(crate) fn select_ready_fds(
        &mut self,
        interests: &[SelectInterest],
        timeout: Option<Duration>,
    ) -> Result<SelectReadyFds, LinuxErrno> {
        let mut ready = SelectReadyFds::default();
        let wait_index = self.select_wait_interest_index(interests, timeout);
        for (index, interest) in interests.iter().enumerate() {
            let wait_timeout = if wait_index == Some(index) {
                timeout
            } else {
                Some(Duration::ZERO)
            };
            let revents = self.poll_fd_revents(interest.fd, interest.events, wait_timeout)?;
            if revents & LINUX_POLLNVAL != 0 {
                return Err(LinuxErrno::EBADF);
            }
            if interest.read && select_revents_readable(revents) {
                ready.read.push(interest.fd);
            }
            if interest.write && select_revents_writable(revents) {
                ready.write.push(interest.fd);
            }
            if interest.exceptional && revents & LINUX_POLLPRI != 0 {
                ready.exceptional.push(interest.fd);
            }
        }
        Ok(ready)
    }

    pub(crate) fn select_wait_interest_index(
        &self,
        interests: &[SelectInterest],
        timeout: Option<Duration>,
    ) -> Option<usize> {
        if matches!(timeout, Some(duration) if duration.is_zero()) {
            return None;
        }
        interests
            .iter()
            .position(|interest| self.files.vfs().socket_id_for_fd(interest.fd).is_ok())
            .or_else(|| (!interests.is_empty()).then_some(0))
    }

    pub(crate) fn poll_fd_revents(
        &mut self,
        fd: Fd,
        events: i16,
        timeout: Option<Duration>,
    ) -> Result<i16, LinuxErrno> {
        if fd < 0 {
            return Ok(0);
        }

        let mut revents = match self.files.vfs().poll_readiness(fd) {
            Ok(readiness) => poll_revents_from_vfs(readiness, events),
            Err(VfsError::BadFd) => return Ok(LINUX_POLLNVAL),
            Err(error) => return Err(vfs_errno(error)),
        };

        if self.files.vfs().socket_id_for_fd(fd).is_ok() {
            let socket_id = self.files.socket_id_for_fd(fd)?;
            let socket_events = poll_interest_to_socket_events(events);
            if !socket_events.is_empty() {
                let readiness = self
                    .files
                    .sockets_mut()
                    .poll(socket_id, socket_events, timeout)
                    .map_err(net_errno)?;
                revents |= poll_revents_from_socket_events(readiness, events);
            }
        }
        Ok(revents)
    }

    pub(crate) fn dispatch_epoll_create1(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = outcome(self.epoll_create1(arg_u32(request, 0)));
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_fds(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }

    pub(crate) fn dispatch_eventfd2(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = outcome(self.eventfd2(arg(request, 0), arg_u32(request, 1)));
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_fds(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }

    pub(crate) fn eventfd2(&mut self, initial: u64, flags: u32) -> Result<u64, LinuxErrno> {
        if flags & !LINUX_EFD_SUPPORTED_FLAGS != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let fd = self
            .files
            .vfs_mut()
            .eventfd(initial, OpenFlags::new(flags))
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    pub(crate) fn dispatch_epoll_ctl(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        outcome(self.epoll_ctl(
            arg_i32(request, 0),
            arg_u32(request, 1),
            arg_i32(request, 2),
            arg(request, 3),
        ))
    }

    pub(crate) fn dispatch_epoll_wait(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let maxevents = match usize_arg(request, 2) {
            Ok(maxevents) => maxevents,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let timeout = match poll_timeout(arg(request, 3)) {
            Ok(timeout) => timeout,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let outcome =
            outcome(self.epoll_wait(arg_i32(request, 0), arg(request, 1), maxevents, timeout));
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

    pub(crate) fn dispatch_epoll_pwait2(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        if arg(request, 4) != 0 || arg(request, 5) != 0 {
            return SyscallOutcome::errno(LinuxErrno::EINVAL);
        }
        let maxevents = match usize_arg(request, 2) {
            Ok(maxevents) => maxevents,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let timeout = match read_futex_timeout(self.files.memory(), arg(request, 3)) {
            Ok(timeout) => timeout,
            Err(errno) => return SyscallOutcome::errno(errno),
        };
        let outcome =
            outcome(self.epoll_wait(arg_i32(request, 0), arg(request, 1), maxevents, timeout));
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

    pub(crate) fn epoll_create1(&mut self, flags: u32) -> Result<u64, LinuxErrno> {
        if flags & !LINUX_EPOLL_CLOEXEC != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let epoll_id = self.events.epolls.create()?;
        let mut open_flags = 0;
        if flags & LINUX_EPOLL_CLOEXEC != 0 {
            open_flags |= mcr_vfs::O_CLOEXEC;
        }
        match self
            .files
            .vfs_mut()
            .insert_epoll(epoll_id, OpenFlags::new(open_flags))
        {
            Ok(fd) => Ok(fd as u64),
            Err(error) => {
                self.events.epolls.close(epoll_id);
                Err(vfs_errno(error))
            }
        }
    }

    pub(crate) fn epoll_ctl(
        &mut self,
        epfd: Fd,
        operation: u32,
        fd: Fd,
        event_addr: u64,
    ) -> Result<u64, LinuxErrno> {
        if fd < 0 {
            return Err(LinuxErrno::EBADF);
        }
        let epoll_id = self.files.vfs().epoll_id_for_fd(epfd).map_err(vfs_errno)?;
        if fd == epfd {
            return Err(LinuxErrno::EINVAL);
        }
        self.files.vfs().poll_readiness(fd).map_err(vfs_errno)?;

        match operation {
            LINUX_EPOLL_CTL_ADD => {
                let event = read_epoll_event(self.files.memory(), event_addr)?;
                validate_epoll_events(event.events)?;
                let instance = self.events.epolls.instance_mut(epoll_id)?;
                instance.insert_watch(EpollWatch {
                    fd,
                    events: event.events,
                    data: event.data,
                })?;
            }
            LINUX_EPOLL_CTL_MOD => {
                let event = read_epoll_event(self.files.memory(), event_addr)?;
                validate_epoll_events(event.events)?;
                let instance = self.events.epolls.instance_mut(epoll_id)?;
                instance.update_watch(fd, event.events, event.data)?;
            }
            LINUX_EPOLL_CTL_DEL => {
                let instance = self.events.epolls.instance_mut(epoll_id)?;
                instance.remove_watch(fd)?;
            }
            _ => return Err(LinuxErrno::EINVAL),
        }
        Ok(0)
    }

    pub(crate) fn epoll_wait(
        &mut self,
        epfd: Fd,
        events_addr: u64,
        maxevents: usize,
        timeout: Option<Duration>,
    ) -> Result<u64, LinuxErrno> {
        const MAX_EPOLL_EVENTS: usize = 4096;
        if maxevents == 0 || maxevents > MAX_EPOLL_EVENTS {
            return Err(LinuxErrno::EINVAL);
        }
        let epoll_id = self.files.vfs().epoll_id_for_fd(epfd).map_err(vfs_errno)?;
        let watches = self.events.epolls.cached_watches(epoll_id)?;

        let mut ready = self.epoll_ready_events(&watches, maxevents, Some(Duration::ZERO))?;
        if ready.is_empty() && !matches!(timeout, Some(duration) if duration.is_zero()) {
            ready = self.epoll_ready_events(&watches, maxevents, timeout)?;
        }

        for (index, event) in ready.iter().enumerate() {
            let event_addr = events_addr
                .checked_add((index * EPOLL_EVENT_SIZE) as u64)
                .ok_or(LinuxErrno::EFAULT)?;
            write_epoll_event(self.files.memory_mut(), event_addr, *event)?;
        }
        Ok(ready.len() as u64)
    }

    pub(crate) fn epoll_ready_events(
        &mut self,
        watches: &[EpollWatch],
        maxevents: usize,
        timeout: Option<Duration>,
    ) -> Result<Vec<LinuxEpollEvent>, LinuxErrno> {
        let mut ready = Vec::new();
        for watch in watches {
            let poll_events = epoll_events_to_poll_events(watch.events);
            let revents = self.epoll_watch_revents(watch.fd, poll_events, timeout)?;
            let epoll_events = poll_revents_to_epoll_events(revents, watch.events);
            if epoll_events != 0 {
                ready.push(LinuxEpollEvent {
                    events: epoll_events,
                    data: watch.data,
                });
                if ready.len() == maxevents {
                    break;
                }
            }
        }
        Ok(ready)
    }

    pub(crate) fn epoll_watch_revents(
        &mut self,
        fd: Fd,
        events: i16,
        timeout: Option<Duration>,
    ) -> Result<i16, LinuxErrno> {
        match self.poll_fd_revents(fd, events, timeout) {
            Ok(revents) if revents & LINUX_POLLNVAL != 0 => Ok(LINUX_POLLERR | LINUX_POLLHUP),
            Ok(revents) => Ok(revents),
            Err(errno) => Err(errno),
        }
    }
}
