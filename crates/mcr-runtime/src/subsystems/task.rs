#[allow(unused_imports)]
use super::*;

impl mcr_sys::TaskSyscalls for RuntimeSubsystems {
    fn supports_fast_task(&self, request: &SyscallRequest) -> bool {
        if self
            .process
            .pending_fork_exec
            .contains_key(&request.context.pid)
        {
            return false;
        }
        matches!(
            request.syscall,
            mcr_sys::Syscall::Getpid | mcr_sys::Syscall::Gettid
        )
    }

    fn dispatch_fast_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let Some(task) = self.process.tasks.task(request.context.tid) else {
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

impl RuntimeSubsystems {
    pub(crate) fn dispatch_sched_yield(&mut self) -> SyscallOutcome {
        std::thread::yield_now();
        SyscallOutcome::success(0)
    }

    pub(crate) fn dispatch_getrlimit(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = outcome(self.write_rlimit(arg(request, 0), arg(request, 1)));
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_memory(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }

    pub(crate) fn dispatch_getrusage(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        let who = arg(request, 0) as i32;
        let outcome = outcome(self.write_rusage(who, arg(request, 1)));
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_memory(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }

    pub(crate) fn dispatch_sysinfo(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = outcome(self.write_sysinfo(arg(request, 0)));
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_memory(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }

    pub(crate) fn dispatch_prctl(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = outcome(self.prctl(
            arg(request, 0),
            arg(request, 1),
            arg(request, 2),
            arg(request, 3),
            arg(request, 4),
        ));
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_memory(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }

    pub(crate) fn dispatch_prlimit64(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = outcome(self.prlimit64(
            request.context.pid,
            arg(request, 0),
            arg(request, 1),
            arg(request, 2),
            arg(request, 3),
        ));
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_memory(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }

    pub(crate) fn dispatch_getcpu(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_memory_for_process(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = outcome(self.getcpu(arg(request, 0), arg(request, 1)));
        if matches!(outcome.result, SyscallReturn::Success(_))
            && let Err(errno) = self.store_selected_process_memory(pid)
        {
            return SyscallOutcome::errno(errno);
        }
        outcome
    }

    pub(crate) fn dispatch_membarrier(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        outcome(self.membarrier(arg(request, 0), arg(request, 1), arg(request, 2)))
    }

    pub(crate) fn write_rlimit(&mut self, resource: u64, addr: u64) -> Result<u64, LinuxErrno> {
        if addr == 0 {
            return Err(LinuxErrno::EFAULT);
        }
        let (soft, hard) = fixed_rlimit(resource)?;
        write_guest_rlimit(self.files.memory_mut(), addr, soft, hard)?;
        Ok(0)
    }

    pub(crate) fn write_rusage(&mut self, who: i32, addr: u64) -> Result<u64, LinuxErrno> {
        if !matches!(
            who,
            LINUX_RUSAGE_SELF | LINUX_RUSAGE_CHILDREN | LINUX_RUSAGE_THREAD
        ) {
            return Err(LinuxErrno::EINVAL);
        }
        if addr == 0 {
            return Err(LinuxErrno::EFAULT);
        }
        write_zeroed(self.files.memory_mut(), addr, 144)?;
        Ok(0)
    }

    pub(crate) fn write_sysinfo(&mut self, addr: u64) -> Result<u64, LinuxErrno> {
        if addr == 0 {
            return Err(LinuxErrno::EFAULT);
        }
        write_guest_sysinfo(self.files.memory_mut(), addr)?;
        Ok(0)
    }

    pub(crate) fn prctl(
        &mut self,
        option: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<u64, LinuxErrno> {
        match option {
            LINUX_PR_GET_DUMPABLE => Ok(1),
            LINUX_PR_SET_DUMPABLE => match arg2 {
                0 | 1 => Ok(0),
                _ => Err(LinuxErrno::EINVAL),
            },
            LINUX_PR_GET_NAME => {
                if arg2 == 0 {
                    return Err(LinuxErrno::EFAULT);
                }
                let mut name = [0; 16];
                name[..3].copy_from_slice(b"mcr");
                self.files
                    .memory_mut()
                    .write_bytes(arg2, &name)
                    .map_err(memory_errno)?;
                Ok(0)
            }
            LINUX_PR_SET_NAME => {
                if arg2 == 0 {
                    return Err(LinuxErrno::EFAULT);
                }
                let mut name = [0; 16];
                self.files
                    .memory()
                    .read_bytes(arg2, &mut name)
                    .map_err(memory_errno)?;
                Ok(0)
            }
            LINUX_PR_GET_TIMERSLACK => Ok(50_000),
            LINUX_PR_SET_TIMERSLACK => Ok(0),
            LINUX_PR_GET_NO_NEW_PRIVS => Ok(0),
            LINUX_PR_SET_NO_NEW_PRIVS => {
                if arg2 == 1 && arg3 == 0 && arg4 == 0 && arg5 == 0 {
                    Ok(0)
                } else {
                    Err(LinuxErrno::EINVAL)
                }
            }
            LINUX_PR_GET_THP_DISABLE => Ok(0),
            LINUX_PR_SET_THP_DISABLE => match arg2 {
                0 | 1 => Ok(0),
                _ => Err(LinuxErrno::EINVAL),
            },
            LINUX_PR_SET_VMA if arg2 == LINUX_PR_SET_VMA_ANON_NAME => Ok(0),
            _ => Err(LinuxErrno::EINVAL),
        }
    }

    pub(crate) fn prlimit64(
        &mut self,
        current_pid: mcr_sys::GuestPid,
        raw_pid: u64,
        resource: u64,
        new_limit_addr: u64,
        old_limit_addr: u64,
    ) -> Result<u64, LinuxErrno> {
        if raw_pid != 0 && raw_pid != u64::from(current_pid) {
            return Err(LinuxErrno::ESRCH);
        }
        let (soft, hard) = fixed_rlimit(resource)?;
        if old_limit_addr != 0 {
            write_guest_rlimit(self.files.memory_mut(), old_limit_addr, soft, hard)?;
        }
        if new_limit_addr != 0 {
            let (requested_soft, requested_hard) =
                read_guest_rlimit(self.files.memory(), new_limit_addr)?;
            if requested_soft > requested_hard {
                return Err(LinuxErrno::EINVAL);
            }
        }
        Ok(0)
    }

    pub(crate) fn getcpu(&mut self, cpu_addr: u64, node_addr: u64) -> Result<u64, LinuxErrno> {
        if cpu_addr != 0 {
            self.files
                .memory_mut()
                .write_bytes(cpu_addr, &0u32.to_le_bytes())
                .map_err(memory_errno)?;
        }
        if node_addr != 0 {
            self.files
                .memory_mut()
                .write_bytes(node_addr, &0u32.to_le_bytes())
                .map_err(memory_errno)?;
        }
        Ok(0)
    }

    pub(crate) fn membarrier(
        &mut self,
        command: u64,
        flags: u64,
        _cpu_id: u64,
    ) -> Result<u64, LinuxErrno> {
        if flags != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        if command == LINUX_MEMBARRIER_CMD_QUERY {
            return Ok(0);
        }
        Err(LinuxErrno::ENOSYS)
    }

    pub(crate) fn dispatch_rt_sigprocmask(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        match self.rt_sigprocmask(request) {
            Ok(()) => SyscallOutcome::success(0),
            Err(errno) => SyscallOutcome::errno(errno),
        }
    }

    pub(crate) fn rt_sigprocmask(&mut self, request: &SyscallRequest) -> Result<(), LinuxErrno> {
        let pid = request.context.pid;
        self.select_memory_for_process(pid)?;
        let args = mcr_sys::RtSigprocmaskSyscallArgs::new(
            arg_u32(request, 0),
            arg(request, 1),
            arg(request, 2),
            arg(request, 3),
        );
        if args.sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
            return Err(LinuxErrno::EINVAL);
        }
        if !args.supported_how() {
            return Err(LinuxErrno::EINVAL);
        }
        let set = if args.set == 0 {
            0
        } else {
            read_guest_u64(self.files.memory(), args.set)?
        };
        let current_mask = self
            .process
            .tasks
            .process(pid)
            .ok_or(LinuxErrno::ESRCH)?
            .signals()
            .blocked();
        if args.oldset != 0 {
            self.files
                .memory_mut()
                .write_bytes(args.oldset, &current_mask.to_le_bytes())
                .map_err(memory_errno)?;
        }
        let kernel_request = SyscallRequest::from_guest_context(GuestContext::new(
            request.context.pid,
            request.context.tid,
            mcr_sys::SyscallRegisters {
                rax: request.number.raw(),
                rdi: u64::from(args.how),
                rsi: set,
                rdx: 0,
                r10: args.sigsetsize,
                r8: 0,
                r9: 0,
                rip: request.context.rip,
            },
        ));
        let outcome = self
            .process
            .tasks
            .dispatch_for_current_task(&kernel_request);
        match outcome.result {
            SyscallReturn::Success(_) => {
                self.store_selected_process_memory(pid)?;
                Ok(())
            }
            SyscallReturn::Errno(errno) => Err(errno),
        }
    }

    pub(crate) fn dispatch_sigaltstack(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        match self.sigaltstack(request) {
            Ok(()) => SyscallOutcome::success(0),
            Err(errno) => SyscallOutcome::errno(errno),
        }
    }

    pub(crate) fn sigaltstack(&mut self, request: &SyscallRequest) -> Result<(), LinuxErrno> {
        let pid = request.context.pid;
        let tid = request.context.tid;
        self.select_memory_for_process(pid)?;
        let ss = arg(request, 0);
        let old_ss = arg(request, 1);
        let current = self
            .events
            .signal_alt_stacks
            .get(&tid)
            .copied()
            .unwrap_or_default();
        let requested = if ss == 0 {
            None
        } else {
            let stack = read_guest_stack_t(self.files.memory(), ss)?;
            validate_sigaltstack(stack)?;
            Some(stack)
        };

        if old_ss != 0 {
            write_guest_stack_t(self.files.memory_mut(), old_ss, current)?;
        }

        if let Some(requested) = requested {
            if requested.disabled() {
                self.events.signal_alt_stacks.remove(&tid);
            } else {
                self.events.signal_alt_stacks.insert(tid, requested);
            }
        }

        self.store_selected_process_memory(pid)
    }

    pub(crate) fn dispatch_kernel_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = self.process.tasks.dispatch_for_current_task(request);
        if !matches!(outcome.result, SyscallReturn::Success(_)) {
            return outcome;
        }
        match request.syscall {
            mcr_sys::Syscall::Uname => {
                if let Err(errno) = self.write_uname(arg(request, 0)) {
                    return SyscallOutcome::errno(errno);
                }
                if let Err(errno) = self.store_selected_process_memory(pid) {
                    return SyscallOutcome::errno(errno);
                }
            }
            mcr_sys::Syscall::Exit | mcr_sys::Syscall::ExitGroup => {
                let exit_group = request.syscall == mcr_sys::Syscall::ExitGroup;
                if let Err(errno) = self.finish_task_exit(pid, request.context.tid, exit_group) {
                    return SyscallOutcome::errno(errno);
                }
            }
            mcr_sys::Syscall::Wait4 => {
                if let Some(child_pid) = fork_child_pid(&outcome.decoded) {
                    if let Err(errno) = self.write_wait_status_from_outcome(pid, request, &outcome)
                    {
                        return SyscallOutcome::errno(errno);
                    }
                    if let Err(errno) = self.drop_process_resources(child_pid) {
                        return SyscallOutcome::errno(errno);
                    }
                }
            }
            _ => {}
        }
        outcome
    }

    pub(crate) fn finish_task_exit(
        &mut self,
        pid: mcr_sys::GuestPid,
        tid: mcr_sys::GuestTid,
        exit_group: bool,
    ) -> Result<(), LinuxErrno> {
        if !exit_group
            && let Some(clear_child_tid) = self
                .process
                .tasks
                .task_mut(tid)
                .and_then(GuestTask::take_clear_child_tid)
        {
            write_guest_u32(self.files.memory_mut(), clear_child_tid, 0)?;
            self.store_selected_process_memory(pid)?;
            self.events.futexes.wake(clear_child_tid, u32::MAX);
            self.process
                .tasks
                .wake_futex_waiters(FutexWaitKey::new(pid, clear_child_tid, true), u32::MAX);
        }

        let process_exited = matches!(
            self.process
                .tasks
                .process(pid)
                .map(GuestProcess::exit_state),
            Some(ExitState::Exited { .. })
        );
        if exit_group || process_exited {
            self.drop_native_fp_for_process(pid);
            self.drop_process_resources(pid)
        } else {
            self.drop_native_fp_for_tid(tid);
            Ok(())
        }
    }

    pub(crate) fn resume_waiting_tasks(&mut self) -> Result<Vec<CompletedWait>, LinuxErrno> {
        let completed = self.process.tasks.resume_waiting_tasks();
        for wait in &completed {
            self.write_wait_status(*wait)?;
            self.drop_native_fp_for_process(wait.waited().pid());
            self.drop_process_resources(wait.waited().pid())?;
        }
        Ok(completed)
    }

    pub(crate) fn resume_fd_waiters(&mut self) {
        let selected_pid = self.process.selected_fds_pid;
        let selected_fds = self.files.vfs().fds().clone();
        let process_fds = self.process.fds.clone();
        let resumed = self.process.tasks.resume_fd_waiters(|pid, fd, write| {
            let fds = if pid == selected_pid {
                Some(&selected_fds)
            } else {
                process_fds.get(&pid)
            };
            fds.and_then(|fds| fd_wait_ready(fds, fd, write).ok())
                .unwrap_or(true)
        });
        self.perf_record_fd_wakeups(resumed);
    }

    pub(crate) fn write_uname(&mut self, addr: u64) -> Result<(), LinuxErrno> {
        let uts = self.process.tasks.uname_value();
        write_guest_uname(self.files.memory_mut(), addr, &uts)
    }

    pub(crate) fn write_wait_status_from_outcome(
        &mut self,
        pid: mcr_sys::GuestPid,
        request: &SyscallRequest,
        outcome: &SyscallOutcome,
    ) -> Result<(), LinuxErrno> {
        let wstatus = arg(request, 1);
        let Some(wait_status) = wait_status_from_decoded(&outcome.decoded) else {
            return Ok(());
        };
        self.write_wait_status_to_process(pid, wstatus, wait_status)
    }

    pub(crate) fn write_wait_status(&mut self, wait: CompletedWait) -> Result<(), LinuxErrno> {
        self.write_wait_status_to_process(
            wait.pid(),
            wait.args().wstatus,
            wait.waited().wait_status(),
        )
    }

    pub(crate) fn write_wait_status_to_process(
        &mut self,
        pid: mcr_sys::GuestPid,
        wstatus: u64,
        wait_status: u32,
    ) -> Result<(), LinuxErrno> {
        if wstatus == 0 {
            return Ok(());
        }
        self.materialize_pending_fork_exec_children(pid)
            .map_err(|error| error.errno())?;
        self.memory_for_process_mut(pid)
            .ok_or(LinuxErrno::ESRCH)?
            .write(wstatus, &wait_status.to_le_bytes())
            .map_err(|error| error.errno())
    }

    pub(crate) fn dispatch_fork_like(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let clone_args = match request.syscall {
            mcr_sys::Syscall::Clone => Some(clone_args_from_request(request)),
            mcr_sys::Syscall::Clone3 => {
                match clone3_args_from_memory(self.files.memory(), arg(request, 0), arg(request, 1))
                {
                    Ok(args) => Some(args),
                    Err(errno) => return SyscallOutcome::errno(errno),
                }
            }
            _ => None,
        };
        self.perf_record_fork_like(request.syscall, clone_args);
        let pending_child_regs = self.native.pending_fork_child_regs.take();
        let outcome = if self.native.enabled {
            match pending_child_regs {
                Some(child_regs) => {
                    self.dispatch_native_fork_like_task(request, clone_args, child_regs)
                }
                None if request.syscall == mcr_sys::Syscall::Clone3 => {
                    self.process.tasks.clone_current(
                        request.context.tid,
                        clone_args.expect("clone3 args decoded"),
                    )
                }
                None => self.process.tasks.dispatch_for_current_task(request),
            }
        } else if request.syscall == mcr_sys::Syscall::Clone3 {
            self.process.tasks.clone_current(
                request.context.tid,
                clone_args.expect("clone3 args decoded"),
            )
        } else {
            self.process.tasks.dispatch_for_current_task(request)
        };
        if !matches!(outcome.result, SyscallReturn::Success(_)) {
            return outcome;
        }
        if let Some(child_tid) = thread_child_tid(&outcome.decoded) {
            if let Some(args) = clone_args
                && let Err(errno) = self.write_clone_tid_pointers(pid, args, child_tid)
            {
                return SyscallOutcome::errno(errno);
            }
            self.clone_native_fp_for_thread(request.context.tid, child_tid);
            return outcome;
        }
        let Some(child_pid) = fork_child_pid(&outcome.decoded) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        self.process.pending_fork_exec.insert(
            child_pid,
            PendingForkExec {
                parent_pid: pid,
                created_at: Instant::now(),
            },
        );
        self.process
            .fds
            .insert(child_pid, self.files.vfs().fds().clone());
        self.fork_native_fp(request.context.tid, child_pid);
        outcome.with_decoded_field("fork_memory", "deferred_exec")
    }

    pub(crate) fn dispatch_native_fork_like_task(
        &mut self,
        request: &SyscallRequest,
        clone_args: Option<CloneSyscallArgs>,
        child_regs: GprState,
    ) -> SyscallOutcome {
        match request.syscall {
            mcr_sys::Syscall::Fork => self
                .process
                .tasks
                .fork_current_with_child_regs(request.context.tid, child_regs),
            mcr_sys::Syscall::Vfork => self
                .process
                .tasks
                .vfork_current_with_child_regs(request.context.tid, child_regs),
            mcr_sys::Syscall::Clone | mcr_sys::Syscall::Clone3 => {
                self.process.tasks.clone_current_with_child_regs(
                    request.context.tid,
                    clone_args.expect("clone args decoded"),
                    child_regs,
                )
            }
            _ => SyscallOutcome::unsupported(),
        }
    }

    pub(crate) fn write_clone_tid_pointers(
        &mut self,
        pid: mcr_sys::GuestPid,
        args: CloneSyscallArgs,
        child_tid: mcr_sys::GuestTid,
    ) -> Result<(), LinuxErrno> {
        let mut wrote = false;
        if args.has_clone_parent_settid() && args.parent_tid != 0 {
            write_guest_u32(self.files.memory_mut(), args.parent_tid, child_tid)?;
            wrote = true;
        }
        if args.has_clone_child_settid() && args.child_tid != 0 {
            write_guest_u32(self.files.memory_mut(), args.child_tid, child_tid)?;
            wrote = true;
        }
        if wrote {
            self.store_selected_process_memory(pid)?;
        }
        Ok(())
    }

    pub(crate) fn dispatch_execve(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        match self.execve(request) {
            Ok(true) => {
                SyscallOutcome::success(0).with_decoded_field("exec_fast_path", "fork_exec")
            }
            Ok(false) => SyscallOutcome::success(0),
            Err(errno) => SyscallOutcome::errno(errno),
        }
    }

    pub(crate) fn execve(&mut self, request: &SyscallRequest) -> Result<bool, LinuxErrno> {
        if self
            .process
            .pending_fork_exec
            .contains_key(&request.context.pid)
        {
            return self.execve_pending_fork_exec_child(request).map(|()| true);
        }
        self.materialize_pending_fork_exec_children(request.context.pid)
            .map_err(|error| error.errno())?;
        self.select_process_context(request.context.pid)?;
        let filename = read_guest_c_bytes(self.files.memory(), arg(request, 0))?;
        let argv = self.files.read_guest_vector(arg(request, 1))?;
        let envp = self.files.read_guest_vector(arg(request, 2))?;
        let program = self.files.load_guest_program(filename, argv, envp)?;
        self.process
            .tasks
            .exec_task(request.context.tid, program)
            .map_err(|error| error.linux_errno())?;
        let closed_fd_ids = self.files.vfs_mut().fds_mut().close_on_exec();
        for socket_id in closed_fd_ids
            .socket_ids
            .into_iter()
            .filter_map(SocketId::new)
        {
            if self.socket_fd_ref_count_excluding_current(request.context.pid, socket_id)
                + self.files.vfs().socket_fd_count(socket_id.get())
                == 0
            {
                self.files
                    .sockets_mut()
                    .close(socket_id)
                    .map_err(net_errno)?;
            }
        }
        for epoll_id in closed_fd_ids.epoll_ids {
            if self.epoll_fd_ref_count_excluding_current(request.context.pid, epoll_id)
                + self.files.vfs().epoll_fd_count(epoll_id)
                == 0
            {
                self.events.epolls.close(epoll_id);
            }
        }
        sync_proc_self(
            self.files.vfs_mut(),
            &self.process.tasks,
            request.context.pid,
        );
        self.native.fp.remove(&request.context.tid);
        self.events.signal_alt_stacks.remove(&request.context.tid);
        self.replace_memory_from_image(request.context.pid)?;
        self.native.patch_caches.remove(&request.context.pid);
        self.native
            .libc_intrinsic_patches
            .retain(|(pid, _), _| *pid != request.context.pid);
        self.store_selected_process_fds(request.context.pid)?;
        self.store_selected_process_memory(request.context.pid)?;
        Ok(false)
    }

    pub(crate) fn execve_pending_fork_exec_child(
        &mut self,
        request: &SyscallRequest,
    ) -> Result<(), LinuxErrno> {
        let child_pid = request.context.pid;
        let pending = self
            .process
            .pending_fork_exec
            .get(&child_pid)
            .copied()
            .ok_or(LinuxErrno::ESRCH)?;
        let parent_pid = pending.parent_pid;
        self.select_fds_for_process(child_pid)?;
        sync_proc_self(self.files.vfs_mut(), &self.process.tasks, child_pid);

        let args = (|| {
            let memory = self
                .memory_for_process(parent_pid)
                .ok_or(LinuxErrno::ESRCH)?;
            let filename = read_guest_c_bytes(memory, arg(request, 0))?;
            let argv = read_guest_vector(memory, arg(request, 1))?;
            let envp = read_guest_vector(memory, arg(request, 2))?;
            Ok((filename, argv, envp))
        })();
        let (filename, argv, envp) = match args {
            Ok(args) => args,
            Err(errno) => {
                self.materialize_pending_fork_exec_child_memory(child_pid)
                    .map_err(|error| error.errno())?;
                return Err(errno);
            }
        };
        let program = match self.files.load_guest_program(filename, argv, envp) {
            Ok(program) => program,
            Err(errno) => {
                self.materialize_pending_fork_exec_child_memory(child_pid)
                    .map_err(|error| error.errno())?;
                return Err(errno);
            }
        };
        if let Err(error) = self.process.tasks.exec_task(request.context.tid, program) {
            self.materialize_pending_fork_exec_child_memory(child_pid)
                .map_err(|error| error.errno())?;
            return Err(error.linux_errno());
        }
        self.process.pending_fork_exec.remove(&child_pid);
        self.perf_record_clone_to_exec(pending.created_at.elapsed());
        let closed_fd_ids = self.files.vfs_mut().fds_mut().close_on_exec();
        for socket_id in closed_fd_ids
            .socket_ids
            .into_iter()
            .filter_map(SocketId::new)
        {
            if self.socket_fd_ref_count_excluding_current(child_pid, socket_id)
                + self.files.vfs().socket_fd_count(socket_id.get())
                == 0
            {
                self.files
                    .sockets_mut()
                    .close(socket_id)
                    .map_err(net_errno)?;
            }
        }
        for epoll_id in closed_fd_ids.epoll_ids {
            if self.epoll_fd_ref_count_excluding_current(child_pid, epoll_id)
                + self.files.vfs().epoll_fd_count(epoll_id)
                == 0
            {
                self.events.epolls.close(epoll_id);
            }
        }
        sync_proc_self(self.files.vfs_mut(), &self.process.tasks, child_pid);
        self.native.fp.remove(&request.context.tid);
        self.events.signal_alt_stacks.remove(&request.context.tid);
        self.replace_memory_from_image(child_pid)?;
        self.native.patch_caches.remove(&child_pid);
        self.native
            .libc_intrinsic_patches
            .retain(|(pid, _), _| *pid != child_pid);
        self.store_selected_process_fds(child_pid)
    }

    pub(crate) fn replace_memory_from_image(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        let image = self
            .process
            .tasks
            .process(pid)
            .ok_or(LinuxErrno::ESRCH)?
            .image()
            .memory()
            .clone();
        if pid == self.process.selected_memory_pid {
            self.drop_selected_memory_allocations();
            let memory = self.memory_from_process_image(&image)?;
            *self.files.memory_mut() = memory;
        } else {
            let memory = self.memory_from_process_image(&image)?;
            self.process.memory.insert(pid, memory);
        }
        self.set_native_image_patch_key(pid, &image);
        Ok(())
    }

    pub(crate) fn set_native_image_patch_key(
        &mut self,
        pid: mcr_sys::GuestPid,
        image: &mcr_elf::GuestMemoryImage,
    ) {
        if let Some((key, ranges)) = native_image_patch_key_and_ranges(image) {
            self.native.image_patch_keys.insert(pid, key);
            self.native.image_patch_ranges.insert(pid, ranges);
        } else {
            self.native.image_patch_keys.remove(&pid);
            self.native.image_patch_ranges.remove(&pid);
        }
    }

    pub(crate) fn memory_from_process_image(
        &self,
        image: &mcr_elf::GuestMemoryImage,
    ) -> Result<GuestMemory, LinuxErrno> {
        let mut memory = GuestMemory::from_image(image).map_err(|error| error.errno())?;
        self.configure_new_process_memory(&mut memory)?;
        Ok(memory)
    }

    pub(crate) fn configure_new_process_memory(
        &self,
        memory: &mut GuestMemory,
    ) -> Result<(), LinuxErrno> {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            if self.native.enabled {
                memory
                    .set_mmap_base(WINDOWS_NATIVE_MMAP_BASE)
                    .map_err(|error| error.errno())?;
            }
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        {
            let _ = memory;
        }
        Ok(())
    }
}
