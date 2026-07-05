#[allow(unused_imports)]
use super::*;

impl RuntimeSubsystems {
    pub(crate) fn select_process_context(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        self.select_memory_for_process(pid)?;
        self.select_fds_for_process(pid)?;
        sync_proc_self(self.files.vfs_mut(), &self.process.tasks, pid);
        Ok(())
    }

    pub(crate) fn select_memory_for_process(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        if self.process.pending_fork_exec.contains_key(&pid) {
            self.materialize_pending_fork_exec_child_memory(pid)
                .map_err(|error| error.errno())?;
        }
        if pid == self.process.selected_memory_pid {
            if self.native.enabled && !self.files.memory().uses_fixed_guest_host_addresses() {
                self.materialize_selected_memory_at_guest_addresses()?;
            }
            return Ok(());
        }
        if self.native.enabled {
            return self.select_native_memory_for_process(pid);
        }
        let selected_pid = self.process.selected_memory_pid;
        let memory = self.process.memory.remove(&pid).ok_or(LinuxErrno::ESRCH)?;
        if self.process.tasks.process(selected_pid).is_some() {
            let selected = std::mem::replace(self.files.memory_mut(), memory);
            self.process.memory.insert(selected_pid, selected);
        } else {
            *self.files.memory_mut() = memory;
        }
        self.process.selected_memory_pid = pid;
        self.perf_record_context_memory_switch();
        Ok(())
    }

    pub(crate) fn prepare_memory_mut_for_process(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        if self.process.pending_fork_exec.contains_key(&pid) {
            self.materialize_pending_fork_exec_child_memory(pid)
                .map_err(|error| error.errno())?;
        }
        self.materialize_pending_fork_exec_children(pid)
            .map_err(|error| error.errno())?;
        self.select_memory_for_process(pid)
    }

    pub(crate) fn select_native_memory_for_process(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        let remap_start = Instant::now();
        let result = (|| {
            let selected_pid = self.process.selected_memory_pid;
            let selected_snapshot = if self.process.tasks.process(selected_pid).is_some() {
                self.perf_record_context_memory_clone();
                Some(
                    self.files
                        .memory()
                        .try_clone_runtime()
                        .map_err(|error| error.errno())?,
                )
            } else {
                None
            };
            let target_snapshot = self.process.memory.remove(&pid).ok_or(LinuxErrno::ESRCH)?;
            self.drop_selected_memory_allocations();
            match target_snapshot.try_clone_runtime_at_guest_addresses() {
                Ok(memory) => {
                    if let Some(snapshot) = selected_snapshot {
                        self.process.memory.insert(selected_pid, snapshot);
                    }
                    *self.files.memory_mut() = memory;
                    self.process.selected_memory_pid = pid;
                    Ok(())
                }
                Err(error) => {
                    self.process.memory.insert(pid, target_snapshot);
                    if let Some(snapshot) = selected_snapshot {
                        let restored = snapshot
                            .try_clone_runtime_at_guest_addresses()
                            .map_err(|restore_error| restore_error.errno())?;
                        self.process.memory.insert(selected_pid, snapshot);
                        *self.files.memory_mut() = restored;
                    }
                    Err(error.errno())
                }
            }
        })();
        self.perf_record_remap(remap_start.elapsed());
        result
    }

    pub(crate) fn materialize_selected_memory_at_guest_addresses(
        &mut self,
    ) -> Result<(), LinuxErrno> {
        let snapshot = self
            .files
            .memory()
            .try_clone_runtime()
            .map_err(|error| error.errno())?;
        self.drop_selected_memory_allocations();
        let memory = snapshot
            .try_clone_runtime_at_guest_addresses()
            .map_err(|error| error.errno())?;
        *self.files.memory_mut() = memory;
        Ok(())
    }

    pub(crate) fn drop_selected_memory_allocations(&mut self) {
        let empty = self.files.memory().empty_clone_layout();
        let selected = std::mem::replace(self.files.memory_mut(), empty);
        drop(selected);
    }

    pub(crate) fn has_pending_fork_exec_child(&self, pid: mcr_sys::GuestPid) -> bool {
        self.process.pending_fork_exec.contains_key(&pid)
    }

    pub(crate) fn has_pending_fork_exec_children(&self, parent_pid: mcr_sys::GuestPid) -> bool {
        self.process
            .pending_fork_exec
            .values()
            .any(|pending| pending.parent_pid == parent_pid)
    }

    pub(crate) fn prioritize_pending_fork_exec_tids(&self, tids: &mut [mcr_sys::GuestTid]) {
        tids.sort_by_key(|tid| {
            let pending_child = self
                .process
                .tasks
                .task(*tid)
                .is_some_and(|task| self.process.pending_fork_exec.contains_key(&task.pid()));
            (!pending_child, *tid)
        });
    }

    pub(crate) fn sticky_scheduler_candidate(
        &self,
        tid: mcr_sys::GuestTid,
    ) -> Option<mcr_sys::GuestTid> {
        let task = self.process.tasks.task(tid)?;
        if !matches!(task.state(), TaskState::Runnable) {
            return None;
        }
        if self.has_pending_fork_exec_children(task.pid()) {
            return None;
        }
        Some(tid)
    }

    pub(crate) fn materialize_pending_fork_exec_children(
        &mut self,
        parent_pid: mcr_sys::GuestPid,
    ) -> Result<(), GuestMemoryError> {
        if unsafe_share_until_exec_enabled() {
            return Ok(());
        }
        let child_pids = self
            .process
            .pending_fork_exec
            .iter()
            .filter_map(|(child_pid, pending)| {
                (pending.parent_pid == parent_pid).then_some(*child_pid)
            })
            .collect::<Vec<_>>();
        for child_pid in child_pids {
            self.materialize_pending_fork_exec_child_memory(child_pid)?;
        }
        Ok(())
    }

    pub(crate) fn materialize_pending_fork_exec_child_memory(
        &mut self,
        child_pid: mcr_sys::GuestPid,
    ) -> Result<(), GuestMemoryError> {
        let materialize_start = Instant::now();
        let pending = self
            .process
            .pending_fork_exec
            .get(&child_pid)
            .copied()
            .ok_or(GuestMemoryError::NotMapped)?;
        host_step_trace(format_args!(
            "runtime materialize-fork-child start parent_pid={} child_pid={child_pid}",
            pending.parent_pid
        ));
        let memory = self
            .memory_for_process(pending.parent_pid)
            .ok_or(GuestMemoryError::NotMapped)?
            .try_clone_runtime()?;
        self.process.pending_fork_exec.remove(&child_pid);
        self.process.memory.insert(child_pid, memory);
        if let Some(cache) = self.native.patch_caches.get(&pending.parent_pid).cloned() {
            self.native.patch_caches.insert(child_pid, cache);
        }
        if let Some(key) = self
            .native
            .image_patch_keys
            .get(&pending.parent_pid)
            .cloned()
        {
            self.native.image_patch_keys.insert(child_pid, key);
        }
        if let Some(ranges) = self
            .native
            .image_patch_ranges
            .get(&pending.parent_pid)
            .cloned()
        {
            self.native.image_patch_ranges.insert(child_pid, ranges);
        }
        let inherited_intrinsic_patches = self
            .native
            .libc_intrinsic_patches
            .iter()
            .filter(|((pid, _), _)| *pid == pending.parent_pid)
            .map(|((_, address), intrinsic)| (*address, *intrinsic))
            .collect::<Vec<_>>();
        for (address, intrinsic) in inherited_intrinsic_patches {
            self.native
                .libc_intrinsic_patches
                .insert((child_pid, address), intrinsic);
        }
        host_step_trace(format_args!(
            "runtime materialize-fork-child done parent_pid={} child_pid={child_pid} elapsed_ms={}",
            pending.parent_pid,
            host_step_elapsed_ms(materialize_start)
        ));
        Ok(())
    }

    pub(crate) fn store_selected_process_memory(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        if pid != self.process.selected_memory_pid {
            return Err(LinuxErrno::ESRCH);
        }
        if self.process.tasks.process(pid).is_none() {
            return Ok(());
        }
        Ok(())
    }

    pub(crate) fn select_fds_for_process(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        if pid == self.process.selected_fds_pid {
            return Ok(());
        }
        let selected_pid = self.process.selected_fds_pid;
        let fds = self.process.fds.remove(&pid).ok_or(LinuxErrno::ESRCH)?;
        let selected = self.files.vfs_mut().replace_fds(fds);
        if self.process.tasks.process(selected_pid).is_some() {
            self.process.fds.insert(selected_pid, selected);
        }
        self.process.selected_fds_pid = pid;
        self.perf_record_context_fd_switch();
        Ok(())
    }

    pub(crate) fn store_selected_process_fds(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        if pid != self.process.selected_fds_pid {
            return Err(LinuxErrno::ESRCH);
        }
        if self.process.tasks.process(pid).is_none() {
            return Ok(());
        }
        Ok(())
    }

    pub(crate) fn drop_process_fds(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        if pid == self.process.selected_fds_pid {
            if pid != mcr_task::INITIAL_GUEST_PID {
                let fds = self
                    .process
                    .fds
                    .remove(&mcr_task::INITIAL_GUEST_PID)
                    .ok_or(LinuxErrno::ESRCH)?;
                self.files.vfs_mut().replace_fds(fds);
                self.process.selected_fds_pid = mcr_task::INITIAL_GUEST_PID;
            }
        } else {
            self.process.fds.remove(&pid);
        }
        Ok(())
    }

    pub(crate) fn drop_process_resources(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        self.close_unshared_process_sockets(pid)?;
        self.drop_process_memory(pid)?;
        self.drop_process_fds(pid)
    }

    pub(crate) fn fork_native_fp(
        &mut self,
        parent_tid: mcr_sys::GuestTid,
        child_pid: mcr_sys::GuestPid,
    ) {
        let Some(state) = self.native.fp.get(&parent_tid).copied() else {
            return;
        };
        let child_tids = self
            .process
            .tasks
            .tasks()
            .filter(|task| task.pid() == child_pid)
            .map(mcr_task::GuestTask::tid)
            .collect::<Vec<_>>();
        for child_tid in child_tids {
            self.native.fp.insert(child_tid, state);
        }
    }

    pub(crate) fn clone_native_fp_for_thread(
        &mut self,
        parent_tid: mcr_sys::GuestTid,
        child_tid: mcr_sys::GuestTid,
    ) {
        if let Some(state) = self.native.fp.get(&parent_tid).copied() {
            self.native.fp.insert(child_tid, state);
        }
    }

    pub(crate) fn drop_native_fp_for_tid(&mut self, tid: mcr_sys::GuestTid) {
        self.native.fp.remove(&tid);
    }

    pub(crate) fn drop_native_fp_for_process(&mut self, pid: mcr_sys::GuestPid) {
        let tids = self
            .process
            .tasks
            .tasks()
            .filter(|task| task.pid() == pid)
            .map(mcr_task::GuestTask::tid)
            .collect::<Vec<_>>();
        for tid in tids {
            self.native.fp.remove(&tid);
        }
    }

    pub(crate) fn drop_native_patch_cache_for_process(&mut self, pid: mcr_sys::GuestPid) {
        self.native.patch_caches.remove(&pid);
        self.native.image_patch_keys.remove(&pid);
        self.native.image_patch_ranges.remove(&pid);
        self.native
            .libc_intrinsic_patches
            .retain(|(patch_pid, _), _| *patch_pid != pid);
    }

    pub(crate) fn close_unshared_process_sockets(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        let Some((socket_ids, epoll_ids)) = self.fd_table_for_process(pid).map(|fds| {
            (
                fds.socket_ids()
                    .filter_map(SocketId::new)
                    .collect::<Vec<_>>(),
                fds.epoll_ids().collect::<Vec<_>>(),
            )
        }) else {
            return Ok(());
        };
        for socket_id in socket_ids {
            if self.socket_fd_ref_count_excluding_current(pid, socket_id) == 0 {
                self.files
                    .sockets_mut()
                    .close(socket_id)
                    .map_err(net_errno)?;
            }
        }
        for epoll_id in epoll_ids {
            if self.epoll_fd_ref_count_excluding_current(pid, epoll_id) == 0 {
                self.events.epolls.close(epoll_id);
            }
        }
        Ok(())
    }

    pub(crate) fn close_process_fd(&mut self, fd: Fd) -> Result<u64, LinuxErrno> {
        let file = self
            .files
            .vfs_mut()
            .close_with_file(fd)
            .map_err(vfs_errno)?;
        self.close_unshared_process_file_resources(&file)?;
        Ok(0)
    }

    pub(crate) fn close_process_fd_range(
        &mut self,
        first: u32,
        last: u32,
        flags: u32,
    ) -> Result<u64, LinuxErrno> {
        if flags & !LINUX_CLOSE_RANGE_SUPPORTED_FLAGS != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let Some((first, last)) = fd_range_bounds(first, last)? else {
            return Ok(0);
        };
        let fds = self.files.vfs().fds().fds_in_range(first, last);
        for fd in fds {
            match self.files.vfs_mut().close_with_file(fd) {
                Ok(file) => self.close_unshared_process_file_resources(&file)?,
                Err(VfsError::BadFd) => {}
                Err(error) => return Err(vfs_errno(error)),
            }
        }
        Ok(0)
    }

    pub(crate) fn close_unshared_process_file_resources(
        &mut self,
        file: &FileRef,
    ) -> Result<(), LinuxErrno> {
        match file.kind() {
            FileKind::Socket => {
                let socket_id = match file.inode().backend() {
                    mcr_vfs::InodeBackend::Socket(socket) => SocketId::new(socket.id()),
                    _ => None,
                };
                if let Some(socket_id) = socket_id
                    && self.socket_fd_ref_count_excluding_current(
                        self.process.selected_fds_pid,
                        socket_id,
                    ) + self.files.vfs().socket_fd_count(socket_id.get())
                        == 0
                {
                    self.files
                        .sockets_mut()
                        .close(socket_id)
                        .map_err(net_errno)?;
                }
            }
            FileKind::Epoll => {
                let epoll_id = match file.inode().backend() {
                    mcr_vfs::InodeBackend::Epoll(epoll) => Some(epoll.id()),
                    _ => None,
                };
                if let Some(epoll_id) = epoll_id
                    && self.epoll_fd_ref_count_excluding_current(
                        self.process.selected_fds_pid,
                        epoll_id,
                    ) + self.files.vfs().epoll_fd_count(epoll_id)
                        == 0
                {
                    self.events.epolls.close(epoll_id);
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn fd_table_for_process(&self, pid: mcr_sys::GuestPid) -> Option<&FdTable> {
        if pid == self.process.selected_fds_pid {
            Some(self.files.vfs().fds())
        } else {
            self.process.fds.get(&pid)
        }
    }

    pub(crate) fn socket_fd_ref_count_excluding_current(
        &self,
        excluded_pid: mcr_sys::GuestPid,
        socket_id: SocketId,
    ) -> usize {
        let selected_count = if self.process.selected_fds_pid != excluded_pid {
            self.files
                .vfs()
                .socket_ids()
                .filter(|raw| *raw == socket_id.get())
                .count()
        } else {
            0
        };
        selected_count
            + self
                .process
                .fds
                .iter()
                .filter(|(pid, _)| **pid != excluded_pid)
                .map(|(_, fds)| {
                    fds.socket_ids()
                        .filter(|raw| *raw == socket_id.get())
                        .count()
                })
                .sum::<usize>()
    }

    pub(crate) fn epoll_fd_ref_count_excluding_current(
        &self,
        excluded_pid: mcr_sys::GuestPid,
        epoll_id: u64,
    ) -> usize {
        let selected_count = if self.process.selected_fds_pid != excluded_pid {
            self.files
                .vfs()
                .epoll_ids()
                .filter(|raw| *raw == epoll_id)
                .count()
        } else {
            0
        };
        selected_count
            + self
                .process
                .fds
                .iter()
                .filter(|(pid, _)| **pid != excluded_pid)
                .map(|(_, fds)| fds.epoll_ids().filter(|raw| *raw == epoll_id).count())
                .sum::<usize>()
    }

    pub(crate) fn drop_process_memory(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        self.materialize_pending_fork_exec_children(pid)
            .map_err(|error| error.errno())?;
        self.process.pending_fork_exec.remove(&pid);
        if pid == self.process.selected_memory_pid {
            if pid != mcr_task::INITIAL_GUEST_PID {
                self.restore_initial_memory_after_selected_drop()?;
            }
        } else {
            self.process.memory.remove(&pid);
        }
        self.drop_native_patch_cache_for_process(pid);
        Ok(())
    }

    pub(crate) fn restore_initial_memory_after_selected_drop(&mut self) -> Result<(), LinuxErrno> {
        let memory = self
            .process
            .memory
            .remove(&mcr_task::INITIAL_GUEST_PID)
            .ok_or(LinuxErrno::ESRCH)?;
        if self.native.enabled {
            self.drop_selected_memory_allocations();
            let memory = memory
                .try_clone_runtime_at_guest_addresses()
                .map_err(|error| error.errno())?;
            *self.files.memory_mut() = memory;
        } else {
            *self.files.memory_mut() = memory;
        }
        self.process.selected_memory_pid = mcr_task::INITIAL_GUEST_PID;
        Ok(())
    }
}
