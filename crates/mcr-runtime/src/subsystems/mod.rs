#[allow(unused_imports)]
use super::*;

mod event;
mod file;
mod memory;
mod network;
mod patch_cache;
mod perf;
mod process;
mod task;
mod time;

pub struct RuntimeSubsystems {
    pub(crate) tasks: GuestKernel,
    pub(crate) guest_task_worker_pool: Option<Arc<HostWorkerPoolExecutor>>,
    pub(crate) files: RuntimeFileSystem<GuestMemory>,
    pub(crate) file_backed_mapping_cache: FileBackedMappingCache,
    pub(crate) libc_intrinsic_symbol_cache:
        BTreeMap<RegularFileCacheKey, Arc<[FileBackedLibcIntrinsicSymbol]>>,
    pub(crate) process_memory: BTreeMap<mcr_sys::GuestPid, GuestMemory>,
    pub(crate) pending_fork_exec: BTreeMap<mcr_sys::GuestPid, PendingForkExec>,
    pub(crate) selected_memory_pid: mcr_sys::GuestPid,
    pub(crate) process_fds: BTreeMap<mcr_sys::GuestPid, FdTable>,
    pub(crate) selected_fds_pid: mcr_sys::GuestPid,
    pub(crate) futexes: FutexRegistry,
    pub(crate) epolls: EpollRegistry,
    pub(crate) native_execution: bool,
    pub(crate) native_fp: BTreeMap<mcr_sys::GuestTid, mcr_win::HostFloatingPointState>,
    pub(crate) signal_alt_stacks: BTreeMap<mcr_sys::GuestTid, GuestSignalAltStack>,
    pub(crate) native_patch_caches: BTreeMap<mcr_sys::GuestPid, NativePatchCache>,
    pub(crate) native_image_patch_keys: NativeImagePatchKeyMap,
    pub(crate) native_image_patch_ranges: NativeImagePatchRangeMap,
    pub(crate) native_image_patch_metadata: BTreeMap<NativeImagePatchKey, NativePatchMetadataEntry>,
    pub(crate) libc_intrinsic_patches: BTreeMap<(mcr_sys::GuestPid, u64), GuestLibcIntrinsic>,
    pub(crate) pending_fork_child_regs: Option<GprState>,
    pub(crate) perf_summary: RuntimePerfSummary,
}

impl fmt::Debug for RuntimeSubsystems {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeSubsystems")
            .field("selected_memory_pid", &self.selected_memory_pid)
            .field("selected_fds_pid", &self.selected_fds_pid)
            .field("process_memory_len", &self.process_memory.len())
            .field("process_fds_len", &self.process_fds.len())
            .field("pending_fork_exec_len", &self.pending_fork_exec.len())
            .field("native_execution", &self.native_execution)
            .field("native_fp_len", &self.native_fp.len())
            .field("signal_alt_stacks_len", &self.signal_alt_stacks.len())
            .field("native_patch_caches_len", &self.native_patch_caches.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PendingForkExec {
    parent_pid: mcr_sys::GuestPid,
    created_at: Instant,
}

pub(crate) fn native_image_patch_maps(
    tasks: &GuestKernel,
    pid: mcr_sys::GuestPid,
) -> (NativeImagePatchKeyMap, NativeImagePatchRangeMap) {
    let Some(process) = tasks.process(pid) else {
        return (BTreeMap::new(), BTreeMap::new());
    };
    let Some((key, ranges)) = native_image_patch_key_and_ranges(process.image().memory()) else {
        return (BTreeMap::new(), BTreeMap::new());
    };
    (
        BTreeMap::from([(pid, key)]),
        BTreeMap::from([(pid, ranges)]),
    )
}

pub(crate) fn start_guest_task_worker_pool() -> Option<Arc<HostWorkerPoolExecutor>> {
    HostWorkerPoolExecutor::new(HostWorkerPoolConfig::default_for(
        HostWorkerPoolRole::GuestTaskExecution,
    ))
    .ok()
    .map(Arc::new)
}

impl RuntimeSubsystems {
    pub fn new(program: GuestProgram) -> Result<Self, RuntimeError> {
        Self::with_vfs(program, Self::default_vfs())
    }

    pub fn with_vfs(
        program: GuestProgram,
        mut vfs: VirtualFileSystem,
    ) -> Result<Self, RuntimeError> {
        let tasks = GuestKernel::new(program)?;
        let memory = GuestMemory::from_image(
            tasks
                .process(mcr_task::INITIAL_GUEST_PID)
                .expect("runtime always starts with an initial process")
                .image()
                .memory(),
        )?;
        sync_proc_self(&mut vfs, &tasks, mcr_task::INITIAL_GUEST_PID);
        let (native_image_patch_keys, native_image_patch_ranges) =
            native_image_patch_maps(&tasks, mcr_task::INITIAL_GUEST_PID);
        Ok(Self {
            tasks,
            guest_task_worker_pool: start_guest_task_worker_pool(),
            files: RuntimeFileSystem::new(vfs, memory),
            file_backed_mapping_cache: FileBackedMappingCache::default(),
            libc_intrinsic_symbol_cache: BTreeMap::new(),
            process_memory: BTreeMap::new(),
            pending_fork_exec: BTreeMap::new(),
            selected_memory_pid: mcr_task::INITIAL_GUEST_PID,
            process_fds: BTreeMap::new(),
            selected_fds_pid: mcr_task::INITIAL_GUEST_PID,
            futexes: FutexRegistry::default(),
            epolls: EpollRegistry::default(),
            native_execution: false,
            native_fp: BTreeMap::new(),
            signal_alt_stacks: BTreeMap::new(),
            native_patch_caches: BTreeMap::new(),
            native_image_patch_keys,
            native_image_patch_ranges,
            native_image_patch_metadata: BTreeMap::new(),
            libc_intrinsic_patches: BTreeMap::new(),
            pending_fork_child_regs: None,
            perf_summary: RuntimePerfSummary::default(),
        })
    }

    pub fn with_vfs_and_socket_transport(
        program: GuestProgram,
        mut vfs: VirtualFileSystem,
        transport: impl HostSocketTransport + 'static,
    ) -> Result<Self, RuntimeError> {
        let tasks = GuestKernel::new(program)?;
        let memory = GuestMemory::from_image(
            tasks
                .process(mcr_task::INITIAL_GUEST_PID)
                .expect("runtime always starts with an initial process")
                .image()
                .memory(),
        )?;
        sync_proc_self(&mut vfs, &tasks, mcr_task::INITIAL_GUEST_PID);
        let (native_image_patch_keys, native_image_patch_ranges) =
            native_image_patch_maps(&tasks, mcr_task::INITIAL_GUEST_PID);
        Ok(Self {
            tasks,
            guest_task_worker_pool: start_guest_task_worker_pool(),
            files: RuntimeFileSystem::with_socket_transport(vfs, memory, transport),
            file_backed_mapping_cache: FileBackedMappingCache::default(),
            libc_intrinsic_symbol_cache: BTreeMap::new(),
            process_memory: BTreeMap::new(),
            pending_fork_exec: BTreeMap::new(),
            selected_memory_pid: mcr_task::INITIAL_GUEST_PID,
            process_fds: BTreeMap::new(),
            selected_fds_pid: mcr_task::INITIAL_GUEST_PID,
            futexes: FutexRegistry::default(),
            epolls: EpollRegistry::default(),
            native_execution: false,
            native_fp: BTreeMap::new(),
            signal_alt_stacks: BTreeMap::new(),
            native_patch_caches: BTreeMap::new(),
            native_image_patch_keys,
            native_image_patch_ranges,
            native_image_patch_metadata: BTreeMap::new(),
            libc_intrinsic_patches: BTreeMap::new(),
            pending_fork_child_regs: None,
            perf_summary: RuntimePerfSummary::default(),
        })
    }

    pub fn enable_native_execution(&mut self) {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            self.files
                .memory_mut()
                .set_mmap_base(WINDOWS_NATIVE_MMAP_BASE)
                .expect("Windows native mmap base is page-aligned and within guest space");
            for memory in self.process_memory.values_mut() {
                memory
                    .set_mmap_base(WINDOWS_NATIVE_MMAP_BASE)
                    .expect("Windows native mmap base is page-aligned and within guest space");
            }
        }
        self.native_execution = true;
    }

    #[cfg(test)]
    pub(crate) fn file_backed_mapping_cache_snapshot(&self) -> FileBackedMappingCacheSnapshot {
        self.file_backed_mapping_cache.snapshot()
    }

    pub(crate) fn native_fp(
        &self,
        tid: mcr_sys::GuestTid,
    ) -> Option<&mcr_win::HostFloatingPointState> {
        self.native_fp.get(&tid)
    }

    pub(crate) fn set_native_fp(
        &mut self,
        tid: mcr_sys::GuestTid,
        state: mcr_win::HostFloatingPointState,
    ) {
        self.native_fp.insert(tid, state);
    }

    pub(crate) fn host_worker_pool_diagnostics(&self) -> [HostWorkerPoolDiagnostics; 2] {
        let mut diagnostics = self.tasks.host_worker_pool_diagnostics();
        if let Some(pool) = self.guest_task_worker_pool.as_ref() {
            diagnostics[0] = pool.diagnostics();
        }
        diagnostics
    }

    pub(crate) fn default_vfs() -> VirtualFileSystem {
        // Runtime::new has no rootfs argument yet. Keep the placeholder explicit and route
        // future rootfs-aware callers through Runtime::with_vfs after loading their VFS.
        let mut vfs = VirtualFileSystem::new("/");
        vfs.mount_minimal_procfs()
            .expect("minimal procfs nodes do not conflict in a new VFS");
        vfs
    }

    #[must_use]
    pub const fn tasks(&self) -> &GuestKernel {
        &self.tasks
    }

    #[must_use]
    pub const fn tasks_mut(&mut self) -> &mut GuestKernel {
        &mut self.tasks
    }

    #[must_use]
    pub fn memory(&self) -> &GuestMemory {
        self.memory_for_process(mcr_task::INITIAL_GUEST_PID)
            .expect("initial guest process memory is present")
    }

    #[must_use]
    pub fn memory_mut(&mut self) -> &mut GuestMemory {
        self.select_memory_for_process(mcr_task::INITIAL_GUEST_PID)
            .expect("initial guest process memory is present");
        self.files.memory_mut()
    }

    #[must_use]
    pub fn memory_for_process(&self, pid: mcr_sys::GuestPid) -> Option<&GuestMemory> {
        if pid == self.selected_memory_pid {
            Some(self.files.memory())
        } else if let Some(memory) = self.process_memory.get(&pid) {
            Some(memory)
        } else if let Some(pending) = self.pending_fork_exec.get(&pid) {
            if pending.parent_pid == self.selected_memory_pid {
                Some(self.files.memory())
            } else {
                self.process_memory.get(&pending.parent_pid)
            }
        } else {
            None
        }
    }

    #[must_use]
    pub fn memory_for_process_mut(&mut self, pid: mcr_sys::GuestPid) -> Option<&mut GuestMemory> {
        if pid == self.selected_memory_pid {
            Some(self.files.memory_mut())
        } else {
            self.process_memory.get_mut(&pid)
        }
    }

    #[must_use]
    pub fn current_image(&self) -> &mcr_elf::GuestMemoryImage {
        self.tasks
            .process(mcr_task::INITIAL_GUEST_PID)
            .expect("runtime always starts with an initial process")
            .image()
            .memory()
    }
}

pub(crate) const POLLFD_SIZE: usize = std::mem::size_of::<LinuxPollfd>();
pub(crate) const EPOLL_EVENT_SIZE: usize = std::mem::size_of::<LinuxEpollEvent>();
pub(crate) const SELECT_FD_BITS: usize = 64;
pub(crate) const MAX_SELECT_FDS: usize = 4096;
