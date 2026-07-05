#[allow(unused_imports)]
use super::*;

mod event;
mod file;
mod memory;
mod network;
mod task;
mod time;

#[derive(Debug)]
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

    pub fn register_libc_intrinsic_patch(
        &mut self,
        pid: mcr_sys::GuestPid,
        address: u64,
        intrinsic: GuestLibcIntrinsic,
    ) -> Result<(), GuestExecutionError> {
        let memory = self
            .memory_for_process_mut(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
        memory.patch_code_fixed([(address, [0xcc, 0x90])])?;
        self.libc_intrinsic_patches
            .insert((pid, address), intrinsic);
        Ok(())
    }

    pub(crate) fn libc_intrinsic_patch(
        &self,
        pid: mcr_sys::GuestPid,
        address: u64,
    ) -> Option<GuestLibcIntrinsic> {
        self.libc_intrinsic_patches.get(&(pid, address)).copied()
    }

    pub(crate) fn cached_native_patch_metadata(
        &mut self,
        key: &NativeImagePatchKey,
        base: u64,
    ) -> Option<NativePatchMetadata> {
        if let Some(entry) = self.native_image_patch_metadata.get(key)
            && let Some(metadata) = rebase_native_patch_metadata(&entry.metadata, entry.base, base)
        {
            return Some(metadata);
        }
        let metadata = load_persistent_native_patch_metadata(key, base)
            .ok()
            .flatten()?;
        self.native_image_patch_metadata.insert(
            key.clone(),
            NativePatchMetadataEntry {
                base,
                metadata: metadata.clone(),
            },
        );
        Some(metadata)
    }

    pub(crate) fn ensure_native_patch_cache(
        &mut self,
        pid: mcr_sys::GuestPid,
        fs_base: u64,
    ) -> Result<(), GuestExecutionError> {
        let patch_start = Instant::now();
        let mut cache = self.native_patch_caches.remove(&pid).unwrap_or_default();
        let mut store_image_metadata = None;
        if !cache.image_metadata_checked && cache.image_metadata_eligible {
            cache.image_metadata_checked = true;
            if let Some(key) = self.native_image_patch_keys.get(&pid).cloned() {
                let image_ranges = self.native_image_patch_ranges.get(&pid).cloned();
                let metadata = image_ranges
                    .as_ref()
                    .and_then(|ranges| self.cached_native_patch_metadata(&key, ranges.base));
                if let Some(metadata) = metadata {
                    {
                        let memory = self
                            .memory_for_process_mut(pid)
                            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
                        apply_native_patch_metadata(memory, fs_base, &metadata)?;
                    }
                    cache.merge_metadata(&metadata);
                } else if let Some(ranges) = image_ranges {
                    store_image_metadata = Some((key, ranges.base, ranges.ranges));
                }
            }
        }

        let executable_ranges = self
            .memory_for_process(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?
            .vmas()
            .filter(|vma| vma.protection().execute)
            .filter(|vma| !range_is_covered(vma.start(), vma.end(), &cache.scanned_ranges))
            .map(|vma| (vma.start(), vma.end(), vma.protection()))
            .collect::<Vec<_>>();
        let mut store_range_metadata = Vec::new();
        for (start, end, protection) in executable_ranges {
            let key = {
                let memory = self
                    .memory_for_process(pid)
                    .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
                native_executable_range_patch_key(memory, start, end, protection)?
            };
            if let Some(metadata) = self.cached_native_patch_metadata(&key, start) {
                {
                    let memory = self
                        .memory_for_process_mut(pid)
                        .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
                    apply_native_patch_metadata(memory, fs_base, &metadata)?;
                }
                cache.merge_metadata(&metadata);
            } else {
                store_range_metadata.push((key, start, (start, end)));
            }
        }

        let scanned_ranges = cache.scanned_ranges.clone();
        let scanned_metadata;
        let guest_task_worker_pool = self.guest_task_worker_pool.clone();
        host_step_trace(format_args!(
            "runtime native-patch-cache start pid={pid} fs_base=0x{fs_base:016x} cached_ranges={}",
            scanned_ranges.len()
        ));
        {
            let memory = self
                .memory_for_process_mut(pid)
                .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
            let patches = find_executable_native_patches(
                memory,
                &scanned_ranges,
                cache.fs_base,
                guest_task_worker_pool.as_deref(),
            )?;
            scanned_metadata = native_patch_metadata_from_patches(&patches);
            apply_executable_syscall_patches(memory, &patches.syscall_patches)?;
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                let cached_fs_patch_count = cache.fs_relative_patches.len();
                let mut new_unmaterialized_fs_patch_addresses = Vec::new();
                let mut new_materialized_fs_patch_addresses = Vec::new();
                for site in patches.fs_relative_patches {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        cache.fs_relative_patches.entry(site.address)
                    {
                        entry.insert(site.patch);
                        if site.materialized {
                            new_materialized_fs_patch_addresses.push(site.address);
                        } else {
                            new_unmaterialized_fs_patch_addresses.push(site.address);
                        }
                    }
                }
                match fs_relative_patch_work(
                    cache.fs_base,
                    fs_base,
                    cached_fs_patch_count,
                    new_unmaterialized_fs_patch_addresses.len(),
                    new_materialized_fs_patch_addresses.len(),
                ) {
                    FsRelativePatchWork::All => {
                        apply_fs_relative_patch_entries(
                            memory,
                            fs_base,
                            cache.fs_relative_patches.len(),
                            cache
                                .fs_relative_patches
                                .iter()
                                .map(|(&address, &patch)| (address, patch)),
                        )?;
                    }
                    FsRelativePatchWork::New => {
                        apply_fs_relative_patch_entries(
                            memory,
                            fs_base,
                            new_unmaterialized_fs_patch_addresses.len(),
                            new_unmaterialized_fs_patch_addresses
                                .iter()
                                .filter_map(|address| {
                                    cache
                                        .fs_relative_patches
                                        .get(address)
                                        .map(|&patch| (*address, patch))
                                }),
                        )?;
                    }
                    FsRelativePatchWork::None
                        if !new_unmaterialized_fs_patch_addresses.is_empty()
                            || !new_materialized_fs_patch_addresses.is_empty() =>
                    {
                        host_step_trace(format_args!(
                            "runtime fs-relative-patch apply skipped patches={} fs_base=0x{fs_base:016x}",
                            new_unmaterialized_fs_patch_addresses.len()
                                + new_materialized_fs_patch_addresses.len()
                        ));
                    }
                    FsRelativePatchWork::None => {}
                }
            }
            #[cfg(not(all(windows, target_arch = "x86_64")))]
            {
                cache.merge_metadata(&scanned_metadata);
            }
        }
        if let Some((key, base, ranges)) = store_image_metadata {
            let image_metadata = metadata_for_ranges(&scanned_metadata, &ranges);
            if !image_metadata.scanned_ranges.is_empty() {
                self.native_image_patch_metadata.insert(
                    key.clone(),
                    NativePatchMetadataEntry {
                        base,
                        metadata: image_metadata.clone(),
                    },
                );
                let _ = store_persistent_native_patch_metadata(&key, &image_metadata, base);
            }
        }
        for (key, base, range) in store_range_metadata {
            let range_metadata = metadata_for_ranges(&scanned_metadata, &[range]);
            if !range_metadata.scanned_ranges.is_empty() {
                self.native_image_patch_metadata.insert(
                    key.clone(),
                    NativePatchMetadataEntry {
                        base,
                        metadata: range_metadata.clone(),
                    },
                );
                let _ = store_persistent_native_patch_metadata(&key, &range_metadata, base);
            }
        }
        let scanned_now = self
            .memory_for_process(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?
            .vmas()
            .filter(|vma| vma.protection().execute)
            .map(|vma| (vma.start(), vma.end()))
            .collect::<Vec<_>>();
        cache.fs_base = fs_base;
        cache.scanned_ranges = scanned_now;
        host_step_trace(format_args!(
            "runtime native-patch-cache done pid={pid} ranges={} elapsed_ms={}",
            cache.scanned_ranges.len(),
            host_step_elapsed_ms(patch_start)
        ));
        self.native_patch_caches.insert(pid, cache);
        Ok(())
    }

    pub(crate) fn invalidate_native_patch_cache(&mut self, pid: mcr_sys::GuestPid) {
        if let Some(cache) = self.native_patch_caches.get_mut(&pid) {
            cache.invalidate();
        }
    }

    pub(crate) fn invalidate_native_patch_cache_range(
        &mut self,
        pid: mcr_sys::GuestPid,
        start: u64,
        len: u64,
    ) {
        let Some(end) = start.checked_add(len) else {
            self.invalidate_native_patch_cache(pid);
            return;
        };
        if let Some(cache) = self.native_patch_caches.get_mut(&pid) {
            cache.invalidate_range(start, end);
        }
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

    pub(crate) fn mmap(
        &mut self,
        pid: mcr_sys::GuestPid,
        args: mcr_sys::MmapSyscallArgs,
    ) -> Result<u64, LinuxErrno> {
        let mapped = self
            .files
            .memory_mut()
            .mmap(args)
            .map_err(|error| error.errno())?;
        if !args.is_anonymous() {
            self.populate_file_backed_mmap(
                mapped,
                args.length,
                args.prot,
                args.flags,
                args.fd,
                args.offset,
            )?;
            self.register_file_backed_libc_intrinsic_patches(
                pid,
                mapped,
                args.length,
                args.prot,
                args.fd,
                args.offset,
            )?;
        }
        Ok(mapped)
    }

    pub(crate) fn populate_file_backed_mmap(
        &mut self,
        mapped: u64,
        length: u64,
        prot: u32,
        flags: u32,
        fd: Fd,
        offset: i64,
    ) -> Result<(), LinuxErrno> {
        if offset < 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let len = usize::try_from(length).map_err(|_| LinuxErrno::ENOMEM)?;
        let bytes = self.file_backed_mmap_bytes(fd, offset as u64, len, prot, flags)?;
        let writable = mcr_sys::MprotectSyscallArgs {
            addr: mapped,
            length,
            prot: mcr_sys::LINUX_PROT_READ | mcr_sys::LINUX_PROT_WRITE,
        };
        self.files
            .memory_mut()
            .mprotect(writable)
            .map_err(|error| error.errno())?;
        let write_result = self.files.memory_mut().write(mapped, bytes.as_ref());
        let restore_result = self
            .files
            .memory_mut()
            .mprotect(mcr_sys::MprotectSyscallArgs {
                addr: mapped,
                length,
                prot,
            });
        write_result.map_err(|error| error.errno())?;
        restore_result.map_err(|error| error.errno())?;
        Ok(())
    }

    pub(crate) fn register_file_backed_libc_intrinsic_patches(
        &mut self,
        pid: mcr_sys::GuestPid,
        mapped: u64,
        length: u64,
        prot: u32,
        fd: Fd,
        offset: i64,
    ) -> Result<(), LinuxErrno> {
        if !self.native_execution || prot & mcr_sys::LINUX_PROT_EXEC == 0 || offset < 0 {
            return Ok(());
        }
        let len = usize::try_from(length).map_err(|_| LinuxErrno::ENOMEM)?;
        let offset = offset as u64;
        let Ok(bytes) = self.read_regular_file_for_symbol_scan(fd) else {
            return Ok(());
        };
        let Some(load_bias) = elf_load_bias_for_mapping(&bytes, offset, mapped) else {
            return Ok(());
        };
        let mapped_end = mapped.checked_add(length).ok_or(LinuxErrno::ENOMEM)?;
        for symbol in self
            .file_backed_libc_intrinsic_symbols(fd, &bytes)?
            .iter()
            .copied()
        {
            let Some(address) = load_bias.checked_add(symbol.value) else {
                continue;
            };
            let patch_end = address.saturating_add(2);
            if address < mapped || patch_end > mapped_end || (address - mapped) as usize >= len {
                continue;
            }
            self.register_libc_intrinsic_patch(pid, address, symbol.intrinsic)
                .map_err(guest_execution_errno)?;
        }
        Ok(())
    }

    pub(crate) fn file_backed_libc_intrinsic_symbols(
        &mut self,
        fd: Fd,
        bytes: &[u8],
    ) -> Result<Arc<[FileBackedLibcIntrinsicSymbol]>, LinuxErrno> {
        let Some(key) = self
            .files
            .vfs()
            .regular_file_cache_key(fd)
            .map_err(vfs_errno)?
        else {
            return Ok(Arc::from([]));
        };
        if let Some(symbols) = self.libc_intrinsic_symbol_cache.get(&key) {
            return Ok(Arc::clone(symbols));
        }
        let symbols: Arc<[FileBackedLibcIntrinsicSymbol]> =
            Arc::from(parse_file_backed_libc_intrinsic_symbols(bytes).into_boxed_slice());
        self.libc_intrinsic_symbol_cache
            .retain(|cached, _| cached.generation() == key.generation());
        self.libc_intrinsic_symbol_cache
            .insert(key, Arc::clone(&symbols));
        Ok(symbols)
    }

    pub(crate) fn read_regular_file_for_symbol_scan(&self, fd: Fd) -> Result<Vec<u8>, LinuxErrno> {
        const MAX_SYMBOL_SCAN_BYTES: u64 = 128 * 1024 * 1024;
        let attr = self.files.vfs().fstat(fd).map_err(vfs_errno)?;
        if attr.size > MAX_SYMBOL_SCAN_BYTES {
            return Err(LinuxErrno::EFBIG);
        }
        let len = usize::try_from(attr.size).map_err(|_| LinuxErrno::ENOMEM)?;
        let mut bytes = vec![0; len];
        let count = self
            .files
            .vfs()
            .pread(fd, 0, &mut bytes)
            .map_err(vfs_errno)?;
        bytes.truncate(count);
        Ok(bytes)
    }

    pub(crate) fn file_backed_mmap_bytes(
        &mut self,
        fd: Fd,
        offset: u64,
        len: usize,
        prot: u32,
        flags: u32,
    ) -> Result<Arc<[u8]>, LinuxErrno> {
        let cache_key = self.file_backed_mmap_cache_key(fd, offset, len, prot, flags)?;
        if let Some(key) = cache_key {
            if let Some(bytes) = self.file_backed_mapping_cache.lookup(key) {
                return Ok(bytes);
            }
            self.file_backed_mapping_cache.record_miss();
            let bytes = self.read_file_backed_mmap_bytes(fd, offset, len)?;
            return Ok(self.file_backed_mapping_cache.insert(key, bytes));
        }

        let bytes = self.read_file_backed_mmap_bytes(fd, offset, len)?;
        Ok(Arc::from(bytes.into_boxed_slice()))
    }

    pub(crate) fn file_backed_mmap_cache_key(
        &self,
        fd: Fd,
        offset: u64,
        len: usize,
        prot: u32,
        flags: u32,
    ) -> Result<Option<FileBackedMappingCacheKey>, LinuxErrno> {
        if prot & mcr_sys::LINUX_PROT_WRITE != 0 || flags & mcr_sys::LINUX_MAP_PRIVATE == 0 {
            return Ok(None);
        }

        let Some(file) = self
            .files
            .vfs()
            .regular_file_cache_key(fd)
            .map_err(vfs_errno)?
        else {
            return Ok(None);
        };

        Ok(Some(FileBackedMappingCacheKey {
            file,
            offset,
            length: len,
        }))
    }

    pub(crate) fn read_file_backed_mmap_bytes(
        &self,
        fd: Fd,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, LinuxErrno> {
        if let Some(mapping) = self
            .files
            .vfs()
            .map_readonly_regular_file_at(fd, offset, len)
            .map_err(vfs_errno)?
        {
            let mut bytes = mapping.as_slice().to_vec();
            zero_elf_load_bss_tail(self.files.vfs(), fd, offset, &mut bytes);
            return Ok(bytes);
        }

        let mut bytes = vec![0; len];
        let count = self
            .files
            .vfs()
            .pread(fd, offset, &mut bytes)
            .map_err(vfs_errno)?;
        zero_elf_load_bss_tail(self.files.vfs(), fd, offset, &mut bytes[..count]);
        bytes.truncate(count);
        Ok(bytes)
    }

    pub(crate) fn perf_begin_run(&mut self) {
        self.perf_summary.begin_run();
    }

    pub(crate) fn perf_finish_run(&mut self) {
        self.perf_summary.finish_run();
    }

    pub(crate) fn perf_record_scheduler_enter(&mut self) {
        self.perf_summary.record_scheduler_enter();
    }

    pub(crate) fn perf_record_no_runnable(&mut self) {
        self.perf_summary.record_no_runnable();
    }

    pub(crate) fn perf_record_dispatch(&mut self, tid: mcr_sys::GuestTid, pid: mcr_sys::GuestPid) {
        let previous_still_runnable =
            self.perf_summary
                .last_dispatched
                .is_some_and(|(last_tid, _)| {
                    self.tasks
                        .task(last_tid)
                        .is_some_and(|task| matches!(task.state(), TaskState::Runnable))
                });
        self.perf_summary
            .record_dispatch(tid, pid, previous_still_runnable);
    }

    pub(crate) fn perf_record_syscall(&mut self, syscall: mcr_sys::Syscall) {
        self.perf_summary.record_syscall(syscall);
    }

    pub(crate) fn perf_record_fork_like(
        &mut self,
        syscall: mcr_sys::Syscall,
        clone_args: Option<CloneSyscallArgs>,
    ) {
        self.perf_summary.record_fork_like(syscall, clone_args);
    }

    pub(crate) fn perf_record_remap(&mut self, elapsed: Duration) {
        self.perf_summary.record_remap(elapsed);
    }

    pub(crate) fn perf_record_clone_to_exec(&mut self, elapsed: Duration) {
        self.perf_summary.record_clone_to_exec(elapsed);
    }

    pub(crate) fn perf_record_fd_wakeups(&mut self, count: usize) {
        self.perf_summary.record_fd_wakeups(count);
    }

    pub(crate) fn perf_record_pipe_io(
        &mut self,
        syscall: mcr_sys::Syscall,
        fd: Fd,
        result: &SyscallReturn,
    ) {
        if !matches!(
            syscall,
            mcr_sys::Syscall::Read
                | mcr_sys::Syscall::Readv
                | mcr_sys::Syscall::Write
                | mcr_sys::Syscall::Writev
        ) {
            return;
        }
        let Ok(entry) = self.files.vfs().fds().get(fd) else {
            return;
        };
        self.perf_summary
            .record_pipe_io(syscall, entry.file().kind(), result);
    }

    pub(crate) fn select_process_context(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        self.select_memory_for_process(pid)?;
        self.select_fds_for_process(pid)?;
        sync_proc_self(self.files.vfs_mut(), &self.tasks, pid);
        Ok(())
    }

    pub(crate) fn select_memory_for_process(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        if self.pending_fork_exec.contains_key(&pid) {
            self.materialize_pending_fork_exec_child_memory(pid)
                .map_err(|error| error.errno())?;
        }
        if pid == self.selected_memory_pid {
            if self.native_execution && !self.files.memory().uses_fixed_guest_host_addresses() {
                self.materialize_selected_memory_at_guest_addresses()?;
            }
            return Ok(());
        }
        if self.native_execution {
            return self.select_native_memory_for_process(pid);
        }
        if self.tasks.process(self.selected_memory_pid).is_some() {
            let selected = self
                .files
                .memory()
                .try_clone_runtime()
                .map_err(|error| error.errno())?;
            self.process_memory
                .insert(self.selected_memory_pid, selected);
        }
        let memory = self.process_memory.remove(&pid).ok_or(LinuxErrno::ESRCH)?;
        *self.files.memory_mut() = memory;
        self.selected_memory_pid = pid;
        Ok(())
    }

    pub(crate) fn prepare_memory_mut_for_process(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        if self.pending_fork_exec.contains_key(&pid) {
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
            let selected_pid = self.selected_memory_pid;
            let selected_snapshot = if self.tasks.process(selected_pid).is_some() {
                Some(
                    self.files
                        .memory()
                        .try_clone_runtime()
                        .map_err(|error| error.errno())?,
                )
            } else {
                None
            };
            let target_snapshot = self.process_memory.remove(&pid).ok_or(LinuxErrno::ESRCH)?;
            self.drop_selected_memory_allocations();
            match target_snapshot.try_clone_runtime_at_guest_addresses() {
                Ok(memory) => {
                    if let Some(snapshot) = selected_snapshot {
                        self.process_memory.insert(selected_pid, snapshot);
                    }
                    *self.files.memory_mut() = memory;
                    self.selected_memory_pid = pid;
                    Ok(())
                }
                Err(error) => {
                    self.process_memory.insert(pid, target_snapshot);
                    if let Some(snapshot) = selected_snapshot {
                        let restored = snapshot
                            .try_clone_runtime_at_guest_addresses()
                            .map_err(|restore_error| restore_error.errno())?;
                        self.process_memory.insert(selected_pid, snapshot);
                        *self.files.memory_mut() = restored;
                    }
                    Err(error.errno())
                }
            }
        })();
        self.perf_record_remap(remap_start.elapsed());
        result
    }

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
        self.pending_fork_exec.contains_key(&pid)
    }

    pub(crate) fn has_pending_fork_exec_children(&self, parent_pid: mcr_sys::GuestPid) -> bool {
        self.pending_fork_exec
            .values()
            .any(|pending| pending.parent_pid == parent_pid)
    }

    pub(crate) fn prioritize_pending_fork_exec_tids(&self, tids: &mut [mcr_sys::GuestTid]) {
        tids.sort_by_key(|tid| {
            let pending_child = self
                .tasks
                .task(*tid)
                .is_some_and(|task| self.pending_fork_exec.contains_key(&task.pid()));
            (!pending_child, *tid)
        });
    }

    pub(crate) fn sticky_scheduler_candidate(
        &self,
        tid: mcr_sys::GuestTid,
    ) -> Option<mcr_sys::GuestTid> {
        let task = self.tasks.task(tid)?;
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
        self.pending_fork_exec.remove(&child_pid);
        self.process_memory.insert(child_pid, memory);
        if let Some(cache) = self.native_patch_caches.get(&pending.parent_pid).cloned() {
            self.native_patch_caches.insert(child_pid, cache);
        }
        if let Some(key) = self
            .native_image_patch_keys
            .get(&pending.parent_pid)
            .cloned()
        {
            self.native_image_patch_keys.insert(child_pid, key);
        }
        if let Some(ranges) = self
            .native_image_patch_ranges
            .get(&pending.parent_pid)
            .cloned()
        {
            self.native_image_patch_ranges.insert(child_pid, ranges);
        }
        let inherited_intrinsic_patches = self
            .libc_intrinsic_patches
            .iter()
            .filter(|((pid, _), _)| *pid == pending.parent_pid)
            .map(|((_, address), intrinsic)| (*address, *intrinsic))
            .collect::<Vec<_>>();
        for (address, intrinsic) in inherited_intrinsic_patches {
            self.libc_intrinsic_patches
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
        if pid != self.selected_memory_pid {
            return Err(LinuxErrno::ESRCH);
        }
        if self.tasks.process(pid).is_none() {
            return Ok(());
        }
        Ok(())
    }

    pub(crate) fn select_fds_for_process(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        if pid == self.selected_fds_pid {
            return Ok(());
        }
        if self.tasks.process(self.selected_fds_pid).is_some() {
            let selected = self.files.vfs().fds().clone();
            self.process_fds.insert(self.selected_fds_pid, selected);
        }
        let fds = self.process_fds.remove(&pid).ok_or(LinuxErrno::ESRCH)?;
        self.files.vfs_mut().replace_fds(fds);
        self.selected_fds_pid = pid;
        Ok(())
    }

    pub(crate) fn store_selected_process_fds(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        if pid != self.selected_fds_pid {
            return Err(LinuxErrno::ESRCH);
        }
        if self.tasks.process(pid).is_none() {
            return Ok(());
        }
        Ok(())
    }

    pub(crate) fn drop_process_fds(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        if pid == self.selected_fds_pid {
            if pid != mcr_task::INITIAL_GUEST_PID {
                let fds = self
                    .process_fds
                    .remove(&mcr_task::INITIAL_GUEST_PID)
                    .ok_or(LinuxErrno::ESRCH)?;
                self.files.vfs_mut().replace_fds(fds);
                self.selected_fds_pid = mcr_task::INITIAL_GUEST_PID;
            }
        } else {
            self.process_fds.remove(&pid);
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
        let Some(state) = self.native_fp.get(&parent_tid).copied() else {
            return;
        };
        let child_tids = self
            .tasks
            .tasks()
            .filter(|task| task.pid() == child_pid)
            .map(mcr_task::GuestTask::tid)
            .collect::<Vec<_>>();
        for child_tid in child_tids {
            self.native_fp.insert(child_tid, state);
        }
    }

    pub(crate) fn clone_native_fp_for_thread(
        &mut self,
        parent_tid: mcr_sys::GuestTid,
        child_tid: mcr_sys::GuestTid,
    ) {
        if let Some(state) = self.native_fp.get(&parent_tid).copied() {
            self.native_fp.insert(child_tid, state);
        }
    }

    pub(crate) fn drop_native_fp_for_tid(&mut self, tid: mcr_sys::GuestTid) {
        self.native_fp.remove(&tid);
    }

    pub(crate) fn drop_native_fp_for_process(&mut self, pid: mcr_sys::GuestPid) {
        let tids = self
            .tasks
            .tasks()
            .filter(|task| task.pid() == pid)
            .map(mcr_task::GuestTask::tid)
            .collect::<Vec<_>>();
        for tid in tids {
            self.native_fp.remove(&tid);
        }
    }

    pub(crate) fn drop_native_patch_cache_for_process(&mut self, pid: mcr_sys::GuestPid) {
        self.native_patch_caches.remove(&pid);
        self.native_image_patch_keys.remove(&pid);
        self.native_image_patch_ranges.remove(&pid);
        self.libc_intrinsic_patches
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
                self.epolls.close(epoll_id);
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
                    && self.socket_fd_ref_count_excluding_current(self.selected_fds_pid, socket_id)
                        + self.files.vfs().socket_fd_count(socket_id.get())
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
                    && self.epoll_fd_ref_count_excluding_current(self.selected_fds_pid, epoll_id)
                        + self.files.vfs().epoll_fd_count(epoll_id)
                        == 0
                {
                    self.epolls.close(epoll_id);
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn fd_table_for_process(&self, pid: mcr_sys::GuestPid) -> Option<&FdTable> {
        if pid == self.selected_fds_pid {
            Some(self.files.vfs().fds())
        } else {
            self.process_fds.get(&pid)
        }
    }

    pub(crate) fn socket_fd_ref_count_excluding_current(
        &self,
        excluded_pid: mcr_sys::GuestPid,
        socket_id: SocketId,
    ) -> usize {
        let selected_count = if self.selected_fds_pid != excluded_pid {
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
                .process_fds
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
        let selected_count = if self.selected_fds_pid != excluded_pid {
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
                .process_fds
                .iter()
                .filter(|(pid, _)| **pid != excluded_pid)
                .map(|(_, fds)| fds.epoll_ids().filter(|raw| *raw == epoll_id).count())
                .sum::<usize>()
    }

    pub(crate) fn drop_process_memory(&mut self, pid: mcr_sys::GuestPid) -> Result<(), LinuxErrno> {
        self.materialize_pending_fork_exec_children(pid)
            .map_err(|error| error.errno())?;
        self.pending_fork_exec.remove(&pid);
        if pid == self.selected_memory_pid {
            if pid != mcr_task::INITIAL_GUEST_PID {
                self.restore_initial_memory_after_selected_drop()?;
            }
        } else {
            self.process_memory.remove(&pid);
        }
        self.drop_native_patch_cache_for_process(pid);
        Ok(())
    }

    pub(crate) fn restore_initial_memory_after_selected_drop(&mut self) -> Result<(), LinuxErrno> {
        let memory = self
            .process_memory
            .remove(&mcr_task::INITIAL_GUEST_PID)
            .ok_or(LinuxErrno::ESRCH)?;
        if self.native_execution {
            self.drop_selected_memory_allocations();
            let memory = memory
                .try_clone_runtime_at_guest_addresses()
                .map_err(|error| error.errno())?;
            *self.files.memory_mut() = memory;
        } else {
            *self.files.memory_mut() = memory;
        }
        self.selected_memory_pid = mcr_task::INITIAL_GUEST_PID;
        Ok(())
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
        let outcome = self.tasks.dispatch_for_current_task(&kernel_request);
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
                self.signal_alt_stacks.remove(&tid);
            } else {
                self.signal_alt_stacks.insert(tid, requested);
            }
        }

        self.store_selected_process_memory(pid)
    }

    pub(crate) fn dispatch_kernel_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let pid = request.context.pid;
        if let Err(errno) = self.select_process_context(pid) {
            return SyscallOutcome::errno(errno);
        }
        let outcome = self.tasks.dispatch_for_current_task(request);
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
                .tasks
                .task_mut(tid)
                .and_then(GuestTask::take_clear_child_tid)
        {
            write_guest_u32(self.files.memory_mut(), clear_child_tid, 0)?;
            self.store_selected_process_memory(pid)?;
            self.futexes.wake(clear_child_tid, u32::MAX);
            self.tasks
                .wake_futex_waiters(FutexWaitKey::new(pid, clear_child_tid, true), u32::MAX);
        }

        let process_exited = matches!(
            self.tasks.process(pid).map(GuestProcess::exit_state),
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
        let completed = self.tasks.resume_waiting_tasks();
        for wait in &completed {
            self.write_wait_status(*wait)?;
            self.drop_native_fp_for_process(wait.waited().pid());
            self.drop_process_resources(wait.waited().pid())?;
        }
        Ok(completed)
    }

    pub(crate) fn resume_fd_waiters(&mut self) {
        let selected_pid = self.selected_fds_pid;
        let selected_fds = self.files.vfs().fds().clone();
        let process_fds = self.process_fds.clone();
        let resumed = self.tasks.resume_fd_waiters(|pid, fd, write| {
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
        let uts = self.tasks.uname_value();
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
        let pending_child_regs = self.pending_fork_child_regs.take();
        let outcome = if self.native_execution {
            match pending_child_regs {
                Some(child_regs) => {
                    self.dispatch_native_fork_like_task(request, clone_args, child_regs)
                }
                None if request.syscall == mcr_sys::Syscall::Clone3 => self.tasks.clone_current(
                    request.context.tid,
                    clone_args.expect("clone3 args decoded"),
                ),
                None => self.tasks.dispatch_for_current_task(request),
            }
        } else if request.syscall == mcr_sys::Syscall::Clone3 {
            self.tasks.clone_current(
                request.context.tid,
                clone_args.expect("clone3 args decoded"),
            )
        } else {
            self.tasks.dispatch_for_current_task(request)
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
        self.pending_fork_exec.insert(
            child_pid,
            PendingForkExec {
                parent_pid: pid,
                created_at: Instant::now(),
            },
        );
        self.process_fds
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
                .tasks
                .fork_current_with_child_regs(request.context.tid, child_regs),
            mcr_sys::Syscall::Vfork => self
                .tasks
                .vfork_current_with_child_regs(request.context.tid, child_regs),
            mcr_sys::Syscall::Clone | mcr_sys::Syscall::Clone3 => {
                self.tasks.clone_current_with_child_regs(
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
        if self.pending_fork_exec.contains_key(&request.context.pid) {
            return self.execve_pending_fork_exec_child(request).map(|()| true);
        }
        self.materialize_pending_fork_exec_children(request.context.pid)
            .map_err(|error| error.errno())?;
        self.select_process_context(request.context.pid)?;
        let filename = read_guest_c_bytes(self.files.memory(), arg(request, 0))?;
        let argv = self.files.read_guest_vector(arg(request, 1))?;
        let envp = self.files.read_guest_vector(arg(request, 2))?;
        let program = self.files.load_guest_program(filename, argv, envp)?;
        self.tasks
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
                self.epolls.close(epoll_id);
            }
        }
        sync_proc_self(self.files.vfs_mut(), &self.tasks, request.context.pid);
        self.native_fp.remove(&request.context.tid);
        self.signal_alt_stacks.remove(&request.context.tid);
        self.replace_memory_from_image(request.context.pid)?;
        self.native_patch_caches.remove(&request.context.pid);
        self.libc_intrinsic_patches
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
            .pending_fork_exec
            .get(&child_pid)
            .copied()
            .ok_or(LinuxErrno::ESRCH)?;
        let parent_pid = pending.parent_pid;
        self.select_fds_for_process(child_pid)?;
        sync_proc_self(self.files.vfs_mut(), &self.tasks, child_pid);

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
        if let Err(error) = self.tasks.exec_task(request.context.tid, program) {
            self.materialize_pending_fork_exec_child_memory(child_pid)
                .map_err(|error| error.errno())?;
            return Err(error.linux_errno());
        }
        self.pending_fork_exec.remove(&child_pid);
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
                self.epolls.close(epoll_id);
            }
        }
        sync_proc_self(self.files.vfs_mut(), &self.tasks, child_pid);
        self.native_fp.remove(&request.context.tid);
        self.signal_alt_stacks.remove(&request.context.tid);
        self.replace_memory_from_image(child_pid)?;
        self.native_patch_caches.remove(&child_pid);
        self.libc_intrinsic_patches
            .retain(|(pid, _), _| *pid != child_pid);
        self.store_selected_process_fds(child_pid)
    }

    pub(crate) fn replace_memory_from_image(
        &mut self,
        pid: mcr_sys::GuestPid,
    ) -> Result<(), LinuxErrno> {
        let image = self
            .tasks
            .process(pid)
            .ok_or(LinuxErrno::ESRCH)?
            .image()
            .memory()
            .clone();
        if pid == self.selected_memory_pid {
            self.drop_selected_memory_allocations();
            let memory = self.memory_from_process_image(&image)?;
            *self.files.memory_mut() = memory;
        } else {
            let memory = self.memory_from_process_image(&image)?;
            self.process_memory.insert(pid, memory);
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
            self.native_image_patch_keys.insert(pid, key);
            self.native_image_patch_ranges.insert(pid, ranges);
        } else {
            self.native_image_patch_keys.remove(&pid);
            self.native_image_patch_ranges.remove(&pid);
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
            if self.native_execution {
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
        match self.tasks.block_task_for_futex(tid, key) {
            Ok(()) => SyscallOutcome::success(0).with_decoded_field("task_blocked", "futex"),
            Err(error) => error.into_outcome(),
        }
    }

    pub(crate) fn futex_wake(&mut self, pid: mcr_sys::GuestPid, args: FutexSyscallArgs) -> u64 {
        let key = FutexWaitKey::new(pid, args.uaddr, args.is_private());
        self.tasks.wake_futex_waiters(key, args.val) as u64
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
        let epoll_id = self.epolls.create()?;
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
                self.epolls.close(epoll_id);
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
                let instance = self.epolls.instance_mut(epoll_id)?;
                if instance.watches.contains_key(&fd) {
                    return Err(LinuxErrno::EEXIST);
                }
                instance.watches.insert(
                    fd,
                    EpollWatch {
                        fd,
                        events: event.events,
                        data: event.data,
                    },
                );
            }
            LINUX_EPOLL_CTL_MOD => {
                let event = read_epoll_event(self.files.memory(), event_addr)?;
                validate_epoll_events(event.events)?;
                let instance = self.epolls.instance_mut(epoll_id)?;
                let watch = instance.watches.get_mut(&fd).ok_or(LinuxErrno::ENOENT)?;
                watch.events = event.events;
                watch.data = event.data;
            }
            LINUX_EPOLL_CTL_DEL => {
                let instance = self.epolls.instance_mut(epoll_id)?;
                if instance.watches.remove(&fd).is_none() {
                    return Err(LinuxErrno::ENOENT);
                }
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
        let watches = self
            .epolls
            .instance(epoll_id)?
            .watches
            .values()
            .cloned()
            .collect::<Vec<_>>();

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

pub(crate) const POLLFD_SIZE: usize = std::mem::size_of::<LinuxPollfd>();
pub(crate) const EPOLL_EVENT_SIZE: usize = std::mem::size_of::<LinuxEpollEvent>();
pub(crate) const SELECT_FD_BITS: usize = 64;
pub(crate) const MAX_SELECT_FDS: usize = 4096;
