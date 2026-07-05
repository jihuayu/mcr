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

impl RuntimeSubsystems {
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
        if !self.native.enabled || prot & mcr_sys::LINUX_PROT_EXEC == 0 || offset < 0 {
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
        if let Some(symbols) = self.native.libc_intrinsic_symbol_cache.get(&key) {
            return Ok(Arc::clone(symbols));
        }
        let symbols: Arc<[FileBackedLibcIntrinsicSymbol]> =
            Arc::from(parse_file_backed_libc_intrinsic_symbols(bytes).into_boxed_slice());
        self.native
            .libc_intrinsic_symbol_cache
            .retain(|cached, _| cached.generation() == key.generation());
        self.native
            .libc_intrinsic_symbol_cache
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
            if let Some(bytes) = self.native.file_backed_mapping_cache.lookup(key) {
                return Ok(bytes);
            }
            self.native.file_backed_mapping_cache.record_miss();
            let bytes = self.read_file_backed_mmap_bytes(fd, offset, len)?;
            return Ok(self.native.file_backed_mapping_cache.insert(key, bytes));
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
}
