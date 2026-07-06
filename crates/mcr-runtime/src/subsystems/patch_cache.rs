#[allow(unused_imports)]
use super::*;

impl RuntimeSubsystems {
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
        self.native
            .libc_intrinsic_patches
            .insert((pid, address), intrinsic);
        Ok(())
    }

    pub(crate) fn libc_intrinsic_patch(
        &self,
        pid: mcr_sys::GuestPid,
        address: u64,
    ) -> Option<GuestLibcIntrinsic> {
        self.native
            .libc_intrinsic_patches
            .get(&(pid, address))
            .copied()
    }

    pub(crate) fn cached_native_patch_metadata(
        &mut self,
        key: &NativeImagePatchKey,
        base: u64,
    ) -> Option<NativePatchMetadata> {
        if let Some(entry) = self.native.image_patch_metadata.get(key)
            && let Some(metadata) = rebase_native_patch_metadata(&entry.metadata, entry.base, base)
        {
            return Some(metadata);
        }
        let metadata = load_persistent_native_patch_metadata(key, base)
            .ok()
            .flatten()?;
        self.native.image_patch_metadata.insert(
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
        let mut cache = self.native.patch_caches.remove(&pid).unwrap_or_default();
        let executable_write_generation = self
            .memory_for_process(pid)
            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?
            .executable_write_generation();
        if cache.executable_write_generation != executable_write_generation {
            cache.invalidate();
        }
        let mut store_image_metadata = None;
        let mut fs_relative_materialized_this_call = false;
        if !cache.image_metadata_checked && cache.image_metadata_eligible {
            cache.image_metadata_checked = true;
            if let Some(key) = self.native.image_patch_keys.get(&pid).cloned() {
                let image_ranges = self.native.image_patch_ranges.get(&pid).cloned();
                let metadata = image_ranges
                    .as_ref()
                    .and_then(|ranges| self.cached_native_patch_metadata(&key, ranges.base));
                if let Some(metadata) = metadata {
                    {
                        let memory = self
                            .memory_for_process_mut(pid)
                            .ok_or(GuestExecutionError::Memory(GuestMemoryError::NotMapped))?;
                        fs_relative_materialized_this_call |=
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
                    fs_relative_materialized_this_call |=
                        apply_native_patch_metadata(memory, fs_base, &metadata)?;
                }
                cache.merge_metadata(&metadata);
            } else {
                store_range_metadata.push((key, start, (start, end)));
            }
        }

        let scanned_ranges = cache.scanned_ranges.clone();
        let scanned_metadata;
        let guest_task_worker_pool = self.native.guest_task_worker_pool.clone();
        let mut materialized_fs_base = fs_base;
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
                if should_materialize_fs_relative_patches(cache.fs_relative_patches.len()) {
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
                                new_unmaterialized_fs_patch_addresses.iter().filter_map(
                                    |address| {
                                        cache
                                            .fs_relative_patches
                                            .get(address)
                                            .map(|&patch| (*address, patch))
                                    },
                                ),
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
                } else {
                    if cache.fs_base != 0 || fs_relative_materialized_this_call {
                        apply_fs_relative_patch_entries(
                            memory,
                            0,
                            cache.fs_relative_patches.len(),
                            cache
                                .fs_relative_patches
                                .iter()
                                .map(|(&address, &patch)| (address, patch)),
                        )?;
                    }
                    host_step_trace(format_args!(
                        "runtime fs-relative-patch materialize skipped patches={} fs_base=0x{fs_base:016x} reason=large-patch-set",
                        cache.fs_relative_patches.len()
                    ));
                    materialized_fs_base = 0;
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
                self.native.image_patch_metadata.insert(
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
                self.native.image_patch_metadata.insert(
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
        cache.fs_base = materialized_fs_base;
        cache.executable_write_generation = executable_write_generation;
        cache.scanned_ranges = scanned_now;
        host_step_trace(format_args!(
            "runtime native-patch-cache done pid={pid} ranges={} elapsed_ms={}",
            cache.scanned_ranges.len(),
            host_step_elapsed_ms(patch_start)
        ));
        self.native.patch_caches.insert(pid, cache);
        Ok(())
    }

    pub(crate) fn invalidate_native_patch_cache(&mut self, pid: mcr_sys::GuestPid) {
        if let Some(cache) = self.native.patch_caches.get_mut(&pid) {
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
        if let Some(cache) = self.native.patch_caches.get_mut(&pid) {
            cache.invalidate_range(start, end);
        }
    }
}
