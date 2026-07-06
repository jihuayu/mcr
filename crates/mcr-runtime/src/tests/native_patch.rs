use super::support::*;

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_execution_uses_patchable_low_mmap_base() {
    let _guard = native_execution_test_guard();
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime.enable_native_execution();

    let mapped = runtime.dispatch_syscall(context(
        Syscall::Mmap,
        [
            0,
            GUEST_PAGE_SIZE,
            u64::from(LINUX_PROT_READ | LINUX_PROT_WRITE),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS),
            u64::MAX,
            0,
        ],
    ));

    assert_eq!(
        mapped.result,
        SyscallReturn::Success(WINDOWS_NATIVE_MMAP_BASE)
    );
    assert!(WINDOWS_NATIVE_MMAP_BASE <= i32::MAX as u64);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_execve_preserves_patchable_low_mmap_base() {
    let _guard = crate::test_support::native_execution_test_guard();
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content("/bin/new", test_program_bytes(0x501000), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
    runtime.enable_native_execution();

    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();
    runtime.memory_mut().write(0x402120, b"/bin/new\0").unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0x402120u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402008, &0u64.to_le_bytes())
        .unwrap();

    let exec = runtime.dispatch_syscall(context(Syscall::Execve, [0x402100, 0x402000, 0, 0, 0, 0]));
    assert_eq!(exec.result, SyscallReturn::Success(0));

    let mapped = runtime.dispatch_syscall(context(
        Syscall::Mmap,
        [
            0,
            GUEST_PAGE_SIZE,
            u64::from(LINUX_PROT_READ | LINUX_PROT_WRITE),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS),
            u64::MAX,
            0,
        ],
    ));

    assert_eq!(
        mapped.result,
        SyscallReturn::Success(WINDOWS_NATIVE_MMAP_BASE)
    );
}

#[test]
fn native_patch_cache_scans_only_new_executable_ranges() {
    let _guard = native_execution_test_guard();
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[0x0f, 0x05, 0x90],
    ))
    .unwrap();
    let pid = INITIAL_GUEST_PID;
    runtime
        .dispatcher
        .subsystems_mut()
        .native
        .image_patch_keys
        .clear();
    runtime
        .dispatcher
        .subsystems_mut()
        .native
        .image_patch_ranges
        .clear();

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0)
        .unwrap();
    assert_eq!(
        runtime
            .dispatcher
            .subsystems()
            .native
            .patch_caches
            .get(&pid)
            .unwrap()
            .scanned_ranges
            .len(),
        1
    );
    assert_eq!(guest_bytes(runtime.memory(), 0x401000, 2), [0xcc, 0x90]);

    runtime
        .memory_mut()
        .patch_code(0x401000, &[0x0f, 0x05])
        .unwrap();
    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0)
        .unwrap();
    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, 2),
        [0x0f, 0x05],
        "cached executable ranges should not be rescanned on every syscall"
    );

    runtime
        .memory_mut()
        .mmap(mcr_sys::MmapSyscallArgs {
            addr: 0x600000,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC,
            flags: LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
            fd: -1,
            offset: 0,
        })
        .unwrap();
    runtime.memory_mut().write(0x600000, &[0x0f, 0x05]).unwrap();
    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0)
        .unwrap();

    assert_eq!(guest_bytes(runtime.memory(), 0x600000, 2), [0xcc, 0x90]);
    assert!(
        runtime
            .dispatcher
            .subsystems()
            .native
            .patch_caches
            .get(&pid)
            .unwrap()
            .scanned_ranges
            .iter()
            .any(|(start, end)| *start <= 0x600000 && 0x600000 < *end)
    );

    runtime.memory_mut().write(0x600000, &[0x0f, 0x05]).unwrap();
    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x600000, 2),
        [0xcc, 0x90],
        "guest writes to executable pages must invalidate native patch metadata"
    );
}

#[test]
fn native_patch_scanner_uses_guest_task_worker_pool() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[0x0f, 0x05, 0x90],
    ))
    .unwrap();
    let pool = mcr_task::HostWorkerPoolExecutor::new(
        mcr_task::HostWorkerPoolConfig::with_queue_capacity(
            mcr_task::HostWorkerPoolRole::GuestTaskExecution,
            1,
            4,
        )
        .unwrap(),
    )
    .unwrap();

    let patches = find_executable_native_patches(runtime.memory_mut(), &[], 0, Some(&pool))
        .expect("native patch scanning should succeed");

    assert_eq!(
        patches.syscall_patches,
        vec![ExecutableSyscallPatch { address: 0x401000 }]
    );
    assert_eq!(
        pool.diagnostics().role(),
        mcr_task::HostWorkerPoolRole::GuestTaskExecution
    );
    assert!(pool.diagnostics().submitted_jobs() >= 1);
}

#[test]
fn file_backed_libc_intrinsic_symbols_parse_dynsym() {
    let symbols = parse_file_backed_libc_intrinsic_symbols(&elf_with_dynsym_memcpy());

    assert_eq!(
        symbols,
        vec![FileBackedLibcIntrinsicSymbol {
            value: 0x2010,
            intrinsic: GuestLibcIntrinsic::Memcpy
        }]
    );
}

#[test]
fn executable_file_mmap_registers_libc_intrinsic_patch_from_dynsym() {
    let mut tree = PathTree::new();
    tree.create_dir("/lib").unwrap();
    tree.create_file_with_content("/lib/libc.so", elf_with_dynsym_memcpy(), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/app", 0x401000), tree);
    runtime.enable_native_execution();
    runtime
        .memory_mut()
        .mmap(mcr_sys::MmapSyscallArgs {
            addr: 0x600000,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
            flags: LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
            fd: -1,
            offset: 0,
        })
        .unwrap();
    runtime
        .memory_mut()
        .write(0x600000, b"/lib/libc.so\0")
        .unwrap();

    let fd = runtime
        .dispatch_syscall(context(
            Syscall::Openat,
            [AT_FDCWD as u64, 0x600000, u64::from(O_RDONLY), 0, 0, 0],
        ))
        .result;
    assert_eq!(fd, SyscallReturn::Success(3));
    let mapped = 0x700000;
    let mmap = runtime.dispatch_syscall(context(
        Syscall::Mmap,
        [
            mapped,
            GUEST_PAGE_SIZE,
            u64::from(LINUX_PROT_READ | LINUX_PROT_EXEC),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_FIXED),
            3,
            0x1000,
        ],
    ));

    assert_eq!(mmap.result, SyscallReturn::Success(mapped));
    let target = mapped + 0x10;
    assert_eq!(
        runtime
            .dispatcher
            .subsystems()
            .libc_intrinsic_patch(INITIAL_GUEST_PID, target),
        Some(GuestLibcIntrinsic::Memcpy)
    );
    assert_eq!(guest_bytes(runtime.memory(), target, 3), [0xcc, 0x90, 0xc3]);
}

#[test]
fn native_libc_intrinsic_patch_dispatches_and_returns_to_caller() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[0x90, 0x90, 0x90],
    ))
    .unwrap();
    runtime
        .dispatcher
        .subsystems_mut()
        .register_libc_intrinsic_patch(INITIAL_GUEST_PID, 0x401000, GuestLibcIntrinsic::Memcpy)
        .unwrap();
    assert_eq!(guest_bytes(runtime.memory(), 0x401000, 2), [0xcc, 0x90]);

    let dst = 0x600000;
    let src = 0x601000;
    let stack = 0x602000;
    for addr in [dst, src, stack] {
        runtime
            .memory_mut()
            .mmap(mcr_sys::MmapSyscallArgs {
                addr,
                length: GUEST_PAGE_SIZE,
                prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
                flags: LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                fd: -1,
                offset: 0,
            })
            .unwrap();
    }
    runtime.memory_mut().write(src, b"copy").unwrap();
    runtime
        .memory_mut()
        .write(stack, &0x402000u64.to_le_bytes())
        .unwrap();
    let registers = mcr_jit::GuestRegisters {
        rip: 0x401000,
        rsp: stack,
        rdi: dst,
        rsi: src,
        rdx: 4,
        ..mcr_jit::GuestRegisters::default()
    };

    let step = dispatch_native_libc_intrinsic_task(
        &mut runtime.dispatcher,
        INITIAL_GUEST_TID,
        INITIAL_GUEST_PID,
        0x401000,
        registers,
        GuestLibcIntrinsic::Memcpy,
    )
    .unwrap();

    assert_eq!(step.after_rip(), 0x402000);
    assert_eq!(step.encoded_rax(), dst);
    assert_eq!(guest_bytes(runtime.memory(), dst, 4), *b"copy");
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(task.regs().rip(), 0x402000);
    assert_eq!(task.regs().rsp(), stack + 8);
}

#[test]
fn native_patch_cache_ignores_syscall_bytes_inside_instruction_operands() {
    let code = [
        0xe8, 0x0f, 0x05, 0xfe, 0xff, // call with 0f 05 in displacement
        0x0f, 0x05, // real syscall instruction
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let pid = INITIAL_GUEST_PID;

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, code.len()),
        [0xe8, 0x0f, 0x05, 0xfe, 0xff, 0xcc, 0x90]
    );
}

#[test]
fn native_patch_cache_does_not_rewrite_syscall_bytes_inside_immediate() {
    let _guard = native_execution_test_guard();
    let code = [
        0xc7, 0x04, 0x24, 0x00, 0x0f, 0x05, 0x00, // mov dword ptr [rsp],0x50f00
        0x0f, 0x05, // syscall
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(INITIAL_GUEST_PID, 0)
        .unwrap();

    assert_eq!(guest_bytes(runtime.memory(), 0x401000, 7), code[..7]);
    assert_eq!(guest_bytes(runtime.memory(), 0x401007, 2), [0xcc, 0x90]);
}

#[test]
fn native_patch_metadata_persistent_cache_round_trips() {
    let dir = unique_test_dir("native-patch-cache-roundtrip");
    let _ = std::fs::remove_dir_all(&dir);
    let key = NativeImagePatchKey {
        hash: 0x1234,
        executable_len: 0x2000,
    };
    let metadata = NativePatchMetadata {
        scanned_ranges: vec![(0x401000, 0x402000)],
        syscall_patches: vec![ExecutableSyscallPatch { address: 0x401123 }],
        #[cfg(all(windows, target_arch = "x86_64"))]
        fs_relative_patches: BTreeMap::from([(
            0x401200,
            FsRelativePatch {
                original: [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0],
            },
        )]),
        #[cfg(all(windows, target_arch = "x86_64"))]
        fs_relative_traps: BTreeMap::from([(
            0x401240,
            FsRelativeTrap::new(&[0x64, 0x48, 0x83, 0x3c, 0x25, 0xe0, 0xff, 0xff, 0xff, 0])
                .unwrap(),
        )]),
    };

    store_persistent_native_patch_metadata_in_dir(&key, &metadata, 0x400000, &dir).unwrap();
    let loaded = load_persistent_native_patch_metadata_from_dir(&key, 0x600000, &dir)
        .unwrap()
        .expect("metadata should load");

    assert_eq!(loaded.scanned_ranges, vec![(0x601000, 0x602000)]);
    assert_eq!(
        loaded.syscall_patches,
        vec![ExecutableSyscallPatch { address: 0x601123 }]
    );
    #[cfg(all(windows, target_arch = "x86_64"))]
    assert_eq!(
        loaded.fs_relative_patches,
        BTreeMap::from([(
            0x601200,
            FsRelativePatch {
                original: [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0],
            },
        )])
    );
    #[cfg(all(windows, target_arch = "x86_64"))]
    assert_eq!(
        loaded.fs_relative_traps,
        BTreeMap::from([(
            0x601240,
            FsRelativeTrap::new(&[0x64, 0x48, 0x83, 0x3c, 0x25, 0xe0, 0xff, 0xff, 0xff, 0,])
                .unwrap(),
        )])
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn native_patch_cache_applies_image_metadata_without_rescanning_image() {
    let code = [0x0f, 0x05, 0x90];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let pid = INITIAL_GUEST_PID;
    let key = runtime
        .dispatcher
        .subsystems()
        .native
        .image_patch_keys
        .get(&pid)
        .cloned()
        .expect("test image should have native patch key");
    let ranges = runtime
        .dispatcher
        .subsystems()
        .native
        .image_patch_ranges
        .get(&pid)
        .cloned()
        .expect("test image should have native patch ranges");
    runtime
        .dispatcher
        .subsystems_mut()
        .native
        .image_patch_metadata
        .insert(
            key,
            NativePatchMetadataEntry {
                base: ranges.base,
                metadata: NativePatchMetadata {
                    scanned_ranges: ranges.ranges,
                    syscall_patches: vec![ExecutableSyscallPatch { address: 0x401000 }],
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    fs_relative_patches: BTreeMap::new(),
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    fs_relative_traps: BTreeMap::new(),
                },
            },
        );

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0)
        .unwrap();

    assert_eq!(guest_bytes(runtime.memory(), 0x401000, 2), [0xcc, 0x90]);
}

#[test]
fn native_patch_cache_applies_executable_range_metadata_at_current_base() {
    let code = [0x0f, 0x05, 0x90];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let pid = INITIAL_GUEST_PID;
    let (start, end, protection) = runtime
        .memory()
        .vmas()
        .find(|vma| vma.protection().execute)
        .map(|vma| (vma.start(), vma.end(), vma.protection()))
        .expect("test image should have executable VMA");
    let key = native_executable_range_patch_key(runtime.memory(), start, end, protection).unwrap();
    {
        let subsystems = runtime.dispatcher.subsystems_mut();
        subsystems.native.image_patch_keys.remove(&pid);
        subsystems.native.image_patch_ranges.remove(&pid);
        subsystems.native.image_patch_metadata.insert(
            key,
            NativePatchMetadataEntry {
                base: 0x500000,
                metadata: NativePatchMetadata {
                    scanned_ranges: vec![(0x500000, 0x500000 + (end - start))],
                    syscall_patches: vec![ExecutableSyscallPatch { address: 0x500000 }],
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    fs_relative_patches: BTreeMap::new(),
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    fs_relative_traps: BTreeMap::new(),
                },
            },
        );
    }

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0)
        .unwrap();

    assert_eq!(guest_bytes(runtime.memory(), 0x401000, 2), [0xcc, 0x90]);
}

#[test]
fn native_patch_cache_survives_guest_brk_changes() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[0x0f, 0x05, 0x90],
    ))
    .unwrap();
    let pid = INITIAL_GUEST_PID;

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0)
        .unwrap();
    let scanned_ranges = runtime
        .dispatcher
        .subsystems()
        .native
        .patch_caches
        .get(&pid)
        .unwrap()
        .scanned_ranges
        .clone();
    let current_brk = runtime.memory().current_brk();
    let request =
        SyscallRequest::from_guest_context(context(Syscall::Brk, [current_brk, 0, 0, 0, 0, 0]));

    let outcome = runtime
        .dispatcher
        .subsystems_mut()
        .dispatch_memory(&request);

    assert_eq!(outcome.result, SyscallReturn::Success(current_brk));
    assert_eq!(
        runtime
            .dispatcher
            .subsystems()
            .native
            .patch_caches
            .get(&pid)
            .unwrap()
            .scanned_ranges,
        scanned_ranges
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_patch_cache_ignores_fs_relative_bytes_inside_instruction_operands() {
    let fs_load = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0];
    let mut code = vec![
        0x48, 0xb8, // movabs rax, imm64
        0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0,
    ];
    code.extend_from_slice(&fs_load);
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let pid = INITIAL_GUEST_PID;

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x7000_0000)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, 10),
        [0x48, 0xb8, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0]
    );
    assert_eq!(
        guest_bytes(runtime.memory(), 0x40100a, fs_load.len()),
        [0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x70, 0x90]
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_patch_cache_rewrites_fs_relative_tls_accesses_per_base() {
    let _guard = native_execution_test_guard();
    let fs_load = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0];
    let mut code = fs_load.to_vec();
    code.extend_from_slice(&[0x0f, 0x05]);
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let pid = INITIAL_GUEST_PID;

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x7000_0000)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, fs_load.len()),
        [0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x70, 0x90]
    );
    assert_eq!(guest_bytes(runtime.memory(), 0x401009, 2), [0xcc, 0x90]);

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x7010_0000)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, fs_load.len()),
        [0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x10, 0x70, 0x90]
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_patch_cache_defers_zero_fs_base_tls_rewrites() {
    let _guard = native_execution_test_guard();
    let fs_load = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0];
    let mut code = fs_load.to_vec();
    code.extend_from_slice(&[0x0f, 0x05]);
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let pid = INITIAL_GUEST_PID;

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, fs_load.len()),
        fs_load
    );
    assert_eq!(
        runtime
            .dispatcher
            .subsystems()
            .native
            .patch_caches
            .get(&pid)
            .unwrap()
            .fs_relative_patches
            .len(),
        1,
        "zero-base native patching should record TLS candidates for a later nonzero base"
    );

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x7000_0000)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, fs_load.len()),
        [0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x70, 0x90]
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_patch_cache_traps_unmaterialized_fs_tls_sites() {
    let _guard = native_execution_test_guard();
    let fs_cmp = [0x64, 0x48, 0x83, 0x3c, 0x25, 0xe0, 0xff, 0xff, 0xff, 0x00];
    let mut code = fs_cmp.to_vec();
    code.extend_from_slice(&[0x0f, 0x05]);
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let pid = INITIAL_GUEST_PID;

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x600020)
        .unwrap();

    assert_eq!(guest_bytes(runtime.memory(), 0x401000, 1), [0xcc]);
    assert_eq!(guest_bytes(runtime.memory(), 0x40100a, 2), [0xcc, 0x90]);
    let cache = runtime
        .dispatcher
        .subsystems()
        .native
        .patch_caches
        .get(&pid)
        .unwrap();
    assert_eq!(cache.fs_relative_traps.len(), 1);
    assert_eq!(
        cache
            .fs_relative_traps
            .get(&0x401000)
            .unwrap()
            .original_bytes(),
        fs_cmp
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_execution_emulates_fs_relative_trap_before_syscall() {
    let _guard = native_execution_test_guard();
    let mut code = Vec::new();
    code.extend_from_slice(&[0x49, 0xba, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]); // mov r10,0x123456789abcdef0
    code.extend_from_slice(&[0x64, 0x4c, 0x89, 0x14, 0x25, 0xe0, 0xff, 0xff, 0xff]); // mov fs:[-0x20],r10
    code.extend_from_slice(&[0xb8, 0x27, 0x00, 0x00, 0x00]); // mov eax,getpid
    code.extend_from_slice(&[0x0f, 0x05]); // syscall
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime.enable_native_execution();
    runtime
        .memory_mut()
        .mmap(mcr_sys::MmapSyscallArgs {
            addr: 0x600000,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
            flags: LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
            fd: -1,
            offset: 0,
        })
        .unwrap();
    let arch = runtime.dispatch_syscall(context(
        Syscall::ArchPrctl,
        [ARCH_SET_FS, 0x600020, 0, 0, 0, 0],
    ));
    assert_eq!(arch.result, SyscallReturn::Success(0));

    let trap_step = runtime
        .dispatch_guest_execution()
        .expect("native FS trap should emulate one instruction");
    assert_eq!(trap_step.before_rip(), 0x401000);
    assert_eq!(trap_step.after_rip(), 0x401013);
    let mut stored = [0; 8];
    runtime.memory().read(0x600000, &mut stored).unwrap();
    assert_eq!(stored, 0x1234_5678_9abc_def0u64.to_le_bytes());

    let syscall_step = runtime
        .dispatch_guest_execution()
        .expect("guest should continue to syscall after FS trap");
    assert_eq!(syscall_step.before_rip(), 0x401013);
    assert_eq!(syscall_step.encoded_rax(), u64::from(INITIAL_GUEST_PID));
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_patch_cache_keeps_high_fs_relative_original_for_fault_fallback() {
    let _guard = native_execution_test_guard();
    let fs_load = [0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0];
    let mut code = fs_load.to_vec();
    code.extend_from_slice(&[0x0f, 0x05]);
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(INITIAL_GUEST_PID, 0x7000_0020_0000)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, fs_load.len()),
        fs_load
    );
    assert_eq!(guest_bytes(runtime.memory(), 0x401009, 2), [0xcc, 0x90]);
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative fault instruction decodes");
    assert!(native_fault_is_unrewritten_fs_relative(&instruction));
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_patch_cache_keeps_large_fs_relative_sets_unmaterialized() {
    let _guard = native_execution_test_guard();
    let fs_load = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0];
    let mut code = Vec::new();
    for _ in 0..=FS_RELATIVE_PATCH_MATERIALIZE_LIMIT {
        code.extend_from_slice(&fs_load);
    }
    code.extend_from_slice(&[0x0f, 0x05]);
    let load_len = ((code.len() as u64) + 0xfff) & !0xfff;
    let program = GuestProgram::new(GuestExecutable::new(
        b"/bin/app".to_vec(),
        Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_X,
                0x1000,
                0x401000,
                load_len,
                load_len,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000 + load_len,
                0x401000 + load_len,
                0x08,
                0x100,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R,
                0,
                0x402000 + load_len,
                0x100,
                0x100,
            ))
            .data_at(0x1000, code)
            .data_at(0x2000 + load_len, vec![0; 0x08])
            .build(),
    ));
    let mut runtime = Runtime::new(program).unwrap();
    let pid = INITIAL_GUEST_PID;

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x7000_0000)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, fs_load.len()),
        fs_load
    );
    let cache = runtime
        .dispatcher
        .subsystems()
        .native
        .patch_caches
        .get(&pid)
        .unwrap();
    assert_eq!(cache.fs_base, 0);
    assert_eq!(
        cache.fs_relative_patches.len(),
        FS_RELATIVE_PATCH_MATERIALIZE_LIMIT + 1
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_register_relative_mov_load() {
    let _guard = native_execution_test_guard();
    let code = [0x64, 0x8b, 0x00, 0x0f, 0x05];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x402004, &0x1234_5678u32.to_le_bytes())
        .unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative register fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rax: 4,
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402000,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rax, 0x1234_5678);
    assert_eq!(registers.rip, 0x401003);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_extended_register_relative_mov32_load() {
    let _guard = native_execution_test_guard();
    let code = [0x64, 0x44, 0x8b, 0x28, 0x0f, 0x05];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x402030, &0x89ab_cdefu32.to_le_bytes())
        .unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative extended register fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rax: 0x30,
            r13: u64::MAX,
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402000,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.r13, 0x89ab_cdef);
    assert_eq!(registers.rip, 0x401004);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_mov64_load() {
    let _guard = native_execution_test_guard();
    let code = [0x64, 0x48, 0x8b, 0x0c, 0x25, 0, 0, 0, 0, 0x0f, 0x05];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0x1234_5678_9abc_def0u64.to_le_bytes())
        .unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative absolute fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402000,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rcx, 0x1234_5678_9abc_def0);
    assert_eq!(registers.rip, 0x401009);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_prefixed_absolute_mov64_load() {
    let _guard = native_execution_test_guard();
    let code = [
        0x66, 0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x0f, 0x05,
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0x1234_5678_9abc_def0u64.to_le_bytes())
        .unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("prefixed fs-relative absolute fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402000,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rax, 0x1234_5678_9abc_def0);
    assert_eq!(registers.rip, 0x40100d);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_movzx8_load() {
    let _guard = native_execution_test_guard();
    let code = [
        0x64, 0x0f, 0xb6, 0x04, 0x25, 0x00, 0xff, 0xff, 0xff, 0x0f, 0x05,
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime.memory_mut().write(0x402100, &[0xab]).unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative movzx fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rax: 0xffff_ffff_ffff_ffff,
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402200,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rax, 0xab);
    assert_eq!(registers.rip, 0x401009);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_mov64_store() {
    let _guard = native_execution_test_guard();
    let code = [
        0x64, 0x48, 0x89, 0x04, 0x25, 0xc8, 0xff, 0xff, 0xff, 0x0f, 0x05,
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative mov store fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rax: 0x1234_5678_9abc_def0,
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402200,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rip, 0x401009);
    let mut stored = [0; 8];
    runtime.memory().read(0x4021c8, &mut stored).unwrap();
    assert_eq!(stored, 0x1234_5678_9abc_def0u64.to_le_bytes());
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_mov64_immediate_store() {
    let _guard = native_execution_test_guard();
    let code = [
        0x64, 0x48, 0xc7, 0x04, 0x25, 0xe0, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05,
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x4021e0, &0xffff_ffff_ffff_ffffu64.to_le_bytes())
        .unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative mov immediate store fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402200,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rip, 0x40100d);
    let mut stored = [0xff; 8];
    runtime.memory().read(0x4021e0, &mut stored).unwrap();
    assert_eq!(stored, 0u64.to_le_bytes());
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_register_relative_mov32_immediate_store() {
    let _guard = native_execution_test_guard();
    let code = [0x64, 0xc7, 0x00, 0, 0, 0, 0, 0x0f, 0x05];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x402030, &0xffff_ffffu32.to_le_bytes())
        .unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative register immediate store fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rax: 0x30,
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402000,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rip, 0x401007);
    let mut stored = [0xff; 4];
    runtime.memory().read(0x402030, &mut stored).unwrap();
    assert_eq!(stored, 0u32.to_le_bytes());
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_mov8_immediate_store() {
    let _guard = native_execution_test_guard();
    let code = [
        0x64, 0xc6, 0x04, 0x25, 0x58, 0xff, 0xff, 0xff, 0x01, 0x0f, 0x05,
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime.memory_mut().write(0x402158, &[0]).unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative mov imm8 store fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402200,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rip, 0x401009);
    let mut stored = [0];
    runtime.memory().read(0x402158, &mut stored).unwrap();
    assert_eq!(stored, [1]);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_movhps_load() {
    let _guard = native_execution_test_guard();
    let code = [
        0x64, 0x0f, 0x16, 0x04, 0x25, 0x98, 0xff, 0xff, 0xff, 0x0f, 0x05,
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x402198, &0x8877_6655_4433_2211u64.to_le_bytes())
        .unwrap();
    let mut xmm = mcr_win::HostXmmRegisters::default();
    xmm[0][..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative movhps fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rip: 0x401000,
            xmm,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402200,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rip, 0x401009);
    assert_eq!(
        &registers.xmm[0],
        &[
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ]
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_cmp64_imm8() {
    let _guard = native_execution_test_guard();
    let code = [
        0x64, 0x48, 0x83, 0x3c, 0x25, 0xe8, 0xff, 0xff, 0xff, 0x00, 0x0f, 0x05,
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x4021e8, &0u64.to_le_bytes())
        .unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative cmp imm8 fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rflags: 0x202,
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402200,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rip, 0x40100a);
    assert_ne!(registers.rflags & 0x40, 0);
    assert_eq!(registers.rflags & 0x01, 0);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_cmp8_imm8() {
    let _guard = native_execution_test_guard();
    let code = [
        0x64, 0x80, 0x3c, 0x25, 0x58, 0xff, 0xff, 0xff, 0x00, 0x0f, 0x05,
    ];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime.memory_mut().write(0x402158, &[0]).unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative cmp imm8 fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rflags: 0x202,
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402200,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rip, 0x401009);
    assert_ne!(registers.rflags & 0x40, 0);
    assert_eq!(registers.rflags & 0x01, 0);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_add64() {
    let _guard = native_execution_test_guard();
    let code = [0x64, 0x48, 0x03, 0x04, 0x25, 0, 0, 0, 0, 0x0f, 0x05];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x402200, &0x402200u64.to_le_bytes())
        .unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative add fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rax: u64::MAX - 0xf,
            rflags: 0x202,
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402200,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rax, 0x4021f0);
    assert_eq!(registers.rip, 0x401009);
    assert_ne!(registers.rflags & 0x01, 0);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_fs_fault_emulates_absolute_sub64() {
    let _guard = native_execution_test_guard();
    let code = [0x64, 0x48, 0x2b, 0x04, 0x25, 0x28, 0, 0, 0, 0x0f, 0x05];
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    runtime
        .memory_mut()
        .write(0x402028, &0x42u64.to_le_bytes())
        .unwrap();
    let instruction = native_fault_instruction(runtime.memory(), 0x401000)
        .expect("fs-relative sub fault instruction decodes");

    let registers = emulate_fs_relative_native_fault(
        runtime.memory_mut(),
        mcr_win::HostCpuRegisters {
            rax: 0x42,
            rflags: 0x202,
            rip: 0x401000,
            ..mcr_win::HostCpuRegisters::default()
        },
        0x402000,
        &instruction,
    )
    .unwrap()
    .expect("instruction is emulated");

    assert_eq!(registers.rax, 0);
    assert_eq!(registers.rip, 0x401009);
    assert_ne!(registers.rflags & 0x40, 0);
    assert_eq!(registers.rflags & 0x01, 0);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_patch_cache_skips_new_zero_base_fs_patch_work() {
    assert_eq!(
        fs_relative_patch_work(0, 0, 0, 45_171, 0),
        FsRelativePatchWork::None
    );
    assert_eq!(
        fs_relative_patch_work(0, 0x7000_0000, 0, 45_171, 0),
        FsRelativePatchWork::All
    );
    assert_eq!(
        fs_relative_patch_work(0x7000_0000, 0, 0, 45_171, 0),
        FsRelativePatchWork::None
    );
    assert_eq!(
        fs_relative_patch_work(0x7000_0000, 0, 0, 0, 1),
        FsRelativePatchWork::All
    );
    assert_eq!(
        fs_relative_patch_work(0x7000_0000, 0, 1, 0, 0),
        FsRelativePatchWork::All
    );
    assert_eq!(
        fs_relative_patch_work(0x7000_0000, 0x7000_0000, 0, 1, 0),
        FsRelativePatchWork::New
    );
    assert_eq!(
        fs_relative_patch_work(0x7000_0000, 0x7000_0000, 0, 0, 1),
        FsRelativePatchWork::None
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_patch_cache_survives_memory_rematerialization() {
    let _guard = native_execution_test_guard();
    let fs_load = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0];
    let mut code = fs_load.to_vec();
    code.extend_from_slice(&[0x0f, 0x05]);
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let pid = INITIAL_GUEST_PID;

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x7000_0000)
        .unwrap();
    runtime
        .dispatcher
        .subsystems_mut()
        .materialize_selected_memory_at_guest_addresses()
        .unwrap();
    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x7010_0000)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, fs_load.len()),
        [0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x10, 0x70, 0x90]
    );
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn native_patch_cache_recovers_existing_fs_replacement_after_invalidation() {
    let _guard = native_execution_test_guard();
    let fs_load = [0x64, 0x48, 0x8b, 0x1c, 0x25, 0, 0, 0, 0];
    let mut code = fs_load.to_vec();
    code.extend_from_slice(&[0x0f, 0x05]);
    let mut runtime =
        Runtime::new(test_program_with_entry_code("/bin/app", 0x401000, &code)).unwrap();
    let pid = INITIAL_GUEST_PID;

    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x7000_0000)
        .unwrap();
    runtime
        .dispatcher
        .subsystems_mut()
        .invalidate_native_patch_cache(pid);
    runtime
        .dispatcher
        .subsystems_mut()
        .ensure_native_patch_cache(pid, 0x5010_0000)
        .unwrap();

    assert_eq!(
        guest_bytes(runtime.memory(), 0x401000, fs_load.len()),
        [0x48, 0x8b, 0x1c, 0x25, 0x00, 0x00, 0x10, 0x50, 0x90]
    );
}
