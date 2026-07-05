use super::support::*;

#[test]
fn dispatcher_connects_openat_read_write_lseek_and_close_to_vfs() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    runtime.memory_mut().write(0x2000, b"!!");
    let fd = dispatch(
        &mut runtime,
        Syscall::Openat,
        [AT_FDCWD as u64, 0x1000, u64::from(O_RDWR), 0, 0, 0],
    );
    assert_eq!(fd, SyscallReturn::Success(3));

    assert_eq!(
        dispatch(&mut runtime, Syscall::Lseek, [3, 5, 0, 0, 0, 0]),
        SyscallReturn::Success(5)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Write, [3, 0x2000, 2, 0, 0, 0]),
        SyscallReturn::Success(2)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Lseek, [3, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Read, [3, 0x3000, 7, 0, 0, 0]),
        SyscallReturn::Success(7)
    );
    assert_eq!(runtime.memory().read(0x3000, 7), b"hello!!");
    assert_eq!(
        dispatch(&mut runtime, Syscall::Close, [3, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Read, [3, 0x3000, 1, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::EBADF)
    );
}

#[test]
fn dispatcher_routes_pwrite64_without_changing_fd_offset() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    runtime.memory_mut().write(0x2000, b"YY");
    runtime.memory_mut().write(0x2010, b"!");
    let fd = dispatch(
        &mut runtime,
        Syscall::Openat,
        [AT_FDCWD as u64, 0x1000, u64::from(O_RDWR), 0, 0, 0],
    );
    assert_eq!(fd, SyscallReturn::Success(3));
    assert_eq!(
        dispatch(&mut runtime, Syscall::Lseek, [3, 5, 0, 0, 0, 0]),
        SyscallReturn::Success(5)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Pwrite64, [3, 0x2000, 2, 1, 0, 0]),
        SyscallReturn::Success(2)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Write, [3, 0x2010, 1, 0, 0, 0]),
        SyscallReturn::Success(1)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Lseek, [3, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Read, [3, 0x3000, 6, 0, 0, 0]),
        SyscallReturn::Success(6)
    );
    assert_eq!(runtime.memory().read(0x3000, 6), b"hYYlo!");
}

#[test]
fn openat2_degrades_simple_open_how_to_openat() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    runtime
        .memory_mut()
        .write(0x2000, &u64::from(O_RDONLY).to_le_bytes());
    runtime.memory_mut().write(0x2008, &0u64.to_le_bytes());
    runtime.memory_mut().write(0x2010, &0u64.to_le_bytes());

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat2,
            [AT_FDCWD as u64, 0x1000, 0x2000, 24, 0, 0],
        ),
        SyscallReturn::Success(3)
    );

    runtime.memory_mut().write(0x2010, &1u64.to_le_bytes());
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat2,
            [AT_FDCWD as u64, 0x1000, 0x2000, 24, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::ENOSYS)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat2,
            [AT_FDCWD as u64, 0x1000, 0x2000, 16, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn statfs_and_fstatfs_write_fixed_linux_layouts() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    assert_eq!(
        dispatch(&mut runtime, Syscall::Statfs, [0x1000, 0x3000, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(u64_at(runtime.memory(), 0x3000), LINUX_EXT_SUPER_MAGIC);
    assert_eq!(u64_at(runtime.memory(), 0x3000 + 8), 4096);
    assert_eq!(u64_at(runtime.memory(), 0x3000 + 64), 255);

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Fstatfs, [3, 0x3100, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(u64_at(runtime.memory(), 0x3100), LINUX_EXT_SUPER_MAGIC);
}

#[test]
fn faccessat2_degrades_simple_flags_to_access_semantics() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    runtime.memory_mut().write_cstr(0x1100, "file");
    runtime.memory_mut().write_cstr(0x1200, "");
    runtime.memory_mut().write_cstr(0x1300, "/tmp");

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Faccessat2,
            [AT_FDCWD as u64, 0x1000, u64::from(mcr_vfs::R_OK), 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [
                AT_FDCWD as u64,
                0x1300,
                u64::from(O_RDONLY | O_DIRECTORY),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Faccessat2,
            [3, 0x1100, u64::from(mcr_vfs::R_OK), 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Faccessat2,
            [
                3,
                0x1200,
                u64::from(mcr_vfs::R_OK),
                u64::from(AT_EMPTY_PATH),
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Faccessat2,
            [AT_FDCWD as u64, 0x1000, 0, 0x8000_0000, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn close_range_closes_fds_and_ignores_missing_entries() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
        ),
        SyscallReturn::Success(4)
    );

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::CloseRange,
            [4, u64::from(u32::MAX), 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert!(runtime.vfs().fds().get(3).is_ok());
    assert!(runtime.vfs().fds().get(4).is_err());
    assert_eq!(
        dispatch(&mut runtime, Syscall::CloseRange, [5, 4, 0, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn runtime_file_backed_mmap_populates_private_mapping_from_vfs_fd() {
    let mut runtime = Runtime::with_vfs(test_program("/bin/app", 0x401000), sample_vfs()).unwrap();
    runtime
        .memory_mut()
        .write(0x402000, b"/tmp/file\0")
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Openat,
                [AT_FDCWD as u64, 0x402000, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Lseek, [3, 2, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(2)
    );

    let mapped = runtime.dispatch_syscall(context(
        Syscall::Mmap,
        [
            0x7000_0000,
            GUEST_PAGE_SIZE,
            u64::from(mcr_sys::LINUX_PROT_READ),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_FIXED),
            3,
            0,
        ],
    ));

    assert_eq!(mapped.result, SyscallReturn::Success(0x7000_0000));
    let mut bytes = [0; 8];
    runtime.memory().read(0x7000_0000, &mut bytes).unwrap();
    assert_eq!(&bytes[..5], b"hello");
    assert_eq!(&bytes[5..], &[0, 0, 0]);
    assert_eq!(runtime.vfs().fds().get(3).unwrap().offset(), 2);
    assert_eq!(
        runtime.memory_mut().write(0x7000_0000, b"x"),
        Err(GuestMemoryError::AccessDenied)
    );
}

#[test]
fn runtime_file_backed_mmap_uses_calling_process_fd_table() {
    let mut runtime = Runtime::with_vfs(test_program("/bin/app", 0x401000), sample_vfs()).unwrap();
    runtime
        .memory_mut()
        .write(0x402000, b"/tmp/file\0")
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Fork, [0; 6]))
            .result,
        SyscallReturn::Success(2)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context_for(
                2,
                2,
                Syscall::Openat,
                [AT_FDCWD as u64, 0x402000, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Close, [99, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EBADF)
    );

    let mapped = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Mmap,
        [
            0x7000_0000,
            GUEST_PAGE_SIZE,
            u64::from(mcr_sys::LINUX_PROT_READ),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_FIXED),
            3,
            0,
        ],
    ));

    assert_eq!(mapped.result, SyscallReturn::Success(0x7000_0000));
    let mut bytes = [0; 5];
    runtime
        .memory_for_process(2)
        .unwrap()
        .read(0x7000_0000, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"hello");
}

#[test]
fn runtime_file_backed_mmap_zero_fills_elf_load_bss_tail() {
    let mut tree = PathTree::new();
    tree.create_dir("/tmp").unwrap();
    tree.create_file_with_content("/tmp/libcrypto.so.3", elf_with_bss_tail_garbage(), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/app", 0x401000), tree);
    runtime
        .memory_mut()
        .write(0x402000, b"/tmp/libcrypto.so.3\0")
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Openat,
                [AT_FDCWD as u64, 0x402000, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(3)
    );

    let mapped = runtime.dispatch_syscall(context(
        Syscall::Mmap,
        [
            0x7000_0000,
            GUEST_PAGE_SIZE,
            u64::from(mcr_sys::LINUX_PROT_READ),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_FIXED),
            3,
            0,
        ],
    ));

    assert_eq!(mapped.result, SyscallReturn::Success(0x7000_0000));
    let mut bytes = [0xff; 16];
    runtime.memory().read(0x7000_0100, &mut bytes).unwrap();
    assert_eq!(&bytes[..8], b"LOADDATA");
    assert_eq!(&bytes[8..], &[0; 8]);
}

#[test]
fn runtime_file_backed_mmap_reuses_read_only_cache_and_keeps_private_vmas() {
    let page_size = usize::try_from(GUEST_PAGE_SIZE).unwrap();
    let data = (0u16..5000)
        .map(|index| u8::try_from(index % 251 + 1).unwrap())
        .collect::<Vec<_>>();
    let mut tree = PathTree::new();
    tree.create_dir("/tmp").unwrap();
    tree.create_file_with_content("/tmp/large", data.clone(), 0o644)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/app", 0x401000), tree);
    runtime
        .memory_mut()
        .write(0x402000, b"/tmp/large\0")
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Openat,
                [AT_FDCWD as u64, 0x402000, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(3)
    );

    let first_addr = 0x7000_0000;
    let first = runtime.dispatch_syscall(context(
        Syscall::Mmap,
        [
            first_addr,
            GUEST_PAGE_SIZE,
            u64::from(LINUX_PROT_READ),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_FIXED),
            3,
            GUEST_PAGE_SIZE,
        ],
    ));
    assert_eq!(first.result, SyscallReturn::Success(first_addr));
    assert_eq!(
        runtime
            .dispatcher
            .subsystems()
            .file_backed_mapping_cache_snapshot(),
        FileBackedMappingCacheSnapshot {
            entries: 1,
            hits: 0,
            misses: 1
        }
    );
    let first_vma = runtime.memory().vma_containing(first_addr).unwrap();
    assert_eq!(
        first_vma.protection(),
        GuestMemoryProtection::new(true, false, false)
    );
    assert!(matches!(
        first_vma.kind(),
        GuestVmaKind::FileBacked {
            fd: 3,
            offset: 4096,
            shared: false
        }
    ));

    let mapped_file_bytes = data.len() - page_size;
    let tail_probe = mapped_file_bytes - 4;
    let mut tail = [0xff; 8];
    runtime
        .memory()
        .read(first_addr + tail_probe as u64, &mut tail)
        .unwrap();
    assert_eq!(&tail[..4], &data[data.len() - 4..]);
    assert_eq!(&tail[4..], &[0; 4]);

    let second_addr = first_addr + GUEST_PAGE_SIZE;
    let second = runtime.dispatch_syscall(context(
        Syscall::Mmap,
        [
            second_addr,
            GUEST_PAGE_SIZE,
            u64::from(LINUX_PROT_READ),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_FIXED),
            3,
            GUEST_PAGE_SIZE,
        ],
    ));
    assert_eq!(second.result, SyscallReturn::Success(second_addr));
    let after_read_only = runtime
        .dispatcher
        .subsystems()
        .file_backed_mapping_cache_snapshot();
    assert_eq!(
        after_read_only,
        FileBackedMappingCacheSnapshot {
            entries: 1,
            hits: 1,
            misses: 1
        }
    );

    runtime
        .memory_mut()
        .mprotect(mcr_sys::MprotectSyscallArgs {
            addr: first_addr,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
        })
        .unwrap();
    runtime.memory_mut().write(first_addr, b"Q").unwrap();
    let mut second_byte = [0];
    runtime
        .memory()
        .read(second_addr, &mut second_byte)
        .unwrap();
    assert_eq!(second_byte, [data[page_size]]);

    let writable_first_addr = first_addr + GUEST_PAGE_SIZE * 2;
    let writable_first = runtime.dispatch_syscall(context(
        Syscall::Mmap,
        [
            writable_first_addr,
            GUEST_PAGE_SIZE,
            u64::from(LINUX_PROT_READ | LINUX_PROT_WRITE),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_FIXED),
            3,
            GUEST_PAGE_SIZE,
        ],
    ));
    assert_eq!(
        writable_first.result,
        SyscallReturn::Success(writable_first_addr)
    );
    let writable_second_addr = first_addr + GUEST_PAGE_SIZE * 3;
    let writable_second = runtime.dispatch_syscall(context(
        Syscall::Mmap,
        [
            writable_second_addr,
            GUEST_PAGE_SIZE,
            u64::from(LINUX_PROT_READ | LINUX_PROT_WRITE),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_FIXED),
            3,
            GUEST_PAGE_SIZE,
        ],
    ));
    assert_eq!(
        writable_second.result,
        SyscallReturn::Success(writable_second_addr)
    );
    assert_eq!(
        runtime
            .dispatcher
            .subsystems()
            .file_backed_mapping_cache_snapshot(),
        after_read_only
    );
    runtime
        .memory_mut()
        .write(writable_first_addr, b"W")
        .unwrap();
    let mut writable_second_byte = [0];
    runtime
        .memory()
        .read(writable_second_addr, &mut writable_second_byte)
        .unwrap();
    assert_eq!(writable_second_byte, [data[page_size]]);
}

#[test]
fn runtime_dispatch_reads_proc_self_from_current_process_image() {
    let mut runtime = Runtime::new(test_program_with_args(
        "/bin/app",
        0x401000,
        ["/bin/app", "--flag"],
        ["A=B"],
    ))
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402100, b"/proc/self/cmdline\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402140, b"/proc/self/environ\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402180, b"/proc/self/exe\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x4021c0, b"/proc/self/fd/3\0")
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Openat,
                [AT_FDCWD as u64, 0x402100, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Read, [3, 0x402300, 64, 0, 0, 0]))
            .result,
        SyscallReturn::Success(16)
    );
    let mut cmdline = [0; 16];
    runtime.memory().read(0x402300, &mut cmdline).unwrap();
    assert_eq!(&cmdline, b"/bin/app\0--flag\0");

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Openat,
                [AT_FDCWD as u64, 0x402140, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(4)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Read, [4, 0x402320, 64, 0, 0, 0]))
            .result,
        SyscallReturn::Success(4)
    );
    let mut environ = [0; 4];
    runtime.memory().read(0x402320, &mut environ).unwrap();
    assert_eq!(&environ, b"A=B\0");

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Readlink,
                [0x402180, 0x402340, 64, 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(8)
    );
    let mut exe = [0; 8];
    runtime.memory().read(0x402340, &mut exe).unwrap();
    assert_eq!(&exe, b"/bin/app");

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Readlink,
                [0x4021c0, 0x402360, 64, 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(18)
    );
    let mut fd_target = [0; 18];
    runtime.memory().read(0x402360, &mut fd_target).unwrap();
    assert_eq!(&fd_target, b"/proc/self/cmdline");
}

#[test]
fn readv_writev_move_multiple_guest_buffers() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/iov");
    runtime.memory_mut().write(0x2100, b"ab");
    runtime.memory_mut().write(0x2200, b"cd");
    runtime.memory_mut().write_iovec(0x2000, 0x2100, 2);
    runtime.memory_mut().write_iovec(0x2010, 0x2200, 2);
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [
                AT_FDCWD as u64,
                0x1000,
                u64::from(mcr_vfs::O_CREAT | O_RDWR),
                0o644,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Writev, [3, 0x2000, 2, 0, 0, 0]),
        SyscallReturn::Success(4)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Lseek, [3, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    runtime.memory_mut().write_iovec(0x3000, 0x3100, 2);
    runtime.memory_mut().write_iovec(0x3010, 0x3200, 2);
    assert_eq!(
        dispatch(&mut runtime, Syscall::Readv, [3, 0x3000, 2, 0, 0, 0]),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.memory().read(0x3100, 2), b"ab");
    assert_eq!(runtime.memory().read(0x3200, 2), b"cd");
}

#[test]
fn fsync_and_fdatasync_validate_guest_fd_as_noop_flushes() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDWR), 0, 0, 0],
        ),
        SyscallReturn::Success(3)
    );

    assert_eq!(
        dispatch(&mut runtime, Syscall::Fsync, [3, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Fdatasync, [3, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Fsync, [99, 0, 0, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::EBADF)
    );
}

#[test]
fn pread64_reads_without_changing_guest_fd_offset() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
        ),
        SyscallReturn::Success(3)
    );

    assert_eq!(
        dispatch(&mut runtime, Syscall::Pread64, [3, 0x2000, 3, 1, 0, 0]),
        SyscallReturn::Success(3)
    );
    assert_eq!(runtime.memory().read(0x2000, 3), b"ell");
    assert_eq!(
        dispatch(&mut runtime, Syscall::Read, [3, 0x2100, 1, 0, 0, 0]),
        SyscallReturn::Success(1)
    );
    assert_eq!(runtime.memory().read(0x2100, 1), b"h");
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Pread64,
            [3, 0x2200, 1, u64::MAX, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn stat_access_readlink_and_getdents64_write_linux_layouts() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    runtime.memory_mut().write_cstr(0x1100, "/tmp");
    runtime.memory_mut().write_cstr(0x1200, "/link");

    let fd = dispatch(
        &mut runtime,
        Syscall::Openat,
        [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
    );
    assert_eq!(fd, SyscallReturn::Success(3));
    assert_eq!(
        dispatch(&mut runtime, Syscall::Fstat, [3, 0x4000, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(u64_at(runtime.memory(), 0x4000 + 48), 5);
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Newfstatat,
            [AT_FDCWD as u64, 0x1000, 0x4100, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(u64_at(runtime.memory(), 0x4100 + 48), 5);
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Statx,
            [AT_FDCWD as u64, 0x1000, 0, 0, 0x4200, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(u64_at(runtime.memory(), 0x4200 + 40), 5);
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Access,
            [0x1000, u64::from(mcr_vfs::R_OK), 0, 0, 0, 0]
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Readlink,
            [0x1200, 0x4300, 32, 0, 0, 0]
        ),
        SyscallReturn::Success(9)
    );
    assert_eq!(runtime.memory().read(0x4300, 9), b"/tmp/file");

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [
                AT_FDCWD as u64,
                0x1100,
                u64::from(O_RDONLY | O_DIRECTORY),
                0,
                0,
                0
            ],
        ),
        SyscallReturn::Success(4)
    );
    let dents = dispatch(&mut runtime, Syscall::Getdents64, [4, 0x5000, 256, 0, 0, 0]);
    assert!(matches!(dents, SyscallReturn::Success(value) if value > 0));
    let first_reclen = u16_at(runtime.memory(), 0x5000 + 16);
    assert_eq!(first_reclen % 8, 0);
    assert_eq!(runtime.memory().read(0x5000 + 19, 2), b".\0");
}

#[test]
fn writable_vfs_syscalls_mutate_paths_and_cwd() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/pkg");
    runtime.memory_mut().write_cstr(0x1100, "file");
    runtime.memory_mut().write_cstr(0x1200, "/tmp/pkg/file");
    runtime.memory_mut().write_cstr(0x1300, "/tmp/pkg/link");
    runtime.memory_mut().write_cstr(0x1400, "../file");
    runtime.memory_mut().write_cstr(0x1500, "/tmp/pkg/renamed");

    assert_eq!(
        dispatch(&mut runtime, Syscall::Umask, [0o077, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0o022)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Mkdirat,
            [AT_FDCWD as u64, 0x1000, 0o777, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Chdir, [0x1000, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Getcwd, [0x3000, 64, 0, 0, 0, 0]),
        SyscallReturn::Success(0x3000)
    );
    assert_eq!(runtime.memory().read(0x3000, 9), b"/tmp/pkg\0");

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [
                AT_FDCWD as u64,
                0x1100,
                u64::from(O_CREAT | O_WRONLY),
                0o666,
                0,
                0
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Ftruncate, [3, 7, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(runtime.vfs().fstat(3).unwrap().size, 7);
    assert_eq!(
        dispatch(&mut runtime, Syscall::Fallocate, [3, 0, 4, 8, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(runtime.vfs().fstat(3).unwrap().size, 12);
    assert_eq!(
        dispatch(&mut runtime, Syscall::Fallocate, [3, 0, 1, 2, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(runtime.vfs().fstat(3).unwrap().size, 12);
    assert_eq!(
        dispatch(&mut runtime, Syscall::Fallocate, [3, 1, 0, 1, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::EOPNOTSUPP)
    );

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Symlinkat,
            [0x1400, AT_FDCWD as u64, 0x1300, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Readlinkat,
            [AT_FDCWD as u64, 0x1300, 0x3100, 32, 0, 0],
        ),
        SyscallReturn::Success(7)
    );
    assert_eq!(runtime.memory().read(0x3100, 7), b"../file");

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Linkat,
            [AT_FDCWD as u64, 0x1200, AT_FDCWD as u64, 0x1500, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Renameat2,
            [
                AT_FDCWD as u64,
                0x1500,
                AT_FDCWD as u64,
                0x1200,
                u64::from(RENAME_NOREPLACE),
                0,
            ],
        ),
        SyscallReturn::Errno(LinuxErrno::EEXIST)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Unlinkat,
            [AT_FDCWD as u64, 0x1500, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );

    runtime.memory_mut().write(0x2000, &10i64.to_le_bytes());
    runtime.memory_mut().write(0x2008, &20i64.to_le_bytes());
    runtime.memory_mut().write(0x2010, &30i64.to_le_bytes());
    runtime.memory_mut().write(0x2018, &40i64.to_le_bytes());
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Utimensat,
            [AT_FDCWD as u64, 0x1200, 0x2000, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    let touched = runtime
        .vfs()
        .newfstatat(AT_FDCWD, "/tmp/pkg/file", 0)
        .unwrap();
    assert_eq!(touched.atime_sec, 10);
    assert_eq!(touched.atime_nsec, 20);
    assert_eq!(touched.mtime_sec, 30);
    assert_eq!(touched.mtime_nsec, 40);

    assert_eq!(
        dispatch(&mut runtime, Syscall::Chmod, [0x1200, 0o600, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Chown, [0x1200, 1000, 1001, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    let owned = runtime
        .vfs()
        .newfstatat(AT_FDCWD, "/tmp/pkg/file", 0)
        .unwrap();
    assert_eq!(owned.mode & 0o777, 0o600);
    assert_eq!(owned.uid, 1000);
    assert_eq!(owned.gid, 1001);
}

#[test]
fn fd_management_syscalls_wire_to_vfs_and_guest_memory() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDWR), 0, 0, 0],
        ),
        SyscallReturn::Success(3)
    );

    assert_eq!(
        dispatch(&mut runtime, Syscall::Dup, [3, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(4)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Dup2, [3, 7, 0, 0, 0, 0]),
        SyscallReturn::Success(7)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Dup3,
            [3, 8, u64::from(O_CLOEXEC), 0, 0, 0]
        ),
        SyscallReturn::Success(8)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Fcntl,
            [8, u64::from(F_GETFD), 0, 0, 0, 0]
        ),
        SyscallReturn::Success(1)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Fcntl,
            [3, u64::from(F_DUPFD_CLOEXEC), 20, 0, 0, 0],
        ),
        SyscallReturn::Success(20)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Fcntl,
            [
                4,
                u64::from(mcr_vfs::F_SETFL),
                u64::from(O_NONBLOCK),
                0,
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Fcntl,
            [3, u64::from(F_GETFL), 0, 0, 0, 0]
        ),
        SyscallReturn::Success(u64::from(O_RDWR | O_NONBLOCK))
    );

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Pipe2,
            [0x2000, u64::from(O_CLOEXEC | O_NONBLOCK), 0, 0, 0, 0]
        ),
        SyscallReturn::Success(0)
    );
    let read_fd = i32_at(runtime.memory(), 0x2000);
    let write_fd = i32_at(runtime.memory(), 0x2004);
    assert!(runtime.vfs().fds().cloexec(read_fd).unwrap());
    assert!(runtime.vfs().fds().cloexec(write_fd).unwrap());

    runtime.memory_mut().write(0x2100, b"pipe");
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Write,
            [write_fd as u64, 0x2100, 4, 0, 0, 0]
        ),
        SyscallReturn::Success(4)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Ioctl,
            [read_fd as u64, FIONREAD, 0x2200, 0, 0, 0]
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(u32_at(runtime.memory(), 0x2200), 4);
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Read,
            [read_fd as u64, 0x2300, 4, 0, 0, 0]
        ),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.memory().read(0x2300, 4), b"pipe");
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Ioctl,
            [1, TIOCGWINSZ, 0x2400, 0, 0, 0]
        ),
        SyscallReturn::Errno(LinuxErrno::ENOTTY)
    );
}

#[test]
fn errno_cases_match_linux_shapes() {
    let mut runtime = runtime_with_sample_vfs();
    runtime.memory_mut().write_cstr(0x1000, "/missing");
    runtime.memory_mut().write_cstr(0x1100, "/tmp/file");
    runtime.memory_mut().write_cstr(0x1200, "child");
    runtime.memory_mut().write_cstr(0x1300, "/private/secret");
    runtime
        .vfs_mut()
        .tree_mut()
        .lookup_path_mut(&guest_path("/private"))
        .unwrap()
        .set_mode(0o600);

    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::ENOENT)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Read, [99, 0x2000, 1, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::EBADF)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1100, u64::from(O_RDONLY), 0, 0, 0],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Openat,
            [3, 0x1200, u64::from(O_RDONLY), 0, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::ENOTDIR)
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Access,
            [0x1300, u64::from(mcr_vfs::R_OK), 0, 0, 0, 0]
        ),
        SyscallReturn::Errno(LinuxErrno::EACCES)
    );
}

#[test]
fn memory_syscalls_route_to_request_process_memory() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));

    let child_mmap = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Mmap,
        [
            0x600000,
            4096,
            u64::from(LINUX_PROT_READ | LINUX_PROT_WRITE),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED),
            u64::MAX,
            0,
        ],
    ));

    assert_eq!(child_mmap.result, SyscallReturn::Success(0x600000));
    assert!(runtime.memory().vma_containing(0x600000).is_none());
    assert!(
        runtime
            .memory_for_process(2)
            .unwrap()
            .vma_containing(0x600000)
            .is_some()
    );
}
