use std::{cell::RefCell, collections::BTreeMap, rc::Rc, sync::MutexGuard};

use mcr_net::SocketState;
use mcr_sys::{
    GuestContext, InMemorySyscallTracer, LINUX_AF_INET, LINUX_AF_INET6, LINUX_CLONE_CHILD_CLEARTID,
    LINUX_CLONE_CHILD_SETTID, LINUX_CLONE_FILES, LINUX_CLONE_FS, LINUX_CLONE_PARENT_SETTID,
    LINUX_CLONE_SETTLS, LINUX_CLONE_SIGHAND, LINUX_CLONE_SYSVSEM, LINUX_CLONE_THREAD,
    LINUX_CLONE_VFORK, LINUX_CLONE_VM, LINUX_EPOLL_CLOEXEC, LINUX_EPOLL_CTL_ADD,
    LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD, LINUX_EPOLLERR, LINUX_EPOLLET, LINUX_EPOLLEXCLUSIVE,
    LINUX_EPOLLHUP, LINUX_EPOLLIN, LINUX_EPOLLONESHOT, LINUX_EPOLLOUT, LINUX_IPPROTO_TCP,
    LINUX_MAP_ANONYMOUS, LINUX_MAP_FIXED, LINUX_MAP_PRIVATE, LINUX_MSG_CMSG_CLOEXEC, LINUX_POLLHUP,
    LINUX_POLLIN, LINUX_POLLNVAL, LINUX_POLLOUT, LINUX_POLLPRI, LINUX_POLLRDNORM, LINUX_POLLWRNORM,
    LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE, LINUX_SHUT_RDWR, LINUX_SIGCHLD,
    LINUX_SO_ERROR, LINUX_SO_KEEPALIVE, LINUX_SO_REUSEADDR, LINUX_SO_TYPE, LINUX_SOCK_CLOEXEC,
    LINUX_SOCK_DGRAM, LINUX_SOCK_NONBLOCK, LINUX_SOCK_STREAM, LINUX_SOL_SOCKET, LINUX_TCP_NODELAY,
    Syscall, SyscallArgs, SyscallEnterEvent, SyscallExitEvent, SyscallRegisters, SyscallReturn,
    SyscallTraceEvent, TraceContext, Wait4SyscallArgs,
};
use mcr_task::{ARCH_SET_FS, ExitState, INITIAL_GUEST_PID, INITIAL_GUEST_TID};
use mcr_testkit::elf::{Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X};

fn native_execution_test_guard() -> MutexGuard<'static, ()> {
    crate::test_support::native_execution_test_guard()
}

fn env_test_guard() -> MutexGuard<'static, ()> {
    crate::test_support::env_test_guard()
}
use mcr_vfs::{
    AT_FDCWD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, FIONREAD, FdTable, O_CLOEXEC, O_CREAT,
    O_DIRECTORY, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, PathTree, RENAME_NOREPLACE, Rootfs,
    TIOCGWINSZ, VirtualFileSystem,
};

use super::*;

#[test]
fn package_name_is_stable() {
    assert_eq!(CRATE_NAME, "mcr-runtime");
}

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
fn close_releases_socket_table_entry_after_vfs_fd() {
    let transport = runtime_socket_transport();
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Close, [3, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );

    let socket_id = SocketId::new(1).unwrap();
    assert_eq!(
        runtime.sockets().socket(socket_id).unwrap().state(),
        SocketState::Closed
    );
    assert_eq!(
        dispatch_network(&mut runtime, Syscall::Sendto, [3, 0x2000, 0, 0, 0, 0],),
        SyscallReturn::Errno(LinuxErrno::EBADF)
    );
}

#[test]
fn close_range_releases_socket_and_epoll_resources() {
    let transport = runtime_socket_transport();
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(8080))
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(4)
    );

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::CloseRange, [3, 4, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    assert!(runtime.vfs().fds().get(3).is_err());
    assert!(runtime.vfs().fds().get(4).is_err());
    let socket_id = SocketId::new(1).unwrap();
    assert_eq!(
        runtime
            .dispatcher
            .subsystems()
            .files
            .sockets()
            .socket(socket_id)
            .unwrap()
            .state(),
        SocketState::Closed
    );
    let epoll_wait =
        runtime.dispatch_syscall(context(Syscall::EpollWait, [4, 0x402200, 4, 0, 0, 0]));
    assert_eq!(epoll_wait.result, SyscallReturn::Errno(LinuxErrno::EBADF));
}

#[test]
fn runtime_wires_task_syscalls_through_dispatcher() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let result = runtime.dispatch_syscall(context(Syscall::Getpid, [0; 6]));

    assert_eq!(result.result, SyscallReturn::Success(1));
    assert_eq!(result.encoded_rax, 1);
    assert_eq!(
        runtime.kernel().process(INITIAL_GUEST_PID).unwrap().pid(),
        1
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
fn private_futex_wait_mismatch_returns_eagain() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0u32.to_le_bytes())
        .unwrap();

    let result = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            0x402000,
            u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
            1,
            0,
            0,
            0,
        ],
    ));

    assert_eq!(result.result, SyscallReturn::Errno(LinuxErrno::EAGAIN));
}

#[test]
fn private_futex_wait_unmapped_returns_efault() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let result = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            0x7000_0000,
            u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
            0,
            0,
            0,
            0,
        ],
    ));

    assert_eq!(result.result, SyscallReturn::Errno(LinuxErrno::EFAULT));
}

#[test]
fn private_futex_unaligned_uaddr_returns_einval() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let result = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            0x402001,
            u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
            0,
            0,
            0,
            0,
        ],
    ));

    assert_eq!(result.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
}

#[test]
fn process_shared_futex_wait_mismatch_and_wake_are_supported() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0u32.to_le_bytes())
        .unwrap();

    let wait = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [0x402000, u64::from(LINUX_FUTEX_WAIT), 1, 0, 0, 0],
    ));
    let wake = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [0x402000, u64::from(LINUX_FUTEX_WAKE), 1, 0, 0, 0],
    ));

    assert_eq!(wait.result, SyscallReturn::Errno(LinuxErrno::EAGAIN));
    assert_eq!(wake.result, SyscallReturn::Success(0));
}

#[test]
fn futex_wait_blocks_guest_task_and_wake_resumes_it() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &7u32.to_le_bytes())
        .unwrap();
    let flags = LINUX_CLONE_VM
        | LINUX_CLONE_FS
        | LINUX_CLONE_FILES
        | LINUX_CLONE_SIGHAND
        | LINUX_CLONE_THREAD
        | LINUX_CLONE_SYSVSEM;

    let clone = runtime.dispatch_syscall(context(Syscall::Clone, [flags, 0, 0, 0, 0, 0]));
    assert_eq!(clone.result, SyscallReturn::Success(2));

    let wait = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            0x402000,
            u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
            7,
            0,
            0,
            0,
        ],
    ));
    assert_eq!(wait.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::WaitingForFutex {
            key: FutexWaitKey::new(INITIAL_GUEST_PID, 0x402000, true)
        }
    );

    let wake = runtime.dispatch_syscall(context_for(
        INITIAL_GUEST_PID,
        2,
        Syscall::Futex,
        [
            0x402000,
            u64::from(LINUX_FUTEX_WAKE | LINUX_FUTEX_PRIVATE_FLAG),
            1,
            0,
            0,
            0,
        ],
    ));

    assert_eq!(wake.result, SyscallReturn::Success(1));
    assert_eq!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Runnable
    );
}

#[test]
fn futex_unknown_command_and_unsupported_flags_return_einval() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let unknown = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            0x402000,
            u64::from(99 | LINUX_FUTEX_PRIVATE_FLAG),
            0,
            0,
            0,
            0,
        ],
    ));
    let unsupported_flags = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            0x402000,
            u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG | 0x100),
            0,
            0,
            0,
            0,
        ],
    ));

    assert_eq!(unknown.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
    assert_eq!(
        unsupported_flags.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn private_futex_wake_returns_zero_without_waiter_registry() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let result = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            0x402000,
            u64::from(LINUX_FUTEX_WAKE | LINUX_FUTEX_PRIVATE_FLAG),
            1,
            0,
            0,
            0,
        ],
    ));

    assert_eq!(result.result, SyscallReturn::Success(0));
}

#[test]
fn private_futex_registry_null_timeout_wait_blocks_until_wake() {
    let mut registry = FutexRegistry::default();
    let waiter_registry = registry.clone();
    let waiter = std::thread::spawn(move || {
        let mut registry = waiter_registry;
        registry.wait(0x402000, 7, None, || false)
    });

    while registry.waiter_count(0x402000) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(registry.wake(0x402000, 1), 1);
    assert_eq!(waiter.join().unwrap(), Ok(0));
    assert_eq!(registry.waiter_count(0x402000), 0);
}

#[test]
fn clock_gettime_writes_linux_timespec_for_supported_clocks() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let realtime = runtime.dispatch_syscall(context(
        Syscall::ClockGettime,
        [LINUX_CLOCK_REALTIME, 0x402000, 0, 0, 0, 0],
    ));
    let monotonic = runtime.dispatch_syscall(context(
        Syscall::ClockGettime,
        [LINUX_CLOCK_MONOTONIC, 0x402020, 0, 0, 0, 0],
    ));

    assert_eq!(realtime.result, SyscallReturn::Success(0));
    assert_eq!(monotonic.result, SyscallReturn::Success(0));
    let realtime = timespec_from_memory(runtime.memory(), 0x402000);
    let monotonic = timespec_from_memory(runtime.memory(), 0x402020);
    assert!(realtime.tv_sec > 0);
    assert!((0..1_000_000_000).contains(&realtime.tv_nsec));
    assert!(monotonic.tv_sec >= 0);
    assert!((0..1_000_000_000).contains(&monotonic.tv_nsec));
}

#[test]
fn clock_gettime_rejects_invalid_clock_and_null_timespec() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let invalid_clock =
        runtime.dispatch_syscall(context(Syscall::ClockGettime, [99, 0x402000, 0, 0, 0, 0]));
    let null_timespec = runtime.dispatch_syscall(context(
        Syscall::ClockGettime,
        [LINUX_CLOCK_REALTIME, 0, 0, 0, 0, 0],
    ));

    assert_eq!(
        invalid_clock.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        null_timespec.result,
        SyscallReturn::Errno(LinuxErrno::EFAULT)
    );
}

#[test]
fn nanosleep_accepts_zero_duration_and_ignores_rem_on_success() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    write_timespec(runtime.memory_mut(), 0x402000, 0, 0);

    let result = runtime.dispatch_syscall(context(
        Syscall::Nanosleep,
        [0x402000, 0x7000_0000, 0, 0, 0, 0],
    ));

    assert_eq!(result.result, SyscallReturn::Success(0));
}

#[test]
fn nanosleep_rejects_null_and_invalid_timespecs() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    write_timespec(runtime.memory_mut(), 0x402000, 0, 1_000_000_000);
    write_timespec(runtime.memory_mut(), 0x402020, -1, 0);

    let null_req = runtime.dispatch_syscall(context(Syscall::Nanosleep, [0, 0, 0, 0, 0, 0]));
    let invalid_nsec =
        runtime.dispatch_syscall(context(Syscall::Nanosleep, [0x402000, 0, 0, 0, 0, 0]));
    let negative_sec =
        runtime.dispatch_syscall(context(Syscall::Nanosleep, [0x402020, 0, 0, 0, 0, 0]));

    assert_eq!(null_req.result, SyscallReturn::Errno(LinuxErrno::EFAULT));
    assert_eq!(
        invalid_nsec.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        negative_sec.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn getrandom_fills_guest_buffer_and_accepts_linux_flags() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime.memory_mut().write(0x402000, &[0xaa; 32]).unwrap();

    let result = runtime.dispatch_syscall(context(
        Syscall::Getrandom,
        [
            0x402000,
            32,
            LINUX_GRND_NONBLOCK | LINUX_GRND_RANDOM,
            0,
            0,
            0,
        ],
    ));

    let mut bytes = [0; 32];
    runtime.memory().read(0x402000, &mut bytes).unwrap();
    assert_eq!(result.result, SyscallReturn::Success(32));
    assert_ne!(bytes, [0xaa; 32]);
}

#[test]
fn getrandom_accepts_empty_buffer_without_touching_pointer() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let result = runtime.dispatch_syscall(context(Syscall::Getrandom, [0, 0, 0, 0, 0, 0]));

    assert_eq!(result.result, SyscallReturn::Success(0));
}

#[test]
fn getrandom_rejects_unknown_flags_and_null_non_empty_buffer() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let invalid_flags =
        runtime.dispatch_syscall(context(Syscall::Getrandom, [0x402000, 8, 0x4, 0, 0, 0]));
    let null_buffer = runtime.dispatch_syscall(context(Syscall::Getrandom, [0, 8, 0, 0, 0, 0]));

    assert_eq!(
        invalid_flags.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(null_buffer.result, SyscallReturn::Errno(LinuxErrno::EFAULT));
}

#[test]
fn runtime_memory_syscalls_update_memory_used_by_futex() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let mmap = runtime.dispatch_syscall(context(
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
    let SyscallReturn::Success(addr) = mmap.result else {
        panic!("mmap should succeed: {:?}", mmap.result);
    };
    runtime
        .memory_mut()
        .write(addr, &9u32.to_le_bytes())
        .unwrap();
    runtime.memory_mut().write(0x402000, &[0; 16]).unwrap();

    let wait = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            addr,
            u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
            9,
            0x402000,
            0,
            0,
        ],
    ));

    assert_eq!(wait.result, SyscallReturn::Errno(LinuxErrno::ETIMEDOUT));
}

#[test]
fn private_futex_wait_timeout_pointer_is_validated_and_controls_timeout() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &1u32.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402100, &0i64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402108, &1_000_000_000i64.to_le_bytes())
        .unwrap();

    let invalid = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            0x402000,
            u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
            1,
            0x402100,
            0,
            0,
        ],
    ));
    runtime
        .memory_mut()
        .write(0x402108, &0i64.to_le_bytes())
        .unwrap();
    let timed_out = runtime.dispatch_syscall(context(
        Syscall::Futex,
        [
            0x402000,
            u64::from(LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG),
            1,
            0x402100,
            0,
            0,
        ],
    ));

    assert_eq!(invalid.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
    assert_eq!(
        timed_out.result,
        SyscallReturn::Errno(LinuxErrno::ETIMEDOUT)
    );
}

#[test]
fn private_futex_registry_wake_releases_registered_waiter() {
    let mut registry = FutexRegistry::default();
    let waiter_registry = registry.clone();
    let waiter = std::thread::spawn(move || {
        let mut registry = waiter_registry;
        registry.wait(0x402000, 3, Some(Duration::from_secs(5)), || false)
    });

    while registry.waiter_count(0x402000) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(registry.wake(0x402000, 1), 1);
    assert_eq!(waiter.join().unwrap(), Ok(0));
    assert_eq!(registry.waiter_count(0x402000), 0);
}

#[test]
fn runtime_dispatch_routes_socket_control_syscalls_through_vfs() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let socket = runtime.dispatch_syscall(context(
        Syscall::Socket,
        [
            u64::from(LINUX_AF_INET),
            u64::from(LINUX_SOCK_STREAM | LINUX_SOCK_CLOEXEC | LINUX_SOCK_NONBLOCK),
            u64::from(LINUX_IPPROTO_TCP),
            0,
            0,
            0,
        ],
    ));
    assert_eq!(socket.result, SyscallReturn::Success(3));

    let fcntl_fd =
        runtime.dispatch_syscall(context(Syscall::Fcntl, [3, u64::from(F_GETFD), 0, 0, 0, 0]));
    assert_eq!(
        fcntl_fd.result,
        SyscallReturn::Success(u64::from(mcr_vfs::FD_CLOEXEC))
    );

    let fcntl_fl =
        runtime.dispatch_syscall(context(Syscall::Fcntl, [3, u64::from(F_GETFL), 0, 0, 0, 0]));
    assert_eq!(
        fcntl_fl.result,
        SyscallReturn::Success(u64::from(O_RDWR | O_NONBLOCK))
    );

    let fstat = runtime.dispatch_syscall(context(Syscall::Fstat, [3, 0x402000, 0, 0, 0, 0]));
    assert_eq!(fstat.result, SyscallReturn::Success(0));
    let mut mode = [0; 4];
    runtime.memory().read(0x402000 + 24, &mut mode).unwrap();
    assert_eq!(
        u32::from_le_bytes(mode) & mcr_vfs::S_IFMT,
        mcr_vfs::S_IFSOCK
    );
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
fn runtime_dispatch_routes_socket_address_and_option_controls() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );

    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(8080))
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Bind,
                [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Listen, [3, 16, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Accept4, [3, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EAGAIN)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Accept, [3, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EAGAIN)
    );

    runtime
        .memory_mut()
        .write(0x402100, &(SOCKADDR_IN_LEN as u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Getsockname,
                [3, 0x402200, 0x402100, 0, 0, 0],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    let mut len = [0; 4];
    runtime.memory().read(0x402100, &mut len).unwrap();
    assert_eq!(u32::from_le_bytes(len), SOCKADDR_IN_LEN as u32);

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ]
            ))
            .result,
        SyscallReturn::Success(4)
    );
    runtime
        .memory_mut()
        .write(0x402300, &ipv4_sockaddr(443))
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [4, 0x402300, SOCKADDR_IN_LEN as u64, 0, 0, 0],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    runtime
        .memory_mut()
        .write(0x402400, &(SOCKADDR_IN_LEN as u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Getpeername,
                [4, 0x402500, 0x402400, 0, 0, 0],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Shutdown,
                [4, u64::from(LINUX_SHUT_RDWR), 0, 0, 0, 0],
            ))
            .result,
        SyscallReturn::Success(0)
    );

    runtime
        .memory_mut()
        .write(0x402600, &1u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Setsockopt,
                [
                    4,
                    u64::from(LINUX_SOL_SOCKET),
                    u64::from(LINUX_SO_REUSEADDR),
                    0x402600,
                    4,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    runtime
        .memory_mut()
        .write(0x402800, &4u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Getsockopt,
                [
                    4,
                    u64::from(LINUX_SOL_SOCKET),
                    u64::from(LINUX_SO_REUSEADDR),
                    0x402700,
                    0x402800,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    let mut opt = [0; 4];
    runtime.memory().read(0x402700, &mut opt).unwrap();
    assert_eq!(u32::from_le_bytes(opt), 1);
}

#[test]
fn poll_reports_regular_file_readiness_and_invalid_fds() {
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
    write_pollfd(
        runtime.memory_mut(),
        0x402100,
        3,
        LINUX_POLLIN | LINUX_POLLOUT,
    );
    write_pollfd(runtime.memory_mut(), 0x402108, 99, LINUX_POLLIN);

    let result = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 2, 0, 0, 0, 0]));

    assert_eq!(result.result, SyscallReturn::Success(2));
    assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLIN);
    assert_eq!(pollfd_revents(runtime.memory(), 0x402108), LINUX_POLLNVAL);

    write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLIN);
    let infinite_timeout =
        runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, u64::MAX, 0, 0, 0]));
    assert_eq!(infinite_timeout.result, SyscallReturn::Success(1));
    assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLIN);
}

#[test]
fn poll_reports_pipe_buffer_state_and_hangup() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    let read_fd = i32_from_memory(runtime.memory(), 0x402000);
    let write_fd = i32_from_memory(runtime.memory(), 0x402004);
    write_pollfd(runtime.memory_mut(), 0x402100, read_fd, LINUX_POLLIN);

    let empty = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
    assert_eq!(empty.result, SyscallReturn::Success(0));
    assert_eq!(pollfd_revents(runtime.memory(), 0x402100), 0);

    runtime.memory_mut().write(0x402200, b"x").unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Write,
                [write_fd as u64, 0x402200, 1, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(1)
    );
    write_pollfd(runtime.memory_mut(), 0x402100, read_fd, LINUX_POLLIN);
    let readable = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
    assert_eq!(readable.result, SyscallReturn::Success(1));
    assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLIN);

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Read,
                [read_fd as u64, 0x402300, 1, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(1)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Close, [write_fd as u64, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    write_pollfd(runtime.memory_mut(), 0x402100, read_fd, LINUX_POLLIN);
    let hangup = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
    assert_eq!(hangup.result, SyscallReturn::Success(1));
    assert_eq!(
        pollfd_revents(runtime.memory(), 0x402100),
        LINUX_POLLIN | LINUX_POLLHUP
    );
}

#[test]
fn poll_reports_socket_transport_readiness() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"pong");
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(8080))
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    write_pollfd(
        runtime.memory_mut(),
        0x402100,
        3,
        LINUX_POLLIN | LINUX_POLLOUT,
    );

    let result = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));

    assert_eq!(result.result, SyscallReturn::Success(1));
    assert_eq!(
        pollfd_revents(runtime.memory(), 0x402100),
        LINUX_POLLIN | LINUX_POLLOUT
    );
}

#[test]
fn poll_reports_socket_normal_band_aliases() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"pong");
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(8080))
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    write_pollfd(
        runtime.memory_mut(),
        0x402100,
        3,
        LINUX_POLLRDNORM | LINUX_POLLOUT | LINUX_POLLWRNORM | LINUX_POLLPRI,
    );

    let result = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));

    assert_eq!(result.result, SyscallReturn::Success(1));
    assert_eq!(
        pollfd_revents(runtime.memory(), 0x402100),
        LINUX_POLLRDNORM | LINUX_POLLOUT | LINUX_POLLWRNORM
    );
}

#[test]
fn select_reports_regular_file_readiness_and_clears_unready_sets() {
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
    write_select_fdset(runtime.memory_mut(), 0x402100, 4, &[3]);
    write_select_fdset(runtime.memory_mut(), 0x402180, 4, &[3]);
    write_timeval(runtime.memory_mut(), 0x402200, 0, 0);

    let result = runtime.dispatch_syscall(context(
        Syscall::Select,
        [4, 0x402100, 0x402180, 0, 0x402200, 0],
    ));

    assert_eq!(result.result, SyscallReturn::Success(1));
    assert!(select_fdset_contains(runtime.memory(), 0x402100, 3));
    assert!(!select_fdset_contains(runtime.memory(), 0x402180, 3));
}

#[test]
fn select_reports_socket_readiness_and_bad_fds() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"pong");
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(8080))
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );

    write_select_fdset(runtime.memory_mut(), 0x402100, 4, &[3]);
    write_select_fdset(runtime.memory_mut(), 0x402180, 4, &[3]);
    write_timeval(runtime.memory_mut(), 0x402200, 0, 0);
    let ready = runtime.dispatch_syscall(context(
        Syscall::Select,
        [4, 0x402100, 0x402180, 0, 0x402200, 0],
    ));
    assert_eq!(ready.result, SyscallReturn::Success(1));
    assert!(select_fdset_contains(runtime.memory(), 0x402100, 3));
    assert!(select_fdset_contains(runtime.memory(), 0x402180, 3));

    write_select_fdset(runtime.memory_mut(), 0x402300, 100, &[99]);
    write_timeval(runtime.memory_mut(), 0x402380, 0, 0);
    let bad_fd =
        runtime.dispatch_syscall(context(Syscall::Select, [100, 0x402300, 0, 0, 0x402380, 0]));
    assert_eq!(bad_fd.result, SyscallReturn::Errno(LinuxErrno::EBADF));
}

#[test]
fn runtime_nonblocking_connect_completes_after_poll_writable() {
    let transport = runtime_socket_transport();
    transport.set_connect_would_block_once();
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(8080))
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402300, &4u32.to_le_bytes())
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM | LINUX_SOCK_NONBLOCK),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINPROGRESS)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Getsockopt,
                [
                    3,
                    u64::from(LINUX_SOL_SOCKET),
                    u64::from(LINUX_SO_ERROR),
                    0x402200,
                    0x402300,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(u32_from_guest(runtime.memory(), 0x402200), 0);

    write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLOUT);
    let ready = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
    assert_eq!(ready.result, SyscallReturn::Success(1));
    assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLOUT);

    runtime
        .memory_mut()
        .write(0x402300, &4u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Getsockopt,
                [
                    3,
                    u64::from(LINUX_SOL_SOCKET),
                    u64::from(LINUX_SO_ERROR),
                    0x402200,
                    0x402300,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(u32_from_guest(runtime.memory(), 0x402200), 0);
}

#[test]
fn runtime_getsockname_completes_nonblocking_connect() {
    let transport = runtime_socket_transport();
    transport.set_connect_would_block_once();
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(8080))
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402300, &(SOCKADDR_IN_LEN as u32).to_le_bytes())
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM | LINUX_SOCK_NONBLOCK),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINPROGRESS)
    );

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Getsockname,
                [3, 0x402200, 0x402300, 0, 0, 0],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    let mut address = [0; SOCKADDR_IN_LEN];
    runtime.memory().read(0x402200, &mut address).unwrap();
    assert_eq!(address, ipv4_sockaddr_for([0, 0, 0, 0], 0)[..]);
    assert_eq!(
        u32_from_guest(runtime.memory(), 0x402300),
        SOCKADDR_IN_LEN as u32
    );
}

#[test]
fn ppoll_reads_timespec_and_rejects_signal_masks() {
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
    write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLIN);
    write_timespec(runtime.memory_mut(), 0x402200, 0, 0);

    let ready = runtime.dispatch_syscall(context(Syscall::Ppoll, [0x402100, 1, 0x402200, 0, 0, 0]));
    assert_eq!(ready.result, SyscallReturn::Success(1));
    assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLIN);

    write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLIN);
    write_timespec(runtime.memory_mut(), 0x402200, 0, 1_000_000_000);
    let invalid_timespec =
        runtime.dispatch_syscall(context(Syscall::Ppoll, [0x402100, 1, 0x402200, 0, 0, 0]));
    assert_eq!(
        invalid_timespec.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    let sigmask =
        runtime.dispatch_syscall(context(Syscall::Ppoll, [0x402100, 1, 0x402200, 1, 8, 0]));
    assert_eq!(sigmask.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
}

#[test]
fn epoll_create1_allocates_cloexec_event_fd() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let epfd = runtime.dispatch_syscall(context(
        Syscall::EpollCreate1,
        [u64::from(LINUX_EPOLL_CLOEXEC), 0, 0, 0, 0, 0],
    ));
    assert_eq!(epfd.result, SyscallReturn::Success(3));
    assert!(runtime.vfs().fds().cloexec(3).unwrap());

    let invalid =
        runtime.dispatch_syscall(context(Syscall::EpollCreate1, [0x8000_0000, 0, 0, 0, 0, 0]));
    assert_eq!(invalid.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
}

#[test]
fn eventfd2_allocates_counter_fd_for_event_wakeups() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let eventfd = runtime.dispatch_syscall(context(
        Syscall::Eventfd2,
        [
            0,
            u64::from(LINUX_EFD_CLOEXEC | LINUX_EFD_NONBLOCK),
            0,
            0,
            0,
            0,
        ],
    ));
    assert_eq!(eventfd.result, SyscallReturn::Success(3));
    assert!(runtime.vfs().fds().cloexec(3).unwrap());

    write_pollfd(
        runtime.memory_mut(),
        0x402100,
        3,
        LINUX_POLLIN | LINUX_POLLOUT,
    );
    let empty = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
    assert_eq!(empty.result, SyscallReturn::Success(1));
    assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLOUT);

    let empty_read = runtime.dispatch_syscall(context(Syscall::Read, [3, 0x402200, 8, 0, 0, 0]));
    assert_eq!(empty_read.result, SyscallReturn::Errno(LinuxErrno::EAGAIN));

    runtime
        .memory_mut()
        .write(0x402300, &9u64.to_le_bytes())
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Write, [3, 0x402300, 8, 0, 0, 0]))
            .result,
        SyscallReturn::Success(8)
    );
    write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLIN);
    let ready = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 1, 0, 0, 0, 0]));
    assert_eq!(ready.result, SyscallReturn::Success(1));
    assert_eq!(pollfd_revents(runtime.memory(), 0x402100), LINUX_POLLIN);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Read, [3, 0x402200, 8, 0, 0, 0]))
            .result,
        SyscallReturn::Success(8)
    );
    assert_eq!(u64_from_guest(runtime.memory(), 0x402200), 9);

    let invalid =
        runtime.dispatch_syscall(context(Syscall::Eventfd2, [0, 0x8000_0000, 0, 0, 0, 0]));
    assert_eq!(invalid.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[test]
fn native_blocking_fd_wait_ignores_nonblocking_descriptors() {
    let mut vfs = sample_vfs();
    let blocking = vfs.eventfd(0, OpenFlags::new(0)).unwrap();
    let nonblocking = vfs.eventfd(0, OpenFlags::new(mcr_vfs::O_NONBLOCK)).unwrap();

    assert_eq!(
        blocking_fd_wait(vfs.fds(), Syscall::Read.number().raw(), blocking as u64),
        Some((blocking, false))
    );
    assert_eq!(
        blocking_fd_wait(vfs.fds(), Syscall::Read.number().raw(), nonblocking as u64),
        None
    );
}

#[test]
fn epoll_wait_reports_pipe_readiness_level_triggered() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    let read_fd = i32_from_memory(runtime.memory(), 0x402000);
    let write_fd = i32_from_memory(runtime.memory(), 0x402004);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(5)
    );
    write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 0xfeed);
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [
                    5,
                    u64::from(LINUX_EPOLL_CTL_ADD),
                    read_fd as u64,
                    0x402100,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    let empty = runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
    assert_eq!(empty.result, SyscallReturn::Success(0));

    runtime.memory_mut().write(0x402300, b"x").unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Write,
                [write_fd as u64, 0x402300, 1, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(1)
    );

    let ready = runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
    assert_eq!(ready.result, SyscallReturn::Success(1));
    assert_eq!(
        epoll_event_from_memory(runtime.memory(), 0x402200),
        (LINUX_EPOLLIN, 0xfeed)
    );

    let still_ready =
        runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
    assert_eq!(still_ready.result, SyscallReturn::Success(1));
}

#[test]
fn epoll_ctl_mod_and_del_update_watch_set() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    let read_fd = i32_from_memory(runtime.memory(), 0x402000);
    let write_fd = i32_from_memory(runtime.memory(), 0x402004);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(5)
    );
    write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 1);
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [
                    5,
                    u64::from(LINUX_EPOLL_CTL_ADD),
                    read_fd as u64,
                    0x402100,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    write_epoll_event_for_test(runtime.memory_mut(), 0x402110, LINUX_EPOLLOUT, 2);
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [
                    5,
                    u64::from(LINUX_EPOLL_CTL_MOD),
                    write_fd as u64,
                    0x402110,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Errno(LinuxErrno::ENOENT)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [
                    5,
                    u64::from(LINUX_EPOLL_CTL_MOD),
                    read_fd as u64,
                    0x402110,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );

    let not_ready =
        runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
    assert_eq!(not_ready.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [5, u64::from(LINUX_EPOLL_CTL_DEL), read_fd as u64, 0, 0, 0,],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [5, u64::from(LINUX_EPOLL_CTL_DEL), read_fd as u64, 0, 0, 0,],
            ))
            .result,
        SyscallReturn::Errno(LinuxErrno::ENOENT)
    );
}

#[test]
fn epoll_ctl_rejects_unsupported_event_flags() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    let read_fd = i32_from_memory(runtime.memory(), 0x402000);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(5)
    );

    for unsupported in [
        LINUX_EPOLLET,
        LINUX_EPOLLONESHOT,
        LINUX_EPOLLEXCLUSIVE,
        0x0000_2000,
    ] {
        write_epoll_event_for_test(
            runtime.memory_mut(),
            0x402100,
            LINUX_EPOLLIN | unsupported,
            1,
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::EpollCtl,
                    [
                        5,
                        u64::from(LINUX_EPOLL_CTL_ADD),
                        read_fd as u64,
                        0x402100,
                        0,
                        0,
                    ],
                ))
                .result,
            SyscallReturn::Errno(LinuxErrno::EINVAL)
        );
    }

    write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 1);
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [
                    5,
                    u64::from(LINUX_EPOLL_CTL_ADD),
                    read_fd as u64,
                    0x402100,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    write_epoll_event_for_test(
        runtime.memory_mut(),
        0x402110,
        LINUX_EPOLLIN | LINUX_EPOLLET,
        2,
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [
                    5,
                    u64::from(LINUX_EPOLL_CTL_MOD),
                    read_fd as u64,
                    0x402110,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn sigaltstack_reports_disabled_stack_and_persists_enabled_stack() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    write_stack_t(runtime.memory_mut(), 0x402000, 0x7000_0000, 0, 8192);

    let set = runtime.dispatch_syscall(context(
        Syscall::Sigaltstack,
        [0x402000, 0x402020, 0, 0, 0, 0],
    ));
    assert_eq!(set.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402020), 0);
    assert_eq!(
        u32_from_guest(runtime.memory(), 0x402020 + LINUX_STACK_T_FLAGS_OFFSET),
        LINUX_SS_DISABLE
    );
    assert_eq!(
        u64_from_guest(runtime.memory(), 0x402020 + LINUX_STACK_T_SIZE_OFFSET),
        0
    );

    let query = runtime.dispatch_syscall(context(Syscall::Sigaltstack, [0, 0x402040, 0, 0, 0, 0]));
    assert_eq!(query.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402040), 0x7000_0000);
    assert_eq!(
        u32_from_guest(runtime.memory(), 0x402040 + LINUX_STACK_T_FLAGS_OFFSET),
        0
    );
    assert_eq!(
        u64_from_guest(runtime.memory(), 0x402040 + LINUX_STACK_T_SIZE_OFFSET),
        8192
    );
}

#[test]
fn sigaltstack_rejects_bad_flags_and_too_small_enabled_stack() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    write_stack_t(runtime.memory_mut(), 0x402000, 0x7000_0000, 4, 8192);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Sigaltstack, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    write_stack_t(runtime.memory_mut(), 0x402000, 0x7000_0000, 0, 1024);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Sigaltstack, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::ENOMEM)
    );
}

#[test]
fn epoll_wait_reports_closed_watch_as_hup_error() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    let read_fd = i32_from_memory(runtime.memory(), 0x402000);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(5)
    );
    write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 9);
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [
                    5,
                    u64::from(LINUX_EPOLL_CTL_ADD),
                    read_fd as u64,
                    0x402100,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Close, [read_fd as u64, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );

    let ready = runtime.dispatch_syscall(context(Syscall::EpollWait, [5, 0x402200, 4, 0, 0, 0]));
    assert_eq!(ready.result, SyscallReturn::Success(1));
    assert_eq!(
        epoll_event_from_memory(runtime.memory(), 0x402200),
        (LINUX_EPOLLERR | LINUX_EPOLLHUP, 9)
    );
}

#[test]
fn epoll_wait_reports_socket_transport_readiness() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"pong");
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(8080))
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(4)
    );
    write_epoll_event_for_test(
        runtime.memory_mut(),
        0x402100,
        LINUX_EPOLLIN | LINUX_EPOLLOUT,
        0x51,
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [4, u64::from(LINUX_EPOLL_CTL_ADD), 3, 0x402100, 0, 0,],
            ))
            .result,
        SyscallReturn::Success(0)
    );

    let ready = runtime.dispatch_syscall(context(Syscall::EpollWait, [4, 0x402200, 4, 0, 0, 0]));

    assert_eq!(ready.result, SyscallReturn::Success(1));
    assert_eq!(
        epoll_event_from_memory(runtime.memory(), 0x402200),
        (LINUX_EPOLLIN | LINUX_EPOLLOUT, 0x51)
    );
}

#[test]
fn epoll_pwait2_reuses_epoll_wait_without_sigmask() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    let read_fd = i32_from_memory(runtime.memory(), 0x402000);
    let write_fd = i32_from_memory(runtime.memory(), 0x402004);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(5)
    );
    write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 0x71);
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [
                    5,
                    u64::from(LINUX_EPOLL_CTL_ADD),
                    read_fd as u64,
                    0x402100,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(0)
    );
    write_timespec(runtime.memory_mut(), 0x402300, 0, 0);
    let empty = runtime.dispatch_syscall(context(
        Syscall::EpollPwait2,
        [5, 0x402200, 4, 0x402300, 0, 0],
    ));
    assert_eq!(empty.result, SyscallReturn::Success(0));

    runtime.memory_mut().write(0x402400, b"x").unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Write,
                [write_fd as u64, 0x402400, 1, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(1)
    );
    let ready = runtime.dispatch_syscall(context(
        Syscall::EpollPwait2,
        [5, 0x402200, 4, 0x402300, 0, 0],
    ));
    assert_eq!(ready.result, SyscallReturn::Success(1));
    assert_eq!(
        epoll_event_from_memory(runtime.memory(), 0x402200),
        (LINUX_EPOLLIN, 0x71)
    );

    let sigmask = runtime.dispatch_syscall(context(
        Syscall::EpollPwait2,
        [5, 0x402200, 4, 0x402300, 0x402500, 8],
    ));
    assert_eq!(sigmask.result, SyscallReturn::Errno(LinuxErrno::EINVAL));
}

#[test]
fn epoll_wait_passes_timeout_to_socket_transport_after_readiness_probe() {
    let transport = runtime_socket_transport();
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(8080))
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(4)
    );
    write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 0x52);
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [4, u64::from(LINUX_EPOLL_CTL_ADD), 3, 0x402100, 0, 0,],
            ))
            .result,
        SyscallReturn::Success(0)
    );

    let ready = runtime.dispatch_syscall(context(Syscall::EpollWait, [4, 0x402200, 4, 25, 0, 0]));

    assert_eq!(ready.result, SyscallReturn::Success(0));
    assert_eq!(
        transport.poll_timeouts(),
        vec![Some(Duration::ZERO), Some(Duration::from_millis(25))]
    );
}

#[test]
fn connected_socket_sendto_and_recvfrom_move_guest_buffers() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"pong");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));
    runtime.memory_mut().write(0x2000, b"ping");

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Sendto,
            [3, 0x2000, 4, u64::from(LINUX_MSG_NOSIGNAL), 0, 0],
        ),
        SyscallReturn::Success(4)
    );
    assert_eq!(transport.sent_bytes(), b"ping");

    assert_eq!(
        dispatch_network(&mut runtime, Syscall::Recvfrom, [3, 0x2100, 8, 0, 0, 0],),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.memory().read(0x2100, 4), b"pong");
}

#[test]
fn connected_socket_read_and_write_use_stream_io() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"pong");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));
    runtime.memory_mut().write(0x2000, b"ping");

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Write, [3, 0x2000, 4, 0, 0, 0]),
        SyscallReturn::Success(4)
    );
    assert_eq!(transport.sent_bytes(), b"ping");

    assert_eq!(
        dispatch(&mut runtime, Syscall::Read, [3, 0x2100, 8, 0, 0, 0]),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.memory().read(0x2100, 4), b"pong");
}

#[test]
fn connected_socket_readv_and_writev_use_stream_io() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"abcdef");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));
    runtime.memory_mut().write(0x2000, b"ab");
    runtime.memory_mut().write(0x2010, b"cd");
    runtime.memory_mut().write_iovec(0x3000, 0x2000, 2);
    runtime.memory_mut().write_iovec(0x3010, 0x2010, 2);
    runtime.memory_mut().write_iovec(0x5000, 0x6000, 3);
    runtime.memory_mut().write_iovec(0x5010, 0x6010, 3);

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch(&mut runtime, Syscall::Writev, [3, 0x3000, 2, 0, 0, 0]),
        SyscallReturn::Success(4)
    );
    assert_eq!(transport.sent_bytes(), b"abcd");
    assert_eq!(transport.sent_calls(), vec![b"abcd".to_vec()]);

    assert_eq!(
        dispatch(&mut runtime, Syscall::Readv, [3, 0x5000, 2, 0, 0, 0]),
        SyscallReturn::Success(6)
    );
    assert_eq!(runtime.memory().read(0x6000, 3), b"abc");
    assert_eq!(runtime.memory().read(0x6010, 3), b"def");
    assert_eq!(transport.recv_calls(), 1);
}

#[test]
fn connected_socket_sendmsg_and_recvmsg_move_iovecs() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"abcdef");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));
    runtime.memory_mut().write(0x2000, b"ab");
    runtime.memory_mut().write(0x2010, b"cd");
    runtime.memory_mut().write_iovec(0x3000, 0x2000, 2);
    runtime.memory_mut().write_iovec(0x3010, 0x2010, 2);
    runtime.memory_mut().write_msghdr(0x4000, 0, 0, 0x3000, 2);
    runtime.memory_mut().write_iovec(0x5000, 0x6000, 3);
    runtime.memory_mut().write_iovec(0x5010, 0x6010, 3);
    runtime.memory_mut().write_msghdr(0x5100, 0, 0, 0x5000, 2);

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );

    assert_eq!(
        dispatch_network(&mut runtime, Syscall::Sendmsg, [3, 0x4000, 0, 0, 0, 0],),
        SyscallReturn::Success(4)
    );
    assert_eq!(transport.sent_bytes(), b"abcd");
    assert_eq!(transport.sent_calls(), vec![b"abcd".to_vec()]);
    assert_eq!(
        dispatch_network(&mut runtime, Syscall::Recvmsg, [3, 0x5100, 0, 0, 0, 0],),
        SyscallReturn::Success(6)
    );
    assert_eq!(runtime.memory().read(0x6000, 3), b"abc");
    assert_eq!(runtime.memory().read(0x6010, 3), b"def");
    assert_eq!(transport.recv_calls(), 1);
    assert_eq!(u32_at(runtime.memory(), 0x5100 + 48), 0);
}

#[test]
fn recvmsg_accepts_cmsg_cloexec_without_control_messages() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"pong");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));
    runtime.memory_mut().write_iovec(0x3000, 0x4000, 4);
    runtime.memory_mut().write_msghdr(0x5000, 0, 0, 0x3000, 1);

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Recvmsg,
            [3, 0x5000, u64::from(LINUX_MSG_CMSG_CLOEXEC), 0, 0, 0],
        ),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.memory().read(0x4000, 4), b"pong");
}

#[test]
fn connected_stream_recvmsg_ignores_name_buffer() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"pong");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(8080));
    runtime.memory_mut().write_iovec(0x3000, 0x4000, 4);
    runtime.memory_mut().write(0x5000, &[0xaa; SOCKADDR_IN_LEN]);
    runtime
        .memory_mut()
        .write_msghdr(0x5100, 0x5000, SOCKADDR_IN_LEN as u32, 0x3000, 1);

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );

    assert_eq!(
        dispatch_network(&mut runtime, Syscall::Recvmsg, [3, 0x5100, 0, 0, 0, 0],),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.memory().read(0x4000, 4), b"pong");
    assert_eq!(
        runtime.memory().read(0x5000, SOCKADDR_IN_LEN),
        [0xaa; SOCKADDR_IN_LEN]
    );
    assert_eq!(u32_at(runtime.memory(), 0x5100 + 8), 0);
    assert_eq!(u32_at(runtime.memory(), 0x5100 + 48), 0);
}

#[test]
fn datagram_sendto_and_recvfrom_move_guest_buffers_and_addresses() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"dns!");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(53));
    runtime.memory_mut().write(0x2000, b"query");
    runtime.memory_mut().write(0x2200, &[0xaa; SOCKADDR_IN_LEN]);
    runtime
        .memory_mut()
        .write(0x2300, &(SOCKADDR_IN_LEN as u32).to_le_bytes());

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_DGRAM),
                u64::from(mcr_sys::LINUX_IPPROTO_UDP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Sendto,
            [
                3,
                0x2000,
                5,
                u64::from(LINUX_MSG_DONTWAIT | LINUX_MSG_NOSIGNAL),
                0x1000,
                SOCKADDR_IN_LEN as u64,
            ],
        ),
        SyscallReturn::Success(5)
    );
    assert_eq!(transport.sent_bytes(), b"query");

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Recvfrom,
            [3, 0x2100, 8, u64::from(LINUX_MSG_DONTWAIT), 0x2200, 0x2300],
        ),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.memory().read(0x2100, 4), b"dns!");
    assert_eq!(u32_at(runtime.memory(), 0x2300), SOCKADDR_IN_LEN as u32);
    assert_eq!(
        runtime.memory().read(0x2200, SOCKADDR_IN_LEN),
        ipv4_sockaddr(53)
    );
}

#[test]
fn connected_datagram_sendto_and_recvfrom_use_connected_peer() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"dns!");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(53));
    runtime.memory_mut().write(0x2000, b"query");

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_DGRAM),
                u64::from(mcr_sys::LINUX_IPPROTO_UDP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Sendto,
            [3, 0x2000, 5, u64::from(LINUX_MSG_NOSIGNAL), 0, 0],
        ),
        SyscallReturn::Success(5)
    );
    assert_eq!(transport.sent_bytes(), b"query");

    assert_eq!(
        dispatch_network(&mut runtime, Syscall::Recvfrom, [3, 0x2100, 8, 0, 0, 0],),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.memory().read(0x2100, 4), b"dns!");
}

#[test]
fn runtime_dispatch_routes_datagram_socket_io_through_transport() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"dns!");
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_DGRAM),
                    u64::from(mcr_sys::LINUX_IPPROTO_UDP),
                    0,
                    0,
                    0,
                ],
            ))
            .result,
        SyscallReturn::Success(3)
    );

    runtime
        .memory_mut()
        .write(0x402000, &ipv4_sockaddr(53))
        .unwrap();
    runtime.memory_mut().write(0x402100, b"query").unwrap();
    runtime
        .memory_mut()
        .write(0x402200, &[0xaa; SOCKADDR_IN_LEN])
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402300, &(SOCKADDR_IN_LEN as u32).to_le_bytes())
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Sendto,
                [
                    3,
                    0x402100,
                    5,
                    u64::from(LINUX_MSG_DONTWAIT | LINUX_MSG_NOSIGNAL),
                    0x402000,
                    SOCKADDR_IN_LEN as u64,
                ],
            ))
            .result,
        SyscallReturn::Success(5)
    );
    assert_eq!(transport.sent_bytes(), b"query");

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Recvfrom,
                [
                    3,
                    0x402180,
                    8,
                    u64::from(LINUX_MSG_DONTWAIT),
                    0x402200,
                    0x402300,
                ],
            ))
            .result,
        SyscallReturn::Success(4)
    );
    let mut received = [0; 4];
    runtime.memory().read(0x402180, &mut received).unwrap();
    assert_eq!(&received, b"dns!");

    let mut name_len = [0; 4];
    runtime.memory().read(0x402300, &mut name_len).unwrap();
    assert_eq!(u32::from_le_bytes(name_len), SOCKADDR_IN_LEN as u32);

    let mut peer_name = [0; SOCKADDR_IN_LEN];
    runtime.memory().read(0x402200, &mut peer_name).unwrap();
    assert_eq!(peer_name, ipv4_sockaddr(53)[..]);
}

#[test]
fn datagram_sendmsg_and_recvmsg_move_iovecs_and_addresses() {
    let transport = runtime_socket_transport();
    transport.push_incoming(b"dns!");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(53));
    runtime.memory_mut().write(0x2000, b"dn");
    runtime.memory_mut().write(0x2010, b"s?");
    runtime.memory_mut().write_iovec(0x3000, 0x2000, 2);
    runtime.memory_mut().write_iovec(0x3010, 0x2010, 2);
    runtime
        .memory_mut()
        .write_msghdr(0x4000, 0x1000, SOCKADDR_IN_LEN as u32, 0x3000, 2);
    runtime.memory_mut().write_iovec(0x5000, 0x6000, 2);
    runtime.memory_mut().write_iovec(0x5010, 0x6010, 2);
    runtime.memory_mut().write(0x5200, &[0xaa; SOCKADDR_IN_LEN]);
    runtime
        .memory_mut()
        .write_msghdr(0x5100, 0x5200, SOCKADDR_IN_LEN as u32, 0x5000, 2);

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_DGRAM),
                u64::from(mcr_sys::LINUX_IPPROTO_UDP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Sendmsg,
            [3, 0x4000, u64::from(LINUX_MSG_DONTWAIT), 0, 0, 0],
        ),
        SyscallReturn::Success(4)
    );
    assert_eq!(transport.sent_bytes(), b"dns?");
    assert_eq!(transport.sent_calls(), vec![b"dns?".to_vec()]);

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Recvmsg,
            [3, 0x5100, u64::from(LINUX_MSG_DONTWAIT), 0, 0, 0],
        ),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.memory().read(0x6000, 2), b"dn");
    assert_eq!(runtime.memory().read(0x6010, 2), b"s!");
    assert_eq!(
        runtime.memory().read(0x5200, SOCKADDR_IN_LEN),
        ipv4_sockaddr(53)
    );
    assert_eq!(u32_at(runtime.memory(), 0x5100 + 8), SOCKADDR_IN_LEN as u32);
    assert_eq!(u32_at(runtime.memory(), 0x5100 + 48), 0);
}

#[test]
fn connected_datagram_sendmsg_moves_one_datagram_from_iovecs() {
    let transport = runtime_socket_transport();
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    runtime.memory_mut().write(0x1000, &ipv4_sockaddr(53));
    runtime.memory_mut().write(0x2000, b"dn");
    runtime.memory_mut().write(0x2010, b"s?");
    runtime.memory_mut().write_iovec(0x3000, 0x2000, 2);
    runtime.memory_mut().write_iovec(0x3010, 0x2010, 2);
    runtime.memory_mut().write_msghdr(0x4000, 0, 0, 0x3000, 2);

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_DGRAM),
                u64::from(mcr_sys::LINUX_IPPROTO_UDP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x1000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Sendmsg,
            [3, 0x4000, u64::from(LINUX_MSG_NOSIGNAL), 0, 0, 0],
        ),
        SyscallReturn::Success(4)
    );
    assert_eq!(transport.sent_calls(), vec![b"dns?".to_vec()]);
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
fn socket_syscall_creates_vfs_socket_fd_with_flags_and_metadata() {
    let mut runtime = runtime_with_sample_vfs();

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM | LINUX_SOCK_CLOEXEC | LINUX_SOCK_NONBLOCK),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );

    assert_eq!(runtime.vfs().socket_id_for_fd(3).unwrap(), 1);
    assert_eq!(
        dispatch(&mut runtime, Syscall::Fstat, [3, 0x3000, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        u32_at(runtime.memory(), 0x3000 + 24) & mcr_vfs::S_IFMT,
        mcr_vfs::S_IFSOCK
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Fcntl,
            [3, u64::from(F_GETFD), 0, 0, 0, 0],
        ),
        SyscallReturn::Success(u64::from(mcr_vfs::FD_CLOEXEC))
    );
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Fcntl,
            [3, u64::from(F_GETFL), 0, 0, 0, 0],
        ),
        SyscallReturn::Success(u64::from(O_RDWR | O_NONBLOCK))
    );
}

#[test]
fn fcntl_setfl_propagates_socket_nonblocking_to_host_handle() {
    let transport = runtime_socket_transport();
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    runtime.memory_mut().write(0x2000, &ipv4_sockaddr(443));
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, 0x2000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );

    assert!(!transport.nonblocking());
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Fcntl,
            [
                3,
                u64::from(mcr_vfs::F_SETFL),
                u64::from(O_NONBLOCK),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(0)
    );

    assert!(transport.nonblocking());
    assert_eq!(
        dispatch(
            &mut runtime,
            Syscall::Fcntl,
            [3, u64::from(F_GETFL), 0, 0, 0, 0],
        ),
        SyscallReturn::Success(u64::from(O_RDWR | O_NONBLOCK))
    );
}

#[test]
fn bind_listen_and_getsockname_round_trip_ipv4_sockaddr() {
    let mut runtime = runtime_with_bound_ipv4_socket(8080);

    assert_eq!(
        dispatch_network(&mut runtime, Syscall::Listen, [3, 128, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );

    runtime.memory_mut().write(0x2100, &[0xaa; SOCKADDR_IN_LEN]);
    runtime.memory_mut().write(0x2200, &8u32.to_le_bytes());
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Getsockname,
            [3, 0x2100, 0x2200, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(u32_at(runtime.memory(), 0x2200), SOCKADDR_IN_LEN as u32);
    assert_eq!(runtime.memory().read(0x2100, 8), ipv4_sockaddr(8080)[..8]);
}

#[test]
fn accept4_creates_socket_fd_and_writes_peer_sockaddr() {
    let transport = runtime_socket_transport();
    let peer = SocketAddress::inet([127, 0, 0, 1], 49152);
    transport.push_accepted(peer, b"hello");
    let mut runtime = RuntimeFileSystem::with_socket_transport(
        sample_vfs(),
        TestMemory::default(),
        transport.handle(),
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_INET),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    runtime.memory_mut().write(0x2000, &ipv4_sockaddr(8080));
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Bind,
            [3, 0x2000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_network(&mut runtime, Syscall::Listen, [3, 1, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    runtime.memory_mut().write(0x2100, &[0xaa; SOCKADDR_IN_LEN]);
    runtime
        .memory_mut()
        .write(0x2200, &(SOCKADDR_IN_LEN as u32).to_le_bytes());

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Accept4,
            [
                3,
                0x2100,
                0x2200,
                u64::from(LINUX_SOCK_CLOEXEC | LINUX_SOCK_NONBLOCK),
                0,
                0,
            ],
        ),
        SyscallReturn::Success(4)
    );
    assert_eq!(runtime.vfs().socket_id_for_fd(4).unwrap(), 2);
    assert!(runtime.vfs().fds().cloexec(4).unwrap());
    assert_eq!(
        runtime.vfs().fds().status_flags(4).unwrap(),
        O_RDWR | O_NONBLOCK
    );
    assert_eq!(u32_at(runtime.memory(), 0x2200), SOCKADDR_IN_LEN as u32);
    assert_eq!(
        runtime.memory().read(0x2100, SOCKADDR_IN_LEN),
        ipv4_sockaddr(49152)
    );
    assert_eq!(
        runtime
            .sockets()
            .socket(SocketId::new(2).unwrap())
            .unwrap()
            .state(),
        SocketState::Connected {
            local: SocketAddress::inet([127, 0, 0, 1], 8080),
            peer,
        }
    );
}

#[test]
fn connect_getpeername_and_shutdown_round_trip_ipv6_sockaddr() {
    let mut runtime = runtime_with_socket(LINUX_AF_INET6);
    let peer_addr = 0x3000;
    let out_addr = 0x3100;
    let out_len = 0x3200;
    let local_addr = 0x3300;
    let local_len = 0x3400;
    let address = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    runtime
        .memory_mut()
        .write(peer_addr, &ipv6_sockaddr(address, 443, 7, 2));

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Connect,
            [3, peer_addr, SOCKADDR_IN6_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );

    runtime
        .memory_mut()
        .write(out_len, &(SOCKADDR_IN6_LEN as u32).to_le_bytes());
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Getpeername,
            [3, out_addr, out_len, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(u32_at(runtime.memory(), out_len), SOCKADDR_IN6_LEN as u32);
    assert_eq!(
        runtime.memory().read(out_addr, SOCKADDR_IN6_LEN),
        ipv6_sockaddr(address, 443, 7, 2)
    );
    runtime
        .memory_mut()
        .write(local_len, &(SOCKADDR_IN6_LEN as u32).to_le_bytes());
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Getsockname,
            [3, local_addr, local_len, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(u32_at(runtime.memory(), local_len), SOCKADDR_IN6_LEN as u32);
    assert_eq!(
        runtime.memory().read(local_addr, SOCKADDR_IN6_LEN),
        ipv6_sockaddr([0; 16], 0, 0, 0)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Shutdown,
            [3, u64::from(LINUX_SHUT_RDWR), 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert!(
        runtime
            .sockets()
            .socket(SocketId::new(1).unwrap())
            .unwrap()
            .shutdown()
            .read
    );
    assert!(
        runtime
            .sockets()
            .socket(SocketId::new(1).unwrap())
            .unwrap()
            .shutdown()
            .write
    );
}

#[test]
fn setsockopt_and_getsockopt_use_socklen_pointer() {
    let mut runtime = runtime_with_socket(LINUX_AF_INET);
    runtime.memory_mut().write(0x4000, &1u32.to_le_bytes());
    runtime.memory_mut().write(0x4010, &0u32.to_le_bytes());
    runtime.memory_mut().write(0x4020, &8u32.to_le_bytes());

    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Setsockopt,
            [
                3,
                u64::from(LINUX_SOL_SOCKET),
                u64::from(LINUX_SO_REUSEADDR),
                0x4000,
                4,
                0,
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Setsockopt,
            [
                3,
                u64::from(LINUX_SOL_SOCKET),
                u64::from(LINUX_SO_KEEPALIVE),
                0x4000,
                4,
                0,
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Setsockopt,
            [
                3,
                u64::from(mcr_net::LINUX_IPPROTO_TCP_LEVEL),
                u64::from(LINUX_TCP_NODELAY),
                0x4000,
                4,
                0,
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Getsockopt,
            [
                3,
                u64::from(LINUX_SOL_SOCKET),
                u64::from(LINUX_SO_REUSEADDR),
                0x4010,
                0x4020,
                0,
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(u32_at(runtime.memory(), 0x4010), 1);
    assert_eq!(u32_at(runtime.memory(), 0x4020), 4);

    runtime.memory_mut().write(0x4020, &4u32.to_le_bytes());
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Getsockopt,
            [
                3,
                u64::from(LINUX_SOL_SOCKET),
                u64::from(LINUX_SO_TYPE),
                0x4010,
                0x4020,
                0,
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(u32_at(runtime.memory(), 0x4010), LINUX_SOCK_STREAM);
}

#[test]
fn socket_control_error_paths_match_linux_shapes() {
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
        dispatch_network(&mut runtime, Syscall::Listen, [3, 1, 0, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::ENOTSOCK)
    );

    let mut socket_runtime = runtime_with_socket(LINUX_AF_INET);
    socket_runtime
        .memory_mut()
        .write(0x2000, &ipv6_sockaddr([0; 16], 80, 0, 0));
    assert_eq!(
        dispatch_network(
            &mut socket_runtime,
            Syscall::Bind,
            [3, 0x2000, SOCKADDR_IN6_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EAFNOSUPPORT)
    );
    socket_runtime
        .memory_mut()
        .write(0x2100, &ipv4_sockaddr(80));
    assert_eq!(
        dispatch_network(&mut socket_runtime, Syscall::Bind, [3, 0x2100, 4, 0, 0, 0],),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        dispatch_network(
            &mut socket_runtime,
            Syscall::Getpeername,
            [3, 0x2200, 0x2300, 0, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::ENOTCONN)
    );
    assert_eq!(
        dispatch_network(
            &mut socket_runtime,
            Syscall::Shutdown,
            [3, u64::from(LINUX_SHUT_RDWR), 0, 0, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::ENOTCONN)
    );
    socket_runtime
        .memory_mut()
        .write(0x2400, &2u32.to_le_bytes());
    assert_eq!(
        dispatch_network(
            &mut socket_runtime,
            Syscall::Getsockopt,
            [
                3,
                u64::from(LINUX_SOL_SOCKET),
                u64::from(LINUX_SO_ERROR),
                0x2500,
                0x2400,
                0,
            ],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        dispatch_network(
            &mut socket_runtime,
            Syscall::Accept4,
            [3, 0, 0, 0x8000_0000, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    let mut listener = runtime_with_bound_ipv4_socket(9090);
    assert_eq!(
        dispatch_network(&mut listener, Syscall::Listen, [3, 1, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_network(&mut listener, Syscall::Accept, [3, 0, 0, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::EAGAIN)
    );
}

#[derive(Clone, Default)]
struct TestMemory {
    bytes: BTreeMap<u64, u8>,
}

impl TestMemory {
    fn write(&mut self, addr: u64, bytes: &[u8]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            self.bytes.insert(addr + index as u64, byte);
        }
    }

    fn write_cstr(&mut self, addr: u64, value: &str) {
        self.write(addr, value.as_bytes());
        self.write(addr + value.len() as u64, &[0]);
    }

    fn write_iovec(&mut self, addr: u64, base: u64, len: u64) {
        self.write(addr, &base.to_le_bytes());
        self.write(addr + 8, &len.to_le_bytes());
    }

    fn write_msghdr(&mut self, addr: u64, name: u64, namelen: u32, iov: u64, iovlen: u64) {
        self.write(addr, &name.to_le_bytes());
        self.write(addr + 8, &namelen.to_le_bytes());
        self.write(addr + 12, &0u32.to_le_bytes());
        self.write(addr + 16, &iov.to_le_bytes());
        self.write(addr + 24, &iovlen.to_le_bytes());
        self.write(addr + 32, &0u64.to_le_bytes());
        self.write(addr + 40, &0u64.to_le_bytes());
        self.write(addr + 48, &0u32.to_le_bytes());
        self.write(addr + 52, &0u32.to_le_bytes());
    }

    fn read(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.read_bytes(addr, &mut bytes).unwrap();
        bytes
    }
}

impl GuestMemoryAccess for TestMemory {
    fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), GuestMemoryAccessError> {
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = *self
                .bytes
                .get(&(addr + index as u64))
                .ok_or(GuestMemoryAccessError::Fault)?;
        }
        Ok(())
    }

    fn write_bytes(&mut self, addr: u64, buffer: &[u8]) -> Result<(), GuestMemoryAccessError> {
        self.write(addr, buffer);
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct TestSocketTransport {
    state: Rc<RefCell<TestSocketState>>,
}

impl TestSocketTransport {
    fn handle(&self) -> TestSocketTransportHandle {
        TestSocketTransportHandle {
            state: self.state.clone(),
        }
    }

    fn sent_bytes(&self) -> Vec<u8> {
        self.state.borrow().sent.clone()
    }

    fn sent_calls(&self) -> Vec<Vec<u8>> {
        self.state.borrow().sent_calls.clone()
    }

    fn recv_calls(&self) -> usize {
        self.state.borrow().recv_calls
    }

    fn push_incoming(&self, bytes: &[u8]) {
        self.state.borrow_mut().incoming.extend_from_slice(bytes);
    }

    fn set_connect_would_block_once(&self) {
        self.state.borrow_mut().connect_would_block_once = true;
    }

    fn nonblocking(&self) -> bool {
        self.state.borrow().nonblocking
    }

    fn poll_timeouts(&self) -> Vec<Option<Duration>> {
        self.state.borrow().poll_timeouts.clone()
    }

    fn push_accepted(&self, peer: SocketAddress, incoming: &[u8]) {
        self.state.borrow_mut().accepted.push((
            Rc::new(RefCell::new(TestSocketState {
                incoming: incoming.to_vec(),
                connected: Some(peer),
                ..TestSocketState::default()
            })),
            peer,
        ));
    }
}

#[derive(Debug, Default)]
struct TestSocketState {
    sent: Vec<u8>,
    sent_calls: Vec<Vec<u8>>,
    recv_calls: usize,
    incoming: Vec<u8>,
    connected: Option<SocketAddress>,
    connect_would_block_once: bool,
    nonblocking: bool,
    accepted: Vec<(Rc<RefCell<TestSocketState>>, SocketAddress)>,
    bound: Option<SocketAddress>,
    listened: bool,
    poll_timeouts: Vec<Option<Duration>>,
}

#[derive(Clone, Debug)]
struct TestSocketTransportHandle {
    state: Rc<RefCell<TestSocketState>>,
}

impl HostSocketTransport for TestSocketTransportHandle {
    fn open_socket(
        &self,
        _spec: SocketSpec,
        _options: mcr_net::SocketOptions,
    ) -> Result<Box<dyn mcr_net::HostSocketHandle>, mcr_net::HostIoError> {
        Ok(Box::new(TestSocketHandle {
            state: self.state.clone(),
        }))
    }
}

#[derive(Debug)]
struct TestSocketHandle {
    state: Rc<RefCell<TestSocketState>>,
}

impl mcr_net::HostSocketHandle for TestSocketHandle {
    fn bind(&mut self, address: SocketAddress) -> Result<SocketAddress, mcr_net::HostIoError> {
        self.state.borrow_mut().bound = Some(address);
        Ok(address)
    }

    fn listen(&mut self, _backlog: u32) -> Result<(), mcr_net::HostIoError> {
        self.state.borrow_mut().listened = true;
        Ok(())
    }

    fn accept(
        &mut self,
    ) -> Result<(Box<dyn mcr_net::HostSocketHandle>, SocketAddress), mcr_net::HostIoError> {
        let mut state = self.state.borrow_mut();
        if state.accepted.is_empty() {
            return Err(mcr_net::HostIoError::new(
                mcr_net::LinuxErrno::OperationWouldBlock,
                "no pending test socket",
            ));
        }
        let (accepted, peer) = state.accepted.remove(0);
        Ok((Box::new(TestSocketHandle { state: accepted }), peer))
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), mcr_net::HostIoError> {
        self.state.borrow_mut().nonblocking = nonblocking;
        Ok(())
    }

    fn connect(&mut self, address: SocketAddress) -> Result<(), mcr_net::HostIoError> {
        let mut state = self.state.borrow_mut();
        if state.connect_would_block_once {
            state.connect_would_block_once = false;
            state.connected = Some(address);
            return Err(mcr_net::HostIoError::new(
                mcr_net::LinuxErrno::OperationWouldBlock,
                "connect would block",
            ));
        }
        state.connected = Some(address);
        Ok(())
    }

    fn take_error(&mut self) -> Result<Option<mcr_net::HostIoError>, mcr_net::HostIoError> {
        Ok(None)
    }

    fn local_addr(&self) -> Result<SocketAddress, mcr_net::HostIoError> {
        let state = self.state.borrow();
        Ok(state.bound.unwrap_or_else(|| {
            SocketAddress::unspecified_for_domain(
                state
                    .connected
                    .map_or(mcr_net::SocketDomain::Inet, SocketAddress::domain),
            )
        }))
    }

    fn peer_addr(&self) -> Result<SocketAddress, mcr_net::HostIoError> {
        self.state.borrow().connected.ok_or_else(|| {
            mcr_net::HostIoError::new(mcr_net::LinuxErrno::NotConnected, "socket is not connected")
        })
    }

    fn send(&mut self, buffer: &[u8]) -> Result<usize, mcr_net::HostIoError> {
        let mut state = self.state.borrow_mut();
        state.sent.extend_from_slice(buffer);
        state.sent_calls.push(buffer.to_vec());
        Ok(buffer.len())
    }

    fn send_to(
        &mut self,
        buffer: &[u8],
        address: SocketAddress,
    ) -> Result<usize, mcr_net::HostIoError> {
        self.state.borrow_mut().connected = Some(address);
        self.send(buffer)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, mcr_net::HostIoError> {
        let mut state = self.state.borrow_mut();
        state.recv_calls += 1;
        let count = buffer.len().min(state.incoming.len());
        buffer[..count].copy_from_slice(&state.incoming[..count]);
        state.incoming.drain(..count);
        Ok(count)
    }

    fn recv_from(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddress), mcr_net::HostIoError> {
        let count = self.recv(buffer)?;
        let address = self
            .state
            .borrow()
            .connected
            .unwrap_or_else(|| SocketAddress::inet([127, 0, 0, 1], 53));
        Ok((count, address))
    }

    fn poll(
        &mut self,
        interest: SocketEvents,
        timeout: Option<Duration>,
    ) -> Result<SocketEvents, mcr_net::HostIoError> {
        self.state.borrow_mut().poll_timeouts.push(timeout);
        let state = self.state.borrow();
        Ok(SocketEvents {
            readable: interest.readable && !state.incoming.is_empty(),
            writable: interest.writable,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        })
    }

    fn shutdown(&mut self, _how: ShutdownHow) -> Result<(), mcr_net::HostIoError> {
        Ok(())
    }
}

fn runtime_socket_transport() -> TestSocketTransport {
    TestSocketTransport::default()
}

fn sample_vfs() -> VirtualFileSystem {
    let rootfs = Rootfs::new("/host/root");
    let mut tree = PathTree::new();
    tree.create_dir("/tmp").unwrap();
    tree.create_file_with_content("/tmp/file", b"hello", 0o644)
        .unwrap();
    tree.create_dir("/private").unwrap();
    tree.create_file_with_content("/private/secret", b"secret", 0o600)
        .unwrap();
    tree.create_symlink("/link", "/tmp/file").unwrap();
    VirtualFileSystem::from_parts(rootfs, tree, FdTable::with_stdio())
}

fn runtime_with_sample_vfs() -> RuntimeFileSystem<TestMemory> {
    RuntimeFileSystem::new(sample_vfs(), TestMemory::default())
}

fn runtime_from_program_and_tree(program: GuestProgram, tree: PathTree) -> Runtime {
    Runtime::with_vfs(
        program,
        VirtualFileSystem::from_parts(Rootfs::new("/host/root"), tree, FdTable::with_stdio()),
    )
    .unwrap()
}

fn runtime_with_socket(domain: u32) -> RuntimeFileSystem<TestMemory> {
    let mut runtime = runtime_with_sample_vfs();
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(domain),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    runtime
}

fn runtime_with_bound_ipv4_socket(port: u16) -> RuntimeFileSystem<TestMemory> {
    let mut runtime = runtime_with_socket(LINUX_AF_INET);
    runtime.memory_mut().write(0x2000, &ipv4_sockaddr(port));
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Bind,
            [3, 0x2000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    runtime
}

fn elf_with_bss_tail_garbage() -> Vec<u8> {
    const PH_OFFSET: usize = 64;
    const LOAD_OFFSET: usize = 0x100;
    let mut bytes = vec![0; LOAD_OFFSET + 16];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&(PH_OFFSET as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

    bytes[PH_OFFSET..PH_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[PH_OFFSET + 4..PH_OFFSET + 8].copy_from_slice(&4u32.to_le_bytes());
    bytes[PH_OFFSET + 8..PH_OFFSET + 16].copy_from_slice(&(LOAD_OFFSET as u64).to_le_bytes());
    bytes[PH_OFFSET + 16..PH_OFFSET + 24].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[PH_OFFSET + 24..PH_OFFSET + 32].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[PH_OFFSET + 32..PH_OFFSET + 40].copy_from_slice(&8u64.to_le_bytes());
    bytes[PH_OFFSET + 40..PH_OFFSET + 48].copy_from_slice(&16u64.to_le_bytes());
    bytes[PH_OFFSET + 48..PH_OFFSET + 56].copy_from_slice(&8u64.to_le_bytes());

    bytes[LOAD_OFFSET..LOAD_OFFSET + 8].copy_from_slice(b"LOADDATA");
    bytes[LOAD_OFFSET + 8..LOAD_OFFSET + 16].copy_from_slice(b"garbage!");
    bytes
}

fn elf_with_dynsym_memcpy() -> Vec<u8> {
    const PH_OFFSET: usize = 64;
    const LOAD_OFFSET: usize = 0x1000;
    const DYNSYM_OFFSET: usize = 0x2800;
    const STRTAB_OFFSET: usize = 0x2900;
    const SH_OFFSET: usize = 0x3000;
    const MEMCPY_VADDR: u64 = 0x2010;
    let mut bytes = vec![0; SH_OFFSET + 64 * 3];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    write_test_u16(&mut bytes, 16, 3);
    write_test_u16(&mut bytes, 18, 0x3e);
    write_test_u32(&mut bytes, 20, 1);
    write_test_u64(&mut bytes, 32, PH_OFFSET as u64);
    write_test_u64(&mut bytes, 40, SH_OFFSET as u64);
    write_test_u16(&mut bytes, 52, 64);
    write_test_u16(&mut bytes, 54, 56);
    write_test_u16(&mut bytes, 56, 1);
    write_test_u16(&mut bytes, 58, 64);
    write_test_u16(&mut bytes, 60, 3);

    write_test_u32(&mut bytes, PH_OFFSET, 1);
    write_test_u32(&mut bytes, PH_OFFSET + 4, PF_R | PF_X);
    write_test_u64(&mut bytes, PH_OFFSET + 8, LOAD_OFFSET as u64);
    write_test_u64(&mut bytes, PH_OFFSET + 16, 0x2000);
    write_test_u64(&mut bytes, PH_OFFSET + 24, 0x2000);
    write_test_u64(&mut bytes, PH_OFFSET + 32, GUEST_PAGE_SIZE);
    write_test_u64(&mut bytes, PH_OFFSET + 40, GUEST_PAGE_SIZE);
    write_test_u64(&mut bytes, PH_OFFSET + 48, GUEST_PAGE_SIZE);

    bytes[LOAD_OFFSET + 0x10..LOAD_OFFSET + 0x13].copy_from_slice(&[0x90, 0x90, 0xc3]);
    bytes[STRTAB_OFFSET..STRTAB_OFFSET + 8].copy_from_slice(b"\0memcpy\0");
    write_test_u32(&mut bytes, DYNSYM_OFFSET + 24, 1);
    bytes[DYNSYM_OFFSET + 28] = 0x12;
    write_test_u64(&mut bytes, DYNSYM_OFFSET + 32, MEMCPY_VADDR);
    write_test_u64(&mut bytes, DYNSYM_OFFSET + 40, 3);

    let dynsym = SH_OFFSET + 64;
    write_test_u32(&mut bytes, dynsym + 4, 11);
    write_test_u64(&mut bytes, dynsym + 24, DYNSYM_OFFSET as u64);
    write_test_u64(&mut bytes, dynsym + 32, 48);
    write_test_u32(&mut bytes, dynsym + 40, 2);
    write_test_u64(&mut bytes, dynsym + 56, 24);

    let strtab = SH_OFFSET + 64 * 2;
    write_test_u32(&mut bytes, strtab + 4, 3);
    write_test_u64(&mut bytes, strtab + 24, STRTAB_OFFSET as u64);
    write_test_u64(&mut bytes, strtab + 32, 8);
    bytes
}

fn write_test_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_test_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_test_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn ipv4_sockaddr(port: u16) -> Vec<u8> {
    ipv4_sockaddr_for([127, 0, 0, 1], port)
}

fn ipv4_sockaddr_for(address: [u8; 4], port: u16) -> Vec<u8> {
    let mut bytes = vec![0; SOCKADDR_IN_LEN];
    bytes[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4..8].copy_from_slice(&address);
    bytes
}

fn ipv6_sockaddr(address: [u8; 16], port: u16, flowinfo: u32, scope_id: u32) -> Vec<u8> {
    let mut bytes = vec![0; SOCKADDR_IN6_LEN];
    bytes[0..2].copy_from_slice(&(LINUX_AF_INET6 as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4..8].copy_from_slice(&flowinfo.to_le_bytes());
    bytes[8..24].copy_from_slice(&address);
    bytes[24..28].copy_from_slice(&scope_id.to_le_bytes());
    bytes
}

fn dispatch(
    runtime: &mut RuntimeFileSystem<TestMemory>,
    syscall: Syscall,
    args: [u64; 6],
) -> SyscallReturn {
    let registers = SyscallRegisters {
        rax: syscall.number().raw(),
        rdi: args[0],
        rsi: args[1],
        rdx: args[2],
        r10: args[3],
        r8: args[4],
        r9: args[5],
        rip: 0,
    };
    let request = mcr_sys::SyscallRequest::from_guest_context(GuestContext::new(1, 1, registers));
    runtime.dispatch_file(&request).result
}

fn dispatch_network(
    runtime: &mut RuntimeFileSystem<TestMemory>,
    syscall: Syscall,
    args: [u64; 6],
) -> SyscallReturn {
    let registers = SyscallRegisters {
        rax: syscall.number().raw(),
        rdi: args[0],
        rsi: args[1],
        rdx: args[2],
        r10: args[3],
        r8: args[4],
        r9: args[5],
        rip: 0,
    };
    let request = mcr_sys::SyscallRequest::from_guest_context(GuestContext::new(1, 1, registers));
    runtime.dispatch_network(&request).result
}

fn guest_path(path: &str) -> mcr_vfs::GuestPath {
    Rootfs::new("/host")
        .resolve_path(path, &PathTree::new())
        .unwrap()
        .guest_path()
        .clone()
}

fn u64_at(memory: &TestMemory, addr: u64) -> u64 {
    u64::from_le_bytes(memory.read(addr, 8).try_into().expect("slice len"))
}

fn u32_at(memory: &TestMemory, addr: u64) -> u32 {
    u32::from_le_bytes(memory.read(addr, 4).try_into().expect("slice len"))
}

fn i32_at(memory: &TestMemory, addr: u64) -> i32 {
    i32::from_le_bytes(memory.read(addr, 4).try_into().expect("slice len"))
}

fn i32_from_memory(memory: &GuestMemory, addr: u64) -> i32 {
    let mut bytes = [0; 4];
    memory.read(addr, &mut bytes).unwrap();
    i32::from_le_bytes(bytes)
}

fn u64_from_guest(memory: &GuestMemory, addr: u64) -> u64 {
    let mut bytes = [0; 8];
    memory.read(addr, &mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}

fn i64_from_guest(memory: &GuestMemory, addr: u64) -> i64 {
    let mut bytes = [0; 8];
    memory.read(addr, &mut bytes).unwrap();
    i64::from_le_bytes(bytes)
}

fn u32_from_guest(memory: &GuestMemory, addr: u64) -> u32 {
    let mut bytes = [0; 4];
    memory.read(addr, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

fn guest_bytes(memory: &GuestMemory, addr: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    memory.read(addr, &mut bytes).unwrap();
    bytes
}

fn u16_from_guest(memory: &GuestMemory, addr: u64) -> u16 {
    let mut bytes = [0; 2];
    memory.read(addr, &mut bytes).unwrap();
    u16::from_le_bytes(bytes)
}

fn write_stack_t(memory: &mut GuestMemory, addr: u64, sp: u64, flags: u32, size: u64) {
    memory.write(addr, &sp.to_le_bytes()).unwrap();
    memory
        .write(addr + LINUX_STACK_T_FLAGS_OFFSET, &flags.to_le_bytes())
        .unwrap();
    memory
        .write(addr + LINUX_STACK_T_SIZE_OFFSET, &size.to_le_bytes())
        .unwrap();
}

fn write_pollfd(memory: &mut GuestMemory, addr: u64, fd: i32, events: i16) {
    memory.write(addr, &fd.to_le_bytes()).unwrap();
    memory.write(addr + 4, &events.to_le_bytes()).unwrap();
    memory.write(addr + 6, &0i16.to_le_bytes()).unwrap();
}

fn pollfd_revents(memory: &GuestMemory, addr: u64) -> i16 {
    let mut bytes = [0; 2];
    memory.read(addr + 6, &mut bytes).unwrap();
    i16::from_le_bytes(bytes)
}

fn write_select_fdset(memory: &mut GuestMemory, addr: u64, nfds: usize, fds: &[Fd]) {
    write_select_fd_set(memory, addr, nfds, fds).unwrap();
}

fn select_fdset_contains(memory: &GuestMemory, addr: u64, fd: usize) -> bool {
    select_fd_set_contains(memory, addr, fd).unwrap()
}

fn write_timeval(memory: &mut GuestMemory, addr: u64, sec: i64, usec: i64) {
    memory.write(addr, &sec.to_le_bytes()).unwrap();
    memory.write(addr + 8, &usec.to_le_bytes()).unwrap();
}

fn write_clone3_args(
    memory: &mut GuestMemory,
    addr: u64,
    flags: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
) {
    for (index, value) in [flags, 0, 0, 0, exit_signal, stack, stack_size, 0, 0, 0, 0]
        .into_iter()
        .enumerate()
    {
        memory
            .write(addr + (index * 8) as u64, &value.to_le_bytes())
            .unwrap();
    }
}

struct TestUnsafeShareUntilExec;

impl TestUnsafeShareUntilExec {
    fn enable() -> Self {
        UNSAFE_SHARE_UNTIL_EXEC_TEST_OVERRIDE.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for TestUnsafeShareUntilExec {
    fn drop(&mut self) {
        UNSAFE_SHARE_UNTIL_EXEC_TEST_OVERRIDE.store(false, Ordering::SeqCst);
    }
}

fn write_timespec(memory: &mut GuestMemory, addr: u64, sec: i64, nsec: i64) {
    memory.write(addr, &sec.to_le_bytes()).unwrap();
    memory.write(addr + 8, &nsec.to_le_bytes()).unwrap();
}

fn timespec_from_memory(memory: &GuestMemory, addr: u64) -> LinuxTimespec {
    let mut sec = [0; 8];
    let mut nsec = [0; 8];
    memory.read(addr, &mut sec).unwrap();
    memory.read(addr + 8, &mut nsec).unwrap();
    LinuxTimespec {
        tv_sec: i64::from_le_bytes(sec),
        tv_nsec: i64::from_le_bytes(nsec),
    }
}

fn write_epoll_event_for_test(memory: &mut GuestMemory, addr: u64, events: u32, data: u64) {
    memory.write(addr, &events.to_le_bytes()).unwrap();
    memory.write(addr + 4, &data.to_le_bytes()).unwrap();
}

fn epoll_event_from_memory(memory: &GuestMemory, addr: u64) -> (u32, u64) {
    let mut events = [0; 4];
    let mut data = [0; 8];
    memory.read(addr, &mut events).unwrap();
    memory.read(addr + 4, &mut data).unwrap();
    (u32::from_le_bytes(events), u64::from_le_bytes(data))
}

fn u16_at(memory: &TestMemory, addr: u64) -> u16 {
    u16::from_le_bytes(memory.read(addr, 2).try_into().expect("slice len"))
}

#[test]
fn runtime_dispatch_supports_tls_and_exit_state() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let arch = runtime.dispatch_syscall(context(
        Syscall::ArchPrctl,
        [ARCH_SET_FS, 0x7000_0000, 0, 0, 0, 0],
    ));
    assert_eq!(arch.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .tls()
            .fs_base(),
        0x7000_0000
    );

    let exit = runtime.dispatch_syscall(context(Syscall::ExitGroup, [9, 0, 0, 0, 0, 0]));
    assert_eq!(exit.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 9 }
    );
}

#[test]
fn guest_registers_round_trip_preserves_argument_register_order() {
    let registers = GuestRegisters {
        rax: 1,
        rbx: 2,
        rcx: 3,
        rdx: 4,
        rsi: 5,
        rdi: 6,
        rbp: 7,
        rsp: 8,
        r8: 9,
        r9: 10,
        r10: 11,
        r11: 12,
        r12: 13,
        r13: 14,
        r14: 15,
        r15: 16,
        rip: 17,
        fs_base: 0,
        rflags: 18,
    };

    assert_eq!(registers_from_gpr(gpr_from_registers(registers)), registers);
}

#[test]
fn guest_execution_dispatch_advances_registers_and_exposes_exit_state() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    let rsp = runtime
        .kernel()
        .task(INITIAL_GUEST_TID)
        .unwrap()
        .regs()
        .rsp();
    runtime
        .kernel_mut()
        .task_mut(INITIAL_GUEST_TID)
        .unwrap()
        .set_regs(GprState::with_syscall_registers(
            0x401000,
            rsp,
            Syscall::ExitGroup.number().raw(),
            [42, 0, 0, 0, 0, 0],
        ));

    let step = runtime
        .dispatch_guest_execution()
        .expect("execute guest syscall block");

    assert_eq!(step.tid(), INITIAL_GUEST_TID);
    assert_eq!(step.before_rip(), 0x401000);
    assert_eq!(step.after_rip(), 0x401000);
    assert_eq!(step.encoded_rax(), 0);
    assert_eq!(step.task_state(), TaskState::Exited { status: 42 });
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rip(),
        0x401000
    );
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 42 }
    );
}

#[test]
fn guest_execution_preserves_non_syscall_registers_across_steps() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x48, 0xbb, 0x7f, 0x4d, 0x3c, 0x2b, 0x1a, 0x09, 0x08,
            0x07, // mov rbx,0x0708091a2b3c4d7f
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,getpid
            0x0f, 0x05, // syscall
            0x48, 0x89, 0xdf, // mov rdi,rbx
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();

    let first_step = runtime
        .dispatch_guest_execution()
        .expect("getpid step executes");
    assert_eq!(first_step.before_rip(), 0x401000);
    assert_eq!(first_step.after_rip(), 0x401011);
    assert_eq!(first_step.encoded_rax(), u64::from(INITIAL_GUEST_PID));
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rbx(),
        0x0708_091a_2b3c_4d7f
    );

    let second_step = runtime
        .dispatch_guest_execution()
        .expect("exit_group step executes");

    assert_eq!(second_step.before_rip(), 0x401011);
    assert_eq!(second_step.after_rip(), 0x401019);
    assert_eq!(second_step.task_state(), TaskState::Exited { status: 0x7f });
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 0x7f }
    );
}

#[test]
fn guest_execution_dispatches_syscall_after_guest_memory_load() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x8b, 0x3d, 0xfa, 0x0f, 0x00, 0x00, // mov edi,[rip+0xffa]
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &[77, 0, 0, 0])
        .unwrap();

    let step = runtime
        .dispatch_guest_execution()
        .expect("guest memory load feeds exit_group syscall");

    assert_eq!(step.before_rip(), 0x401000);
    assert_eq!(step.after_rip(), 0x40100b);
    assert_eq!(step.task_state(), TaskState::Exited { status: 77 });
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 77 }
    );
}

#[test]
fn guest_execution_dispatches_syscall_after_fs_relative_guest_memory_load() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // mov rax,fs:[0x28]
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
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
        .write(0x600028, &Syscall::Getpid.number().raw().to_le_bytes())
        .unwrap();
    let arch = runtime.dispatch_syscall(context(
        Syscall::ArchPrctl,
        [ARCH_SET_FS, 0x600000, 0, 0, 0, 0],
    ));
    assert_eq!(arch.result, SyscallReturn::Success(0));

    let step = runtime
        .dispatch_guest_execution()
        .expect("fs-relative load feeds guest syscall dispatch");

    assert_eq!(step.before_rip(), 0x401000);
    assert_eq!(step.after_rip(), 0x40100b);
    assert_eq!(step.encoded_rax(), u64::from(INITIAL_GUEST_PID));
}

#[test]
fn guest_execution_persists_guest_memory_store_before_syscall() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x48, 0xbb, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, // mov rbx,0x1122334455667788
            0x48, 0x89, 0x1d, 0xef, 0x0f, 0x00, 0x00, // mov [rip+0xfef],rbx
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x31, 0xff, // xor edi,edi
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();

    let step = runtime
        .dispatch_guest_execution()
        .expect("guest memory store runs before exit_group");

    assert_eq!(step.task_state(), TaskState::Exited { status: 0 });
    let mut stored = [0; 8];
    runtime.memory().read(0x402000, &mut stored).unwrap();
    assert_eq!(u64::from_le_bytes(stored), 0x1122_3344_5566_7788);
}

#[test]
fn guest_execution_preserves_stack_push_pop_before_syscall() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0xbb, 0x2a, 0x00, 0x00, 0x00, // mov ebx,42
            0x53, // push rbx
            0x5f, // pop rdi
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    let initial_rsp = runtime
        .kernel()
        .task(INITIAL_GUEST_TID)
        .unwrap()
        .regs()
        .rsp();

    let step = runtime
        .dispatch_guest_execution()
        .expect("stack push/pop feeds exit_group syscall");

    assert_eq!(step.task_state(), TaskState::Exited { status: 42 });
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rsp(),
        initial_rsp
    );
}

#[test]
fn guest_execution_follows_call_ret_before_syscall() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0xe8, 0x07, 0x00, 0x00, 0x00, // call 0x40100c
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x0f, 0x05, // syscall
            0x48, 0xc7, 0xc7, 0x21, 0x00, 0x00, 0x00, // mov rdi,33
            0xc3, // ret
        ],
    ))
    .unwrap();

    let step = runtime
        .dispatch_guest_execution()
        .expect("call/ret feeds exit_group syscall");

    assert_eq!(step.task_state(), TaskState::Exited { status: 33 });
}

#[test]
fn guest_execution_surfaces_guest_memory_operand_fault() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x48, 0x8b, 0x00, // mov rax,[rax]
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();

    let error = runtime
        .dispatch_guest_execution()
        .expect_err("unmapped memory load stops guest execution");

    assert_eq!(error.linux_errno(), LinuxErrno::ENOEXEC);
    assert!(matches!(
        error,
        GuestExecutionError::Execution(ExecutionError::MemoryOperand { .. })
    ));
}

#[test]
fn guest_run_loop_returns_exit_group_status() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(
        &mut runtime,
        0x401000,
        Syscall::ExitGroup,
        [42, 0, 0, 0, 0, 0],
    );

    let status = runtime
        .run_guest_until_exit()
        .expect("guest run exits through exit_group");

    assert_eq!(status, 42);
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 42 }
    );
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rip(),
        0x401000
    );
}

#[test]
fn guest_run_loop_returns_exit_status_from_exit_syscall() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::Exit, [300, 0, 0, 0, 0, 0]);

    let status = runtime
        .run_guest_until_exit()
        .expect("guest run exits through exit");

    assert_eq!(status, 44);
    assert_eq!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Exited { status: 44 }
    );
}

#[test]
fn guest_run_loop_schedules_child_when_parent_waits() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, exit_group
            0xbf, 0x00, 0x00, 0x00, 0x00, // mov edi, 0
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::Fork, [0; 6]);

    let fork = runtime
        .dispatch_guest_execution()
        .expect("parent fork syscall executes");
    assert_eq!(fork.encoded_rax(), 2);
    runtime
        .kernel_mut()
        .task_mut(INITIAL_GUEST_TID)
        .unwrap()
        .set_regs(GprState::with_syscall_registers(
            0x401000,
            0x8000_0000,
            Syscall::Wait4.number().raw(),
            [-1i64 as u64, 0x402000, 0, 0, 0, 0],
        ));
    runtime
        .kernel_mut()
        .task_mut(2)
        .unwrap()
        .set_regs(GprState::with_syscall_registers(
            0x401000,
            0x8000_0000,
            Syscall::ExitGroup.number().raw(),
            [23, 0, 0, 0, 0, 0],
        ));

    let status = runtime
        .run_guest_until_exit()
        .expect("parent exits after reaping child");

    assert_eq!(status, 0);
    let parent = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(parent.state(), TaskState::Exited { status: 0 });
    assert_eq!(u32_from_guest(runtime.memory(), 0x402000), 23 << 8);
    assert!(runtime.kernel().process(2).is_none());
    assert!(runtime.memory_for_process(2).is_none());
}

#[test]
fn thread_clone_writes_tid_pointers_and_exit_keeps_process_alive() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime.memory_mut().write(0x402000, &[0xaa; 8]).unwrap();
    let flags = LINUX_CLONE_VM
        | LINUX_CLONE_FS
        | LINUX_CLONE_FILES
        | LINUX_CLONE_SIGHAND
        | LINUX_CLONE_THREAD
        | LINUX_CLONE_SYSVSEM
        | LINUX_CLONE_SETTLS
        | LINUX_CLONE_PARENT_SETTID
        | LINUX_CLONE_CHILD_SETTID
        | LINUX_CLONE_CHILD_CLEARTID;

    let clone = runtime.dispatch_syscall(context(
        Syscall::Clone,
        [flags, 0x7000_0000, 0x402000, 0x402004, 0x6000_0000, 0],
    ));

    assert_eq!(clone.result, SyscallReturn::Success(2));
    assert_eq!(u32_from_guest(runtime.memory(), 0x402000), 2);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402004), 2);
    let child = runtime.kernel().task(2).unwrap();
    assert_eq!(child.pid(), INITIAL_GUEST_PID);
    assert_eq!(child.regs().rsp(), 0x7000_0000);
    assert_eq!(child.tls().fs_base(), 0x6000_0000);

    let exit = runtime.dispatch_syscall(context_for(
        INITIAL_GUEST_PID,
        2,
        Syscall::Exit,
        [0, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exit.result, SyscallReturn::Success(0));
    assert_eq!(u32_from_guest(runtime.memory(), 0x402004), 0);
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Running
    );
    assert_eq!(
        runtime.kernel().task(2).unwrap().state(),
        TaskState::Exited { status: 0 }
    );
    assert_eq!(runtime.kernel().task(2).unwrap().clear_child_tid(), None);
}

#[test]
fn set_tid_address_returns_current_guest_tid() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let set_tid =
        runtime.dispatch_syscall(context(Syscall::SetTidAddress, [0x402000, 0, 0, 0, 0, 0]));

    assert_eq!(
        set_tid.result,
        SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
    );
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .clear_child_tid(),
        Some(0x402000)
    );

    let clear_tid = runtime.dispatch_syscall(context(Syscall::SetTidAddress, [0, 0, 0, 0, 0, 0]));

    assert_eq!(
        clear_tid.result,
        SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
    );
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .clear_child_tid(),
        None
    );
}

#[test]
fn guest_run_loop_returns_existing_exit_status() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let exit = runtime.dispatch_syscall(context(Syscall::ExitGroup, [9, 0, 0, 0, 0, 0]));
    assert_eq!(exit.result, SyscallReturn::Success(0));

    let status = runtime
        .run_guest_until_exit()
        .expect("guest run returns already exited process status");

    assert_eq!(status, 9);
}

#[test]
fn guest_run_loop_surfaces_guest_execution_error() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0xc3, // ret
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::ExitGroup, [0; 6]);

    let error = runtime
        .run_guest_until_exit()
        .expect_err("guest run should stop on a block without syscall");

    assert_eq!(error.linux_errno(), LinuxErrno::ENOEXEC);
    assert!(matches!(
        error,
        GuestRunError::GuestExecution(GuestExecutionError::Execution(
            ExecutionError::MissingSyscall { .. }
        ))
    ));
}

#[test]
fn guest_run_errors_expose_linux_errno_shapes() {
    assert_eq!(
        GuestRunError::MissingInitialProcess.linux_errno(),
        LinuxErrno::ESRCH
    );
    assert_eq!(
        GuestRunError::MissingInitialTask.linux_errno(),
        LinuxErrno::ESRCH
    );
    assert_eq!(
        GuestRunError::InitialTaskNotRunnable {
            tid: INITIAL_GUEST_TID,
            state: TaskState::Exited { status: 1 },
        }
        .linux_errno(),
        LinuxErrno::ESRCH
    );
    assert_eq!(
        GuestRunError::GuestExecution(GuestExecutionError::Memory(GuestMemoryError::NotMapped))
            .linux_errno(),
        LinuxErrno::ENOMEM
    );
}

#[test]
fn guest_run_loop_surfaces_guest_memory_error() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x402000, Syscall::ExitGroup, [0; 6]);

    let error = runtime
        .run_guest_until_exit()
        .expect_err("guest run should stop on non-executable rip");

    assert_eq!(error.linux_errno(), LinuxErrno::EACCES);
    assert!(matches!(
        error,
        GuestRunError::GuestExecution(GuestExecutionError::Memory(GuestMemoryError::AccessDenied))
    ));
}

#[test]
fn runtime_dispatches_fork_child_exit_and_wait4() {
    let mut runtime = Runtime::new(test_program("/bin/parent", 0x401000)).unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime.kernel().process(2).unwrap().parent(),
        Some(INITIAL_GUEST_PID)
    );

    let child_exit =
        runtime.dispatch_syscall(context_for(2, 2, Syscall::ExitGroup, [23, 0, 0, 0, 0, 0]));
    assert_eq!(child_exit.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime.kernel().process(2).unwrap().exit_state(),
        ExitState::Exited { status: 23 }
    );

    let wait = runtime.dispatch_syscall(context(Syscall::Wait4, [-1i64 as u64, 0, 0, 0, 0, 0]));
    assert_eq!(wait.result, SyscallReturn::Success(2));
    assert!(runtime.kernel().process(2).is_none());
    assert!(runtime.kernel().task(2).is_none());
    assert!(
        !runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .children()
            .contains(&2)
    );
}

#[test]
fn guest_execution_can_dispatch_forked_child_task() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::Fork, [0; 6]);

    let parent_step = runtime
        .dispatch_guest_execution()
        .expect("parent fork syscall executes");
    assert_eq!(parent_step.tid(), INITIAL_GUEST_TID);
    assert_eq!(parent_step.encoded_rax(), 2);

    runtime
        .kernel_mut()
        .task_mut(2)
        .unwrap()
        .set_regs(GprState::with_syscall_registers(
            0x401000,
            0x8000_0000,
            Syscall::ExitGroup.number().raw(),
            [17, 0, 0, 0, 0, 0],
        ));

    let child_step = dispatch_guest_task_with_dispatcher(&mut runtime.dispatcher, 2)
        .expect("child exit syscall executes");
    assert_eq!(child_step.tid(), 2);
    assert_eq!(child_step.task_state(), TaskState::Exited { status: 17 });
    assert_eq!(
        runtime.kernel().process(2).unwrap().exit_state(),
        ExitState::Exited { status: 17 }
    );
}

#[test]
fn forked_child_memory_is_isolated_from_parent_memory() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let marker_addr = 0x402000;
    runtime.memory_mut().write(marker_addr, b"parent").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime
            .dispatch_syscall(context_for(
                2,
                2,
                Syscall::Write,
                [1, marker_addr, 5, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(5)
    );

    runtime
        .memory_for_process_mut(2)
        .unwrap()
        .write(marker_addr, b"child!")
        .unwrap();

    let mut parent_bytes = [0; 6];
    runtime
        .memory()
        .read(marker_addr, &mut parent_bytes)
        .unwrap();
    let mut child_bytes = [0; 6];
    runtime
        .memory_for_process(2)
        .unwrap()
        .read(marker_addr, &mut child_bytes)
        .unwrap();
    assert_eq!(&parent_bytes, b"parent");
    assert_eq!(&child_bytes, b"child!");
}

#[test]
fn runtime_fork_child_dup2_close_does_not_mutate_parent_fds() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    let parent_read_fd = i32_from_memory(runtime.memory(), 0x402000);
    let parent_write_fd = i32_from_memory(runtime.memory(), 0x402004);
    assert_eq!(parent_read_fd, 3);
    assert_eq!(parent_write_fd, 4);

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime
            .dispatch_syscall(context_for(
                2,
                2,
                Syscall::Dup2,
                [parent_write_fd as u64, 7, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(7)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context_for(
                2,
                2,
                Syscall::Close,
                [parent_write_fd as u64, 0, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );

    runtime.memory_mut().write(0x402100, b"ok").unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Write,
                [parent_write_fd as u64, 0x402100, 2, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(2)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Read,
                [parent_read_fd as u64, 0x402200, 2, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(2)
    );
    let mut bytes = [0; 2];
    runtime.memory().read(0x402200, &mut bytes).unwrap();
    assert_eq!(&bytes, b"ok");
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Close, [7, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EBADF)
    );
}

#[test]
fn runtime_fork_child_close_shared_socket_keeps_parent_socket_open() {
    let transport = runtime_socket_transport();
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ]
            ))
            .result,
        SyscallReturn::Success(3)
    );
    runtime.memory_mut().write(0x402000, b"ping").unwrap();
    runtime
        .memory_mut()
        .write(0x402100, &ipv4_sockaddr(8080))
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402100, SOCKADDR_IN_LEN as u64, 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime
            .dispatch_syscall(context_for(2, 2, Syscall::Close, [3, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Sendto, [3, 0x402000, 4, 0, 0, 0]))
            .result,
        SyscallReturn::Success(4)
    );
}

#[test]
fn forked_child_exec_replaces_only_child_memory() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
    runtime.memory_mut().write(0x402000, b"parent").unwrap();
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/new"
    );
    assert_eq!(runtime.kernel().task(2).unwrap().regs().rip(), 0x501000);
    let mut parent_bytes = [0; 6];
    runtime.memory().read(0x402000, &mut parent_bytes).unwrap();
    assert_eq!(&parent_bytes, b"parent");

    let mut loaded_text = [0; 4];
    runtime
        .memory_for_process(2)
        .unwrap()
        .read(0x501200, &mut loaded_text)
        .unwrap();
    assert_eq!(loaded_text, [0x5a; 4]);
    assert_eq!(
        runtime
            .memory_for_process(2)
            .unwrap()
            .read(0x402000, &mut [0; 1]),
        Err(GuestMemoryError::NotMapped)
    );
}

#[test]
fn fork_exec_defers_memory_clone_until_child_execve() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
    runtime.memory_mut().write(0x402000, b"parent").unwrap();
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert!(
        runtime
            .dispatcher
            .subsystems()
            .pending_fork_exec
            .contains_key(&2)
    );
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process_memory
            .contains_key(&2)
    );

    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .pending_fork_exec
            .contains_key(&2)
    );
    assert!(
        runtime
            .dispatcher
            .subsystems()
            .process_memory
            .contains_key(&2)
    );
    let mut parent_bytes = [0; 6];
    runtime.memory().read(0x402000, &mut parent_bytes).unwrap();
    assert_eq!(&parent_bytes, b"parent");
    assert_eq!(
        runtime
            .memory_for_process(2)
            .unwrap()
            .read(0x402000, &mut [0; 1]),
        Err(GuestMemoryError::NotMapped)
    );
}

#[test]
fn clone3_vfork_defers_memory_clone_until_child_execve() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();
    write_clone3_args(
        runtime.memory_mut(),
        0x402200,
        LINUX_CLONE_VM | LINUX_CLONE_VFORK,
        LINUX_SIGCHLD,
        0x7000_0000,
        0x1000,
    );

    let clone3 = runtime.dispatch_syscall(context(Syscall::Clone3, [0x402200, 88, 0, 0, 0, 0]));

    assert_eq!(clone3.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::WaitingForVfork { child_pid: 2 }
    );
    assert_eq!(runtime.kernel().task(2).unwrap().regs().rsp(), 0x7000_1000);
    assert!(
        runtime
            .dispatcher
            .subsystems()
            .pending_fork_exec
            .contains_key(&2)
    );
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process_memory
            .contains_key(&2)
    );

    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Runnable
    );
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/new"
    );
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .pending_fork_exec
            .contains_key(&2)
    );
}

#[test]
fn parent_memory_mutation_materializes_deferred_fork_child_first() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime.memory_mut().write(0x402000, b"parent").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert!(
        runtime
            .dispatcher
            .subsystems()
            .pending_fork_exec
            .contains_key(&2)
    );

    runtime.memory_mut().write(0x402000, b"PARENT").unwrap();

    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .pending_fork_exec
            .contains_key(&2)
    );
    let mut parent_bytes = [0; 6];
    runtime.memory().read(0x402000, &mut parent_bytes).unwrap();
    let mut child_bytes = [0; 6];
    runtime
        .memory_for_process(2)
        .unwrap()
        .read(0x402000, &mut child_bytes)
        .unwrap();
    assert_eq!(&parent_bytes, b"PARENT");
    assert_eq!(&child_bytes, b"parent");
}

#[test]
fn unsafe_share_until_exec_keeps_child_pending_after_parent_memory_write() {
    let _guard = env_test_guard();
    let _unsafe_share = TestUnsafeShareUntilExec::enable();
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content("/bin/new", test_program_bytes(0x501000), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();

    assert!(
        runtime
            .dispatcher
            .subsystems()
            .pending_fork_exec
            .contains_key(&2)
    );
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process_memory
            .contains_key(&2)
    );

    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/new"
    );
}

#[test]
fn deferred_fork_exec_failure_preserves_child_memory() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
    runtime.memory_mut().write(0x402000, b"parent").unwrap();
    runtime
        .memory_mut()
        .write(0x402100, b"/bin/missing\0")
        .unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Errno(LinuxErrno::ENOENT));
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .pending_fork_exec
            .contains_key(&2)
    );
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/old"
    );
    let mut child_bytes = [0; 6];
    runtime
        .memory_for_process(2)
        .unwrap()
        .read(0x402000, &mut child_bytes)
        .unwrap();
    assert_eq!(&child_bytes, b"parent");
}

#[test]
fn pending_fork_child_can_exec_from_read_only_parent_memory() {
    let mut exec_code = Vec::new();
    exec_code.extend_from_slice(&[0x48, 0xbf]);
    exec_code.extend_from_slice(&0x402100u64.to_le_bytes());
    exec_code.extend_from_slice(&[0x31, 0xf6, 0x31, 0xd2, 0xb8]);
    exec_code.extend_from_slice(&(Syscall::Execve.number().raw() as u32).to_le_bytes());
    exec_code.extend_from_slice(&[0x0f, 0x05]);

    let old_program = test_program_with_entry_code("/bin/old", 0x401000, &exec_code);
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", old_program.executable().bytes().to_vec(), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    let mut runtime = runtime_from_program_and_tree(old_program, tree);
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    runtime
        .kernel_mut()
        .task_mut(2)
        .unwrap()
        .set_regs(GprState::new(0x401000, 0x8000_0000));

    let step = dispatch_guest_task_with_dispatcher(&mut runtime.dispatcher, 2)
        .expect("pending child executes execve from parent memory");

    assert_eq!(step.tid(), 2);
    assert_eq!(step.task_state(), TaskState::Runnable);
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/new"
    );
    assert_eq!(runtime.kernel().task(2).unwrap().regs().rip(), 0x501000);
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .pending_fork_exec
            .contains_key(&2)
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

#[test]
fn native_fork_keeps_parent_and_child_memory_isolated() {
    let _guard = native_execution_test_guard();
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0xb8, 0x39, 0x00, 0x00, 0x00, // mov eax,fork
            0x0f, 0x05, // syscall
            0x85, 0xc0, // test eax,eax
            0x75, 0x19, // jne parent
            0x48, 0xbb, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx,0x402000
            0xc7, 0x03, b'c', b'h', b'l', b'd', // mov dword ptr [rbx],"chld"
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x31, 0xff, // xor edi,edi
            0x0f, 0x05, // syscall
            0x48, 0xbb, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx,0x402000
            0xc7, 0x03, b'p', b'a', b'r', b'e', // mov dword ptr [rbx],"pare"
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x31, 0xff, // xor edi,edi
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    runtime.enable_native_execution();
    runtime.memory_mut().write(0x402000, b"parent").unwrap();

    let fork = runtime
        .dispatch_guest_execution()
        .expect("parent native fork syscall executes");
    assert_eq!(fork.encoded_rax(), 2);

    let child = dispatch_guest_task_with_dispatcher(&mut runtime.dispatcher, 2)
        .expect("child native branch exits");
    assert_eq!(child.task_state(), TaskState::Exited { status: 0 });

    let mut parent_bytes = [0; 6];
    runtime.memory().read(0x402000, &mut parent_bytes).unwrap();

    assert_eq!(&parent_bytes, b"parent");
}

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
fn runtime_execve_reads_filename_argv_envp_from_guest_memory_and_vfs() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    tree.mount_minimal_procfs().unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();
    runtime.memory_mut().write(0x402120, b"/bin/new\0").unwrap();
    runtime.memory_mut().write(0x402140, b"--flag\0").unwrap();
    runtime
        .memory_mut()
        .write(0x402160, b"PATH=/bin\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0x402120u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402008, &0x402140u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402010, &0u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402040, &0x402160u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402048, &0u64.to_le_bytes())
        .unwrap();

    let exec = runtime.dispatch_syscall(context(
        Syscall::Execve,
        [0x402100, 0x402000, 0x402040, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(process.image().executable().path(), b"/bin/new");
    assert_eq!(
        process.image().argv(),
        &[b"/bin/new".to_vec(), b"--flag".to_vec()]
    );
    assert_eq!(process.image().envp(), &[b"PATH=/bin".to_vec()]);
    assert_eq!(task.regs().rip(), 0x501000);
    let mut loaded_text = [0; 4];
    runtime.memory().read(0x501200, &mut loaded_text).unwrap();
    assert_eq!(loaded_text, [0x5a; 4]);

    runtime
        .memory_mut()
        .write(0x502100, b"/proc/self/cmdline\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x502140, b"/proc/self/environ\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x502180, b"/proc/self/exe\0")
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Openat,
                [AT_FDCWD as u64, 0x502100, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Read, [3, 0x502300, 64, 0, 0, 0]))
            .result,
        SyscallReturn::Success(16)
    );
    let mut cmdline = [0; 16];
    runtime.memory().read(0x502300, &mut cmdline).unwrap();
    assert_eq!(&cmdline, b"/bin/new\0--flag\0");
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Openat,
                [AT_FDCWD as u64, 0x502140, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(4)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Read, [4, 0x502320, 64, 0, 0, 0]))
            .result,
        SyscallReturn::Success(10)
    );
    let mut environ = [0; 10];
    runtime.memory().read(0x502320, &mut environ).unwrap();
    assert_eq!(&environ, b"PATH=/bin\0");
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Readlink,
                [0x502180, 0x502340, 64, 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(8)
    );
    let mut exe = [0; 8];
    runtime.memory().read(0x502340, &mut exe).unwrap();
    assert_eq!(&exe, b"/bin/new");
}

#[test]
fn runtime_execve_loads_interpreter_from_vfs() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_dir("/lib").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/dynamic",
        dynamic_program_bytes("/lib/ld-musl-x86_64.so.1"),
        0o755,
    )
    .unwrap();
    tree.create_file_with_content("/lib/ld-musl-x86_64.so.1", interpreter_bytes(), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

    runtime
        .memory_mut()
        .write(0x402100, b"/bin/dynamic\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402120, b"/bin/dynamic\0")
        .unwrap();
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
    let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(process.image().executable().path(), b"/bin/dynamic");
    assert_eq!(
        process.image().interpreter().unwrap().path(),
        b"/lib/ld-musl-x86_64.so.1"
    );
    assert_eq!(
        task.regs().rip(),
        mcr_elf::DEFAULT_INTERPRETER_LOAD_BASE + 0x400
    );
}

#[test]
fn runtime_execve_missing_vfs_target_keeps_current_image() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

    runtime
        .memory_mut()
        .write(0x402100, b"/bin/missing\0")
        .unwrap();

    let exec = runtime.dispatch_syscall(context(Syscall::Execve, [0x402100, 0, 0, 0, 0, 0]));

    assert_eq!(exec.result, SyscallReturn::Errno(LinuxErrno::ENOENT));
    let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(process.image().executable().path(), b"/bin/old");
    assert_eq!(task.regs().rip(), 0x401000);
}

#[test]
fn runtime_tracer_records_task_syscall_events() {
    let mut runtime = Runtime::with_tracer(
        test_program("/bin/app", 0x401000),
        InMemorySyscallTracer::new(),
    )
    .unwrap();

    let result = runtime.dispatch_syscall(context(Syscall::Gettid, [0; 6]));

    assert_eq!(result.result, SyscallReturn::Success(1));
    assert!(matches!(
        runtime.tracer().events(),
        [SyscallTraceEvent::Enter(_), SyscallTraceEvent::Exit(_)]
    ));
}

#[test]
fn runtime_diagnostics_tracer_bounds_retained_events() {
    let mut tracer = RuntimeDiagnosticsTracer::new();
    for index in 0..(RUNTIME_DIAGNOSTICS_EVENT_LIMIT + 17) {
        tracer.record(SyscallTraceEvent::Exit(SyscallExitEvent {
            context: TraceContext {
                pid: INITIAL_GUEST_PID,
                tid: INITIAL_GUEST_TID,
                rip: index as u64,
            },
            syscall: Syscall::Getpid,
            args: SyscallArgs::new([0; 6]),
            result: SyscallReturn::Success(index as u64),
            decoded: Vec::new(),
            host_error: None,
        }));
    }

    assert_eq!(tracer.events().len(), RUNTIME_DIAGNOSTICS_EVENT_DRAIN + 17);
    assert_eq!(
        tracer.dropped_events(),
        RUNTIME_DIAGNOSTICS_EVENT_DRAIN as u64
    );
    let last = tracer.last_syscall().unwrap();
    assert_eq!(last.name(), "getpid");
    assert_eq!(
        last.result(),
        Some(SyscallReturn::Success(
            (RUNTIME_DIAGNOSTICS_EVENT_LIMIT + 16) as u64
        ))
    );
}

#[test]
fn runtime_getpid_gettid_fast_path_preserves_trace_and_esrch() {
    let mut runtime = Runtime::with_tracer(
        test_program("/bin/app", 0x401000),
        InMemorySyscallTracer::new(),
    )
    .unwrap();

    let getpid = runtime.dispatch_syscall(context(Syscall::Getpid, [0; 6]));
    let gettid = runtime.dispatch_syscall(context(Syscall::Gettid, [0; 6]));
    let invalid_gettid = runtime.dispatch_syscall(context_for(
        INITIAL_GUEST_PID,
        INITIAL_GUEST_TID + 99,
        Syscall::Gettid,
        [0; 6],
    ));

    assert_eq!(
        getpid.result,
        SyscallReturn::Success(u64::from(INITIAL_GUEST_PID))
    );
    assert_eq!(
        gettid.result,
        SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
    );
    assert_eq!(
        invalid_gettid.result,
        SyscallReturn::Errno(LinuxErrno::ESRCH)
    );
    assert!(matches!(
        runtime.tracer().events(),
        [
            SyscallTraceEvent::Enter(_),
            SyscallTraceEvent::Exit(_),
            SyscallTraceEvent::Enter(_),
            SyscallTraceEvent::Exit(_),
            SyscallTraceEvent::Enter(_),
            SyscallTraceEvent::Exit(_)
        ]
    ));
}

#[test]
fn task_time_resource_fake_syscalls_write_compat_structs() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::SchedYield, [0; 6]))
            .result,
        SyscallReturn::Success(0)
    );

    let gettimeofday = runtime.dispatch_syscall(context(
        Syscall::Gettimeofday,
        [0x402000, 0x402020, 0, 0, 0, 0],
    ));
    assert_eq!(gettimeofday.result, SyscallReturn::Success(0));
    assert!(u64_from_guest(runtime.memory(), 0x402000) > 0);
    assert!(u64_from_guest(runtime.memory(), 0x402008) < 1_000_000);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402020), 0);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402024), 0);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Gettimeofday, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );

    let clock_getres =
        runtime.dispatch_syscall(context(Syscall::ClockGetres, [1, 0x402040, 0, 0, 0, 0]));
    assert_eq!(clock_getres.result, SyscallReturn::Success(0));
    assert_eq!(i64_from_guest(runtime.memory(), 0x402040), 0);
    assert_eq!(i64_from_guest(runtime.memory(), 0x402048), 1_000_000);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::ClockGetres, [99, 0x402040, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    let getrlimit =
        runtime.dispatch_syscall(context(Syscall::Getrlimit, [7, 0x402100, 0, 0, 0, 0]));
    assert_eq!(getrlimit.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402100), 1024);
    assert_eq!(u64_from_guest(runtime.memory(), 0x402108), 1024);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Getrlimit, [99, 0x402100, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    runtime.memory_mut().write(0x402180, &[0xaa; 144]).unwrap();
    let getrusage =
        runtime.dispatch_syscall(context(Syscall::Getrusage, [0, 0x402180, 0, 0, 0, 0]));
    assert_eq!(getrusage.result, SyscallReturn::Success(0));
    let mut rusage = [0xaa; 144];
    runtime.memory().read(0x402180, &mut rusage).unwrap();
    assert_eq!(rusage, [0; 144]);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Getrusage, [9, 0x402180, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    let sysinfo = runtime.dispatch_syscall(context(Syscall::Sysinfo, [0x402300, 0, 0, 0, 0, 0]));
    assert_eq!(sysinfo.result, SyscallReturn::Success(0));
    assert_eq!(i64_from_guest(runtime.memory(), 0x402300), 3600);
    assert_eq!(
        u64_from_guest(runtime.memory(), 0x402320),
        512 * 1024 * 1024
    );
    assert_eq!(u16_from_guest(runtime.memory(), 0x402350), 1);
}

#[test]
fn task_time_resource_fake_syscalls_handle_limits_prctl_cpu_and_fallbacks() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    runtime
        .memory_mut()
        .write(0x402000, &512u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402008, &1024u64.to_le_bytes())
        .unwrap();
    let prlimit64 = runtime.dispatch_syscall(context(
        Syscall::Prlimit64,
        [0, 7, 0x402000, 0x402100, 0, 0],
    ));
    assert_eq!(prlimit64.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402100), 1024);
    assert_eq!(u64_from_guest(runtime.memory(), 0x402108), 1024);

    runtime
        .memory_mut()
        .write(0x402000, &2048u64.to_le_bytes())
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Prlimit64, [0, 7, 0x402000, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Prlimit64, [999, 7, 0, 0x402100, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::ESRCH)
    );

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Prctl,
                [LINUX_PR_GET_DUMPABLE, 0, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(1)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Prctl,
                [LINUX_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Prctl,
                [LINUX_PR_GET_NAME, 0x402200, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    let mut name = [0; 4];
    runtime.memory().read(0x402200, &mut name).unwrap();
    assert_eq!(&name, b"mcr\0");
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Prctl, [0xffff, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    let getcpu =
        runtime.dispatch_syscall(context(Syscall::Getcpu, [0x402300, 0x402304, 0, 0, 0, 0]));
    assert_eq!(getcpu.result, SyscallReturn::Success(0));
    assert_eq!(u32_from_guest(runtime.memory(), 0x402300), 0);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402304), 0);

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Membarrier, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Membarrier, [1, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::ENOSYS)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Membarrier, [0, 1, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Rseq, [0x402000, 32, 0, 0x53053053, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::ENOSYS)
    );
}

#[test]
fn runtime_dispatches_fake_syscall_compat_behaviors() {
    let mut runtime = Runtime::with_tracer_and_vfs(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        InMemorySyscallTracer::new(),
    )
    .unwrap();

    let gettimeofday = runtime.dispatch_syscall(context(
        Syscall::Gettimeofday,
        [0x402000, 0x402020, 0, 0, 0, 0],
    ));
    assert_eq!(gettimeofday.result, SyscallReturn::Success(0));
    assert!(u64_from_guest(runtime.memory(), 0x402000) > 0);
    assert!(u64_from_guest(runtime.memory(), 0x402008) < 1_000_000);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402020), 0);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402024), 0);

    let getrlimit =
        runtime.dispatch_syscall(context(Syscall::Getrlimit, [7, 0x402100, 0, 0, 0, 0]));
    assert_eq!(getrlimit.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402100), 1024);
    assert_eq!(u64_from_guest(runtime.memory(), 0x402108), 1024);

    let sysinfo = runtime.dispatch_syscall(context(Syscall::Sysinfo, [0x402200, 0, 0, 0, 0, 0]));
    assert_eq!(sysinfo.result, SyscallReturn::Success(0));
    assert_eq!(i64_from_guest(runtime.memory(), 0x402200), 3600);
    assert_eq!(
        u64_from_guest(runtime.memory(), 0x402220),
        512 * 1024 * 1024
    );
    assert_eq!(u16_from_guest(runtime.memory(), 0x402250), 1);

    let getcpu =
        runtime.dispatch_syscall(context(Syscall::Getcpu, [0x402300, 0x402304, 0, 0, 0, 0]));
    assert_eq!(getcpu.result, SyscallReturn::Success(0));
    assert_eq!(u32_from_guest(runtime.memory(), 0x402300), 0);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402304), 0);

    runtime
        .memory_mut()
        .write(0x402400, b"/tmp/file\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402500, &u64::from(O_RDONLY).to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402508, &0u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402510, &0u64.to_le_bytes())
        .unwrap();
    let openat2 = runtime.dispatch_syscall(context(
        Syscall::Openat2,
        [AT_FDCWD as u64, 0x402400, 0x402500, 24, 0, 0],
    ));
    assert_eq!(openat2.result, SyscallReturn::Success(3));

    let faccessat2 = runtime.dispatch_syscall(context(
        Syscall::Faccessat2,
        [AT_FDCWD as u64, 0x402400, u64::from(mcr_vfs::R_OK), 0, 0, 0],
    ));
    assert_eq!(faccessat2.result, SyscallReturn::Success(0));

    let statfs =
        runtime.dispatch_syscall(context(Syscall::Statfs, [0x402400, 0x402600, 0, 0, 0, 0]));
    assert_eq!(statfs.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402600), 0xef53);
    assert_eq!(u64_from_guest(runtime.memory(), 0x402608), 4096);

    let fstatfs = runtime.dispatch_syscall(context(Syscall::Fstatfs, [3, 0x402700, 0, 0, 0, 0]));
    assert_eq!(fstatfs.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402700), 0xef53);

    let close_range = runtime.dispatch_syscall(context(Syscall::CloseRange, [3, 3, 0, 0, 0, 0]));
    assert_eq!(close_range.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Fstatfs, [3, 0x402800, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EBADF)
    );

    assert!(runtime.tracer().events().iter().any(|event| matches!(
        event,
        SyscallTraceEvent::Exit(exit)
            if exit.syscall == Syscall::Openat2
                && exit.result == SyscallReturn::Success(3)
    )));
}

#[test]
fn runtime_unimplemented_fake_syscalls_return_enosys_and_trace_args() {
    let syscall = Syscall::Rseq;
    let args = [0x402000, 32, 0, 0x53053053, 0, 0];
    let decoded_field = ("rseq", "0x402000");
    let mut runtime = Runtime::with_tracer(
        test_program("/bin/app", 0x401000),
        InMemorySyscallTracer::new(),
    )
    .unwrap();

    let result = runtime.dispatch_syscall(context(syscall, args));

    assert_eq!(
        result.result,
        SyscallReturn::Errno(LinuxErrno::ENOSYS),
        "{syscall}"
    );
    match runtime.tracer().events() {
        [
            SyscallTraceEvent::Enter(enter),
            SyscallTraceEvent::Exit(exit),
        ] => {
            assert_eq!(enter.syscall, syscall);
            assert_eq!(exit.syscall, syscall);
            assert_eq!(exit.result, SyscallReturn::Errno(LinuxErrno::ENOSYS));
            assert!(
                exit.decoded
                    .iter()
                    .any(|field| field.name == decoded_field.0 && field.value == decoded_field.1),
                "{syscall} should preserve decoded argument {decoded_field:?}"
            );
        }
        other => panic!("expected enter and exit trace for {syscall}, got {other:?}"),
    }
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
        .native_image_patch_keys
        .clear();
    runtime
        .dispatcher
        .subsystems_mut()
        .native_image_patch_ranges
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
            .native_patch_caches
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
            .native_patch_caches
            .get(&pid)
            .unwrap()
            .scanned_ranges
            .iter()
            .any(|(start, end)| *start <= 0x600000 && 0x600000 < *end)
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
        .native_image_patch_keys
        .get(&pid)
        .cloned()
        .expect("test image should have native patch key");
    let ranges = runtime
        .dispatcher
        .subsystems()
        .native_image_patch_ranges
        .get(&pid)
        .cloned()
        .expect("test image should have native patch ranges");
    runtime
        .dispatcher
        .subsystems_mut()
        .native_image_patch_metadata
        .insert(
            key,
            NativePatchMetadataEntry {
                base: ranges.base,
                metadata: NativePatchMetadata {
                    scanned_ranges: ranges.ranges,
                    syscall_patches: vec![ExecutableSyscallPatch { address: 0x401000 }],
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    fs_relative_patches: BTreeMap::new(),
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
        subsystems.native_image_patch_keys.remove(&pid);
        subsystems.native_image_patch_ranges.remove(&pid);
        subsystems.native_image_patch_metadata.insert(
            key,
            NativePatchMetadataEntry {
                base: 0x500000,
                metadata: NativePatchMetadata {
                    scanned_ranges: vec![(0x500000, 0x500000 + (end - start))],
                    syscall_patches: vec![ExecutableSyscallPatch { address: 0x500000 }],
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    fs_relative_patches: BTreeMap::new(),
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
        .native_patch_caches
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
            .native_patch_caches
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
            .native_patch_caches
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

#[test]
fn runtime_exec_replaces_guest_image_and_keeps_guest_identity() {
    let mut runtime = Runtime::new(test_program("/bin/old", 0x401000)).unwrap();

    runtime
        .kernel_mut()
        .exec_task(INITIAL_GUEST_TID, test_program("/bin/new", 0x501000))
        .unwrap();

    let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();

    assert_eq!(process.pid(), INITIAL_GUEST_PID);
    assert_eq!(task.tid(), INITIAL_GUEST_TID);
    assert_eq!(process.image().executable().path(), b"/bin/new");
    assert_eq!(task.regs().rip(), 0x501000);
}

#[test]
fn diagnostics_capture_image_vmas_and_last_syscall() {
    let mut runtime = RuntimeWithTracer::with_diagnostics(test_program_with_args(
        "/bin/app",
        0x401000,
        ["/bin/app", "--flag"],
        ["A=B"],
    ))
    .unwrap();

    let result = runtime.dispatch_syscall(context(Syscall::Getpid, [0; 6]));
    assert_eq!(result.result, SyscallReturn::Success(1));

    let diagnostics = runtime.diagnostics();
    let last = diagnostics.last_syscall().unwrap();

    assert_eq!(diagnostics.executable_path(), b"/bin/app");
    assert_eq!(
        diagnostics.argv(),
        &[b"/bin/app".to_vec(), b"--flag".to_vec()]
    );
    assert_eq!(diagnostics.envp(), &[b"A=B".to_vec()]);
    assert_eq!(diagnostics.worker_pools().len(), 2);
    assert!(
        diagnostics
            .worker_pools()
            .iter()
            .all(|pool| pool.max_workers() > 0 && pool.active_workers() == 0)
    );
    assert!(diagnostics.vmas().iter().any(|vma| {
        vma.start() <= 0x401000
            && 0x401000 < vma.end()
            && vma.permissions().execute()
            && matches!(
                vma.kind(),
                DiagnosticVmaKind::ElfLoad {
                    program_header_index: 0,
                    ..
                }
            )
    }));
    assert!(diagnostics.vmas().iter().any(|vma| {
        matches!(vma.kind(), DiagnosticVmaKind::Stack) && vma.permissions().write()
    }));
    assert_eq!(last.name(), "getpid");
    assert_eq!(last.number(), Syscall::GETPID.raw());
    assert_eq!(last.args(), [0; 6]);
    assert_eq!(last.result(), Some(SyscallReturn::Success(1)));
    assert_eq!(last.rip(), 0x401234);
}

#[test]
fn stall_diagnostic_identifies_guest_wait_futex() {
    let runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let events = vec![syscall_enter_event(
        Syscall::Futex,
        [0x402000, u64::from(LINUX_FUTEX_WAIT), 7, 0, 0, 0],
    )];

    let diagnostic = RuntimeDiagnostics::capture(runtime.kernel(), &events).stall_diagnostic();

    assert_eq!(diagnostic.kind(), RuntimeStallKind::GuestWaitFutex);
    assert_eq!(diagnostic.in_flight_syscall().unwrap().name(), "futex");
}

#[test]
fn stall_diagnostic_identifies_readiness_wait() {
    let mut runtime =
        RuntimeWithTracer::with_diagnostics(test_program("/bin/app", 0x401000)).unwrap();
    runtime
        .kernel_mut()
        .block_task_for_fd(INITIAL_GUEST_TID, 3, false)
        .unwrap();

    let diagnostic = runtime.stall_diagnostic();

    assert_eq!(diagnostic.kind(), RuntimeStallKind::Readiness);
    assert_eq!(diagnostic.fd_wait_tasks(), 1);
}

#[test]
fn stall_diagnostic_identifies_scheduling_wait() {
    let mut runtime =
        RuntimeWithTracer::with_diagnostics(test_program("/bin/app", 0x401000)).unwrap();
    let child_pid = runtime.kernel_mut().fork_child(INITIAL_GUEST_TID).unwrap();
    let wait = runtime.kernel_mut().wait4_current(
        INITIAL_GUEST_TID,
        Wait4SyscallArgs::new(child_pid as i32, 0x402000, 0, 0),
    );
    assert_eq!(wait.result, SyscallReturn::Success(0));

    let diagnostic = runtime.stall_diagnostic();

    assert_eq!(diagnostic.kind(), RuntimeStallKind::Scheduling);
    assert_eq!(diagnostic.child_wait_tasks(), 1);
}

#[test]
fn stall_diagnostic_identifies_native_execution_window() {
    let _guard = native_execution_test_guard();
    let mut runtime =
        RuntimeWithTracer::with_diagnostics(test_program("/bin/app", 0x401000)).unwrap();
    runtime.enable_native_execution();

    let diagnostic = runtime.stall_diagnostic();

    assert_eq!(diagnostic.kind(), RuntimeStallKind::NativeExecution);
    assert_eq!(diagnostic.runnable_tasks(), 1);
}

#[test]
fn bounded_guest_run_reports_timeout_stall_diagnostic() {
    let _guard = native_execution_test_guard();
    let mut code = vec![0xb8];
    code.extend_from_slice(&(Syscall::Getpid.number().raw() as u32).to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0xeb, 0xf7]);
    let mut runtime = RuntimeWithTracer::with_diagnostics(test_program_with_entry_code(
        "/bin/spin",
        0x401000,
        &code,
    ))
    .unwrap();
    runtime.enable_native_execution();

    let error = runtime
        .run_guest_until_exit_with_step_limit(3)
        .expect_err("looping guest should hit the diagnostic step limit");

    match error {
        GuestRunError::StepLimitExceeded { steps, diagnostic } => {
            assert_eq!(steps, 3);
            assert_eq!(diagnostic.kind(), RuntimeStallKind::NativeExecution);
            assert_eq!(diagnostic.last_syscall().unwrap().name(), "getpid");
            assert_eq!(
                diagnostic.last_syscall().unwrap().result(),
                Some(SyscallReturn::Success(1))
            );
        }
        other => panic!("expected step-limit diagnostic, got {other:?}"),
    }
}

#[test]
fn crash_report_includes_registers_and_runtime_diagnostics() {
    let mut runtime =
        RuntimeWithTracer::with_diagnostics(test_program("/bin/app", 0x401000)).unwrap();
    runtime.dispatch_syscall(context(Syscall::Gettid, [0; 6]));

    let registers = GuestRegisters {
        rax: Syscall::Gettid.number().raw(),
        rip: 0x401234,
        rsp: runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rsp(),
        ..GuestRegisters::default()
    };
    let report = runtime.crash_report("invalid instruction", registers);

    assert_eq!(report.reason(), "invalid instruction");
    assert_eq!(report.registers(), registers);
    assert_eq!(report.diagnostics().executable_path(), b"/bin/app");
    assert_eq!(
        report.diagnostics().last_syscall().unwrap().name(),
        "gettid"
    );
}

fn syscall_enter_event(syscall: Syscall, args: [u64; 6]) -> SyscallTraceEvent {
    SyscallTraceEvent::Enter(SyscallEnterEvent {
        context: TraceContext {
            pid: INITIAL_GUEST_PID,
            tid: INITIAL_GUEST_TID,
            rip: 0x401234,
        },
        syscall,
        args: SyscallArgs::new(args),
        decoded: Vec::new(),
    })
}

fn context(syscall: Syscall, args: [u64; 6]) -> GuestContext {
    context_for(INITIAL_GUEST_PID, INITIAL_GUEST_TID, syscall, args)
}

fn context_for(pid: u32, tid: u32, syscall: Syscall, args: [u64; 6]) -> GuestContext {
    GuestContext::new(
        pid,
        tid,
        SyscallRegisters {
            rax: syscall.number().raw(),
            rdi: args[0],
            rsi: args[1],
            rdx: args[2],
            r10: args[3],
            r8: args[4],
            r9: args[5],
            rip: 0x401234,
        },
    )
}

fn set_initial_syscall_regs(runtime: &mut Runtime, rip: u64, syscall: Syscall, args: [u64; 6]) {
    let rsp = runtime
        .kernel()
        .task(INITIAL_GUEST_TID)
        .unwrap()
        .regs()
        .rsp();
    runtime
        .kernel_mut()
        .task_mut(INITIAL_GUEST_TID)
        .unwrap()
        .set_regs(GprState::with_syscall_registers(
            rip,
            rsp,
            syscall.number().raw(),
            args,
        ));
}

fn unique_test_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("mcr-{name}-{}-{nanos}", std::process::id()))
}

fn test_program(path: &str, entrypoint: u64) -> GuestProgram {
    GuestProgram::new(GuestExecutable::new(
        path.as_bytes().to_vec(),
        test_program_bytes(entrypoint),
    ))
}

fn test_program_bytes(entrypoint: u64) -> Vec<u8> {
    test_program_bytes_with_marker(entrypoint, 0x90)
}

fn test_program_with_entry_code(path: &str, entrypoint: u64, code: &[u8]) -> GuestProgram {
    GuestProgram::new(GuestExecutable::new(
        path.as_bytes().to_vec(),
        test_program_bytes_with_entry_code(entrypoint, code),
    ))
}

fn test_program_bytes_with_entry_code(entrypoint: u64, code: &[u8]) -> Vec<u8> {
    Elf64Builder::new()
        .entrypoint(entrypoint)
        .program_header(Elf64ProgramHeader::load(
            PF_R | PF_X,
            0x1000,
            entrypoint & !0xfff,
            0x1000,
            0x1000,
        ))
        .program_header(Elf64ProgramHeader::load(
            PF_R | PF_W,
            0x2000,
            (entrypoint & !0xfff) + 0x1000,
            0x08,
            0x100,
        ))
        .program_header(Elf64ProgramHeader::load(
            PF_R,
            0,
            (entrypoint & !0xfff) + 0x2000,
            0x100,
            0x100,
        ))
        .data_at(0x1000 + (entrypoint & 0xfff), code.to_vec())
        .data_at(0x2000, vec![0; 0x08])
        .build()
}

fn test_program_bytes_with_marker(entrypoint: u64, marker: u8) -> Vec<u8> {
    Elf64Builder::new()
        .entrypoint(entrypoint)
        .program_header(Elf64ProgramHeader::load(
            PF_R | PF_X,
            0,
            entrypoint & !0xfff,
            0x1000,
            0x1000,
        ))
        .program_header(Elf64ProgramHeader::load(
            PF_R | PF_W,
            0x2000,
            (entrypoint & !0xfff) + 0x1000,
            0x08,
            0x100,
        ))
        .data_at(0x200, vec![marker; 0x20])
        .data_at(0x2000, vec![0; 0x08])
        .build()
}

fn dynamic_program_bytes(interpreter: &str) -> Vec<u8> {
    let mut interpreter_path = interpreter.as_bytes().to_vec();
    interpreter_path.push(0);
    Elf64Builder::new()
        .object_type(mcr_testkit::elf::ET_DYN)
        .entrypoint(0x1010)
        .program_header(Elf64ProgramHeader::new(
            mcr_testkit::elf::PT_INTERP,
            PF_R,
            0x300,
            0,
            interpreter_path.len() as u64,
            interpreter_path.len() as u64,
            1,
        ))
        .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x2000))
        .data_at(0x300, interpreter_path)
        .data_at(0x400, vec![0x90; 4])
        .build()
}

fn interpreter_bytes() -> Vec<u8> {
    Elf64Builder::new()
        .object_type(mcr_testkit::elf::ET_DYN)
        .entrypoint(0x400)
        .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x1000))
        .data_at(0x400, vec![0x90; 4])
        .build()
}

fn test_program_with_args<const A: usize, const E: usize>(
    path: &str,
    entrypoint: u64,
    argv: [&str; A],
    envp: [&str; E],
) -> GuestProgram {
    test_program(path, entrypoint)
        .with_args(argv.map(|value| value.as_bytes().to_vec()))
        .with_env(envp.map(|value| value.as_bytes().to_vec()))
}
