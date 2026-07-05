use super::support::*;

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
fn private_futex_wait_finite_timeout_blocks_until_deadline() {
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
        .write(0x402108, &1_000_000i64.to_le_bytes())
        .unwrap();

    let wait = runtime.dispatch_syscall(context(
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

    assert_eq!(wait.result, SyscallReturn::Success(0));
    assert!(matches!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::WaitingForFutex { .. }
    ));

    runtime
        .dispatcher
        .subsystems_mut()
        .expire_next_futex_timeout();

    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(task.state(), TaskState::Runnable);
    assert_eq!(
        task.regs().rax(),
        SyscallReturn::Errno(LinuxErrno::ETIMEDOUT).encode_u64()
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

#[test]
fn epoll_wait_infinite_timeout_blocks_until_eventfd_ready() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Eventfd2, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::EpollCreate1, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(4)
    );
    write_epoll_event_for_test(runtime.memory_mut(), 0x402100, LINUX_EPOLLIN, 0x77);
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::EpollCtl,
                [4, u64::from(LINUX_EPOLL_CTL_ADD), 3, 0x402100, 0, 0],
            ))
            .result,
        SyscallReturn::Success(0)
    );

    let would_block = runtime.dispatch_syscall(context(
        Syscall::EpollWait,
        [4, 0x402200, 4, u64::MAX, 0, 0],
    ));
    assert_eq!(would_block.result, SyscallReturn::Errno(LinuxErrno::EAGAIN));

    runtime
        .memory_mut()
        .write(0x402300, &1u64.to_le_bytes())
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Write, [3, 0x402300, 8, 0, 0, 0]))
            .result,
        SyscallReturn::Success(8)
    );
    let ready = runtime.dispatch_syscall(context(
        Syscall::EpollWait,
        [4, 0x402200, 4, u64::MAX, 0, 0],
    ));
    assert_eq!(ready.result, SyscallReturn::Success(1));
    assert_eq!(
        epoll_event_from_memory(runtime.memory(), 0x402200),
        (LINUX_EPOLLIN, 0x77)
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
