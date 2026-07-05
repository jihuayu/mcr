use super::support::*;

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
fn poll_coalesces_multiple_socket_timeout_checks() {
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

    for fd in [3, 4] {
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
            SyscallReturn::Success(fd)
        );
        assert_eq!(
            runtime
                .dispatch_syscall(context(
                    Syscall::Connect,
                    [fd, 0x402000, SOCKADDR_IN_LEN as u64, 0, 0, 0]
                ))
                .result,
            SyscallReturn::Success(0)
        );
    }
    write_pollfd(runtime.memory_mut(), 0x402100, 3, LINUX_POLLIN);
    write_pollfd(runtime.memory_mut(), 0x402108, 4, LINUX_POLLIN);

    let result = runtime.dispatch_syscall(context(Syscall::Poll, [0x402100, 2, 25, 0, 0, 0]));

    assert_eq!(result.result, SyscallReturn::Success(0));
    assert_eq!(pollfd_revents(runtime.memory(), 0x402100), 0);
    assert_eq!(pollfd_revents(runtime.memory(), 0x402108), 0);
    assert_eq!(
        transport.poll_timeouts(),
        vec![Some(Duration::from_millis(25)), Some(Duration::ZERO)]
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
