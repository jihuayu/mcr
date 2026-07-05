use super::support::*;

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
