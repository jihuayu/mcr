use super::support::*;

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
fn bind_listen_and_getsockname_round_trip_unix_sockaddr() {
    let mut runtime = runtime_with_sample_vfs();
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(LINUX_AF_UNIX),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_IP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );

    let address = unix_sockaddr(b"/tmp/mysql.sock");
    runtime.memory_mut().write(0x2000, &address);
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Bind,
            [3, 0x2000, address.len() as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_network(&mut runtime, Syscall::Listen, [3, 128, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );

    runtime.memory_mut().write(0x2100, &[0xaa; SOCKADDR_UN_LEN]);
    runtime
        .memory_mut()
        .write(0x2200, &(SOCKADDR_UN_LEN as u32).to_le_bytes());
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Getsockname,
            [3, 0x2100, 0x2200, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );

    assert_eq!(u32_at(runtime.memory(), 0x2200), address.len() as u32);
    assert_eq!(runtime.memory().read(0x2100, address.len()), address);
    assert_eq!(
        runtime
            .sockets()
            .socket(SocketId::new(1).unwrap())
            .unwrap()
            .state(),
        SocketState::Listening(SocketAddress::unix(b"/tmp/mysql.sock").unwrap())
    );
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
