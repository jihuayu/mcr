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
