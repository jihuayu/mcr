use super::support::*;

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
