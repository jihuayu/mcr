use super::support::*;

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
