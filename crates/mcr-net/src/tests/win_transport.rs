use super::support::*;

#[cfg(windows)]
#[test]
fn win_host_transport_connectex_completes_nonblocking_connect() {
    let stack = NetworkStack::start().expect("network stack");
    let listener = stack
        .open_socket(
            AddressFamily::Inet,
            SocketKind::Stream,
            HostSocketProtocol::Tcp,
        )
        .expect("listener socket");
    listener
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let server_addr = SocketAddress::from(listener.local_addr().unwrap());

    let mut table =
        GuestSocketTable::with_transport(WinHostSocketTransport::new().expect("host transport"));
    let client = table
        .create_socket_from_spec(
            SocketSpec::with_flags(
                SocketDomain::Inet,
                SocketType::Stream,
                SocketProtocol::Tcp,
                SocketCreationFlags {
                    nonblocking: true,
                    cloexec: false,
                },
            )
            .expect("tcp spec"),
        )
        .expect("client socket");

    assert_eq!(
        table
            .connect(client, server_addr)
            .expect_err("ConnectEx should be pending")
            .linux_errno(),
        LinuxErrno::OperationInProgress
    );
    for _ in 0..10 {
        let _ = table.poll(
            client,
            SocketEvents::write(),
            Some(Duration::from_millis(50)),
        );
        if matches!(
            table.socket(client).expect("client state").state(),
            SocketState::Connected { .. }
        ) {
            break;
        }
    }
    assert!(matches!(
        table.socket(client).expect("client state").state(),
        SocketState::Connected { .. }
    ));
    let (server, _) = listener.accept().unwrap();
    assert_eq!(
        table.peer_address(client).expect("peer address"),
        Some(SocketAddress::from(server.local_addr().unwrap()))
    );
}

#[cfg(windows)]
#[test]
fn win_host_transport_acceptex_completes_nonblocking_accept() {
    let mut table =
        GuestSocketTable::with_transport(WinHostSocketTransport::new().expect("host transport"));
    let listener = table
        .create_socket_from_spec(
            SocketSpec::with_flags(
                SocketDomain::Inet,
                SocketType::Stream,
                SocketProtocol::Tcp,
                SocketCreationFlags {
                    nonblocking: true,
                    cloexec: false,
                },
            )
            .expect("tcp spec"),
        )
        .expect("listener socket");
    table
        .set_option(listener, SocketOptionName::ReuseAddr, 1)
        .expect("reuse addr");
    table
        .bind(listener, SocketAddress::inet([127, 0, 0, 1], 0))
        .expect("bind listener");
    let local = table
        .local_address(listener)
        .expect("listener local")
        .expect("bound address");
    table.listen(listener, 1).expect("listen");

    assert_eq!(
        table
            .accept(listener)
            .expect_err("AcceptEx should be pending")
            .linux_errno(),
        LinuxErrno::OperationWouldBlock
    );

    let stack = NetworkStack::start().expect("network stack");
    let client = stack
        .open_socket(
            AddressFamily::Inet,
            SocketKind::Stream,
            HostSocketProtocol::Tcp,
        )
        .expect("client socket");
    client
        .connect(SocketAddr::from(local))
        .expect("client connect");

    for _ in 0..10 {
        let readiness = table
            .poll(
                listener,
                SocketEvents::read(),
                Some(Duration::from_millis(50)),
            )
            .expect("poll listener");
        if readiness.readable {
            break;
        }
    }

    let client_addr = SocketAddress::from(client.local_addr().expect("client local"));
    let (accepted, peer) = table.accept(listener).expect("accepted socket");

    assert_eq!(peer, client_addr);
    assert_eq!(
        table.local_address(accepted).expect("accepted local"),
        Some(local)
    );
    assert_eq!(
        table.peer_address(accepted).expect("accepted peer"),
        Some(client_addr)
    );
}

#[cfg(windows)]
#[test]
fn win_host_transport_iocp_recv_completion_feeds_readiness() {
    let stack = NetworkStack::start().expect("network stack");
    let listener = stack
        .open_socket(
            AddressFamily::Inet,
            SocketKind::Stream,
            HostSocketProtocol::Tcp,
        )
        .expect("listener socket");
    listener
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let server_addr = SocketAddress::from(listener.local_addr().unwrap());

    let mut table =
        GuestSocketTable::with_transport(WinHostSocketTransport::new().expect("host transport"));
    let client = table
        .create_socket_from_spec(
            SocketSpec::with_flags(
                SocketDomain::Inet,
                SocketType::Stream,
                SocketProtocol::Tcp,
                SocketCreationFlags {
                    nonblocking: true,
                    cloexec: false,
                },
            )
            .expect("tcp spec"),
        )
        .expect("client socket");

    assert_eq!(
        table
            .connect(client, server_addr)
            .expect_err("ConnectEx should be pending")
            .linux_errno(),
        LinuxErrno::OperationInProgress
    );
    for _ in 0..10 {
        let _ = table.poll(
            client,
            SocketEvents::write(),
            Some(Duration::from_millis(50)),
        );
        if matches!(
            table.socket(client).expect("client state").state(),
            SocketState::Connected { .. }
        ) {
            break;
        }
    }
    assert!(matches!(
        table.socket(client).expect("client state").state(),
        SocketState::Connected { .. }
    ));

    let (server, _) = listener.accept().unwrap();
    assert_eq!(server.send(b"iocp-data").unwrap(), 9);

    for _ in 0..10 {
        let readiness = table
            .poll(
                client,
                SocketEvents::read(),
                Some(Duration::from_millis(50)),
            )
            .expect("read poll");
        if readiness.readable {
            break;
        }
    }

    let mut buffer = [0; 16];
    let count = table
        .recv_connected(client, &mut buffer)
        .expect("cached IOCP recv");

    assert_eq!(count, 9);
    assert_eq!(&buffer[..count], b"iocp-data");
}

#[cfg(windows)]
#[test]
fn win_host_transport_iocp_send_moves_stream_bytes() {
    let worker_pool = Arc::new(
        HostWorkerPoolExecutor::new(
            HostWorkerPoolConfig::with_queue_capacity(HostWorkerPoolRole::IoCompletion, 1, 4)
                .unwrap(),
        )
        .unwrap(),
    );
    let stack = NetworkStack::start().expect("network stack");
    let listener = stack
        .open_socket(
            AddressFamily::Inet,
            SocketKind::Stream,
            HostSocketProtocol::Tcp,
        )
        .expect("listener socket");
    listener
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let server_addr = SocketAddress::from(listener.local_addr().unwrap());

    let mut table = GuestSocketTable::with_transport(
        WinHostSocketTransport::with_io_completion_pool(worker_pool.clone())
            .expect("host transport"),
    );
    let client = table
        .create_socket_from_spec(
            SocketSpec::with_flags(
                SocketDomain::Inet,
                SocketType::Stream,
                SocketProtocol::Tcp,
                SocketCreationFlags {
                    nonblocking: true,
                    cloexec: false,
                },
            )
            .expect("tcp spec"),
        )
        .expect("client socket");

    assert_eq!(
        table
            .connect(client, server_addr)
            .expect_err("ConnectEx should be pending")
            .linux_errno(),
        LinuxErrno::OperationInProgress
    );
    for _ in 0..10 {
        let _ = table.poll(
            client,
            SocketEvents::write(),
            Some(Duration::from_millis(50)),
        );
        if matches!(
            table.socket(client).expect("client state").state(),
            SocketState::Connected { .. }
        ) {
            break;
        }
    }
    assert!(matches!(
        table.socket(client).expect("client state").state(),
        SocketState::Connected { .. }
    ));
    table
        .set_nonblocking(client, false)
        .expect("blocking send mode");

    let (server, _) = listener.accept().unwrap();
    assert_eq!(table.send_connected(client, b"iocp-send").unwrap(), 9);

    let mut buffer = [0; 16];
    let count = server.recv(&mut buffer).unwrap();
    assert_eq!(count, 9);
    assert_eq!(&buffer[..count], b"iocp-send");
    assert_eq!(worker_pool.diagnostics().completed_jobs(), 1);
}

#[cfg(windows)]
#[test]
fn win_host_transport_moves_udp_dns_like_datagrams() {
    let stack = NetworkStack::start().expect("network stack");
    let server = stack
        .open_socket(
            AddressFamily::Inet,
            SocketKind::Datagram,
            HostSocketProtocol::Udp,
        )
        .expect("server UDP socket");
    server
        .bind("127.0.0.1:0".parse().expect("loopback bind"))
        .unwrap();
    let server_addr = SocketAddress::from(server.local_addr().expect("server local addr"));

    let mut table =
        GuestSocketTable::with_transport(WinHostSocketTransport::new().expect("host transport"));
    let client = table
        .create_socket_from_spec(
            SocketSpec::new(
                SocketDomain::Inet,
                SocketType::Datagram,
                SocketProtocol::Udp,
            )
            .expect("udp spec"),
        )
        .expect("client socket");

    assert_eq!(
        table
            .send_to(client, b"dns?", server_addr)
            .expect("send DNS query"),
        4
    );

    let mut query = [0; 16];
    let (query_len, client_addr) = server.recv_from(&mut query).expect("server recv");
    assert_eq!(&query[..query_len], b"dns?");
    assert_eq!(client_addr.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());

    assert_eq!(
        server.send_to(b"dns!", client_addr).expect("server send"),
        4
    );
    let mut response = [0; 16];
    let (response_len, response_addr) = table
        .recv_from(client, &mut response)
        .expect("client recv DNS response");

    assert_eq!(&response[..response_len], b"dns!");
    assert_eq!(response_addr, server_addr);
}
