use super::support::*;

#[test]
fn iocp_readiness_receive_completion_feeds_poll_without_wsapoll_fallback() {
    let poll_calls = Rc::new(Cell::new(0));
    let handle = FakeHostSocketHandle::with_readiness(
        vec![ReadinessCompletionFixture::Current(
            SocketCompletionKind::Receive,
        )],
        None,
        Rc::clone(&poll_calls),
    );
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(handle),
        )
        .expect("socket with readiness handle");

    let readiness = table
        .poll(stream, SocketEvents::read(), Some(Duration::from_secs(30)))
        .expect("completion readiness");

    assert!(readiness.readable);
    assert!(!readiness.writable);
    assert_eq!(poll_calls.get(), 0);
}

#[test]
fn iocp_readiness_ignores_stale_completion_generation() {
    let poll_calls = Rc::new(Cell::new(0));
    let handle = FakeHostSocketHandle::with_readiness(
        vec![ReadinessCompletionFixture::Stale(
            SocketCompletionKind::Receive,
        )],
        Some(SocketEvents::default()),
        Rc::clone(&poll_calls),
    );
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(handle),
        )
        .expect("socket with readiness handle");

    let readiness = table
        .poll(stream, SocketEvents::read(), Some(Duration::ZERO))
        .expect("fallback readiness");

    assert!(readiness.is_empty());
    assert_eq!(poll_calls.get(), 1);
}

#[test]
fn iocp_readiness_uses_wsapoll_fallback_without_completion() {
    let poll_calls = Rc::new(Cell::new(0));
    let handle = FakeHostSocketHandle::with_readiness(
        Vec::new(),
        Some(SocketEvents::write()),
        Rc::clone(&poll_calls),
    );
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(handle),
        )
        .expect("socket with readiness handle");

    let readiness = table
        .poll(stream, SocketEvents::write(), Some(Duration::ZERO))
        .expect("fallback readiness");

    assert!(readiness.writable);
    assert!(!readiness.readable);
    assert_eq!(poll_calls.get(), 1);
}

#[test]
fn acceptex_unsupported_uses_plain_accept_fallback() {
    let accept_calls = Rc::new(Cell::new(0));
    let peer = SocketAddress::inet([127, 0, 0, 1], 49152);
    let listener_handle =
        FakeHostSocketHandle::with_counted_accepted(peer, b"fallback", Rc::clone(&accept_calls));
    let mut table = GuestSocketTable::with_transport(NoopHostSocketTransport);
    let listener = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(listener_handle),
        )
        .expect("listener");
    let local = SocketAddress::inet([127, 0, 0, 1], 8080);

    table.bind(listener, local).expect("bind");
    table.listen(listener, 1).expect("listen");
    let (accepted, accepted_peer) = table.accept(listener).expect("plain accept fallback");

    assert_eq!(accepted_peer, peer);
    assert_eq!(accept_calls.get(), 1);
    assert_eq!(
        table.socket(accepted).expect("accepted").state(),
        SocketState::Connected { local, peer }
    );
}

#[test]
fn acceptex_pending_completion_feeds_readiness_then_accepts_without_plain_fallback() {
    let accept_calls = Rc::new(Cell::new(0));
    let poll_calls = Rc::new(Cell::new(0));
    let peer = SocketAddress::inet([127, 0, 0, 1], 49152);
    let mut listener_handle =
        FakeHostSocketHandle::with_acceptex(peer, b"accepted", Rc::clone(&accept_calls));
    listener_handle.poll_calls = Some(Rc::clone(&poll_calls));
    let mut table = GuestSocketTable::with_transport(NoopHostSocketTransport);
    let listener = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(listener_handle),
        )
        .expect("listener");
    let local = SocketAddress::inet([127, 0, 0, 1], 8080);

    table.bind(listener, local).expect("bind");
    table.listen(listener, 1).expect("listen");
    assert_eq!(
        table
            .accept(listener)
            .expect_err("AcceptEx submit should be pending")
            .linux_errno(),
        LinuxErrno::OperationWouldBlock
    );
    assert_eq!(accept_calls.get(), 0);

    let readiness = table
        .poll(listener, SocketEvents::read(), Some(Duration::ZERO))
        .expect("AcceptEx readiness");
    assert!(readiness.readable);
    assert_eq!(poll_calls.get(), 0);

    let (accepted, accepted_peer) = table.accept(listener).expect("completed AcceptEx");
    assert_eq!(accepted_peer, peer);
    assert_eq!(accept_calls.get(), 0);
    assert_eq!(
        table.socket(accepted).expect("accepted").state(),
        SocketState::Connected { local, peer }
    );
}

#[test]
fn connectex_unsupported_uses_plain_connect_fallback() {
    let connect_calls = Rc::new(Cell::new(0));
    let local = SocketAddress::inet([127, 0, 0, 1], 49152);
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(FakeHostSocketHandle::with_counted_connect(
                local,
                Rc::clone(&connect_calls),
            )),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 8080);

    table.connect(stream, peer).expect("plain connect fallback");

    assert_eq!(connect_calls.get(), 1);
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connected { local, peer }
    );
}

#[test]
fn connectex_pending_completion_preserves_nonblocking_state_and_so_error() {
    let connect_calls = Rc::new(Cell::new(0));
    let poll_calls = Rc::new(Cell::new(0));
    let local = SocketAddress::inet([127, 0, 0, 1], 49152);
    let mut handle = FakeHostSocketHandle::with_connectex(local, Rc::clone(&connect_calls));
    handle.poll_calls = Some(Rc::clone(&poll_calls));
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
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
            Box::new(handle),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 8080);

    assert_eq!(
        table
            .connect(stream, peer)
            .expect_err("ConnectEx submit should be pending")
            .linux_errno(),
        LinuxErrno::OperationInProgress
    );
    assert_eq!(connect_calls.get(), 0);
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connecting(peer)
    );

    let readiness = table
        .poll(stream, SocketEvents::write(), Some(Duration::ZERO))
        .expect("ConnectEx readiness");
    assert!(readiness.writable);
    assert_eq!(poll_calls.get(), 0);
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connected { local, peer }
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR"),
        0
    );
}

#[test]
fn connected_tcp_socket_handle_maps_host_failure() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(FakeHostSocketHandle::with_send_error(HostIoError::new(
                LinuxErrno::BrokenPipe,
                "send failed",
            ))),
        )
        .expect("socket with handle");
    table
        .connect(stream, SocketAddress::inet([127, 0, 0, 1], 8080))
        .expect("connect handle");

    assert_eq!(
        table
            .send_connected(stream, b"ping")
            .expect_err("host send failure")
            .linux_errno(),
        LinuxErrno::BrokenPipe
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR"),
        LinuxErrno::BrokenPipe.code() as u32
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR is consumed"),
        0
    );
}

#[test]
fn set_nonblocking_updates_socket_flags() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(FakeHostSocketHandle::default()),
        )
        .expect("socket with handle");

    table
        .set_nonblocking(stream, true)
        .expect("set host nonblocking");
    assert!(table.socket(stream).expect("socket").flags().nonblocking);

    table
        .set_nonblocking(stream, false)
        .expect("clear host nonblocking");
    assert!(!table.socket(stream).expect("socket").flags().nonblocking);
}

#[test]
fn nonblocking_connect_completes_after_writable_poll() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
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
            Box::new(FakeHostSocketHandle::with_connect_error(HostIoError::new(
                LinuxErrno::OperationWouldBlock,
                "connect would block",
            ))),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 8080);

    assert_eq!(
        table
            .connect(stream, peer)
            .expect_err("connect should be pending")
            .linux_errno(),
        LinuxErrno::OperationInProgress
    );
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connecting(peer)
    );
    assert_eq!(
        table
            .connect(stream, peer)
            .expect_err("second connect should already be pending")
            .linux_errno(),
        LinuxErrno::OperationAlreadyInProgress
    );
    let readiness = table
        .poll(stream, SocketEvents::write(), Some(Duration::ZERO))
        .expect("poll writable");
    assert!(readiness.writable);
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connected {
            local: SocketAddress::inet([0, 0, 0, 0], 0),
            peer,
        }
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR"),
        0
    );
}

#[test]
fn nonblocking_connect_completes_after_so_error_query() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
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
            Box::new(FakeHostSocketHandle::with_connect_error(HostIoError::new(
                LinuxErrno::OperationWouldBlock,
                "connect would block",
            ))),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 8080);

    assert_eq!(
        table
            .connect(stream, peer)
            .expect_err("connect should be pending")
            .linux_errno(),
        LinuxErrno::OperationInProgress
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR"),
        0
    );
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connected {
            local: SocketAddress::inet([0, 0, 0, 0], 0),
            peer,
        }
    );
}

#[test]
fn nonblocking_connect_completes_before_local_address_query() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
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
            Box::new(FakeHostSocketHandle::with_connect_error(HostIoError::new(
                LinuxErrno::OperationWouldBlock,
                "connect would block",
            ))),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 8080);

    assert_eq!(
        table
            .connect(stream, peer)
            .expect_err("connect should be pending")
            .linux_errno(),
        LinuxErrno::OperationInProgress
    );
    assert_eq!(
        table.local_address(stream).expect("local address"),
        Some(SocketAddress::inet([0, 0, 0, 0], 0))
    );
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connected {
            local: SocketAddress::inet([0, 0, 0, 0], 0),
            peer,
        }
    );
}

#[test]
fn nonblocking_connect_failure_is_reported_after_writable_poll() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
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
            Box::new(FakeHostSocketHandle::with_pending_connect_error(
                HostIoError::new(LinuxErrno::ConnectionRefused, "connection refused"),
            )),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 9);

    assert_eq!(
        table
            .connect(stream, peer)
            .expect_err("connect should be pending")
            .linux_errno(),
        LinuxErrno::OperationInProgress
    );
    assert_eq!(
        table
            .poll(stream, SocketEvents::write(), Some(Duration::ZERO))
            .expect_err("poll should surface connect failure")
            .linux_errno(),
        LinuxErrno::ConnectionRefused
    );
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Created
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR"),
        LinuxErrno::ConnectionRefused.code() as u32
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR is consumed"),
        0
    );
}

#[test]
fn nonblocking_connect_failure_is_reported_after_so_error_query() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
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
            Box::new(FakeHostSocketHandle::with_pending_connect_error(
                HostIoError::new(LinuxErrno::ConnectionRefused, "connection refused"),
            )),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 9);

    assert_eq!(
        table
            .connect(stream, peer)
            .expect_err("connect should be pending")
            .linux_errno(),
        LinuxErrno::OperationInProgress
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR"),
        LinuxErrno::ConnectionRefused.code() as u32
    );
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Created
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR is consumed"),
        0
    );
}

#[test]
fn rejects_invalid_state_transitions() {
    let mut table = GuestSocketTable::new();
    let datagram = table
        .create_socket(
            SocketDomain::Inet,
            SocketType::Datagram,
            SocketProtocol::Udp,
        )
        .expect("datagram socket");
    let stream = table
        .create_socket(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
        .expect("stream socket");

    assert_eq!(
        table
            .listen(datagram, 1)
            .expect_err("datagrams cannot listen")
            .linux_errno(),
        LinuxErrno::OperationNotSupported
    );
    assert_eq!(
        table
            .listen(stream, 1)
            .expect_err("unbound stream cannot listen")
            .linux_errno(),
        LinuxErrno::InvalidArgument
    );
    assert_eq!(
        table
            .shutdown(stream, ShutdownHow::Read)
            .expect_err("unconnected stream cannot shutdown")
            .linux_errno(),
        LinuxErrno::NotConnected
    );
    assert_eq!(
        table
            .bind(stream, SocketAddress::inet6([0; 16], 80, 0, 0))
            .expect_err("address family mismatch")
            .linux_errno(),
        LinuxErrno::AddressFamilyNotSupported
    );

    let address = SocketAddress::inet([127, 0, 0, 1], 8080);
    table.bind(stream, address).expect("bind");
    table.listen(stream, 1).expect("listen");
    assert_eq!(
        table
            .accept(stream)
            .expect_err("accept placeholder would block")
            .linux_errno(),
        LinuxErrno::OperationWouldBlock
    );
    assert_eq!(
        table
            .connect(stream, address)
            .expect_err("listening socket cannot connect")
            .linux_errno(),
        LinuxErrno::InvalidArgument
    );

    table.close(stream).expect("close");
    assert_eq!(
        table
            .bind(stream, address)
            .expect_err("closed socket is bad")
            .linux_errno(),
        LinuxErrno::BadFileDescriptor
    );
}

#[test]
fn accept_uses_host_listener_and_registers_connected_socket() {
    let peer = SocketAddress::inet([127, 0, 0, 1], 49152);
    let listener_handle = FakeHostSocketHandle::with_accepted(peer, b"server-side accepted bytes");
    let mut table = GuestSocketTable::with_transport(NoopHostSocketTransport);
    let listener = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp).unwrap(),
            Box::new(listener_handle),
        )
        .expect("listener");
    let local = SocketAddress::inet([127, 0, 0, 1], 8080);

    table.bind(listener, local).expect("bind");
    table.listen(listener, 1).expect("listen");
    let (accepted, accepted_peer) = table.accept(listener).expect("accept");

    assert_eq!(accepted_peer, peer);
    assert_eq!(
        table.socket(listener).expect("listener").state(),
        SocketState::Listening(local)
    );
    assert_eq!(
        table.socket(accepted).expect("accepted").state(),
        SocketState::Connected { local, peer }
    );
    let mut buffer = [0; 5];
    assert_eq!(
        table.recv_connected(accepted, &mut buffer).expect("recv"),
        5
    );
    assert_eq!(&buffer, b"serve");
}

#[test]
fn rio_capability_defaults_to_explicit_fallback() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(FakeHostSocketHandle::default()),
        )
        .expect("socket with handle");

    let capability = table.rio_capability(stream).expect("RIO capability");

    assert!(!capability.is_supported());
    assert_eq!(capability.error_code(), None);
    assert_eq!(capability.function_count(), 0);
}
