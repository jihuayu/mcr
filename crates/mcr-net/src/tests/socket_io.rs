use super::support::*;

#[test]
fn connected_tcp_socket_handle_sends_and_receives_bytes() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(FakeHostSocketHandle::with_incoming(b"pong")),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 8080);

    table.connect(stream, peer).expect("connect handle");
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connected {
            local: SocketAddress::inet([0, 0, 0, 0], 0),
            peer,
        }
    );
    assert_eq!(
        table
            .send_connected(stream, b"ping")
            .expect("send connected"),
        4
    );

    let mut buffer = [0; 8];
    let count = table
        .recv_connected(stream, &mut buffer)
        .expect("recv connected");
    assert_eq!(count, 4);
    assert_eq!(&buffer[..count], b"pong");
}

#[test]
fn sendmsg_vectored_stream_uses_single_host_call() {
    let state = Rc::new(RefCell::new(VectoredHostState::default()));
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(VectoredHostSocketHandle::new(Rc::clone(&state))),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 8080);
    let buffers = [IoSlice::new(b"pi"), IoSlice::new(b""), IoSlice::new(b"ng")];

    table.connect(stream, peer).expect("connect handle");
    assert_eq!(
        table
            .send_connected_vectored(stream, &buffers)
            .expect("send vectored"),
        4
    );

    let state = state.borrow();
    assert_eq!(state.send_vectored_calls, 1);
    assert_eq!(state.send_calls, 0);
    assert_eq!(state.sent.as_slice(), b"ping");
}

#[test]
fn recvmsg_vectored_stream_scatters_single_host_call() {
    let state = Rc::new(RefCell::new(VectoredHostState::with_incoming(b"abcdef")));
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(VectoredHostSocketHandle::new(Rc::clone(&state))),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([127, 0, 0, 1], 8080);
    let mut first = [0; 2];
    let mut second = [0; 3];
    let mut third = [0; 1];

    table.connect(stream, peer).expect("connect handle");
    {
        let mut buffers = [
            IoSliceMut::new(&mut first),
            IoSliceMut::new(&mut second),
            IoSliceMut::new(&mut third),
        ];
        assert_eq!(
            table
                .recv_connected_vectored(stream, &mut buffers)
                .expect("recv vectored"),
            6
        );
    }

    assert_eq!(&first, b"ab");
    assert_eq!(&second, b"cde");
    assert_eq!(&third, b"f");
    let state = state.borrow();
    assert_eq!(state.recv_vectored_calls, 1);
    assert_eq!(state.recv_calls, 0);
}

#[test]
fn sendmsg_recvmsg_vectored_datagram_preserves_single_message() {
    let state = Rc::new(RefCell::new(VectoredHostState::with_incoming(b"dns!")));
    let mut table = GuestSocketTable::new();
    let datagram = table
        .create_socket_with_handle(
            SocketSpec::new(
                SocketDomain::Inet,
                SocketType::Datagram,
                SocketProtocol::Udp,
            )
            .expect("udp spec"),
            Box::new(VectoredHostSocketHandle::new(Rc::clone(&state))),
        )
        .expect("socket with handle");
    let server = SocketAddress::inet([127, 0, 0, 1], 53);
    let query = [IoSlice::new(b"dn"), IoSlice::new(b"s?")];

    assert_eq!(
        table
            .send_to_vectored(datagram, &query, server)
            .expect("send datagram"),
        4
    );
    {
        let state = state.borrow();
        assert_eq!(state.send_to_vectored_calls, 1);
        assert_eq!(state.send_to_calls, 0);
        assert_eq!(state.sent.as_slice(), b"dns?");
        assert_eq!(state.peer, Some(server));
    }

    let mut first = [0; 2];
    let mut second = [0; 2];
    let (count, address) = {
        let mut response = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        table
            .recv_from_vectored(datagram, &mut response)
            .expect("recv datagram")
    };

    assert_eq!(count, 4);
    assert_eq!(address, server);
    assert_eq!(&first, b"dn");
    assert_eq!(&second, b"s!");
    let state = state.borrow();
    assert_eq!(state.recv_from_vectored_calls, 1);
    assert_eq!(state.recv_from_calls, 0);
}

#[test]
fn connected_udp_socket_handle_sends_and_receives_bytes() {
    let mut table = GuestSocketTable::new();
    let datagram = table
        .create_socket_with_handle(
            SocketSpec::new(
                SocketDomain::Inet,
                SocketType::Datagram,
                SocketProtocol::Udp,
            )
            .expect("udp spec"),
            Box::new(FakeHostSocketHandle::with_incoming(b"dns!")),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([1, 1, 1, 1], 53);

    table.connect(datagram, peer).expect("connect handle");
    assert_eq!(
        table
            .send_connected(datagram, b"dns?")
            .expect("send connected"),
        4
    );

    let mut buffer = [0; 8];
    let count = table
        .recv_connected(datagram, &mut buffer)
        .expect("recv connected");
    assert_eq!(count, 4);
    assert_eq!(&buffer[..count], b"dns!");
}

#[test]
fn connected_udp_socket_does_not_require_host_peer_addr_query() {
    let mut table = GuestSocketTable::new();
    let datagram = table
        .create_socket_with_handle(
            SocketSpec::new(
                SocketDomain::Inet,
                SocketType::Datagram,
                SocketProtocol::Udp,
            )
            .expect("udp spec"),
            Box::new(FakeHostSocketHandle::with_udp_peer_addr_unsupported()),
        )
        .expect("socket with handle");
    let peer = SocketAddress::inet([1, 1, 1, 1], 53);

    table.connect(datagram, peer).expect("connect UDP handle");

    assert_eq!(
        table.socket(datagram).expect("socket").state(),
        SocketState::Connected {
            local: SocketAddress::inet([0, 0, 0, 0], 0),
            peer,
        }
    );
}

#[test]
fn connect_records_host_reported_local_endpoint() {
    let mut table = GuestSocketTable::new();
    let local = SocketAddress::inet([127, 0, 0, 1], 49152);
    let peer = SocketAddress::inet([127, 0, 0, 1], 8080);
    let stream = table
        .create_socket_with_handle(
            SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                .expect("tcp spec"),
            Box::new(FakeHostSocketHandle::with_local_endpoint(local)),
        )
        .expect("socket with handle");

    table.connect(stream, peer).expect("connect handle");

    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connected { local, peer }
    );
    assert_eq!(
        table
            .socket(stream)
            .expect("socket")
            .state()
            .local_address(),
        Some(local)
    );
}
