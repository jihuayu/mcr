use super::support::*;

#[test]
fn package_name_is_stable() {
    assert_eq!(CRATE_NAME, "mcr-net");
}

#[test]
fn allocates_monotonic_socket_ids() {
    let mut table = GuestSocketTable::new();

    let first = table
        .create_socket(
            SocketDomain::Inet,
            SocketType::Stream,
            SocketProtocol::Default,
        )
        .expect("stream socket");
    let second = table
        .create_socket(
            SocketDomain::Inet6,
            SocketType::Datagram,
            SocketProtocol::Udp,
        )
        .expect("datagram socket");

    assert_eq!(first.get(), 1);
    assert_eq!(second.get(), 2);
    assert_eq!(table.len(), 2);
    assert_eq!(table.socket(first).expect("first socket").id(), first);
    assert_eq!(
        table
            .socket(first)
            .expect("first socket")
            .effective_protocol(),
        SocketProtocol::Tcp
    );
    assert_eq!(
        table
            .socket(second)
            .expect("second socket")
            .effective_protocol(),
        SocketProtocol::Udp
    );
}

#[test]
fn validates_linux_socket_creation_inputs() {
    let spec = SocketSpec::from_linux(
        LINUX_AF_INET,
        LINUX_SOCK_STREAM | LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC,
        LINUX_IPPROTO_TCP,
    )
    .expect("valid tcp spec");

    assert_eq!(spec.domain, SocketDomain::Inet);
    assert_eq!(spec.socket_type, SocketType::Stream);
    assert_eq!(spec.protocol, SocketProtocol::Tcp);
    assert!(spec.flags.nonblocking);
    assert!(spec.flags.cloexec);

    assert_eq!(
        SocketSpec::from_linux(LINUX_AF_UNIX, LINUX_SOCK_STREAM, LINUX_IPPROTO_IP)
            .expect_err("unix sockets are unsupported")
            .linux_errno(),
        LinuxErrno::AddressFamilyNotSupported
    );
    assert_eq!(
        SocketSpec::from_linux(LINUX_AF_INET, LINUX_SOCK_RAW, LINUX_IPPROTO_IP)
            .expect_err("raw sockets are unsupported")
            .linux_errno(),
        LinuxErrno::SocketTypeNotSupported
    );
    assert_eq!(
        SocketSpec::from_linux(LINUX_AF_INET, LINUX_SOCK_DGRAM, LINUX_IPPROTO_TCP)
            .expect_err("tcp datagrams are unsupported")
            .linux_errno(),
        LinuxErrno::ProtocolWrongTypeForSocket
    );
    assert_eq!(
        SocketSpec::from_linux(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM | 0x1000_0000,
            LINUX_IPPROTO_IP
        )
        .expect_err("unknown flags are invalid")
        .linux_errno(),
        LinuxErrno::InvalidArgument
    );
}

#[test]
fn gets_and_sets_supported_socket_options() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket(
            SocketDomain::Inet,
            SocketType::Stream,
            SocketProtocol::Default,
        )
        .expect("stream socket");

    assert_eq!(
        SocketOptionName::from_linux(LINUX_SOL_SOCKET, LINUX_SO_TYPE).expect("SO_TYPE option"),
        SocketOptionName::SocketType
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketType)
            .expect("SO_TYPE"),
        LINUX_SOCK_STREAM
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SocketError)
            .expect("SO_ERROR"),
        0
    );

    table
        .set_option(stream, SocketOptionName::ReuseAddr, 1)
        .expect("enable reuseaddr");
    table
        .set_option(stream, SocketOptionName::KeepAlive, 1)
        .expect("enable keepalive");
    table
        .set_option(stream, SocketOptionName::SendBuffer, 65_536)
        .expect("send buffer");
    table
        .set_option(stream, SocketOptionName::ReceiveBuffer, 131_072)
        .expect("receive buffer");
    table
        .set_option(stream, SocketOptionName::TcpNoDelay, 1)
        .expect("enable nodelay");

    assert_eq!(
        table
            .get_option(stream, SocketOptionName::ReuseAddr)
            .expect("SO_REUSEADDR"),
        1
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::KeepAlive)
            .expect("SO_KEEPALIVE"),
        1
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::SendBuffer)
            .expect("SO_SNDBUF"),
        65_536
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::ReceiveBuffer)
            .expect("SO_RCVBUF"),
        131_072
    );
    assert_eq!(
        table
            .get_option(stream, SocketOptionName::TcpNoDelay)
            .expect("TCP_NODELAY"),
        1
    );

    let options = table.socket(stream).expect("socket").options();
    assert!(options.reuse_addr);
    assert!(options.keep_alive);
    assert!(options.tcp_no_delay);
}

#[test]
fn rejects_invalid_socket_options() {
    let mut table = GuestSocketTable::new();
    let datagram = table
        .create_socket(
            SocketDomain::Inet,
            SocketType::Datagram,
            SocketProtocol::Default,
        )
        .expect("datagram socket");

    assert_eq!(
        SocketOptionName::from_linux(LINUX_SOL_SOCKET, 0xfeed)
            .expect_err("unknown option")
            .linux_errno(),
        LinuxErrno::ProtocolNotAvailable
    );
    assert_eq!(
        table
            .set_option(datagram, SocketOptionName::SocketType, LINUX_SOCK_STREAM)
            .expect_err("SO_TYPE is readonly")
            .linux_errno(),
        LinuxErrno::InvalidArgument
    );
    assert_eq!(
        table
            .set_option(datagram, SocketOptionName::SendBuffer, 0)
            .expect_err("zero buffer size")
            .linux_errno(),
        LinuxErrno::InvalidArgument
    );
    assert_eq!(
        table
            .set_option(datagram, SocketOptionName::TcpNoDelay, 1)
            .expect_err("TCP_NODELAY requires TCP")
            .linux_errno(),
        LinuxErrno::InvalidArgument
    );
    assert_eq!(
        table
            .get_option(
                SocketId::new(404).expect("socket id"),
                SocketOptionName::SocketType
            )
            .expect_err("unknown socket")
            .linux_errno(),
        LinuxErrno::BadFileDescriptor
    );
}

#[test]
fn bind_and_listen_update_stream_socket_state() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket(
            SocketDomain::Inet,
            SocketType::Stream,
            SocketProtocol::Default,
        )
        .expect("stream socket");
    let address = SocketAddress::inet([127, 0, 0, 1], 8080);

    table.bind(stream, address).expect("bind stream");
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Bound(address)
    );
    assert_eq!(
        table
            .socket(stream)
            .expect("socket")
            .state()
            .local_address(),
        Some(address)
    );

    table.listen(stream, 128).expect("listen stream");
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Listening(address)
    );
    table
        .listen(stream, 128)
        .expect("listen is idempotent while listening");
}

#[test]
fn connect_and_shutdown_record_placeholder_state() {
    let mut table = GuestSocketTable::new();
    let stream = table
        .create_socket(SocketDomain::Inet6, SocketType::Stream, SocketProtocol::Tcp)
        .expect("stream socket");
    let peer = SocketAddress::inet6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443, 0, 0);

    table.connect(stream, peer).expect("connect placeholder");
    assert_eq!(
        table.socket(stream).expect("socket").state(),
        SocketState::Connected {
            local: SocketAddress::inet6([0; 16], 0, 0, 0),
            peer,
        }
    );
    assert_eq!(
        table
            .socket(stream)
            .expect("socket")
            .state()
            .local_address(),
        Some(SocketAddress::inet6([0; 16], 0, 0, 0))
    );
    assert_eq!(
        table.socket(stream).expect("socket").state().peer_address(),
        Some(peer)
    );

    table
        .shutdown(stream, ShutdownHow::Write)
        .expect("shutdown write");
    assert_eq!(
        table.socket(stream).expect("socket").shutdown(),
        ShutdownFlags {
            read: false,
            write: true
        }
    );

    table
        .shutdown(stream, ShutdownHow::ReadWrite)
        .expect("shutdown both");
    assert_eq!(
        table.socket(stream).expect("socket").shutdown(),
        ShutdownFlags {
            read: true,
            write: true
        }
    );
    assert_eq!(
        ShutdownHow::from_linux(LINUX_SHUT_RDWR).expect("shutdown mode"),
        ShutdownHow::ReadWrite
    );
}
