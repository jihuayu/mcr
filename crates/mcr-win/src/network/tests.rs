use super::{
    HostAcceptExSubmission, HostConnectExSubmission, HostSocketIoDirection, HostSocketIoSubmission,
    NetworkStack, SocketCompletionKind, SocketEvents,
};

#[cfg(windows)]
use std::io::{IoSlice, IoSliceMut};

#[cfg(windows)]
use crate::iocp::HostIoCompletionPort;

#[cfg(windows)]
use super::{
    AddressFamily, HostShutdown, HostSocketOptionName, HostSocketOptionValue, SocketFastPathKind,
    SocketKind, SocketPoll, SocketProtocol,
};

#[test]
fn socket_events_empty_detects_flags() {
    assert!(SocketEvents::default().is_empty());
}

#[test]
fn network_stack_polls_empty_set() {
    let stack = NetworkStack::start().unwrap();
    let mut entries = [];

    let ready = stack
        .poll(&mut entries, Some(std::time::Duration::ZERO))
        .unwrap();

    assert_eq!(ready, 0);
}

#[test]
fn socket_completion_kind_maps_to_readiness_bits() {
    assert_eq!(
        SocketCompletionKind::Accept.readiness(),
        SocketEvents::read()
    );
    assert_eq!(
        SocketCompletionKind::Receive.readiness(),
        SocketEvents::read()
    );
    assert_eq!(
        SocketCompletionKind::Connect.readiness(),
        SocketEvents::write()
    );
    assert_eq!(
        SocketCompletionKind::Send.readiness(),
        SocketEvents::write()
    );

    let peer_closed = SocketCompletionKind::PeerClosed.readiness();
    assert!(peer_closed.readable);
    assert!(peer_closed.hang_up);
    assert!(!peer_closed.error);

    let closed = SocketCompletionKind::Closed.readiness();
    assert!(closed.hang_up);
    assert!(closed.error);

    let error = SocketCompletionKind::Error.readiness();
    assert!(error.error);
    assert!(!error.hang_up);
}

#[test]
fn socket_fast_path_kinds_map_to_completion_classes() {
    assert_eq!(
        super::SocketFastPathKind::AcceptEx.completion_kind(),
        SocketCompletionKind::Accept
    );
    assert_eq!(
        super::SocketFastPathKind::ConnectEx.completion_kind(),
        SocketCompletionKind::Connect
    );
}

#[cfg(windows)]
#[test]
fn udp_socket_accepts_nonblocking_mode() {
    let stack = NetworkStack::start().unwrap();
    let socket = stack
        .open_socket(
            AddressFamily::Inet,
            SocketKind::Datagram,
            SocketProtocol::Udp,
        )
        .unwrap();

    socket.set_nonblocking(true).unwrap();
    socket.set_nonblocking(false).unwrap();
}

#[cfg(windows)]
#[test]
fn tcp_socket_resolves_winsock_extension_functions() {
    let stack = NetworkStack::start().unwrap();
    let socket = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();

    assert_ne!(
        socket
            .extension_function(SocketFastPathKind::AcceptEx)
            .unwrap(),
        0
    );
    assert_ne!(
        socket
            .extension_function(SocketFastPathKind::ConnectEx)
            .unwrap(),
        0
    );
}

#[cfg(windows)]
#[test]
fn rio_capability_reports_supported_or_explicit_fallback() {
    let stack = NetworkStack::start().unwrap();
    let socket = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();

    let capability = socket.rio_capability().unwrap();
    if capability.is_supported() {
        assert_eq!(capability.error_code(), None);
        assert!(capability.function_count() > 0);
    } else {
        assert_eq!(capability.function_count(), 0);
    }
}

#[cfg(windows)]
#[test]
fn iocp_socket_open_associates_with_completion_port() {
    let stack = NetworkStack::start().unwrap();
    let port = HostIoCompletionPort::new().unwrap();
    let socket = stack
        .open_socket_with_iocp(
            AddressFamily::Inet,
            SocketKind::Stream,
            SocketProtocol::Tcp,
            &port,
            17,
        )
        .unwrap();

    socket.set_nonblocking(true).unwrap();
    port.post(4, 17, 0x55).unwrap();
    let packet = port.get(Some(std::time::Duration::ZERO)).unwrap().unwrap();

    assert_eq!(packet.bytes_transferred(), 4);
    assert_eq!(packet.completion_key(), 17);
    assert_eq!(packet.overlapped(), 0x55);
}

#[cfg(windows)]
#[test]
fn iocp_socket_recv_completion_returns_owned_buffer() {
    let stack = NetworkStack::start().unwrap();
    let port = HostIoCompletionPort::new().unwrap();
    let listener = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();
    listener
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let local = listener.local_addr().unwrap();
    let client = stack
        .open_socket_with_iocp(
            AddressFamily::Inet,
            SocketKind::Stream,
            SocketProtocol::Tcp,
            &port,
            23,
        )
        .unwrap();
    client.connect(local).unwrap();
    let (server, _) = listener.accept().unwrap();

    let pending = match client.submit_overlapped_recv(vec![0; 4]) {
        HostSocketIoSubmission::Pending(pending) => pending,
        other => panic!("expected pending recv, got {other:?}"),
    };
    assert_eq!(pending.direction(), HostSocketIoDirection::Receive);
    assert_eq!(server.send(b"pong").unwrap(), 4);
    let packet = port
        .get(Some(std::time::Duration::from_secs(1)))
        .unwrap()
        .unwrap();
    assert_eq!(packet.completion_key(), 23);
    assert!(pending.matches_completion(packet));
    let completion = match pending.complete_from_packet(packet) {
        HostSocketIoSubmission::Completed(completion) => completion,
        other => panic!("expected completed recv, got {other:?}"),
    };

    assert_eq!(completion.direction(), HostSocketIoDirection::Receive);
    assert_eq!(completion.bytes_transferred(), 4);
    assert_eq!(completion.buffer(), b"pong");
}

#[cfg(windows)]
#[test]
fn iocp_socket_send_completion_returns_owned_buffer() {
    let stack = NetworkStack::start().unwrap();
    let port = HostIoCompletionPort::new().unwrap();
    let listener = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();
    listener
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let local = listener.local_addr().unwrap();
    let client = stack
        .open_socket_with_iocp(
            AddressFamily::Inet,
            SocketKind::Stream,
            SocketProtocol::Tcp,
            &port,
            29,
        )
        .unwrap();
    client.connect(local).unwrap();
    let (server, _) = listener.accept().unwrap();

    let pending = match client.submit_overlapped_send(b"ping".to_vec()) {
        HostSocketIoSubmission::Pending(pending) => pending,
        other => panic!("expected pending send, got {other:?}"),
    };
    assert_eq!(pending.direction(), HostSocketIoDirection::Send);
    let packet = port
        .get(Some(std::time::Duration::from_secs(1)))
        .unwrap()
        .unwrap();
    assert_eq!(packet.completion_key(), 29);
    assert!(pending.matches_completion(packet));
    let completion = match pending.complete_from_packet(packet) {
        HostSocketIoSubmission::Completed(completion) => completion,
        other => panic!("expected completed send, got {other:?}"),
    };
    let mut buffer = [0; 4];
    assert_eq!(server.recv(&mut buffer).unwrap(), 4);

    assert_eq!(completion.direction(), HostSocketIoDirection::Send);
    assert_eq!(completion.bytes_transferred(), 4);
    assert_eq!(completion.buffer(), b"ping");
    assert_eq!(&buffer, b"ping");
}

#[cfg(windows)]
#[test]
fn connectex_completion_updates_socket_context() {
    let stack = NetworkStack::start().unwrap();
    let port = HostIoCompletionPort::new().unwrap();
    let listener = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();
    listener
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let local = listener.local_addr().unwrap();
    let client = stack
        .open_socket_with_iocp(
            AddressFamily::Inet,
            SocketKind::Stream,
            SocketProtocol::Tcp,
            &port,
            31,
        )
        .unwrap();
    client.bind("0.0.0.0:0".parse().unwrap()).unwrap();

    let pending = match client.submit_connect_ex(local) {
        HostConnectExSubmission::Pending(pending) => pending,
        other => panic!("expected pending ConnectEx, got {other:?}"),
    };
    let packet = port
        .get(Some(std::time::Duration::from_secs(1)))
        .unwrap()
        .unwrap();
    assert_eq!(packet.completion_key(), 31);
    assert!(pending.matches_completion(packet));
    pending.complete_from_packet(packet).unwrap();
    let (server, peer) = listener.accept().unwrap();

    assert_eq!(client.peer_addr().unwrap(), server.local_addr().unwrap());
    assert_eq!(peer.ip(), client.local_addr().unwrap().ip());
}

#[cfg(windows)]
#[test]
fn acceptex_completion_updates_socket_context() {
    let stack = NetworkStack::start().unwrap();
    let port = HostIoCompletionPort::new().unwrap();
    let listener = stack
        .open_socket_with_iocp(
            AddressFamily::Inet,
            SocketKind::Stream,
            SocketProtocol::Tcp,
            &port,
            37,
        )
        .unwrap();
    listener
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let local = listener.local_addr().unwrap();
    let pending = match listener.submit_accept_ex() {
        HostAcceptExSubmission::Pending(pending) => pending,
        other => panic!("expected pending AcceptEx, got {other:?}"),
    };
    let client = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();
    client.connect(local).unwrap();
    let packet = port
        .get(Some(std::time::Duration::from_secs(1)))
        .unwrap()
        .unwrap();
    assert_eq!(packet.completion_key(), 37);
    assert!(pending.matches_completion(packet));
    let (server, peer) = pending.complete_from_packet(packet).unwrap();

    assert_eq!(peer.ip(), client.local_addr().unwrap().ip());
    assert_eq!(client.peer_addr().unwrap(), server.local_addr().unwrap());
}

#[cfg(windows)]
#[test]
fn tcp_loopback_socket_round_trip_uses_host_adapter() {
    let stack = NetworkStack::start().unwrap();
    let listener = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();
    listener
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let local = listener.local_addr().unwrap();

    let client = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();
    client
        .set_option(
            HostSocketOptionName::TcpNoDelay,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    client.connect(local).unwrap();

    let (server, peer) = listener.accept().unwrap();
    assert_eq!(peer.ip(), client.local_addr().unwrap().ip());
    assert_eq!(client.peer_addr().unwrap(), server.local_addr().unwrap());
    assert_eq!(
        client.get_option(HostSocketOptionName::TcpNoDelay).unwrap(),
        HostSocketOptionValue::Bool(true)
    );
    assert_eq!(
        client.get_option(HostSocketOptionName::SocketType).unwrap(),
        HostSocketOptionValue::Kind(SocketKind::Stream)
    );

    let mut poll = [SocketPoll::new(&client, SocketEvents::write())];
    assert_eq!(
        stack
            .poll(&mut poll, Some(std::time::Duration::from_millis(50)))
            .unwrap(),
        1
    );
    assert!(poll[0].readiness.writable);

    assert_eq!(client.send(b"ping").unwrap(), 4);
    let mut buffer = [0; 4];
    assert_eq!(server.recv(&mut buffer).unwrap(), 4);
    assert_eq!(&buffer, b"ping");

    let chunks = [IoSlice::new(b"ve"), IoSlice::new(b"c!")];
    assert_eq!(client.send_vectored(&chunks).unwrap(), 4);
    let mut first = [0; 2];
    let mut second = [0; 2];
    let mut buffers = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
    assert_eq!(server.recv_vectored(&mut buffers).unwrap(), 4);
    assert_eq!(&first, b"ve");
    assert_eq!(&second, b"c!");

    server.shutdown(HostShutdown::Both).unwrap();
}

#[cfg(windows)]
#[test]
fn tcp_poll_ignores_priority_interest_for_write_readiness() {
    let stack = NetworkStack::start().unwrap();
    let listener = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();
    listener
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(true),
        )
        .unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let local = listener.local_addr().unwrap();

    let client = stack
        .open_socket(AddressFamily::Inet, SocketKind::Stream, SocketProtocol::Tcp)
        .unwrap();
    client.connect(local).unwrap();
    let (server, _) = listener.accept().unwrap();

    let mut poll = [SocketPoll::new(
        &client,
        SocketEvents {
            writable: true,
            priority: true,
            ..SocketEvents::default()
        },
    )];

    assert_eq!(
        stack
            .poll(&mut poll, Some(std::time::Duration::from_millis(50)))
            .unwrap(),
        1
    );
    assert!(poll[0].readiness.writable);
    assert!(!poll[0].readiness.priority);

    server.shutdown(HostShutdown::Both).unwrap();
}
