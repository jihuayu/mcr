use std::{
    cell::{Cell, RefCell},
    io::{IoSlice, IoSliceMut},
    net::{IpAddr, SocketAddr},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use mcr_task::{HostWorkerPoolConfig, HostWorkerPoolExecutor, HostWorkerPoolRole};
use mcr_win::{
    AddressFamily, HostSocketOptionName, HostSocketOptionValue, NetworkStack, SocketCompletionKind,
    SocketEvents, SocketFastPathKind, SocketKind, SocketProtocol as HostSocketProtocol,
};

use super::*;

#[derive(Debug, Default)]
struct FakeHostSocketHandle {
    sent: Vec<u8>,
    incoming: Vec<u8>,
    local: Option<SocketAddress>,
    connected: Option<SocketAddress>,
    fail_peer_addr: bool,
    connect_error: Option<HostIoError>,
    socket_error: Option<HostIoError>,
    fail_send: Option<HostIoError>,
    readiness_completions: Vec<ReadinessCompletionFixture>,
    fallback_readiness: Option<SocketEvents>,
    poll_calls: Option<Rc<Cell<usize>>>,
    accept_calls: Option<Rc<Cell<usize>>>,
    connect_calls: Option<Rc<Cell<usize>>>,
    fast_path_accept: Option<FastPathAcceptFixture>,
    fast_path_connect: Option<FastPathConnectFixture>,
    accepted: Vec<(FakeHostSocketHandle, SocketAddress)>,
    bound: Option<SocketAddress>,
    listened: bool,
    nonblocking: bool,
}

#[derive(Debug)]
struct FastPathAcceptFixture {
    accepted: Option<(Box<FakeHostSocketHandle>, SocketAddress)>,
    submitted: bool,
    ready: bool,
}

#[derive(Debug)]
struct FastPathConnectFixture {
    submitted: bool,
    ready: bool,
}

impl FakeHostSocketHandle {
    fn with_incoming(bytes: &[u8]) -> Self {
        Self {
            incoming: bytes.to_vec(),
            ..Self::default()
        }
    }

    fn with_send_error(error: HostIoError) -> Self {
        Self {
            fail_send: Some(error),
            ..Self::default()
        }
    }

    fn with_connect_error(error: HostIoError) -> Self {
        Self {
            connect_error: Some(error),
            ..Self::default()
        }
    }

    fn with_pending_connect_error(error: HostIoError) -> Self {
        Self {
            connect_error: Some(HostIoError::new(
                LinuxErrno::OperationWouldBlock,
                "connect would block",
            )),
            socket_error: Some(error),
            ..Self::default()
        }
    }

    fn with_local_endpoint(local: SocketAddress) -> Self {
        Self {
            local: Some(local),
            ..Self::default()
        }
    }

    fn with_udp_peer_addr_unsupported() -> Self {
        Self {
            fail_peer_addr: true,
            ..Self::default()
        }
    }

    fn with_accepted(peer: SocketAddress, incoming: &[u8]) -> Self {
        Self {
            accepted: vec![(Self::with_incoming(incoming), peer)],
            ..Self::default()
        }
    }

    fn with_counted_accepted(
        peer: SocketAddress,
        incoming: &[u8],
        accept_calls: Rc<Cell<usize>>,
    ) -> Self {
        Self {
            accept_calls: Some(accept_calls),
            ..Self::with_accepted(peer, incoming)
        }
    }

    fn with_acceptex(peer: SocketAddress, incoming: &[u8], accept_calls: Rc<Cell<usize>>) -> Self {
        Self {
            accept_calls: Some(accept_calls),
            fast_path_accept: Some(FastPathAcceptFixture {
                accepted: Some((Box::new(Self::with_incoming(incoming)), peer)),
                submitted: false,
                ready: false,
            }),
            ..Self::default()
        }
    }

    fn with_counted_connect(local: SocketAddress, connect_calls: Rc<Cell<usize>>) -> Self {
        Self {
            local: Some(local),
            connect_calls: Some(connect_calls),
            ..Self::default()
        }
    }

    fn with_connectex(local: SocketAddress, connect_calls: Rc<Cell<usize>>) -> Self {
        Self {
            local: Some(local),
            connect_calls: Some(connect_calls),
            fast_path_connect: Some(FastPathConnectFixture {
                submitted: false,
                ready: false,
            }),
            ..Self::default()
        }
    }

    fn with_readiness(
        completions: Vec<ReadinessCompletionFixture>,
        fallback_readiness: Option<SocketEvents>,
        poll_calls: Rc<Cell<usize>>,
    ) -> Self {
        Self {
            readiness_completions: completions,
            fallback_readiness,
            poll_calls: Some(poll_calls),
            ..Self::default()
        }
    }
}

#[derive(Debug)]
struct VectoredHostState {
    sent: Vec<u8>,
    incoming: Vec<u8>,
    local: SocketAddress,
    peer: Option<SocketAddress>,
    send_calls: usize,
    send_vectored_calls: usize,
    send_to_calls: usize,
    send_to_vectored_calls: usize,
    recv_calls: usize,
    recv_vectored_calls: usize,
    recv_from_calls: usize,
    recv_from_vectored_calls: usize,
}

impl Default for VectoredHostState {
    fn default() -> Self {
        Self {
            sent: Vec::new(),
            incoming: Vec::new(),
            local: SocketAddress::inet([0, 0, 0, 0], 0),
            peer: None,
            send_calls: 0,
            send_vectored_calls: 0,
            send_to_calls: 0,
            send_to_vectored_calls: 0,
            recv_calls: 0,
            recv_vectored_calls: 0,
            recv_from_calls: 0,
            recv_from_vectored_calls: 0,
        }
    }
}

impl VectoredHostState {
    fn with_incoming(bytes: &[u8]) -> Self {
        Self {
            incoming: bytes.to_vec(),
            ..Self::default()
        }
    }

    fn drain_into(&mut self, buffer: &mut [u8]) -> usize {
        let count = buffer.len().min(self.incoming.len());
        buffer[..count].copy_from_slice(&self.incoming[..count]);
        self.incoming.drain(..count);
        count
    }
}

#[derive(Debug)]
struct VectoredHostSocketHandle {
    state: Rc<RefCell<VectoredHostState>>,
}

impl VectoredHostSocketHandle {
    fn new(state: Rc<RefCell<VectoredHostState>>) -> Self {
        Self { state }
    }
}

impl HostSocketHandle for VectoredHostSocketHandle {
    fn bind(&mut self, address: SocketAddress) -> Result<SocketAddress, HostIoError> {
        self.state.borrow_mut().local = address;
        Ok(address)
    }

    fn listen(&mut self, _backlog: u32) -> Result<(), HostIoError> {
        Ok(())
    }

    fn accept(&mut self) -> Result<(Box<dyn HostSocketHandle>, SocketAddress), HostIoError> {
        Err(HostIoError::new(
            LinuxErrno::OperationWouldBlock,
            "no pending vectored fake socket connection",
        ))
    }

    fn set_nonblocking(&mut self, _nonblocking: bool) -> Result<(), HostIoError> {
        Ok(())
    }

    fn connect(&mut self, address: SocketAddress) -> Result<(), HostIoError> {
        self.state.borrow_mut().peer = Some(address);
        Ok(())
    }

    fn take_error(&mut self) -> Result<Option<HostIoError>, HostIoError> {
        Ok(None)
    }

    fn local_addr(&self) -> Result<SocketAddress, HostIoError> {
        Ok(self.state.borrow().local)
    }

    fn peer_addr(&self) -> Result<SocketAddress, HostIoError> {
        self.state
            .borrow()
            .peer
            .ok_or_else(|| HostIoError::new(LinuxErrno::NotConnected, "socket is not connected"))
    }

    fn send(&mut self, buffer: &[u8]) -> Result<usize, HostIoError> {
        let mut state = self.state.borrow_mut();
        state.send_calls += 1;
        state.sent.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn send_vectored(&mut self, buffers: &[IoSlice<'_>]) -> Result<usize, HostIoError> {
        let mut state = self.state.borrow_mut();
        state.send_vectored_calls += 1;
        let mut count = 0usize;
        for buffer in buffers {
            count = count.checked_add(buffer.len()).ok_or_else(|| {
                HostIoError::new(LinuxErrno::InvalidArgument, "sent byte count overflowed")
            })?;
            state.sent.extend_from_slice(buffer.as_ref());
        }
        Ok(count)
    }

    fn send_to(&mut self, buffer: &[u8], address: SocketAddress) -> Result<usize, HostIoError> {
        let mut state = self.state.borrow_mut();
        state.send_to_calls += 1;
        state.peer = Some(address);
        state.sent.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn send_to_vectored(
        &mut self,
        buffers: &[IoSlice<'_>],
        address: SocketAddress,
    ) -> Result<usize, HostIoError> {
        let mut state = self.state.borrow_mut();
        state.send_to_vectored_calls += 1;
        state.peer = Some(address);
        let mut count = 0usize;
        for buffer in buffers {
            count = count.checked_add(buffer.len()).ok_or_else(|| {
                HostIoError::new(LinuxErrno::InvalidArgument, "sent byte count overflowed")
            })?;
            state.sent.extend_from_slice(buffer.as_ref());
        }
        Ok(count)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, HostIoError> {
        let mut state = self.state.borrow_mut();
        state.recv_calls += 1;
        Ok(state.drain_into(buffer))
    }

    fn recv_vectored(&mut self, buffers: &mut [IoSliceMut<'_>]) -> Result<usize, HostIoError> {
        let mut state = self.state.borrow_mut();
        state.recv_vectored_calls += 1;
        let mut total = 0usize;
        for buffer in buffers {
            let count = state.drain_into(buffer);
            total = total.checked_add(count).ok_or_else(|| {
                HostIoError::new(
                    LinuxErrno::InvalidArgument,
                    "received byte count overflowed",
                )
            })?;
            if count < buffer.len() {
                break;
            }
        }
        Ok(total)
    }

    fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddress), HostIoError> {
        let mut state = self.state.borrow_mut();
        state.recv_from_calls += 1;
        let count = state.drain_into(buffer);
        let address = state
            .peer
            .unwrap_or_else(|| SocketAddress::inet([127, 0, 0, 1], 53));
        Ok((count, address))
    }

    fn recv_from_vectored(
        &mut self,
        buffers: &mut [IoSliceMut<'_>],
    ) -> Result<(usize, SocketAddress), HostIoError> {
        let mut state = self.state.borrow_mut();
        state.recv_from_vectored_calls += 1;
        let mut total = 0usize;
        for buffer in buffers {
            let count = state.drain_into(buffer);
            total = total.checked_add(count).ok_or_else(|| {
                HostIoError::new(
                    LinuxErrno::InvalidArgument,
                    "received byte count overflowed",
                )
            })?;
            if count < buffer.len() {
                break;
            }
        }
        let address = state
            .peer
            .unwrap_or_else(|| SocketAddress::inet([127, 0, 0, 1], 53));
        Ok((total, address))
    }

    fn poll(
        &mut self,
        interest: SocketEvents,
        _timeout: Option<Duration>,
    ) -> Result<SocketEvents, HostIoError> {
        Ok(SocketEvents {
            readable: interest.readable && !self.state.borrow().incoming.is_empty(),
            writable: interest.writable,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        })
    }

    fn shutdown(&mut self, _how: ShutdownHow) -> Result<(), HostIoError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadinessCompletionFixture {
    Current(SocketCompletionKind),
    Stale(SocketCompletionKind),
}

impl HostSocketHandle for FakeHostSocketHandle {
    fn bind(&mut self, address: SocketAddress) -> Result<SocketAddress, HostIoError> {
        self.bound = Some(address);
        Ok(address)
    }

    fn listen(&mut self, _backlog: u32) -> Result<(), HostIoError> {
        self.listened = true;
        Ok(())
    }

    fn accept_fast_path(
        &mut self,
        _token: SocketReadinessToken,
        _spec: SocketSpec,
    ) -> Result<SocketAcceptFastPath, HostIoError> {
        let Some(fast_path) = self.fast_path_accept.as_mut() else {
            return Ok(SocketAcceptFastPath::Unsupported);
        };
        if fast_path.ready {
            let Some((handle, peer)) = fast_path.accepted.take() else {
                return Err(HostIoError::new(
                    LinuxErrno::OperationWouldBlock,
                    "AcceptEx fixture has no accepted socket",
                ));
            };
            return Ok(SocketAcceptFastPath::Accepted { handle, peer });
        }
        fast_path.submitted = true;
        Ok(SocketAcceptFastPath::Pending)
    }

    fn accept(&mut self) -> Result<(Box<dyn HostSocketHandle>, SocketAddress), HostIoError> {
        if let Some(calls) = &self.accept_calls {
            calls.set(calls.get() + 1);
        }
        if self.accepted.is_empty() {
            return Err(HostIoError::new(
                LinuxErrno::OperationWouldBlock,
                "no pending fake socket connection",
            ));
        }
        let (handle, address) = self.accepted.remove(0);
        Ok((Box::new(handle), address))
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), HostIoError> {
        self.nonblocking = nonblocking;
        Ok(())
    }

    fn connect_fast_path(
        &mut self,
        _token: SocketReadinessToken,
        address: SocketAddress,
    ) -> Result<SocketConnectFastPath, HostIoError> {
        let Some(fast_path) = self.fast_path_connect.as_mut() else {
            return Ok(SocketConnectFastPath::Unsupported);
        };
        fast_path.submitted = true;
        self.connected = Some(address);
        Ok(SocketConnectFastPath::Pending)
    }

    fn connect(&mut self, address: SocketAddress) -> Result<(), HostIoError> {
        if let Some(calls) = &self.connect_calls {
            calls.set(calls.get() + 1);
        }
        if let Some(error) = self.connect_error.take() {
            if error.linux_errno() == LinuxErrno::OperationWouldBlock {
                self.connected = Some(address);
            }
            return Err(error);
        }
        self.connected = Some(address);
        Ok(())
    }

    fn complete_connect_fast_path(
        &mut self,
    ) -> Result<SocketConnectFastPathCompletion, HostIoError> {
        let Some(fast_path) = self.fast_path_connect.as_ref() else {
            return Ok(SocketConnectFastPathCompletion::Inactive);
        };
        if !fast_path.submitted {
            return Ok(SocketConnectFastPathCompletion::Inactive);
        }
        if fast_path.ready {
            Ok(SocketConnectFastPathCompletion::Completed)
        } else {
            Ok(SocketConnectFastPathCompletion::Pending)
        }
    }

    fn take_error(&mut self) -> Result<Option<HostIoError>, HostIoError> {
        Ok(self.socket_error.take())
    }

    fn local_addr(&self) -> Result<SocketAddress, HostIoError> {
        Ok(self.bound.or(self.local).unwrap_or_else(|| {
            SocketAddress::unspecified_for_domain(
                self.connected
                    .map_or(SocketDomain::Inet, SocketAddress::domain),
            )
        }))
    }

    fn peer_addr(&self) -> Result<SocketAddress, HostIoError> {
        if self.fail_peer_addr {
            return Err(HostIoError::new(
                LinuxErrno::ConnectionReset,
                "UDP peer address query failed",
            ));
        }
        self.connected
            .ok_or_else(|| HostIoError::new(LinuxErrno::NotConnected, "socket is not connected"))
    }

    fn send(&mut self, buffer: &[u8]) -> Result<usize, HostIoError> {
        if let Some(error) = &self.fail_send {
            return Err(error.clone());
        }
        self.sent.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn send_to(&mut self, buffer: &[u8], address: SocketAddress) -> Result<usize, HostIoError> {
        self.connected = Some(address);
        self.send(buffer)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, HostIoError> {
        let count = buffer.len().min(self.incoming.len());
        buffer[..count].copy_from_slice(&self.incoming[..count]);
        self.incoming.drain(..count);
        Ok(count)
    }

    fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddress), HostIoError> {
        let count = self.recv(buffer)?;
        let address = self
            .connected
            .unwrap_or_else(|| SocketAddress::inet([127, 0, 0, 1], 53));
        Ok((count, address))
    }

    fn poll(
        &mut self,
        interest: SocketEvents,
        _timeout: Option<Duration>,
    ) -> Result<SocketEvents, HostIoError> {
        if let Some(calls) = &self.poll_calls {
            calls.set(calls.get() + 1);
        }
        if let Some(readiness) = self.fallback_readiness {
            return Ok(readiness);
        }
        Ok(SocketEvents {
            readable: interest.readable && !self.incoming.is_empty(),
            writable: interest.writable,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        })
    }

    fn drain_readiness_completions(
        &mut self,
        token: SocketReadinessToken,
    ) -> Result<Vec<HostSocketCompletion>, HostIoError> {
        let mut completions = self
            .readiness_completions
            .drain(..)
            .map(|completion| match completion {
                ReadinessCompletionFixture::Current(kind) => HostSocketCompletion::new(token, kind),
                ReadinessCompletionFixture::Stale(kind) => HostSocketCompletion::new(
                    SocketReadinessToken::new(token.socket(), token.generation().saturating_add(1)),
                    kind,
                ),
            })
            .collect::<Vec<_>>();
        if let Some(fast_path) = self.fast_path_accept.as_mut()
            && fast_path.submitted
            && !fast_path.ready
        {
            fast_path.ready = true;
            completions.push(HostSocketCompletion::new(
                token,
                SocketFastPathKind::AcceptEx.completion_kind(),
            ));
        }
        if let Some(fast_path) = self.fast_path_connect.as_mut()
            && fast_path.submitted
            && !fast_path.ready
        {
            fast_path.ready = true;
            completions.push(HostSocketCompletion::new(
                token,
                SocketFastPathKind::ConnectEx.completion_kind(),
            ));
        }
        Ok(completions)
    }

    fn shutdown(&mut self, _how: ShutdownHow) -> Result<(), HostIoError> {
        Ok(())
    }
}

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
