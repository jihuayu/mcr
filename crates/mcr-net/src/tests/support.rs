pub(super) use std::{
    cell::{Cell, RefCell},
    io::{IoSlice, IoSliceMut},
    net::{IpAddr, SocketAddr},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

pub(super) use mcr_win::{
    AddressFamily, HostSocketOptionName, HostSocketOptionValue, HostWorkerPoolConfig,
    HostWorkerPoolExecutor, HostWorkerPoolRole, NetworkStack, SocketCompletionKind, SocketEvents,
    SocketFastPathKind, SocketKind, SocketProtocol as HostSocketProtocol,
};

pub(super) use crate::*;

#[derive(Debug, Default)]
pub(super) struct FakeHostSocketHandle {
    pub(super) sent: Vec<u8>,
    pub(super) incoming: Vec<u8>,
    pub(super) local: Option<SocketAddress>,
    connected: Option<SocketAddress>,
    fail_peer_addr: bool,
    connect_error: Option<HostIoError>,
    socket_error: Option<HostIoError>,
    fail_send: Option<HostIoError>,
    readiness_completions: Vec<ReadinessCompletionFixture>,
    fallback_readiness: Option<SocketEvents>,
    pub(super) poll_calls: Option<Rc<Cell<usize>>>,
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
    pub(super) fn with_incoming(bytes: &[u8]) -> Self {
        Self {
            incoming: bytes.to_vec(),
            ..Self::default()
        }
    }

    pub(super) fn with_send_error(error: HostIoError) -> Self {
        Self {
            fail_send: Some(error),
            ..Self::default()
        }
    }

    pub(super) fn with_connect_error(error: HostIoError) -> Self {
        Self {
            connect_error: Some(error),
            ..Self::default()
        }
    }

    pub(super) fn with_pending_connect_error(error: HostIoError) -> Self {
        Self {
            connect_error: Some(HostIoError::new(
                LinuxErrno::OperationWouldBlock,
                "connect would block",
            )),
            socket_error: Some(error),
            ..Self::default()
        }
    }

    pub(super) fn with_local_endpoint(local: SocketAddress) -> Self {
        Self {
            local: Some(local),
            ..Self::default()
        }
    }

    pub(super) fn with_udp_peer_addr_unsupported() -> Self {
        Self {
            fail_peer_addr: true,
            ..Self::default()
        }
    }

    pub(super) fn with_accepted(peer: SocketAddress, incoming: &[u8]) -> Self {
        Self {
            accepted: vec![(Self::with_incoming(incoming), peer)],
            ..Self::default()
        }
    }

    pub(super) fn with_counted_accepted(
        peer: SocketAddress,
        incoming: &[u8],
        accept_calls: Rc<Cell<usize>>,
    ) -> Self {
        Self {
            accept_calls: Some(accept_calls),
            ..Self::with_accepted(peer, incoming)
        }
    }

    pub(super) fn with_acceptex(
        peer: SocketAddress,
        incoming: &[u8],
        accept_calls: Rc<Cell<usize>>,
    ) -> Self {
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

    pub(super) fn with_counted_connect(
        local: SocketAddress,
        connect_calls: Rc<Cell<usize>>,
    ) -> Self {
        Self {
            local: Some(local),
            connect_calls: Some(connect_calls),
            ..Self::default()
        }
    }

    pub(super) fn with_connectex(local: SocketAddress, connect_calls: Rc<Cell<usize>>) -> Self {
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

    pub(super) fn with_readiness(
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
pub(super) struct VectoredHostState {
    pub(super) sent: Vec<u8>,
    pub(super) incoming: Vec<u8>,
    pub(super) local: SocketAddress,
    pub(super) peer: Option<SocketAddress>,
    pub(super) send_calls: usize,
    pub(super) send_vectored_calls: usize,
    pub(super) send_to_calls: usize,
    pub(super) send_to_vectored_calls: usize,
    pub(super) recv_calls: usize,
    pub(super) recv_vectored_calls: usize,
    pub(super) recv_from_calls: usize,
    pub(super) recv_from_vectored_calls: usize,
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
    pub(super) fn with_incoming(bytes: &[u8]) -> Self {
        Self {
            incoming: bytes.to_vec(),
            ..Self::default()
        }
    }

    pub(super) fn drain_into(&mut self, buffer: &mut [u8]) -> usize {
        let count = buffer.len().min(self.incoming.len());
        buffer[..count].copy_from_slice(&self.incoming[..count]);
        self.incoming.drain(..count);
        count
    }
}

#[derive(Debug)]
pub(super) struct VectoredHostSocketHandle {
    state: Rc<RefCell<VectoredHostState>>,
}

impl VectoredHostSocketHandle {
    pub(super) fn new(state: Rc<RefCell<VectoredHostState>>) -> Self {
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
pub(super) enum ReadinessCompletionFixture {
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
