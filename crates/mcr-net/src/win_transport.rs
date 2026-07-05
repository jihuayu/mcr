use std::{
    collections::VecDeque,
    io::{IoSlice, IoSliceMut},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use mcr_win::{
    AddressFamily, HostAcceptExSubmission, HostConnectExSubmission, HostErrorKind,
    HostIoCompletionPort, HostRioCapability, HostShutdown, HostSocket, HostSocketIoDirection,
    HostSocketIoSubmission, HostSocketOptionName, HostSocketOptionValue, HostWorkerPoolConfig,
    HostWorkerPoolExecutor, HostWorkerPoolJobError, HostWorkerPoolRole, HostWorkerPoolSubmitError,
    NetworkStack, PendingHostAcceptEx, PendingHostConnectEx, PendingHostSocketIo,
    SocketCompletionKind, SocketEvents, SocketKind, SocketProtocol as HostSocketProtocol,
};

use crate::{
    error::{HostIoError, LinuxErrno},
    options::SocketOptions,
    table::merge_socket_events,
    transport::{HostSocketBatchPoll, HostSocketHandle, HostSocketTransport},
    types::{
        HostSocketCompletion, ShutdownHow, SocketAcceptFastPath, SocketAddress,
        SocketConnectFastPath, SocketConnectFastPathCompletion, SocketDomain, SocketProtocol,
        SocketReadinessToken, SocketSpec, SocketType,
    },
};

#[derive(Debug)]
pub struct WinHostSocketTransport {
    stack: NetworkStack,
    io_completion_pool: Option<Arc<HostWorkerPoolExecutor>>,
}

impl WinHostSocketTransport {
    pub fn new() -> Result<Self, HostIoError> {
        let io_completion_pool = HostWorkerPoolExecutor::new(HostWorkerPoolConfig::default_for(
            HostWorkerPoolRole::IoCompletion,
        ))
        .map(Arc::new)
        .map_err(|error| {
            HostIoError::new(
                LinuxErrno::OperationNotSupported,
                format!("start IO completion worker pool: {error}"),
            )
        })?;
        Ok(Self {
            stack: NetworkStack::start().map_err(HostIoError::from)?,
            io_completion_pool: Some(io_completion_pool),
        })
    }

    pub fn with_io_completion_pool(
        io_completion_pool: Arc<HostWorkerPoolExecutor>,
    ) -> Result<Self, HostIoError> {
        Ok(Self {
            stack: NetworkStack::start().map_err(HostIoError::from)?,
            io_completion_pool: Some(io_completion_pool),
        })
    }
}

impl HostSocketTransport for WinHostSocketTransport {
    fn open_socket(
        &self,
        spec: SocketSpec,
        options: SocketOptions,
    ) -> Result<Box<dyn HostSocketHandle>, HostIoError> {
        let family = address_family_from_socket_domain(spec.domain);
        let kind = socket_kind_from_socket_type(spec.socket_type);
        let protocol = host_protocol_from_socket_protocol(spec.effective_protocol());
        let (socket, completion_port) = match HostIoCompletionPort::new() {
            Ok(port) => {
                let port = Arc::new(port);
                let socket = self
                    .stack
                    .open_socket_with_iocp(family, kind, protocol, &port, WIN_IOCP_COMPLETION_KEY)
                    .map_err(HostIoError::from)?;
                (socket, Some(port))
            }
            Err(_) => {
                let socket = self
                    .stack
                    .open_socket(family, kind, protocol)
                    .map_err(HostIoError::from)?;
                (socket, None)
            }
        };
        apply_socket_options(&socket, spec, options)?;
        if spec.flags.nonblocking {
            socket.set_nonblocking(true).map_err(HostIoError::from)?;
        }
        Ok(Box::new(WinHostSocketHandle {
            socket,
            spec,
            completion_port,
            io_completion_pool: self.io_completion_pool.clone(),
            pending_accept: None,
            accepted_fast_path: None,
            accept_error: None,
            pending_recv: None,
            recv_ready: VecDeque::new(),
            recv_eof: false,
            recv_error: None,
            pending_connect: None,
            connect_completed: false,
            connect_error: None,
        }))
    }
}

#[derive(Debug)]
struct WinHostSocketHandle {
    socket: HostSocket,
    spec: SocketSpec,
    completion_port: Option<Arc<HostIoCompletionPort>>,
    io_completion_pool: Option<Arc<HostWorkerPoolExecutor>>,
    pending_accept: Option<PendingHostAcceptEx>,
    accepted_fast_path: Option<(HostSocket, SocketAddress)>,
    accept_error: Option<HostIoError>,
    pending_recv: Option<PendingHostSocketIo>,
    recv_ready: VecDeque<u8>,
    recv_eof: bool,
    recv_error: Option<HostIoError>,
    pending_connect: Option<PendingHostConnectEx>,
    connect_completed: bool,
    connect_error: Option<HostIoError>,
}

const WIN_IOCP_COMPLETION_KEY: usize = 1;
const WIN_IOCP_RECV_BUFFER_SIZE: usize = 16 * 1024;

impl WinHostSocketHandle {
    fn can_use_iocp_recv(&self) -> bool {
        self.completion_port.is_some()
            && self.spec.socket_type == SocketType::Stream
            && self.spec.effective_protocol() == SocketProtocol::Tcp
    }

    fn can_use_iocp_send(&self) -> bool {
        self.completion_port.is_some()
            && !self.spec.flags.nonblocking
            && self.pending_accept.is_none()
            && self.pending_connect.is_none()
            && self.pending_recv.is_none()
            && self.spec.socket_type == SocketType::Stream
            && self.spec.effective_protocol() == SocketProtocol::Tcp
    }

    fn has_recv_readiness(&self) -> bool {
        !self.recv_ready.is_empty() || self.recv_eof
    }

    fn submit_recv_fast_path(&mut self) -> Result<(), HostIoError> {
        if self.pending_recv.is_some() || self.has_recv_readiness() || self.recv_error.is_some() {
            return Ok(());
        }

        let submission = self
            .socket
            .submit_overlapped_recv(vec![0; WIN_IOCP_RECV_BUFFER_SIZE]);
        self.apply_recv_submission(submission)
    }

    fn complete_recv_packet(
        &mut self,
        packet: mcr_win::HostIoCompletionPacket,
    ) -> Result<(), HostIoError> {
        let Some(pending) = self.pending_recv.take() else {
            return Ok(());
        };
        if pending.matches_completion(packet) {
            let submission = pending.complete_from_packet(packet);
            self.apply_recv_submission(submission)?;
        } else {
            self.pending_recv = Some(pending);
        }
        Ok(())
    }

    fn apply_recv_submission(
        &mut self,
        submission: HostSocketIoSubmission,
    ) -> Result<(), HostIoError> {
        match submission {
            HostSocketIoSubmission::Completed(completion) => {
                if completion.direction() != HostSocketIoDirection::Receive {
                    return Err(HostIoError::new(
                        LinuxErrno::InvalidArgument,
                        "overlapped socket completion direction mismatch",
                    ));
                }
                let bytes_transferred = completion.bytes_transferred();
                self.cache_recv_completion(bytes_transferred, completion.into_buffer());
                Ok(())
            }
            HostSocketIoSubmission::Failed(failure) => {
                if failure.direction() != HostSocketIoDirection::Receive {
                    return Err(HostIoError::new(
                        LinuxErrno::InvalidArgument,
                        "overlapped socket failure direction mismatch",
                    ));
                }
                let (error, _) = failure.into_parts();
                self.recv_error = Some(HostIoError::from(error));
                Ok(())
            }
            HostSocketIoSubmission::Pending(pending) => {
                if pending.direction() != HostSocketIoDirection::Receive {
                    return Err(HostIoError::new(
                        LinuxErrno::InvalidArgument,
                        "overlapped socket pending direction mismatch",
                    ));
                }
                self.pending_recv = Some(pending);
                Ok(())
            }
        }
    }

    fn cache_recv_completion(&mut self, bytes_transferred: usize, buffer: Vec<u8>) {
        if bytes_transferred == 0 {
            self.recv_eof = true;
            return;
        }
        self.recv_ready
            .extend(buffer.into_iter().take(bytes_transferred));
    }

    fn recv_completion_kind(&self) -> SocketCompletionKind {
        if self.recv_error.is_some() {
            SocketCompletionKind::Error
        } else if self.recv_eof {
            SocketCompletionKind::PeerClosed
        } else {
            SocketCompletionKind::Receive
        }
    }

    fn submit_send_fast_path(&mut self, buffer: &[u8]) -> Result<Option<usize>, HostIoError> {
        if !self.can_use_iocp_send() || buffer.is_empty() {
            return Ok(None);
        }
        let submission = self.socket.submit_overlapped_send(buffer.to_vec());
        self.finish_send_submission(submission).map(Some)
    }

    fn finish_send_submission(
        &mut self,
        submission: HostSocketIoSubmission,
    ) -> Result<usize, HostIoError> {
        match submission {
            HostSocketIoSubmission::Completed(completion) => {
                if completion.direction() != HostSocketIoDirection::Send {
                    return Err(HostIoError::new(
                        LinuxErrno::InvalidArgument,
                        "overlapped socket completion direction mismatch",
                    ));
                }
                Ok(completion.bytes_transferred())
            }
            HostSocketIoSubmission::Failed(failure) => {
                if failure.direction() != HostSocketIoDirection::Send {
                    return Err(HostIoError::new(
                        LinuxErrno::InvalidArgument,
                        "overlapped socket failure direction mismatch",
                    ));
                }
                let (error, _) = failure.into_parts();
                Err(HostIoError::from(error))
            }
            HostSocketIoSubmission::Pending(pending) => self.wait_send_completion(pending),
        }
    }

    fn wait_send_completion(&mut self, pending: PendingHostSocketIo) -> Result<usize, HostIoError> {
        if let Some(pool) = self.io_completion_pool.as_ref()
            && let Some(port) = self.completion_port.as_ref()
        {
            let job = pool
                .submit_result({
                    let port = port.clone();
                    move || wait_socket_io_completion_on_worker(port, pending)
                })
                .map_err(worker_submit_error)?;
            let submission = job.recv().map_err(worker_job_error)??;
            return self.finish_send_submission(submission);
        }

        loop {
            let packet = {
                let port = self.completion_port.as_ref().ok_or_else(|| {
                    HostIoError::new(
                        LinuxErrno::InvalidArgument,
                        "overlapped send requires an IOCP",
                    )
                })?;
                port.get(None).map_err(HostIoError::from)?
            };
            let Some(packet) = packet else {
                continue;
            };
            if pending.matches_completion(packet) {
                return self.finish_send_submission(pending.complete_from_packet(packet));
            }
            self.complete_recv_packet(packet)?;
        }
    }
}

fn wait_socket_io_completion_on_worker(
    port: Arc<HostIoCompletionPort>,
    pending: PendingHostSocketIo,
) -> Result<HostSocketIoSubmission, HostIoError> {
    loop {
        let Some(packet) = port.get(None).map_err(HostIoError::from)? else {
            continue;
        };
        if pending.matches_completion(packet) {
            return Ok(pending.complete_from_packet(packet));
        }
    }
}

fn worker_submit_error(error: HostWorkerPoolSubmitError) -> HostIoError {
    HostIoError::new(
        LinuxErrno::OperationWouldBlock,
        format!("IO completion worker submit failed: {error}"),
    )
}

fn worker_job_error(error: HostWorkerPoolJobError) -> HostIoError {
    let errno = match error {
        HostWorkerPoolJobError::Panicked => LinuxErrno::ConnectionReset,
        HostWorkerPoolJobError::TimedOut => LinuxErrno::TimedOut,
    };
    HostIoError::new(errno, format!("IO completion worker failed: {error}"))
}

impl HostSocketHandle for WinHostSocketHandle {
    fn bind(&mut self, address: SocketAddress) -> Result<SocketAddress, HostIoError> {
        self.socket
            .bind(SocketAddr::from(address))
            .map_err(HostIoError::from)?;
        self.socket
            .local_addr()
            .map(SocketAddress::from)
            .map_err(HostIoError::from)
    }

    fn listen(&mut self, backlog: u32) -> Result<(), HostIoError> {
        let backlog = i32::try_from(backlog).map_err(|_| {
            HostIoError::new(LinuxErrno::InvalidArgument, "listen backlog too large")
        })?;
        self.socket.listen(backlog).map_err(HostIoError::from)
    }

    fn accept_fast_path(
        &mut self,
        _token: SocketReadinessToken,
        spec: SocketSpec,
    ) -> Result<SocketAcceptFastPath, HostIoError> {
        if let Some(error) = self.accept_error.take() {
            return Err(error);
        }
        if let Some((socket, peer)) = self.accepted_fast_path.take() {
            return Ok(SocketAcceptFastPath::Accepted {
                handle: Box::new(Self {
                    socket,
                    spec,
                    completion_port: None,
                    io_completion_pool: self.io_completion_pool.clone(),
                    pending_accept: None,
                    accepted_fast_path: None,
                    accept_error: None,
                    pending_recv: None,
                    recv_ready: VecDeque::new(),
                    recv_eof: false,
                    recv_error: None,
                    pending_connect: None,
                    connect_completed: false,
                    connect_error: None,
                }),
                peer,
            });
        }
        if self.pending_accept.is_some() {
            return Ok(SocketAcceptFastPath::Pending);
        }
        if self.completion_port.is_none()
            || self.spec.socket_type != SocketType::Stream
            || self.spec.effective_protocol() != SocketProtocol::Tcp
        {
            return Ok(SocketAcceptFastPath::Unsupported);
        }

        match self.socket.submit_accept_ex() {
            HostAcceptExSubmission::Pending(pending) => {
                self.pending_accept = Some(pending);
                Ok(SocketAcceptFastPath::Pending)
            }
            HostAcceptExSubmission::Failed(error) if error.kind() == HostErrorKind::Unsupported => {
                Ok(SocketAcceptFastPath::Unsupported)
            }
            HostAcceptExSubmission::Failed(error) => Err(HostIoError::from(error)),
        }
    }

    fn accept(&mut self) -> Result<(Box<dyn HostSocketHandle>, SocketAddress), HostIoError> {
        let (socket, peer) = self.socket.accept().map_err(HostIoError::from)?;
        Ok((
            Box::new(Self {
                socket,
                spec: self.spec,
                completion_port: None,
                io_completion_pool: self.io_completion_pool.clone(),
                pending_accept: None,
                accepted_fast_path: None,
                accept_error: None,
                pending_recv: None,
                recv_ready: VecDeque::new(),
                recv_eof: false,
                recv_error: None,
                pending_connect: None,
                connect_completed: false,
                connect_error: None,
            }),
            SocketAddress::from(peer),
        ))
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), HostIoError> {
        self.socket
            .set_nonblocking(nonblocking)
            .map_err(HostIoError::from)?;
        self.spec.flags.nonblocking = nonblocking;
        Ok(())
    }

    fn connect_fast_path(
        &mut self,
        _token: SocketReadinessToken,
        address: SocketAddress,
    ) -> Result<SocketConnectFastPath, HostIoError> {
        if self.pending_connect.is_some()
            || self.completion_port.is_none()
            || self.spec.socket_type != SocketType::Stream
            || self.spec.effective_protocol() != SocketProtocol::Tcp
        {
            return Ok(SocketConnectFastPath::Unsupported);
        }
        if self.socket.local_addr().is_err() {
            self.socket
                .bind(SocketAddr::from(SocketAddress::unspecified_for_domain(
                    address.domain(),
                )))
                .map_err(HostIoError::from)?;
        }
        match self.socket.submit_connect_ex(SocketAddr::from(address)) {
            HostConnectExSubmission::Pending(pending) => {
                self.pending_connect = Some(pending);
                Ok(SocketConnectFastPath::Pending)
            }
            HostConnectExSubmission::Failed(error) => Err(HostIoError::from(error)),
        }
    }

    fn connect(&mut self, address: SocketAddress) -> Result<(), HostIoError> {
        self.socket
            .connect(SocketAddr::from(address))
            .map_err(HostIoError::from)
    }

    fn complete_connect_fast_path(
        &mut self,
    ) -> Result<SocketConnectFastPathCompletion, HostIoError> {
        if self.connect_completed {
            self.connect_completed = false;
            return Ok(SocketConnectFastPathCompletion::Completed);
        }
        if self.connect_error.is_some() {
            return Ok(SocketConnectFastPathCompletion::Completed);
        }
        if self.pending_connect.is_some() {
            return Ok(SocketConnectFastPathCompletion::Pending);
        }
        Ok(SocketConnectFastPathCompletion::Inactive)
    }

    fn rio_capability(&mut self) -> Result<HostRioCapability, HostIoError> {
        self.socket.rio_capability().map_err(HostIoError::from)
    }

    fn take_error(&mut self) -> Result<Option<HostIoError>, HostIoError> {
        if self.connect_error.is_some() {
            return Ok(self.connect_error.take());
        }
        self.socket
            .take_error()
            .map(|error| error.map(HostIoError::from))
            .map_err(HostIoError::from)
    }

    fn local_addr(&self) -> Result<SocketAddress, HostIoError> {
        self.socket
            .local_addr()
            .map(SocketAddress::from)
            .map_err(HostIoError::from)
    }

    fn peer_addr(&self) -> Result<SocketAddress, HostIoError> {
        self.socket
            .peer_addr()
            .map(SocketAddress::from)
            .map_err(HostIoError::from)
    }

    fn send(&mut self, buffer: &[u8]) -> Result<usize, HostIoError> {
        if let Some(count) = self.submit_send_fast_path(buffer)? {
            return Ok(count);
        }
        self.socket.send(buffer).map_err(HostIoError::from)
    }

    fn send_vectored(&mut self, buffers: &[IoSlice<'_>]) -> Result<usize, HostIoError> {
        self.socket
            .send_vectored(buffers)
            .map_err(HostIoError::from)
    }

    fn send_to(&mut self, buffer: &[u8], address: SocketAddress) -> Result<usize, HostIoError> {
        self.socket
            .send_to(buffer, SocketAddr::from(address))
            .map_err(HostIoError::from)
    }

    fn send_to_vectored(
        &mut self,
        buffers: &[IoSlice<'_>],
        address: SocketAddress,
    ) -> Result<usize, HostIoError> {
        self.socket
            .send_to_vectored(buffers, SocketAddr::from(address))
            .map_err(HostIoError::from)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, HostIoError> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if !self.recv_ready.is_empty() {
            let count = buffer.len().min(self.recv_ready.len());
            for slot in &mut buffer[..count] {
                *slot = self
                    .recv_ready
                    .pop_front()
                    .expect("recv cache length was checked");
            }
            return Ok(count);
        }
        if self.recv_eof {
            return Ok(0);
        }
        if let Some(error) = self.recv_error.take() {
            return Err(error);
        }
        if self.pending_recv.is_some() {
            return Err(HostIoError::new(
                LinuxErrno::OperationWouldBlock,
                "overlapped receive is pending",
            ));
        }
        self.socket.recv(buffer).map_err(HostIoError::from)
    }

    fn recv_vectored(&mut self, buffers: &mut [IoSliceMut<'_>]) -> Result<usize, HostIoError> {
        self.socket
            .recv_vectored(buffers)
            .map_err(HostIoError::from)
    }

    fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddress), HostIoError> {
        self.socket
            .recv_from(buffer)
            .map(|(count, address)| (count, SocketAddress::from(address)))
            .map_err(HostIoError::from)
    }

    fn recv_from_vectored(
        &mut self,
        buffers: &mut [IoSliceMut<'_>],
    ) -> Result<(usize, SocketAddress), HostIoError> {
        self.socket
            .recv_from_vectored(buffers)
            .map(|(count, address)| (count, SocketAddress::from(address)))
            .map_err(HostIoError::from)
    }

    fn poll(
        &mut self,
        interest: SocketEvents,
        timeout: Option<Duration>,
    ) -> Result<SocketEvents, HostIoError> {
        let mut readiness = SocketEvents::default();
        let mut fallback_interest = interest;
        if interest.readable && self.can_use_iocp_recv() {
            fallback_interest.readable = false;
            self.submit_recv_fast_path()?;
            if !self.has_recv_readiness()
                && let Some(port) = self.completion_port.as_ref()
                && self.pending_recv.is_some()
                && let Some(packet) = port.get(timeout).map_err(HostIoError::from)?
            {
                self.complete_recv_packet(packet)?;
            }
            if self.has_recv_readiness() {
                readiness.readable = true;
            }
            if self.recv_error.is_some() {
                readiness.error = true;
            }
        }

        if !fallback_interest.is_empty() {
            let fallback_timeout = if readiness.is_empty() {
                timeout
            } else {
                Some(Duration::ZERO)
            };
            let fallback = self
                .socket
                .poll(fallback_interest, fallback_timeout)
                .map_err(HostIoError::from)?;
            merge_socket_events(&mut readiness, fallback);
        }
        Ok(readiness)
    }

    fn prepare_batch_poll(
        &mut self,
        interest: SocketEvents,
        _timeout: Option<Duration>,
    ) -> Result<Option<HostSocketBatchPoll>, HostIoError> {
        if interest.readable && self.can_use_iocp_recv() {
            return Ok(None);
        }
        Ok(Some(HostSocketBatchPoll::new(
            self.socket.clone(),
            interest,
        )))
    }

    fn finish_batch_poll(&mut self, readiness: SocketEvents) -> Result<SocketEvents, HostIoError> {
        Ok(readiness)
    }

    fn drain_readiness_completions(
        &mut self,
        token: SocketReadinessToken,
    ) -> Result<Vec<HostSocketCompletion>, HostIoError> {
        let mut completions = Vec::new();
        if self.completion_port.is_none() {
            return Ok(completions);
        }
        loop {
            let packet = {
                let port = self
                    .completion_port
                    .as_ref()
                    .expect("completion port was checked");
                port.get(Some(Duration::ZERO)).map_err(HostIoError::from)?
            };
            let Some(packet) = packet else {
                break;
            };
            let mut packet = Some(packet);
            if let Some(pending) = self.pending_accept.take() {
                let current = packet.expect("completion packet is present");
                if pending.matches_completion(current) {
                    match pending.complete_from_packet(current) {
                        Ok((socket, peer)) => {
                            self.accepted_fast_path = Some((socket, SocketAddress::from(peer)));
                            completions.push(HostSocketCompletion::new(
                                token,
                                SocketCompletionKind::Accept,
                            ));
                        }
                        Err(error) => {
                            self.accept_error = Some(HostIoError::from(error));
                            completions.push(HostSocketCompletion::new(
                                token,
                                SocketCompletionKind::Accept,
                            ));
                            completions.push(HostSocketCompletion::new(
                                token,
                                SocketCompletionKind::Error,
                            ));
                        }
                    }
                    packet = None;
                } else {
                    self.pending_accept = Some(pending);
                    packet = Some(current);
                }
            }
            if let Some(current) = packet
                && let Some(pending) = self.pending_recv.take()
            {
                if pending.matches_completion(current) {
                    let submission = pending.complete_from_packet(current);
                    self.apply_recv_submission(submission)?;
                    completions.push(HostSocketCompletion::new(
                        token,
                        self.recv_completion_kind(),
                    ));
                    packet = None;
                } else {
                    self.pending_recv = Some(pending);
                    packet = Some(current);
                }
            }
            let Some(packet) = packet else {
                continue;
            };
            if let Some(pending) = self.pending_connect.take() {
                if pending.matches_completion(packet) {
                    match pending.complete_from_packet(packet) {
                        Ok(()) => {
                            self.connect_completed = true;
                            completions.push(HostSocketCompletion::new(
                                token,
                                SocketCompletionKind::Connect,
                            ));
                        }
                        Err(error) => {
                            self.connect_error = Some(HostIoError::from(error));
                            completions.push(HostSocketCompletion::new(
                                token,
                                SocketCompletionKind::Connect,
                            ));
                            completions.push(HostSocketCompletion::new(
                                token,
                                SocketCompletionKind::Error,
                            ));
                        }
                    }
                } else {
                    self.pending_connect = Some(pending);
                }
            }
        }
        Ok(completions)
    }

    fn shutdown(&mut self, how: ShutdownHow) -> Result<(), HostIoError> {
        self.socket
            .shutdown(host_shutdown_from_how(how))
            .map_err(HostIoError::from)
    }
}
const fn address_family_from_socket_domain(domain: SocketDomain) -> AddressFamily {
    match domain {
        SocketDomain::Inet => AddressFamily::Inet,
        SocketDomain::Inet6 => AddressFamily::Inet6,
    }
}

const fn socket_kind_from_socket_type(socket_type: SocketType) -> SocketKind {
    match socket_type {
        SocketType::Stream => SocketKind::Stream,
        SocketType::Datagram => SocketKind::Datagram,
    }
}

const fn host_protocol_from_socket_protocol(protocol: SocketProtocol) -> HostSocketProtocol {
    match protocol {
        SocketProtocol::Default => HostSocketProtocol::Default,
        SocketProtocol::Tcp => HostSocketProtocol::Tcp,
        SocketProtocol::Udp => HostSocketProtocol::Udp,
    }
}

const fn host_shutdown_from_how(how: ShutdownHow) -> HostShutdown {
    match how {
        ShutdownHow::Read => HostShutdown::Read,
        ShutdownHow::Write => HostShutdown::Write,
        ShutdownHow::ReadWrite => HostShutdown::Both,
    }
}
fn apply_socket_options(
    socket: &HostSocket,
    spec: SocketSpec,
    options: SocketOptions,
) -> Result<(), HostIoError> {
    socket
        .set_option(
            HostSocketOptionName::ReuseAddress,
            HostSocketOptionValue::Bool(options.reuse_addr),
        )
        .map_err(HostIoError::from)?;
    if spec.effective_protocol() == SocketProtocol::Tcp {
        socket
            .set_option(
                HostSocketOptionName::KeepAlive,
                HostSocketOptionValue::Bool(options.keep_alive),
            )
            .map_err(HostIoError::from)?;
    }
    socket
        .set_option(
            HostSocketOptionName::SendBufferSize,
            HostSocketOptionValue::Int(options.send_buffer_size as i32),
        )
        .map_err(HostIoError::from)?;
    socket
        .set_option(
            HostSocketOptionName::ReceiveBufferSize,
            HostSocketOptionValue::Int(options.receive_buffer_size as i32),
        )
        .map_err(HostIoError::from)?;
    if spec.effective_protocol() == SocketProtocol::Tcp {
        socket
            .set_option(
                HostSocketOptionName::TcpNoDelay,
                HostSocketOptionValue::Bool(options.tcp_no_delay),
            )
            .map_err(HostIoError::from)?;
    }
    Ok(())
}
