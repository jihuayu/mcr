use std::{
    collections::BTreeMap,
    fmt,
    io::{IoSlice, IoSliceMut},
    time::Duration,
};

use mcr_win::{HostRioCapability, SocketEvents, SocketPoll, poll_sockets};

use crate::{
    error::{HostIoError, LinuxErrno, SocketError, SocketOperation},
    options::{
        SocketOptionName, bool_to_socket_option, socket_option_to_bool, validate_buffer_size,
    },
    transport::{HostSocketBatchPoll, HostSocketHandle, HostSocketTransport},
    types::{
        GuestSocket, HostSocketCompletion, ShutdownFlags, ShutdownHow, SocketAcceptFastPath,
        SocketAddress, SocketConnectFastPath, SocketConnectFastPathCompletion, SocketDomain,
        SocketId, SocketProtocol, SocketReadinessToken, SocketSpec, SocketState, SocketType,
    },
    validation::{
        validate_address_domain, validate_connect, validate_connected_io,
        validate_connected_stream_io, validate_datagram_io, validate_socket_protocol,
    },
};

#[derive(Debug)]
struct HostSocketEntry {
    handle: Box<dyn HostSocketHandle>,
    readiness_token: SocketReadinessToken,
}

#[derive(Debug, Default)]
struct SocketReadinessCache {
    ready: BTreeMap<SocketReadinessToken, SocketEvents>,
}

impl SocketReadinessCache {
    fn apply_completion(
        &mut self,
        active_token: SocketReadinessToken,
        completion: HostSocketCompletion,
    ) {
        if completion.token() != active_token {
            return;
        }

        let readiness = self.ready.entry(active_token).or_default();
        merge_socket_events(readiness, completion.readiness());
    }

    fn readiness(
        &self,
        active_token: SocketReadinessToken,
        interest: SocketEvents,
    ) -> Option<SocketEvents> {
        self.ready
            .get(&active_token)
            .map(|readiness| socket_readiness_for_interest(*readiness, interest))
            .filter(|readiness| !readiness.is_empty())
    }

    fn clear_socket(&mut self, id: SocketId) {
        self.ready.retain(|token, _| token.socket() != id);
    }
}

pub(crate) fn merge_socket_events(target: &mut SocketEvents, update: SocketEvents) {
    target.readable |= update.readable;
    target.writable |= update.writable;
    target.priority |= update.priority;
    target.error |= update.error;
    target.hang_up |= update.hang_up;
    target.invalid |= update.invalid;
}

fn socket_readiness_for_interest(readiness: SocketEvents, interest: SocketEvents) -> SocketEvents {
    SocketEvents {
        readable: readiness.readable && interest.readable,
        writable: readiness.writable && interest.writable,
        priority: readiness.priority && interest.priority,
        error: readiness.error,
        hang_up: readiness.hang_up,
        invalid: readiness.invalid,
    }
}
pub struct GuestSocketTable {
    next_id: u64,
    next_readiness_generation: u64,
    sockets: BTreeMap<SocketId, GuestSocket>,
    host_handles: BTreeMap<SocketId, HostSocketEntry>,
    readiness_cache: SocketReadinessCache,
    transport: Option<Box<dyn HostSocketTransport>>,
}

impl Default for GuestSocketTable {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for GuestSocketTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestSocketTable")
            .field("next_id", &self.next_id)
            .field("next_readiness_generation", &self.next_readiness_generation)
            .field("sockets", &self.sockets)
            .field(
                "host_handles",
                &self.host_handles.keys().collect::<Vec<_>>(),
            )
            .field("readiness_cache", &self.readiness_cache)
            .field("has_transport", &self.transport.is_some())
            .finish()
    }
}

impl GuestSocketTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: SocketId::MIN.get(),
            next_readiness_generation: 1,
            sockets: BTreeMap::new(),
            host_handles: BTreeMap::new(),
            readiness_cache: SocketReadinessCache::default(),
            transport: None,
        }
    }

    #[must_use]
    pub fn with_transport(transport: impl HostSocketTransport + 'static) -> Self {
        Self {
            next_id: SocketId::MIN.get(),
            next_readiness_generation: 1,
            sockets: BTreeMap::new(),
            host_handles: BTreeMap::new(),
            readiness_cache: SocketReadinessCache::default(),
            transport: Some(Box::new(transport)),
        }
    }

    pub fn create_socket(
        &mut self,
        domain: SocketDomain,
        socket_type: SocketType,
        protocol: SocketProtocol,
    ) -> Result<SocketId, SocketError> {
        self.create_socket_from_spec(SocketSpec::new(domain, socket_type, protocol)?)
    }

    pub fn create_socket_from_spec(&mut self, spec: SocketSpec) -> Result<SocketId, SocketError> {
        validate_socket_protocol(spec.socket_type, spec.protocol)?;
        let id = self.allocate_id()?;
        let previous = self.sockets.insert(id, GuestSocket::new(id, spec));
        debug_assert!(previous.is_none());
        Ok(id)
    }

    pub fn create_socket_with_handle(
        &mut self,
        spec: SocketSpec,
        handle: Box<dyn HostSocketHandle>,
    ) -> Result<SocketId, SocketError> {
        validate_socket_protocol(spec.socket_type, spec.protocol)?;
        let id = self.allocate_id()?;
        let readiness_token = self.allocate_readiness_token(id)?;
        let previous_socket = self.sockets.insert(id, GuestSocket::new(id, spec));
        debug_assert!(previous_socket.is_none());
        let previous_handle = self.host_handles.insert(
            id,
            HostSocketEntry {
                handle,
                readiness_token,
            },
        );
        debug_assert!(previous_handle.is_none());
        Ok(id)
    }

    pub fn socket(&self, id: SocketId) -> Result<&GuestSocket, SocketError> {
        self.sockets.get(&id).ok_or(SocketError::BadSocket { id })
    }

    pub fn socket_mut(&mut self, id: SocketId) -> Result<&mut GuestSocket, SocketError> {
        self.sockets
            .get_mut(&id)
            .ok_or(SocketError::BadSocket { id })
    }

    pub fn get_option(
        &mut self,
        id: SocketId,
        option: SocketOptionName,
    ) -> Result<u32, SocketError> {
        if option == SocketOptionName::SocketError
            && matches!(self.socket(id)?.state, SocketState::Connecting(_))
            && let Err(error) = self.finish_nonblocking_connect(id)
        {
            if let Ok(socket) = self.socket_mut(id) {
                socket.last_error = None;
            }
            return Ok(error.linux_errno().code() as u32);
        }

        let socket = self.socket_mut(id)?;
        let value = match option {
            SocketOptionName::SocketType => socket.socket_type.to_linux(),
            SocketOptionName::SocketError => socket
                .last_error
                .take()
                .map_or(0, |errno| errno.code() as u32),
            SocketOptionName::ReuseAddr => bool_to_socket_option(socket.options.reuse_addr),
            SocketOptionName::KeepAlive => bool_to_socket_option(socket.options.keep_alive),
            SocketOptionName::SendBuffer => socket.options.send_buffer_size,
            SocketOptionName::ReceiveBuffer => socket.options.receive_buffer_size,
            SocketOptionName::TcpNoDelay => bool_to_socket_option(socket.options.tcp_no_delay),
        };
        Ok(value)
    }

    pub fn set_option(
        &mut self,
        id: SocketId,
        option: SocketOptionName,
        value: u32,
    ) -> Result<(), SocketError> {
        if option.is_read_only() {
            return Err(SocketError::invalid_input(
                SocketOperation::SetSocketOption,
                LinuxErrno::InvalidArgument,
                "socket option is read-only",
            ));
        }

        let socket = self.socket_mut(id)?;
        match option {
            SocketOptionName::ReuseAddr => socket.options.reuse_addr = socket_option_to_bool(value),
            SocketOptionName::KeepAlive => socket.options.keep_alive = socket_option_to_bool(value),
            SocketOptionName::SendBuffer => {
                socket.options.send_buffer_size = validate_buffer_size(value)?
            }
            SocketOptionName::ReceiveBuffer => {
                socket.options.receive_buffer_size = validate_buffer_size(value)?
            }
            SocketOptionName::TcpNoDelay => {
                if socket.effective_protocol() != SocketProtocol::Tcp {
                    return Err(SocketError::invalid_input(
                        SocketOperation::SetSocketOption,
                        LinuxErrno::InvalidArgument,
                        "TCP_NODELAY is only valid for TCP sockets",
                    ));
                }
                socket.options.tcp_no_delay = socket_option_to_bool(value);
            }
            SocketOptionName::SocketType | SocketOptionName::SocketError => unreachable!(),
        }
        Ok(())
    }

    pub fn local_address(&mut self, id: SocketId) -> Result<Option<SocketAddress>, SocketError> {
        if matches!(self.socket(id)?.state, SocketState::Connecting(_)) {
            let _ = self.finish_nonblocking_connect(id);
        }
        Ok(self.socket(id)?.state().local_address())
    }

    pub fn peer_address(&mut self, id: SocketId) -> Result<Option<SocketAddress>, SocketError> {
        if matches!(self.socket(id)?.state, SocketState::Connecting(_)) {
            let _ = self.finish_nonblocking_connect(id);
        }
        Ok(self.socket(id)?.state().peer_address())
    }

    pub fn bind(&mut self, id: SocketId, address: SocketAddress) -> Result<(), SocketError> {
        let socket = self.socket(id)?;
        validate_address_domain(socket.domain, address)?;
        let state = socket.state;

        if matches!(state, SocketState::Created)
            && (self.transport.is_some() || self.host_handles.contains_key(&id))
        {
            let bound = self
                .ensure_host_entry_mut(id, SocketOperation::Bind)?
                .handle
                .bind(address)
                .map_err(SocketError::from_host)?;
            self.socket_mut(id)?.state = SocketState::Bound(bound);
            return Ok(());
        }

        let socket = self.socket_mut(id)?;
        match state {
            SocketState::Created => {
                socket.state = SocketState::Bound(address);
                Ok(())
            }
            SocketState::Bound(_) | SocketState::Listening(_) => Err(SocketError::invalid_state(
                SocketOperation::Bind,
                LinuxErrno::InvalidArgument,
                "socket is already bound",
            )),
            SocketState::Connecting(_) => Err(SocketError::invalid_state(
                SocketOperation::Bind,
                LinuxErrno::InvalidArgument,
                "connecting socket cannot be bound",
            )),
            SocketState::Connected { .. } => Err(SocketError::invalid_state(
                SocketOperation::Bind,
                LinuxErrno::InvalidArgument,
                "connected socket cannot be bound",
            )),
            SocketState::Closed => Err(SocketError::BadSocket { id }),
        }
    }

    pub fn listen(&mut self, id: SocketId, backlog: u32) -> Result<(), SocketError> {
        let socket = self.socket(id)?;
        if socket.socket_type != SocketType::Stream {
            return Err(SocketError::invalid_state(
                SocketOperation::Listen,
                LinuxErrno::OperationNotSupported,
                "only stream sockets can listen",
            ));
        }
        let state = socket.state;

        if matches!(state, SocketState::Bound(_) | SocketState::Listening(_))
            && (self.transport.is_some() || self.host_handles.contains_key(&id))
        {
            self.ensure_host_entry_mut(id, SocketOperation::Listen)?
                .handle
                .listen(backlog)
                .map_err(SocketError::from_host)?;
        }

        let socket = self.socket_mut(id)?;
        match state {
            SocketState::Created => Err(SocketError::invalid_state(
                SocketOperation::Listen,
                LinuxErrno::InvalidArgument,
                "socket must be bound before listen",
            )),
            SocketState::Bound(address) => {
                socket.state = SocketState::Listening(address);
                Ok(())
            }
            SocketState::Listening(_) => Ok(()),
            SocketState::Connecting(_) => Err(SocketError::invalid_state(
                SocketOperation::Listen,
                LinuxErrno::InvalidArgument,
                "connecting socket cannot listen",
            )),
            SocketState::Connected { .. } => Err(SocketError::invalid_state(
                SocketOperation::Listen,
                LinuxErrno::InvalidArgument,
                "connected socket cannot listen",
            )),
            SocketState::Closed => Err(SocketError::BadSocket { id }),
        }
    }

    pub fn set_nonblocking(&mut self, id: SocketId, nonblocking: bool) -> Result<(), SocketError> {
        let socket = self.socket(id)?;
        if socket.flags.nonblocking == nonblocking {
            return Ok(());
        }

        if let Some(entry) = self.host_handles.get_mut(&id) {
            entry
                .handle
                .set_nonblocking(nonblocking)
                .map_err(SocketError::from_host)?;
        }
        self.socket_mut(id)?.flags.nonblocking = nonblocking;
        Ok(())
    }

    pub fn connect(&mut self, id: SocketId, address: SocketAddress) -> Result<(), SocketError> {
        {
            let socket = self.socket(id)?;
            validate_address_domain(socket.domain, address)?;
            validate_connect(socket, id)?;
        }
        let local = self
            .socket(id)?
            .state
            .local_address()
            .unwrap_or_else(|| SocketAddress::unspecified_for_domain(address.domain()));

        if self.transport.is_some() || self.host_handles.contains_key(&id) {
            match self.connect_host_socket(id, address) {
                Ok((local, peer)) => {
                    self.socket_mut(id)?.state = SocketState::Connected { local, peer }
                }
                Err(error) if error.linux_errno() == LinuxErrno::OperationWouldBlock => {
                    let socket = self.socket_mut(id)?;
                    socket.state = SocketState::Connecting(address);
                    socket.last_error = Some(LinuxErrno::OperationInProgress);
                    return Err(SocketError::would_block(
                        SocketOperation::Connect,
                        "nonblocking connect is in progress",
                    )
                    .with_errno(LinuxErrno::OperationInProgress));
                }
                Err(error) => return Err(error),
            }
        } else {
            self.socket_mut(id)?.state = SocketState::Connected {
                local,
                peer: address,
            };
        }
        Ok(())
    }

    pub fn accept(&mut self, id: SocketId) -> Result<(SocketId, SocketAddress), SocketError> {
        let socket = self.socket(id)?;
        let state = socket.state;
        match state {
            SocketState::Listening(_) => {}
            SocketState::Created
            | SocketState::Bound(_)
            | SocketState::Connecting(_)
            | SocketState::Connected { .. } => {
                return Err(SocketError::invalid_state(
                    SocketOperation::Accept,
                    LinuxErrno::InvalidArgument,
                    "socket is not listening",
                ));
            }
            SocketState::Closed => return Err(SocketError::BadSocket { id }),
        }

        if self.transport.is_none() && !self.host_handles.contains_key(&id) {
            return Err(SocketError::would_block(
                SocketOperation::Accept,
                "no pending guest socket connection is available",
            ));
        }

        let spec = self.socket_spec(id)?;
        let local = self
            .socket(id)?
            .state
            .local_address()
            .unwrap_or_else(|| SocketAddress::unspecified_for_domain(spec.domain));
        let fast_path = {
            let entry = self.ensure_host_entry_mut(id, SocketOperation::Accept)?;
            let token = entry.readiness_token;
            entry
                .handle
                .accept_fast_path(token, spec)
                .map_err(SocketError::from_host)?
        };
        match fast_path {
            SocketAcceptFastPath::Accepted { handle, peer } => {
                return self.register_accepted_socket(spec, handle, local, peer);
            }
            SocketAcceptFastPath::Pending => {
                return Err(SocketError::would_block(
                    SocketOperation::Accept,
                    "AcceptEx operation is pending",
                ));
            }
            SocketAcceptFastPath::Unsupported => {}
        }

        let (handle, peer) = self
            .ensure_host_entry_mut(id, SocketOperation::Accept)?
            .handle
            .accept()
            .map_err(SocketError::from_host)?;
        self.register_accepted_socket(spec, handle, local, peer)
    }

    pub fn shutdown(&mut self, id: SocketId, how: ShutdownHow) -> Result<(), SocketError> {
        {
            let socket = self.socket(id)?;
            match socket.state {
                SocketState::Connected { .. } => {}
                SocketState::Created
                | SocketState::Bound(_)
                | SocketState::Connecting(_)
                | SocketState::Listening(_) => {
                    return Err(SocketError::invalid_state(
                        SocketOperation::Shutdown,
                        LinuxErrno::NotConnected,
                        "socket is not connected",
                    ));
                }
                SocketState::Closed => return Err(SocketError::BadSocket { id }),
            }
        }

        if let Some(entry) = self.host_handles.get_mut(&id) {
            entry.handle.shutdown(how).map_err(SocketError::from_host)?;
        }

        let socket = self.socket_mut(id)?;
        socket.shutdown.apply(how);
        Ok(())
    }

    pub fn send_connected(&mut self, id: SocketId, buffer: &[u8]) -> Result<usize, SocketError> {
        {
            let socket = self.socket(id)?;
            validate_connected_io(socket, SocketOperation::Send)?;
            if socket.shutdown.write {
                return Err(SocketError::invalid_state(
                    SocketOperation::Send,
                    LinuxErrno::Shutdown,
                    "socket write side is shut down",
                ));
            }
        }

        let entry = self.host_entry_mut(id, SocketOperation::Send)?;
        entry
            .handle
            .send(buffer)
            .map_err(|error| self.record_host_error(id, error))
    }

    pub fn send_connected_vectored(
        &mut self,
        id: SocketId,
        buffers: &[IoSlice<'_>],
    ) -> Result<usize, SocketError> {
        {
            let socket = self.socket(id)?;
            validate_connected_io(socket, SocketOperation::SendMsg)?;
            if socket.shutdown.write {
                return Err(SocketError::invalid_state(
                    SocketOperation::SendMsg,
                    LinuxErrno::Shutdown,
                    "socket write side is shut down",
                ));
            }
        }

        let entry = self.host_entry_mut(id, SocketOperation::SendMsg)?;
        entry
            .handle
            .send_vectored(buffers)
            .map_err(|error| self.record_host_error(id, error))
    }

    pub fn recv_connected(
        &mut self,
        id: SocketId,
        buffer: &mut [u8],
    ) -> Result<usize, SocketError> {
        {
            let socket = self.socket(id)?;
            validate_connected_io(socket, SocketOperation::Recv)?;
            if socket.shutdown.read {
                return Err(SocketError::invalid_state(
                    SocketOperation::Recv,
                    LinuxErrno::Shutdown,
                    "socket read side is shut down",
                ));
            }
        }

        let entry = self.host_entry_mut(id, SocketOperation::Recv)?;
        entry
            .handle
            .recv(buffer)
            .map_err(|error| self.record_host_error(id, error))
    }

    pub fn recv_connected_vectored(
        &mut self,
        id: SocketId,
        buffers: &mut [IoSliceMut<'_>],
    ) -> Result<usize, SocketError> {
        {
            let socket = self.socket(id)?;
            validate_connected_io(socket, SocketOperation::RecvMsg)?;
            if socket.shutdown.read {
                return Err(SocketError::invalid_state(
                    SocketOperation::RecvMsg,
                    LinuxErrno::Shutdown,
                    "socket read side is shut down",
                ));
            }
        }

        let entry = self.host_entry_mut(id, SocketOperation::RecvMsg)?;
        entry
            .handle
            .recv_vectored(buffers)
            .map_err(|error| self.record_host_error(id, error))
    }

    pub fn send_to(
        &mut self,
        id: SocketId,
        buffer: &[u8],
        address: SocketAddress,
    ) -> Result<usize, SocketError> {
        {
            let socket = self.socket(id)?;
            validate_address_domain(socket.domain, address)?;
            validate_datagram_io(socket, SocketOperation::Send)?;
            if socket.shutdown.write {
                return Err(SocketError::invalid_state(
                    SocketOperation::Send,
                    LinuxErrno::Shutdown,
                    "socket write side is shut down",
                ));
            }
        }

        let entry = self.ensure_host_entry_mut(id, SocketOperation::Send)?;
        entry
            .handle
            .send_to(buffer, address)
            .map_err(|error| self.record_host_error(id, error))
    }

    pub fn send_to_vectored(
        &mut self,
        id: SocketId,
        buffers: &[IoSlice<'_>],
        address: SocketAddress,
    ) -> Result<usize, SocketError> {
        {
            let socket = self.socket(id)?;
            validate_address_domain(socket.domain, address)?;
            validate_datagram_io(socket, SocketOperation::SendMsg)?;
            if socket.shutdown.write {
                return Err(SocketError::invalid_state(
                    SocketOperation::SendMsg,
                    LinuxErrno::Shutdown,
                    "socket write side is shut down",
                ));
            }
        }

        let entry = self.ensure_host_entry_mut(id, SocketOperation::SendMsg)?;
        entry
            .handle
            .send_to_vectored(buffers, address)
            .map_err(|error| self.record_host_error(id, error))
    }

    pub fn recv_from(
        &mut self,
        id: SocketId,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddress), SocketError> {
        {
            let socket = self.socket(id)?;
            validate_datagram_io(socket, SocketOperation::Recv)?;
            if socket.shutdown.read {
                return Err(SocketError::invalid_state(
                    SocketOperation::Recv,
                    LinuxErrno::Shutdown,
                    "socket read side is shut down",
                ));
            }
        }

        let entry = self.ensure_host_entry_mut(id, SocketOperation::Recv)?;
        entry
            .handle
            .recv_from(buffer)
            .map_err(|error| self.record_host_error(id, error))
    }

    pub fn recv_from_vectored(
        &mut self,
        id: SocketId,
        buffers: &mut [IoSliceMut<'_>],
    ) -> Result<(usize, SocketAddress), SocketError> {
        {
            let socket = self.socket(id)?;
            validate_datagram_io(socket, SocketOperation::RecvMsg)?;
            if socket.shutdown.read {
                return Err(SocketError::invalid_state(
                    SocketOperation::RecvMsg,
                    LinuxErrno::Shutdown,
                    "socket read side is shut down",
                ));
            }
        }

        let entry = self.ensure_host_entry_mut(id, SocketOperation::RecvMsg)?;
        entry
            .handle
            .recv_from_vectored(buffers)
            .map_err(|error| self.record_host_error(id, error))
    }

    pub fn poll(
        &mut self,
        id: SocketId,
        interest: SocketEvents,
        timeout: Option<Duration>,
    ) -> Result<SocketEvents, SocketError> {
        if let Some(readiness) = self.cached_poll_readiness(id, interest)? {
            return Ok(readiness);
        }

        let readiness = {
            let entry = self.host_entry_mut(id, SocketOperation::Poll)?;
            entry
                .handle
                .poll(interest, timeout)
                .map_err(SocketError::from_host)?
        };
        if readiness.writable && matches!(self.socket(id)?.state, SocketState::Connecting(_)) {
            self.finish_nonblocking_connect(id)?;
        }
        Ok(readiness)
    }

    pub fn poll_many(
        &mut self,
        requests: &[(SocketId, SocketEvents)],
        timeout: Option<Duration>,
    ) -> Result<Vec<SocketEvents>, SocketError> {
        let mut readiness = vec![SocketEvents::default(); requests.len()];
        let mut batch = Vec::new();
        let mut fallback = Vec::new();
        let mut has_ready = false;

        for (index, (id, interest)) in requests.iter().copied().enumerate() {
            if let Some(cached) = self.cached_poll_readiness(id, interest)? {
                readiness[index] = cached;
                has_ready = true;
                continue;
            }

            let batch_poll = {
                let entry = self.host_entry_mut(id, SocketOperation::Poll)?;
                entry
                    .handle
                    .prepare_batch_poll(interest, timeout)
                    .map_err(SocketError::from_host)?
            };
            if let Some(batch_poll) = batch_poll {
                batch.push((index, id, batch_poll));
            } else {
                fallback.push((index, id, interest));
            }
        }

        let wait_timeout = if has_ready {
            Some(Duration::ZERO)
        } else {
            timeout
        };

        if !batch.is_empty() {
            self.poll_batch_requests(&batch, wait_timeout, &mut readiness)?;
        }

        let fallback_wait_index =
            (!has_ready && batch.is_empty() && !fallback.is_empty()).then_some(0usize);
        for (fallback_index, (result_index, id, interest)) in fallback.into_iter().enumerate() {
            let poll_timeout = if fallback_wait_index == Some(fallback_index) {
                timeout
            } else {
                Some(Duration::ZERO)
            };
            let polled = {
                let entry = self.host_entry_mut(id, SocketOperation::Poll)?;
                entry
                    .handle
                    .poll(interest, poll_timeout)
                    .map_err(SocketError::from_host)?
            };
            self.finish_polled_readiness(id, polled)?;
            readiness[result_index] = polled;
        }

        Ok(readiness)
    }

    fn cached_poll_readiness(
        &mut self,
        id: SocketId,
        interest: SocketEvents,
    ) -> Result<Option<SocketEvents>, SocketError> {
        if matches!(self.socket(id)?.state, SocketState::Closed) {
            return Err(SocketError::BadSocket { id });
        }

        let (token, completions) = {
            let entry = self.ensure_host_entry_mut(id, SocketOperation::Poll)?;
            let token = entry.readiness_token;
            let completions = entry
                .handle
                .drain_readiness_completions(token)
                .map_err(SocketError::from_host)?;
            (token, completions)
        };
        for completion in completions {
            self.readiness_cache.apply_completion(token, completion);
        }

        let Some(readiness) = self.readiness_cache.readiness(token, interest) else {
            return Ok(None);
        };
        self.finish_polled_readiness(id, readiness)?;
        Ok(Some(readiness))
    }

    fn poll_batch_requests(
        &mut self,
        batch: &[(usize, SocketId, HostSocketBatchPoll)],
        timeout: Option<Duration>,
        readiness: &mut [SocketEvents],
    ) -> Result<(), SocketError> {
        let mut entries = batch
            .iter()
            .map(|(_, _, request)| SocketPoll::new(request.socket(), request.interest()))
            .collect::<Vec<_>>();
        let _ = poll_sockets(&mut entries, timeout)
            .map_err(HostIoError::from)
            .map_err(SocketError::from_host)?;
        let polled = entries
            .iter()
            .map(|entry| entry.readiness)
            .collect::<Vec<_>>();
        drop(entries);

        for ((result_index, id, _), polled) in batch.iter().zip(polled.into_iter()) {
            let finished = {
                let entry = self.host_entry_mut(*id, SocketOperation::Poll)?;
                entry
                    .handle
                    .finish_batch_poll(polled)
                    .map_err(SocketError::from_host)?
            };
            self.finish_polled_readiness(*id, finished)?;
            readiness[*result_index] = finished;
        }
        Ok(())
    }

    fn finish_polled_readiness(
        &mut self,
        id: SocketId,
        readiness: SocketEvents,
    ) -> Result<(), SocketError> {
        if readiness.writable && matches!(self.socket(id)?.state, SocketState::Connecting(_)) {
            self.finish_nonblocking_connect(id)?;
        }
        Ok(())
    }

    pub fn require_connected_stream(&self, id: SocketId) -> Result<(), SocketError> {
        let socket = self.socket(id)?;
        validate_connected_stream_io(socket, SocketOperation::Send)
    }

    pub fn rio_capability(&mut self, id: SocketId) -> Result<HostRioCapability, SocketError> {
        let entry = self.ensure_host_entry_mut(id, SocketOperation::Poll)?;
        entry
            .handle
            .rio_capability()
            .map_err(SocketError::from_host)
    }

    pub fn unsupported_socket_io(operation: SocketOperation) -> SocketError {
        SocketError::unsupported(
            operation,
            LinuxErrno::FunctionNotImplemented,
            "socket I/O shape is not implemented",
        )
    }

    pub fn unsupported_datagram_io(operation: SocketOperation) -> SocketError {
        SocketError::unsupported(
            operation,
            LinuxErrno::FunctionNotImplemented,
            "addressed datagram socket I/O is not implemented",
        )
    }

    pub fn unsupported_socket_flags(operation: SocketOperation) -> SocketError {
        SocketError::unsupported(
            operation,
            LinuxErrno::FunctionNotImplemented,
            "socket message flags are not implemented",
        )
    }

    fn host_entry_mut(
        &mut self,
        id: SocketId,
        operation: SocketOperation,
    ) -> Result<&mut HostSocketEntry, SocketError> {
        self.host_handles.get_mut(&id).ok_or_else(|| {
            SocketError::unsupported(
                operation,
                LinuxErrno::FunctionNotImplemented,
                "socket has no host transport handle",
            )
        })
    }

    fn ensure_host_entry_mut(
        &mut self,
        id: SocketId,
        operation: SocketOperation,
    ) -> Result<&mut HostSocketEntry, SocketError> {
        if !self.host_handles.contains_key(&id) {
            let spec = self.socket_spec(id)?;
            let options = self.socket(id)?.options();
            let handle = {
                let transport = self.transport.as_ref().ok_or_else(|| {
                    SocketError::unsupported(
                        operation,
                        LinuxErrno::FunctionNotImplemented,
                        "host socket transport is not configured",
                    )
                })?;
                transport
                    .open_socket(spec, options)
                    .map_err(SocketError::from_host)?
            };
            let readiness_token = self.allocate_readiness_token(id)?;
            self.host_handles.insert(
                id,
                HostSocketEntry {
                    handle,
                    readiness_token,
                },
            );
        }
        self.host_entry_mut(id, operation)
    }

    fn connect_host_socket(
        &mut self,
        id: SocketId,
        address: SocketAddress,
    ) -> Result<(SocketAddress, SocketAddress), SocketError> {
        let is_udp_datagram = {
            let socket = self.socket(id)?;
            socket.socket_type == SocketType::Datagram
                && socket.effective_protocol() == SocketProtocol::Udp
        };
        let entry = self.ensure_host_entry_mut(id, SocketOperation::Connect)?;
        match entry
            .handle
            .connect_fast_path(entry.readiness_token, address)
            .map_err(SocketError::from_host)?
        {
            SocketConnectFastPath::Connected => {}
            SocketConnectFastPath::Pending => {
                return Err(SocketError::would_block(
                    SocketOperation::Connect,
                    "ConnectEx operation is pending",
                ));
            }
            SocketConnectFastPath::Unsupported => entry
                .handle
                .connect(address)
                .map_err(SocketError::from_host)?,
        }
        let local = entry.handle.local_addr().map_err(SocketError::from_host)?;
        if is_udp_datagram {
            return Ok((local, address));
        }
        let peer = entry.handle.peer_addr().map_err(SocketError::from_host)?;
        Ok((local, peer))
    }

    fn record_host_error(&mut self, id: SocketId, error: HostIoError) -> SocketError {
        if let Ok(socket) = self.socket_mut(id) {
            socket.last_error = Some(error.linux_errno());
        }
        SocketError::from_host(error)
    }

    fn finish_nonblocking_connect(&mut self, id: SocketId) -> Result<(), SocketError> {
        let SocketState::Connecting(address) = self.socket(id)?.state else {
            return Ok(());
        };
        let (local, peer) = if let Some(entry) = self.host_handles.get_mut(&id) {
            if entry
                .handle
                .complete_connect_fast_path()
                .map_err(SocketError::from_host)?
                == SocketConnectFastPathCompletion::Pending
            {
                return Ok(());
            }
            if let Some(error) = entry.handle.take_error().map_err(SocketError::from_host)? {
                let errno = error.linux_errno();
                let socket = self.socket_mut(id)?;
                socket.state = SocketState::Created;
                socket.last_error = Some(errno);
                return Err(SocketError::from_host(error));
            }
            let local = entry.handle.local_addr().map_err(SocketError::from_host)?;
            let peer = entry.handle.peer_addr().map_err(SocketError::from_host)?;
            (local, peer)
        } else {
            (
                SocketAddress::unspecified_for_domain(address.domain()),
                address,
            )
        };
        let socket = self.socket_mut(id)?;
        socket.state = SocketState::Connected { local, peer };
        socket.last_error = None;
        Ok(())
    }

    fn register_accepted_socket(
        &mut self,
        spec: SocketSpec,
        handle: Box<dyn HostSocketHandle>,
        local: SocketAddress,
        peer: SocketAddress,
    ) -> Result<(SocketId, SocketAddress), SocketError> {
        let accepted = self.create_socket_with_handle(spec, handle)?;
        self.socket_mut(accepted)?.state = SocketState::Connected { local, peer };
        Ok((accepted, peer))
    }

    fn socket_spec(&self, id: SocketId) -> Result<SocketSpec, SocketError> {
        let socket = self.socket(id)?;
        SocketSpec::with_flags(
            socket.domain,
            socket.socket_type,
            socket.protocol,
            socket.flags,
        )
    }

    pub fn close(&mut self, id: SocketId) -> Result<(), SocketError> {
        let socket = self.socket_mut(id)?;
        match socket.state {
            SocketState::Closed => Err(SocketError::BadSocket { id }),
            SocketState::Created
            | SocketState::Bound(_)
            | SocketState::Connecting(_)
            | SocketState::Listening(_)
            | SocketState::Connected { .. } => {
                socket.state = SocketState::Closed;
                socket.shutdown = ShutdownFlags {
                    read: true,
                    write: true,
                };
                self.host_handles.remove(&id);
                self.readiness_cache.clear_socket(id);
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }

    fn allocate_id(&mut self) -> Result<SocketId, SocketError> {
        let id = SocketId::new(self.next_id).ok_or_else(|| {
            SocketError::invalid_input(
                SocketOperation::AllocateSocketId,
                LinuxErrno::InvalidArgument,
                "socket id space is exhausted",
            )
        })?;
        self.next_id = self.next_id.checked_add(1).unwrap_or(0);
        Ok(id)
    }

    fn allocate_readiness_token(
        &mut self,
        id: SocketId,
    ) -> Result<SocketReadinessToken, SocketError> {
        let generation = self.next_readiness_generation;
        self.next_readiness_generation =
            self.next_readiness_generation
                .checked_add(1)
                .ok_or_else(|| {
                    SocketError::invalid_input(
                        SocketOperation::AllocateSocketId,
                        LinuxErrno::InvalidArgument,
                        "socket readiness generation space is exhausted",
                    )
                })?;
        Ok(SocketReadinessToken::new(id, generation))
    }
}
