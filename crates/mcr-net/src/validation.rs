use crate::{
    constants::{LINUX_SOCK_DGRAM, LINUX_SOCK_STREAM},
    error::{LinuxErrno, SocketError, SocketOperation},
    types::{
        GuestSocket, SocketAddress, SocketDomain, SocketId, SocketProtocol, SocketState, SocketType,
    },
};

impl SocketType {
    #[must_use]
    pub const fn to_linux(self) -> u32 {
        match self {
            Self::Stream => LINUX_SOCK_STREAM,
            Self::Datagram => LINUX_SOCK_DGRAM,
        }
    }
}

pub(crate) fn validate_socket_protocol(
    socket_type: SocketType,
    protocol: SocketProtocol,
) -> Result<(), SocketError> {
    match (socket_type, protocol) {
        (SocketType::Stream, SocketProtocol::Default | SocketProtocol::Tcp)
        | (SocketType::Datagram, SocketProtocol::Default | SocketProtocol::Udp) => Ok(()),
        (SocketType::Stream, SocketProtocol::Udp) | (SocketType::Datagram, SocketProtocol::Tcp) => {
            Err(SocketError::unsupported(
                SocketOperation::CreateSocket,
                LinuxErrno::ProtocolWrongTypeForSocket,
                "socket protocol does not match socket type",
            ))
        }
    }
}

pub(crate) fn validate_connect(socket: &GuestSocket, id: SocketId) -> Result<(), SocketError> {
    match socket.state {
        SocketState::Created | SocketState::Bound(_) => Ok(()),
        SocketState::Connecting(_) => Err(SocketError::invalid_state(
            SocketOperation::Connect,
            LinuxErrno::OperationAlreadyInProgress,
            "socket connect is already in progress",
        )),
        SocketState::Connected { .. } => Err(SocketError::invalid_state(
            SocketOperation::Connect,
            LinuxErrno::AlreadyConnected,
            "socket is already connected",
        )),
        SocketState::Listening(_) => Err(SocketError::invalid_state(
            SocketOperation::Connect,
            LinuxErrno::InvalidArgument,
            "listening socket cannot connect",
        )),
        SocketState::Closed => Err(SocketError::BadSocket { id }),
    }
}

pub(crate) fn validate_connected_stream_io(
    socket: &GuestSocket,
    operation: SocketOperation,
) -> Result<(), SocketError> {
    if socket.socket_type != SocketType::Stream
        || socket.effective_protocol() != SocketProtocol::Tcp
    {
        return Err(SocketError::unsupported(
            operation,
            LinuxErrno::FunctionNotImplemented,
            "only connected TCP stream socket I/O is implemented",
        ));
    }

    match socket.state {
        SocketState::Connected { .. } => Ok(()),
        SocketState::Created
        | SocketState::Bound(_)
        | SocketState::Connecting(_)
        | SocketState::Listening(_) => Err(SocketError::invalid_state(
            operation,
            LinuxErrno::NotConnected,
            "socket is not connected",
        )),
        SocketState::Closed => Err(SocketError::BadSocket { id: socket.id }),
    }
}

pub(crate) fn validate_connected_io(
    socket: &GuestSocket,
    operation: SocketOperation,
) -> Result<(), SocketError> {
    if socket.socket_type == SocketType::Stream
        && socket.effective_protocol() == SocketProtocol::Tcp
    {
        return validate_connected_stream_io(socket, operation);
    }

    if socket.socket_type != SocketType::Datagram
        || socket.effective_protocol() != SocketProtocol::Udp
    {
        return Err(SocketError::unsupported(
            operation,
            LinuxErrno::FunctionNotImplemented,
            "only connected TCP stream and UDP datagram socket I/O is implemented",
        ));
    }

    match socket.state {
        SocketState::Connected { .. } => Ok(()),
        SocketState::Created
        | SocketState::Bound(_)
        | SocketState::Connecting(_)
        | SocketState::Listening(_) => Err(SocketError::invalid_state(
            operation,
            LinuxErrno::NotConnected,
            "socket is not connected",
        )),
        SocketState::Closed => Err(SocketError::BadSocket { id: socket.id }),
    }
}

pub(crate) fn validate_datagram_io(
    socket: &GuestSocket,
    operation: SocketOperation,
) -> Result<(), SocketError> {
    if socket.socket_type != SocketType::Datagram
        || socket.effective_protocol() != SocketProtocol::Udp
    {
        return Err(SocketError::unsupported(
            operation,
            LinuxErrno::FunctionNotImplemented,
            "only UDP datagram socket I/O is implemented",
        ));
    }

    match socket.state {
        SocketState::Created
        | SocketState::Bound(_)
        | SocketState::Connecting(_)
        | SocketState::Connected { .. } => Ok(()),
        SocketState::Listening(_) => Err(SocketError::invalid_state(
            operation,
            LinuxErrno::InvalidArgument,
            "listening socket cannot use datagram I/O",
        )),
        SocketState::Closed => Err(SocketError::BadSocket { id: socket.id }),
    }
}

pub(crate) fn validate_address_domain(
    domain: SocketDomain,
    address: SocketAddress,
) -> Result<(), SocketError> {
    if domain == address.domain() {
        Ok(())
    } else {
        Err(SocketError::invalid_input(
            SocketOperation::Bind,
            LinuxErrno::AddressFamilyNotSupported,
            "socket address family does not match socket domain",
        ))
    }
}
