use std::collections::BTreeMap;
use std::fmt;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub const LINUX_AF_UNIX: u32 = 1;
pub const LINUX_AF_INET: u32 = 2;
pub const LINUX_AF_INET6: u32 = 10;

pub const LINUX_SOCK_STREAM: u32 = 1;
pub const LINUX_SOCK_DGRAM: u32 = 2;
pub const LINUX_SOCK_RAW: u32 = 3;
pub const LINUX_SOCK_NONBLOCK: u32 = 0o4000;
pub const LINUX_SOCK_CLOEXEC: u32 = 0o2000000;
pub const LINUX_SOCK_TYPE_MASK: u32 = 0xf;
pub const LINUX_SOCK_FLAG_MASK: u32 = LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC;

pub const LINUX_IPPROTO_IP: u32 = 0;
pub const LINUX_IPPROTO_TCP: u32 = 6;
pub const LINUX_IPPROTO_UDP: u32 = 17;

pub const LINUX_SOL_SOCKET: u32 = 1;
pub const LINUX_IPPROTO_TCP_LEVEL: u32 = 6;

pub const LINUX_SO_REUSEADDR: u32 = 2;
pub const LINUX_SO_TYPE: u32 = 3;
pub const LINUX_SO_ERROR: u32 = 4;
pub const LINUX_SO_KEEPALIVE: u32 = 9;
pub const LINUX_SO_SNDBUF: u32 = 7;
pub const LINUX_SO_RCVBUF: u32 = 8;

pub const LINUX_TCP_NODELAY: u32 = 1;

pub const LINUX_SHUT_RD: u32 = 0;
pub const LINUX_SHUT_WR: u32 = 1;
pub const LINUX_SHUT_RDWR: u32 = 2;

const DEFAULT_SOCKET_BUFFER_SIZE: u32 = 212_992;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SocketId(u64);

impl SocketId {
    pub const MIN: Self = Self(1);

    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketDomain {
    Inet,
    Inet6,
}

impl SocketDomain {
    pub fn from_linux(value: u32) -> Result<Self, SocketError> {
        match value {
            LINUX_AF_INET => Ok(Self::Inet),
            LINUX_AF_INET6 => Ok(Self::Inet6),
            LINUX_AF_UNIX => Err(SocketError::unsupported(
                SocketOperation::CreateSocket,
                LinuxErrno::AddressFamilyNotSupported,
                "AF_UNIX sockets are not supported",
            )),
            _ => Err(SocketError::unsupported(
                SocketOperation::CreateSocket,
                LinuxErrno::AddressFamilyNotSupported,
                "socket domain is not supported",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketType {
    Stream,
    Datagram,
}

impl SocketType {
    pub fn from_linux(value: u32) -> Result<Self, SocketError> {
        match value {
            LINUX_SOCK_STREAM => Ok(Self::Stream),
            LINUX_SOCK_DGRAM => Ok(Self::Datagram),
            LINUX_SOCK_RAW => Err(SocketError::unsupported(
                SocketOperation::CreateSocket,
                LinuxErrno::SocketTypeNotSupported,
                "raw sockets are not supported",
            )),
            _ => Err(SocketError::unsupported(
                SocketOperation::CreateSocket,
                LinuxErrno::SocketTypeNotSupported,
                "socket type is not supported",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketProtocol {
    Default,
    Tcp,
    Udp,
}

impl SocketProtocol {
    pub fn from_linux(value: u32) -> Result<Self, SocketError> {
        match value {
            LINUX_IPPROTO_IP => Ok(Self::Default),
            LINUX_IPPROTO_TCP => Ok(Self::Tcp),
            LINUX_IPPROTO_UDP => Ok(Self::Udp),
            _ => Err(SocketError::unsupported(
                SocketOperation::CreateSocket,
                LinuxErrno::ProtocolNotSupported,
                "socket protocol is not supported",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketCreationFlags {
    pub nonblocking: bool,
    pub cloexec: bool,
}

impl SocketCreationFlags {
    #[must_use]
    pub const fn from_linux(kind: u32) -> Self {
        Self {
            nonblocking: kind & LINUX_SOCK_NONBLOCK != 0,
            cloexec: kind & LINUX_SOCK_CLOEXEC != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketSpec {
    pub domain: SocketDomain,
    pub socket_type: SocketType,
    pub protocol: SocketProtocol,
    pub flags: SocketCreationFlags,
}

impl SocketSpec {
    pub fn new(
        domain: SocketDomain,
        socket_type: SocketType,
        protocol: SocketProtocol,
    ) -> Result<Self, SocketError> {
        Self::with_flags(
            domain,
            socket_type,
            protocol,
            SocketCreationFlags::default(),
        )
    }

    pub fn with_flags(
        domain: SocketDomain,
        socket_type: SocketType,
        protocol: SocketProtocol,
        flags: SocketCreationFlags,
    ) -> Result<Self, SocketError> {
        validate_socket_protocol(socket_type, protocol)?;
        Ok(Self {
            domain,
            socket_type,
            protocol,
            flags,
        })
    }

    pub fn from_linux(domain: u32, kind: u32, protocol: u32) -> Result<Self, SocketError> {
        let unsupported_flags = kind & !(LINUX_SOCK_TYPE_MASK | LINUX_SOCK_FLAG_MASK);
        if unsupported_flags != 0 {
            return Err(SocketError::invalid_input(
                SocketOperation::CreateSocket,
                LinuxErrno::InvalidArgument,
                "socket kind contains unsupported flags",
            ));
        }

        let socket_type = SocketType::from_linux(kind & LINUX_SOCK_TYPE_MASK)?;
        Self::with_flags(
            SocketDomain::from_linux(domain)?,
            socket_type,
            SocketProtocol::from_linux(protocol)?,
            SocketCreationFlags::from_linux(kind),
        )
    }

    #[must_use]
    pub const fn effective_protocol(self) -> SocketProtocol {
        match (self.socket_type, self.protocol) {
            (SocketType::Stream, SocketProtocol::Default) => SocketProtocol::Tcp,
            (SocketType::Datagram, SocketProtocol::Default) => SocketProtocol::Udp,
            (_, protocol) => protocol,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketState {
    Created,
    Bound(SocketAddress),
    Listening(SocketAddress),
    Connected(SocketAddress),
    Closed,
}

impl SocketState {
    #[must_use]
    pub const fn local_address(self) -> Option<SocketAddress> {
        match self {
            Self::Bound(address) | Self::Listening(address) => Some(address),
            Self::Created | Self::Connected(_) | Self::Closed => None,
        }
    }

    #[must_use]
    pub const fn peer_address(self) -> Option<SocketAddress> {
        match self {
            Self::Connected(address) => Some(address),
            Self::Created | Self::Bound(_) | Self::Listening(_) | Self::Closed => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketAddress {
    Inet {
        address: [u8; 4],
        port: u16,
    },
    Inet6 {
        address: [u8; 16],
        port: u16,
        flowinfo: u32,
        scope_id: u32,
    },
}

impl SocketAddress {
    #[must_use]
    pub const fn inet(address: [u8; 4], port: u16) -> Self {
        Self::Inet { address, port }
    }

    #[must_use]
    pub const fn inet6(address: [u8; 16], port: u16, flowinfo: u32, scope_id: u32) -> Self {
        Self::Inet6 {
            address,
            port,
            flowinfo,
            scope_id,
        }
    }

    #[must_use]
    pub const fn domain(self) -> SocketDomain {
        match self {
            Self::Inet { .. } => SocketDomain::Inet,
            Self::Inet6 { .. } => SocketDomain::Inet6,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShutdownFlags {
    pub read: bool,
    pub write: bool,
}

impl ShutdownFlags {
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.read && !self.write
    }

    pub fn apply(&mut self, how: ShutdownHow) {
        match how {
            ShutdownHow::Read => self.read = true,
            ShutdownHow::Write => self.write = true,
            ShutdownHow::ReadWrite => {
                self.read = true;
                self.write = true;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownHow {
    Read,
    Write,
    ReadWrite,
}

impl ShutdownHow {
    pub fn from_linux(value: u32) -> Result<Self, SocketError> {
        match value {
            LINUX_SHUT_RD => Ok(Self::Read),
            LINUX_SHUT_WR => Ok(Self::Write),
            LINUX_SHUT_RDWR => Ok(Self::ReadWrite),
            _ => Err(SocketError::invalid_input(
                SocketOperation::Shutdown,
                LinuxErrno::InvalidArgument,
                "shutdown mode is not supported",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestSocket {
    id: SocketId,
    domain: SocketDomain,
    socket_type: SocketType,
    protocol: SocketProtocol,
    state: SocketState,
    shutdown: ShutdownFlags,
    options: SocketOptions,
    last_error: Option<LinuxErrno>,
}

impl GuestSocket {
    fn new(id: SocketId, spec: SocketSpec) -> Self {
        Self {
            id,
            domain: spec.domain,
            socket_type: spec.socket_type,
            protocol: spec.protocol,
            state: SocketState::Created,
            shutdown: ShutdownFlags::default(),
            options: SocketOptions::default(),
            last_error: None,
        }
    }

    #[must_use]
    pub const fn id(&self) -> SocketId {
        self.id
    }

    #[must_use]
    pub const fn domain(&self) -> SocketDomain {
        self.domain
    }

    #[must_use]
    pub const fn socket_type(&self) -> SocketType {
        self.socket_type
    }

    #[must_use]
    pub const fn protocol(&self) -> SocketProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn effective_protocol(&self) -> SocketProtocol {
        match (self.socket_type, self.protocol) {
            (SocketType::Stream, SocketProtocol::Default) => SocketProtocol::Tcp,
            (SocketType::Datagram, SocketProtocol::Default) => SocketProtocol::Udp,
            (_, protocol) => protocol,
        }
    }

    #[must_use]
    pub const fn state(&self) -> SocketState {
        self.state
    }

    #[must_use]
    pub const fn shutdown(&self) -> ShutdownFlags {
        self.shutdown
    }

    #[must_use]
    pub const fn options(&self) -> SocketOptions {
        self.options
    }

    #[must_use]
    pub const fn last_error(&self) -> Option<LinuxErrno> {
        self.last_error
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketOptions {
    pub reuse_addr: bool,
    pub keep_alive: bool,
    pub send_buffer_size: u32,
    pub receive_buffer_size: u32,
    pub tcp_no_delay: bool,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            reuse_addr: false,
            keep_alive: false,
            send_buffer_size: DEFAULT_SOCKET_BUFFER_SIZE,
            receive_buffer_size: DEFAULT_SOCKET_BUFFER_SIZE,
            tcp_no_delay: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketOptionName {
    SocketType,
    SocketError,
    ReuseAddr,
    KeepAlive,
    SendBuffer,
    ReceiveBuffer,
    TcpNoDelay,
}

impl SocketOptionName {
    pub fn from_linux(level: u32, option: u32) -> Result<Self, SocketError> {
        match (level, option) {
            (LINUX_SOL_SOCKET, LINUX_SO_TYPE) => Ok(Self::SocketType),
            (LINUX_SOL_SOCKET, LINUX_SO_ERROR) => Ok(Self::SocketError),
            (LINUX_SOL_SOCKET, LINUX_SO_REUSEADDR) => Ok(Self::ReuseAddr),
            (LINUX_SOL_SOCKET, LINUX_SO_KEEPALIVE) => Ok(Self::KeepAlive),
            (LINUX_SOL_SOCKET, LINUX_SO_SNDBUF) => Ok(Self::SendBuffer),
            (LINUX_SOL_SOCKET, LINUX_SO_RCVBUF) => Ok(Self::ReceiveBuffer),
            (LINUX_IPPROTO_TCP_LEVEL, LINUX_TCP_NODELAY) => Ok(Self::TcpNoDelay),
            (LINUX_SOL_SOCKET, _) | (LINUX_IPPROTO_TCP_LEVEL, _) => Err(SocketError::unsupported(
                SocketOperation::GetSocketOption,
                LinuxErrno::ProtocolNotAvailable,
                "socket option is not supported",
            )),
            _ => Err(SocketError::unsupported(
                SocketOperation::GetSocketOption,
                LinuxErrno::ProtocolNotAvailable,
                "socket option level is not supported",
            )),
        }
    }

    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::SocketType | Self::SocketError)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GuestSocketTable {
    next_id: u64,
    sockets: BTreeMap<SocketId, GuestSocket>,
}

impl GuestSocketTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: SocketId::MIN.get(),
            sockets: BTreeMap::new(),
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

    pub fn bind(&mut self, id: SocketId, address: SocketAddress) -> Result<(), SocketError> {
        let socket = self.socket_mut(id)?;
        validate_address_domain(socket.domain, address)?;

        match socket.state {
            SocketState::Created => {
                socket.state = SocketState::Bound(address);
                Ok(())
            }
            SocketState::Bound(_) | SocketState::Listening(_) => Err(SocketError::invalid_state(
                SocketOperation::Bind,
                LinuxErrno::InvalidArgument,
                "socket is already bound",
            )),
            SocketState::Connected(_) => Err(SocketError::invalid_state(
                SocketOperation::Bind,
                LinuxErrno::InvalidArgument,
                "connected socket cannot be bound",
            )),
            SocketState::Closed => Err(SocketError::BadSocket { id }),
        }
    }

    pub fn listen(&mut self, id: SocketId, _backlog: u32) -> Result<(), SocketError> {
        let socket = self.socket_mut(id)?;
        if socket.socket_type != SocketType::Stream {
            return Err(SocketError::invalid_state(
                SocketOperation::Listen,
                LinuxErrno::OperationNotSupported,
                "only stream sockets can listen",
            ));
        }

        match socket.state {
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
            SocketState::Connected(_) => Err(SocketError::invalid_state(
                SocketOperation::Listen,
                LinuxErrno::InvalidArgument,
                "connected socket cannot listen",
            )),
            SocketState::Closed => Err(SocketError::BadSocket { id }),
        }
    }

    pub fn connect(&mut self, id: SocketId, address: SocketAddress) -> Result<(), SocketError> {
        let socket = self.socket_mut(id)?;
        validate_address_domain(socket.domain, address)?;

        match socket.state {
            SocketState::Created | SocketState::Bound(_) => {
                socket.state = SocketState::Connected(address);
                Ok(())
            }
            SocketState::Connected(_) => Err(SocketError::invalid_state(
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

    pub fn accept_placeholder(&mut self, id: SocketId) -> Result<SocketId, SocketError> {
        let socket = self.socket(id)?;
        match socket.state {
            SocketState::Listening(_) => Err(SocketError::would_block(
                SocketOperation::Accept,
                "no pending guest socket connection is available",
            )),
            SocketState::Created | SocketState::Bound(_) | SocketState::Connected(_) => {
                Err(SocketError::invalid_state(
                    SocketOperation::Accept,
                    LinuxErrno::InvalidArgument,
                    "socket is not listening",
                ))
            }
            SocketState::Closed => Err(SocketError::BadSocket { id }),
        }
    }

    pub fn shutdown(&mut self, id: SocketId, how: ShutdownHow) -> Result<(), SocketError> {
        let socket = self.socket_mut(id)?;
        match socket.state {
            SocketState::Connected(_) => {
                socket.shutdown.apply(how);
                Ok(())
            }
            SocketState::Created | SocketState::Bound(_) | SocketState::Listening(_) => {
                Err(SocketError::invalid_state(
                    SocketOperation::Shutdown,
                    LinuxErrno::NotConnected,
                    "socket is not connected",
                ))
            }
            SocketState::Closed => Err(SocketError::BadSocket { id }),
        }
    }

    pub fn close(&mut self, id: SocketId) -> Result<(), SocketError> {
        let socket = self.socket_mut(id)?;
        match socket.state {
            SocketState::Closed => Err(SocketError::BadSocket { id }),
            SocketState::Created
            | SocketState::Bound(_)
            | SocketState::Listening(_)
            | SocketState::Connected(_) => {
                socket.state = SocketState::Closed;
                socket.shutdown = ShutdownFlags {
                    read: true,
                    write: true,
                };
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketOperation {
    Accept,
    AllocateSocketId,
    Bind,
    Close,
    Connect,
    CreateSocket,
    GetSocketOption,
    Listen,
    SetSocketOption,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxErrno {
    AlreadyConnected,
    BadFileDescriptor,
    InvalidArgument,
    NotConnected,
    OperationWouldBlock,
    OperationNotSupported,
    AddressFamilyNotSupported,
    ProtocolNotAvailable,
    ProtocolNotSupported,
    ProtocolWrongTypeForSocket,
    SocketTypeNotSupported,
}

impl LinuxErrno {
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::AlreadyConnected => 106,
            Self::BadFileDescriptor => 9,
            Self::InvalidArgument => 22,
            Self::OperationNotSupported => 95,
            Self::NotConnected => 107,
            Self::OperationWouldBlock => 11,
            Self::ProtocolWrongTypeForSocket => 91,
            Self::ProtocolNotAvailable => 92,
            Self::ProtocolNotSupported => 93,
            Self::SocketTypeNotSupported => 94,
            Self::AddressFamilyNotSupported => 97,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocketError {
    InvalidInput {
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    },
    Unsupported {
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    },
    InvalidState {
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    },
    WouldBlock {
        operation: SocketOperation,
        errno: LinuxErrno,
        reason: &'static str,
    },
    BadSocket {
        id: SocketId,
    },
}

impl SocketError {
    fn invalid_input(operation: SocketOperation, errno: LinuxErrno, reason: &'static str) -> Self {
        Self::InvalidInput {
            operation,
            errno,
            reason,
        }
    }

    fn unsupported(operation: SocketOperation, errno: LinuxErrno, reason: &'static str) -> Self {
        Self::Unsupported {
            operation,
            errno,
            reason,
        }
    }

    fn invalid_state(operation: SocketOperation, errno: LinuxErrno, reason: &'static str) -> Self {
        Self::InvalidState {
            operation,
            errno,
            reason,
        }
    }

    fn would_block(operation: SocketOperation, reason: &'static str) -> Self {
        Self::WouldBlock {
            operation,
            errno: LinuxErrno::OperationWouldBlock,
            reason,
        }
    }

    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        match self {
            Self::InvalidInput { errno, .. }
            | Self::Unsupported { errno, .. }
            | Self::InvalidState { errno, .. }
            | Self::WouldBlock { errno, .. } => *errno,
            Self::BadSocket { .. } => LinuxErrno::BadFileDescriptor,
        }
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput {
                operation, reason, ..
            } => write!(f, "{operation:?}: invalid input: {reason}"),
            Self::Unsupported {
                operation, reason, ..
            } => write!(f, "{operation:?}: unsupported: {reason}"),
            Self::InvalidState {
                operation, reason, ..
            } => write!(f, "{operation:?}: invalid state: {reason}"),
            Self::WouldBlock {
                operation, reason, ..
            } => write!(f, "{operation:?}: would block: {reason}"),
            Self::BadSocket { id } => write!(f, "bad socket id {id}"),
        }
    }
}

impl std::error::Error for SocketError {}

impl SocketType {
    #[must_use]
    pub const fn to_linux(self) -> u32 {
        match self {
            Self::Stream => LINUX_SOCK_STREAM,
            Self::Datagram => LINUX_SOCK_DGRAM,
        }
    }
}

fn validate_socket_protocol(
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

const fn bool_to_socket_option(value: bool) -> u32 {
    if value { 1 } else { 0 }
}

const fn socket_option_to_bool(value: u32) -> bool {
    value != 0
}

fn validate_buffer_size(value: u32) -> Result<u32, SocketError> {
    if value == 0 {
        Err(SocketError::invalid_input(
            SocketOperation::SetSocketOption,
            LinuxErrno::InvalidArgument,
            "socket buffer size must be greater than zero",
        ))
    } else {
        Ok(value)
    }
}

fn validate_address_domain(
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let peer =
            SocketAddress::inet6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443, 0, 0);

        table.connect(stream, peer).expect("connect placeholder");
        assert_eq!(
            table.socket(stream).expect("socket").state(),
            SocketState::Connected(peer)
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
                .accept_placeholder(stream)
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
}
