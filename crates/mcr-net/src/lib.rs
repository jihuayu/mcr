use std::fmt;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    time::Duration,
};

use mcr_win::{
    AddressFamily, HostError, HostErrorKind, HostShutdown, HostSocket, HostSocketOptionName,
    HostSocketOptionValue, NetworkStack, SocketEvents, SocketKind,
    SocketProtocol as HostSocketProtocol,
};

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
    Connecting(SocketAddress),
    Listening(SocketAddress),
    Connected {
        local: SocketAddress,
        peer: SocketAddress,
    },
    Closed,
}

impl SocketState {
    #[must_use]
    pub const fn local_address(self) -> Option<SocketAddress> {
        match self {
            Self::Bound(address) | Self::Listening(address) => Some(address),
            Self::Connected { local, .. } => Some(local),
            Self::Created | Self::Connecting(_) | Self::Closed => None,
        }
    }

    #[must_use]
    pub const fn peer_address(self) -> Option<SocketAddress> {
        match self {
            Self::Connected { peer, .. } => Some(peer),
            Self::Created
            | Self::Bound(_)
            | Self::Connecting(_)
            | Self::Listening(_)
            | Self::Closed => None,
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

    #[must_use]
    pub const fn unspecified_for_domain(domain: SocketDomain) -> Self {
        match domain {
            SocketDomain::Inet => Self::inet([0, 0, 0, 0], 0),
            SocketDomain::Inet6 => Self::inet6([0; 16], 0, 0, 0),
        }
    }
}

impl From<SocketAddress> for SocketAddr {
    fn from(value: SocketAddress) -> Self {
        match value {
            SocketAddress::Inet { address, port } => {
                Self::new(IpAddr::V4(Ipv4Addr::from(address)), port)
            }
            SocketAddress::Inet6 {
                address,
                port,
                flowinfo,
                scope_id,
            } => Self::V6(SocketAddrV6::new(
                Ipv6Addr::from(address),
                port,
                flowinfo,
                scope_id,
            )),
        }
    }
}

impl From<SocketAddr> for SocketAddress {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(address) => Self::inet(address.ip().octets(), address.port()),
            SocketAddr::V6(address) => Self::inet6(
                address.ip().octets(),
                address.port(),
                address.flowinfo(),
                address.scope_id(),
            ),
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
    flags: SocketCreationFlags,
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
            flags: spec.flags,
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
    pub const fn flags(&self) -> SocketCreationFlags {
        self.flags
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

pub trait HostSocketTransport {
    fn open_socket(
        &self,
        spec: SocketSpec,
        options: SocketOptions,
    ) -> Result<Box<dyn HostSocketHandle>, HostIoError>;
}

pub trait HostSocketHandle: fmt::Debug {
    fn bind(&mut self, address: SocketAddress) -> Result<SocketAddress, HostIoError>;
    fn listen(&mut self, backlog: u32) -> Result<(), HostIoError>;
    fn accept(&mut self) -> Result<(Box<dyn HostSocketHandle>, SocketAddress), HostIoError>;
    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), HostIoError>;
    fn connect(&mut self, address: SocketAddress) -> Result<(), HostIoError>;
    fn take_error(&mut self) -> Result<Option<HostIoError>, HostIoError>;
    fn local_addr(&self) -> Result<SocketAddress, HostIoError>;
    fn peer_addr(&self) -> Result<SocketAddress, HostIoError>;
    fn send(&mut self, buffer: &[u8]) -> Result<usize, HostIoError>;
    fn send_to(&mut self, buffer: &[u8], address: SocketAddress) -> Result<usize, HostIoError>;
    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, HostIoError>;
    fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddress), HostIoError>;
    fn poll(
        &mut self,
        interest: SocketEvents,
        timeout: Option<Duration>,
    ) -> Result<SocketEvents, HostIoError>;
    fn shutdown(&mut self, how: ShutdownHow) -> Result<(), HostIoError>;
}

#[derive(Debug)]
pub struct WinHostSocketTransport {
    stack: NetworkStack,
}

impl WinHostSocketTransport {
    pub fn new() -> Result<Self, HostIoError> {
        Ok(Self {
            stack: NetworkStack::start().map_err(HostIoError::from)?,
        })
    }
}

impl HostSocketTransport for WinHostSocketTransport {
    fn open_socket(
        &self,
        spec: SocketSpec,
        options: SocketOptions,
    ) -> Result<Box<dyn HostSocketHandle>, HostIoError> {
        let socket = self
            .stack
            .open_socket(
                address_family_from_socket_domain(spec.domain),
                socket_kind_from_socket_type(spec.socket_type),
                host_protocol_from_socket_protocol(spec.effective_protocol()),
            )
            .map_err(HostIoError::from)?;
        apply_socket_options(&socket, spec, options)?;
        if spec.flags.nonblocking {
            socket.set_nonblocking(true).map_err(HostIoError::from)?;
        }
        Ok(Box::new(WinHostSocketHandle { socket }))
    }
}

#[derive(Debug)]
struct WinHostSocketHandle {
    socket: HostSocket,
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

    fn accept(&mut self) -> Result<(Box<dyn HostSocketHandle>, SocketAddress), HostIoError> {
        let (socket, peer) = self.socket.accept().map_err(HostIoError::from)?;
        Ok((Box::new(Self { socket }), SocketAddress::from(peer)))
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), HostIoError> {
        self.socket
            .set_nonblocking(nonblocking)
            .map_err(HostIoError::from)
    }

    fn connect(&mut self, address: SocketAddress) -> Result<(), HostIoError> {
        self.socket
            .connect(SocketAddr::from(address))
            .map_err(HostIoError::from)
    }

    fn take_error(&mut self) -> Result<Option<HostIoError>, HostIoError> {
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
        self.socket.send(buffer).map_err(HostIoError::from)
    }

    fn send_to(&mut self, buffer: &[u8], address: SocketAddress) -> Result<usize, HostIoError> {
        self.socket
            .send_to(buffer, SocketAddr::from(address))
            .map_err(HostIoError::from)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, HostIoError> {
        self.socket.recv(buffer).map_err(HostIoError::from)
    }

    fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddress), HostIoError> {
        self.socket
            .recv_from(buffer)
            .map(|(count, address)| (count, SocketAddress::from(address)))
            .map_err(HostIoError::from)
    }

    fn poll(
        &mut self,
        interest: SocketEvents,
        timeout: Option<Duration>,
    ) -> Result<SocketEvents, HostIoError> {
        self.socket
            .poll(interest, timeout)
            .map_err(HostIoError::from)
    }

    fn shutdown(&mut self, how: ShutdownHow) -> Result<(), HostIoError> {
        self.socket
            .shutdown(host_shutdown_from_how(how))
            .map_err(HostIoError::from)
    }
}

#[derive(Default)]
pub struct NoopHostSocketTransport;

impl HostSocketTransport for NoopHostSocketTransport {
    fn open_socket(
        &self,
        _spec: SocketSpec,
        _options: SocketOptions,
    ) -> Result<Box<dyn HostSocketHandle>, HostIoError> {
        Err(HostIoError::unsupported())
    }
}

#[derive(Debug)]
struct HostSocketEntry {
    handle: Box<dyn HostSocketHandle>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostIoError {
    errno: LinuxErrno,
    reason: String,
}

impl HostIoError {
    #[must_use]
    pub fn new(errno: LinuxErrno, reason: impl Into<String>) -> Self {
        Self {
            errno,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn unsupported() -> Self {
        Self {
            errno: LinuxErrno::FunctionNotImplemented,
            reason: "host socket transport is not supported".to_owned(),
        }
    }

    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        self.errno
    }
}

impl fmt::Display for HostIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.errno, self.reason)
    }
}

impl std::error::Error for HostIoError {}

impl From<HostError> for HostIoError {
    fn from(error: HostError) -> Self {
        Self {
            errno: host_error_errno(error.kind()),
            reason: error.to_string(),
        }
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

#[derive(Default)]
pub struct GuestSocketTable {
    next_id: u64,
    sockets: BTreeMap<SocketId, GuestSocket>,
    host_handles: BTreeMap<SocketId, HostSocketEntry>,
    transport: Option<Box<dyn HostSocketTransport>>,
}

impl fmt::Debug for GuestSocketTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestSocketTable")
            .field("next_id", &self.next_id)
            .field("sockets", &self.sockets)
            .field(
                "host_handles",
                &self.host_handles.keys().collect::<Vec<_>>(),
            )
            .field("has_transport", &self.transport.is_some())
            .finish()
    }
}

impl GuestSocketTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: SocketId::MIN.get(),
            sockets: BTreeMap::new(),
            host_handles: BTreeMap::new(),
            transport: None,
        }
    }

    #[must_use]
    pub fn with_transport(transport: impl HostSocketTransport + 'static) -> Self {
        Self {
            next_id: SocketId::MIN.get(),
            sockets: BTreeMap::new(),
            host_handles: BTreeMap::new(),
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
        let previous_socket = self.sockets.insert(id, GuestSocket::new(id, spec));
        debug_assert!(previous_socket.is_none());
        let previous_handle = self.host_handles.insert(id, HostSocketEntry { handle });
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
        let socket = self.socket_mut(id)?;
        let value = match option {
            SocketOptionName::SocketType => socket.socket_type.to_linux(),
            SocketOptionName::SocketError => {
                if matches!(socket.state, SocketState::Connecting(_)) {
                    LinuxErrno::OperationInProgress.code() as u32
                } else {
                    socket
                        .last_error
                        .take()
                        .map_or(0, |errno| errno.code() as u32)
                }
            }
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
        let (handle, peer) = self
            .ensure_host_entry_mut(id, SocketOperation::Accept)?
            .handle
            .accept()
            .map_err(SocketError::from_host)?;
        let accepted = self.create_socket_with_handle(spec, handle)?;
        self.socket_mut(accepted)?.state = SocketState::Connected { local, peer };
        Ok((accepted, peer))
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

    pub fn poll(
        &mut self,
        id: SocketId,
        interest: SocketEvents,
        timeout: Option<Duration>,
    ) -> Result<SocketEvents, SocketError> {
        if matches!(self.socket(id)?.state, SocketState::Closed) {
            return Err(SocketError::BadSocket { id });
        }

        let entry = self.ensure_host_entry_mut(id, SocketOperation::Poll)?;
        let readiness = entry
            .handle
            .poll(interest, timeout)
            .map_err(SocketError::from_host)?;
        if readiness.writable && matches!(self.socket(id)?.state, SocketState::Connecting(_)) {
            self.finish_nonblocking_connect(id)?;
        }
        Ok(readiness)
    }

    pub fn require_connected_stream(&self, id: SocketId) -> Result<(), SocketError> {
        let socket = self.socket(id)?;
        validate_connected_stream_io(socket, SocketOperation::Send)
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
            let transport = self.transport.as_ref().ok_or_else(|| {
                SocketError::unsupported(
                    operation,
                    LinuxErrno::FunctionNotImplemented,
                    "host socket transport is not configured",
                )
            })?;
            let handle = transport
                .open_socket(spec, options)
                .map_err(SocketError::from_host)?;
            self.host_handles.insert(id, HostSocketEntry { handle });
        }
        self.host_entry_mut(id, operation)
    }

    fn connect_host_socket(
        &mut self,
        id: SocketId,
        address: SocketAddress,
    ) -> Result<(SocketAddress, SocketAddress), SocketError> {
        let entry = self.ensure_host_entry_mut(id, SocketOperation::Connect)?;
        entry
            .handle
            .connect(address)
            .map_err(SocketError::from_host)?;
        let local = entry.handle.local_addr().map_err(SocketError::from_host)?;
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
    Poll,
    Recv,
    RecvMsg,
    Send,
    SendMsg,
    SetSocketOption,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxErrno {
    AlreadyConnected,
    BadFileDescriptor,
    BrokenPipe,
    ConnectionRefused,
    ConnectionReset,
    FunctionNotImplemented,
    InvalidArgument,
    NotConnected,
    OperationAlreadyInProgress,
    OperationInProgress,
    OperationWouldBlock,
    OperationNotSupported,
    AddressFamilyNotSupported,
    ProtocolNotAvailable,
    ProtocolNotSupported,
    ProtocolWrongTypeForSocket,
    Shutdown,
    SocketTypeNotSupported,
    TimedOut,
}

impl LinuxErrno {
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::AlreadyConnected => 106,
            Self::BadFileDescriptor => 9,
            Self::BrokenPipe => 32,
            Self::ConnectionRefused => 111,
            Self::ConnectionReset => 104,
            Self::FunctionNotImplemented => 38,
            Self::InvalidArgument => 22,
            Self::OperationNotSupported => 95,
            Self::NotConnected => 107,
            Self::OperationAlreadyInProgress => 114,
            Self::OperationInProgress => 115,
            Self::OperationWouldBlock => 11,
            Self::ProtocolWrongTypeForSocket => 91,
            Self::ProtocolNotAvailable => 92,
            Self::ProtocolNotSupported => 93,
            Self::SocketTypeNotSupported => 94,
            Self::AddressFamilyNotSupported => 97,
            Self::Shutdown => 108,
            Self::TimedOut => 110,
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
    HostIo {
        errno: LinuxErrno,
        reason: String,
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

    fn with_errno(mut self, errno: LinuxErrno) -> Self {
        match &mut self {
            Self::InvalidInput { errno: current, .. }
            | Self::Unsupported { errno: current, .. }
            | Self::InvalidState { errno: current, .. }
            | Self::WouldBlock { errno: current, .. }
            | Self::HostIo { errno: current, .. } => *current = errno,
            Self::BadSocket { .. } => {}
        }
        self
    }

    fn from_host(error: HostIoError) -> Self {
        Self::HostIo {
            errno: error.linux_errno(),
            reason: error.to_string(),
        }
    }

    #[must_use]
    pub const fn linux_errno(&self) -> LinuxErrno {
        match self {
            Self::InvalidInput { errno, .. }
            | Self::Unsupported { errno, .. }
            | Self::InvalidState { errno, .. }
            | Self::WouldBlock { errno, .. }
            | Self::HostIo { errno, .. } => *errno,
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
            Self::HostIo { reason, .. } => write!(f, "host socket I/O failed: {reason}"),
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

fn validate_connect(socket: &GuestSocket, id: SocketId) -> Result<(), SocketError> {
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

fn validate_connected_stream_io(
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

fn validate_connected_io(
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

fn validate_datagram_io(
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

const fn host_error_errno(kind: HostErrorKind) -> LinuxErrno {
    match kind {
        HostErrorKind::InvalidInput => LinuxErrno::InvalidArgument,
        HostErrorKind::Interrupted | HostErrorKind::WouldBlock => LinuxErrno::OperationWouldBlock,
        HostErrorKind::TimedOut => LinuxErrno::TimedOut,
        HostErrorKind::BrokenPipe => LinuxErrno::BrokenPipe,
        HostErrorKind::Unsupported => LinuxErrno::FunctionNotImplemented,
        HostErrorKind::Unavailable => LinuxErrno::ConnectionRefused,
        HostErrorKind::AccessDenied
        | HostErrorKind::NotFound
        | HostErrorKind::AlreadyExists
        | HostErrorKind::OutOfMemory
        | HostErrorKind::Poisoned
        | HostErrorKind::Other => LinuxErrno::ConnectionReset,
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

    #[derive(Debug, Default)]
    struct FakeHostSocketHandle {
        sent: Vec<u8>,
        incoming: Vec<u8>,
        local: Option<SocketAddress>,
        connected: Option<SocketAddress>,
        connect_error: Option<HostIoError>,
        socket_error: Option<HostIoError>,
        fail_send: Option<HostIoError>,
        accepted: Vec<(FakeHostSocketHandle, SocketAddress)>,
        bound: Option<SocketAddress>,
        listened: bool,
        nonblocking: bool,
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

        fn with_accepted(peer: SocketAddress, incoming: &[u8]) -> Self {
            Self {
                accepted: vec![(Self::with_incoming(incoming), peer)],
                ..Self::default()
            }
        }
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

        fn accept(&mut self) -> Result<(Box<dyn HostSocketHandle>, SocketAddress), HostIoError> {
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

        fn connect(&mut self, address: SocketAddress) -> Result<(), HostIoError> {
            if let Some(error) = self.connect_error.take() {
                if error.linux_errno() == LinuxErrno::OperationWouldBlock {
                    self.connected = Some(address);
                }
                return Err(error);
            }
            self.connected = Some(address);
            Ok(())
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
            self.connected.ok_or_else(|| {
                HostIoError::new(LinuxErrno::NotConnected, "socket is not connected")
            })
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
            Ok(SocketEvents {
                readable: interest.readable && !self.incoming.is_empty(),
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
        assert_eq!(
            table
                .get_option(stream, SocketOptionName::SocketError)
                .expect("SO_ERROR"),
            LinuxErrno::OperationInProgress.code() as u32
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
        let listener_handle =
            FakeHostSocketHandle::with_accepted(peer, b"server-side accepted bytes");
        let mut table = GuestSocketTable::with_transport(NoopHostSocketTransport);
        let listener = table
            .create_socket_with_handle(
                SocketSpec::new(SocketDomain::Inet, SocketType::Stream, SocketProtocol::Tcp)
                    .unwrap(),
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

        let mut table = GuestSocketTable::with_transport(
            WinHostSocketTransport::new().expect("host transport"),
        );
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
}
