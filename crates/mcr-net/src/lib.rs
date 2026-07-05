use std::fmt;
use std::io::{IoSlice, IoSliceMut};
use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use mcr_task::{
    HostWorkerPoolConfig, HostWorkerPoolExecutor, HostWorkerPoolJobError, HostWorkerPoolRole,
    HostWorkerPoolSubmitError,
};
use mcr_win::{
    AddressFamily, HostAcceptExSubmission, HostConnectExSubmission, HostError, HostErrorKind,
    HostIoCompletionPort, HostRioCapability, HostShutdown, HostSocket, HostSocketIoDirection,
    HostSocketIoSubmission, HostSocketOptionName, HostSocketOptionValue, NetworkStack,
    PendingHostAcceptEx, PendingHostConnectEx, PendingHostSocketIo, SocketCompletionKind,
    SocketEvents, SocketKind, SocketProtocol as HostSocketProtocol,
};

mod dns_cache;

pub use dns_cache::{DnsCache, DnsCacheQuery, DnsRecordType, GuestDnsConfig};

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
const UNIX_SOCKET_PATH_LEN: usize = 108;

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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SocketReadinessToken {
    socket: SocketId,
    generation: u64,
}

impl SocketReadinessToken {
    #[must_use]
    pub const fn new(socket: SocketId, generation: u64) -> Self {
        Self { socket, generation }
    }

    #[must_use]
    pub const fn socket(self) -> SocketId {
        self.socket
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostSocketCompletion {
    token: SocketReadinessToken,
    kind: SocketCompletionKind,
}

impl HostSocketCompletion {
    #[must_use]
    pub const fn new(token: SocketReadinessToken, kind: SocketCompletionKind) -> Self {
        Self { token, kind }
    }

    #[must_use]
    pub const fn token(self) -> SocketReadinessToken {
        self.token
    }

    #[must_use]
    pub const fn kind(self) -> SocketCompletionKind {
        self.kind
    }

    #[must_use]
    pub const fn readiness(self) -> SocketEvents {
        self.kind.readiness()
    }
}

#[derive(Debug)]
pub enum SocketAcceptFastPath {
    Unsupported,
    Pending,
    Accepted {
        handle: Box<dyn HostSocketHandle>,
        peer: SocketAddress,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketConnectFastPath {
    Unsupported,
    Pending,
    Connected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketConnectFastPathCompletion {
    Inactive,
    Pending,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketDomain {
    Unix,
    Inet,
    Inet6,
}

impl SocketDomain {
    pub fn from_linux(value: u32) -> Result<Self, SocketError> {
        match value {
            LINUX_AF_UNIX => Ok(Self::Unix),
            LINUX_AF_INET => Ok(Self::Inet),
            LINUX_AF_INET6 => Ok(Self::Inet6),
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
        match (self.domain, self.socket_type, self.protocol) {
            (SocketDomain::Unix, _, SocketProtocol::Default) => SocketProtocol::Default,
            (_, SocketType::Stream, SocketProtocol::Default) => SocketProtocol::Tcp,
            (_, SocketType::Datagram, SocketProtocol::Default) => SocketProtocol::Udp,
            (_, _, protocol) => protocol,
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
    Unix {
        path: [u8; UNIX_SOCKET_PATH_LEN],
        len: u8,
    },
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
    pub fn unix(path: &[u8]) -> Result<Self, SocketError> {
        if path.len() > UNIX_SOCKET_PATH_LEN {
            return Err(SocketError::invalid_input(
                SocketOperation::Bind,
                LinuxErrno::InvalidArgument,
                "UNIX socket path is too long",
            ));
        }
        let mut stored = [0; UNIX_SOCKET_PATH_LEN];
        stored[..path.len()].copy_from_slice(path);
        Ok(Self::Unix {
            path: stored,
            len: path
                .len()
                .try_into()
                .expect("UNIX socket path length fits in u8"),
        })
    }

    #[must_use]
    pub fn unix_path_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Unix { path, len } => Some(&path[..usize::from(*len)]),
            Self::Inet { .. } | Self::Inet6 { .. } => None,
        }
    }

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
            Self::Unix { .. } => SocketDomain::Unix,
            Self::Inet { .. } => SocketDomain::Inet,
            Self::Inet6 { .. } => SocketDomain::Inet6,
        }
    }

    #[must_use]
    pub const fn unspecified_for_domain(domain: SocketDomain) -> Self {
        match domain {
            SocketDomain::Unix => Self::Unix {
                path: [0; UNIX_SOCKET_PATH_LEN],
                len: 0,
            },
            SocketDomain::Inet => Self::inet([0, 0, 0, 0], 0),
            SocketDomain::Inet6 => Self::inet6([0; 16], 0, 0, 0),
        }
    }
}

impl From<SocketAddress> for SocketAddr {
    fn from(value: SocketAddress) -> Self {
        match value {
            SocketAddress::Unix { .. } => {
                panic!("AF_UNIX socket addresses cannot be converted to host TCP addresses")
            }
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
        match (self.domain, self.socket_type, self.protocol) {
            (SocketDomain::Unix, _, SocketProtocol::Default) => SocketProtocol::Default,
            (_, SocketType::Stream, SocketProtocol::Default) => SocketProtocol::Tcp,
            (_, SocketType::Datagram, SocketProtocol::Default) => SocketProtocol::Udp,
            (_, _, protocol) => protocol,
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
    /// Attempts to submit or finish an adapter-owned `AcceptEx` operation.
    ///
    /// `Pending` means the adapter owns the in-flight operation and must later
    /// return an `Accept` completion for the supplied readiness token. `Accepted`
    /// means any host `SO_UPDATE_ACCEPT_CONTEXT` work has already completed and
    /// guest-visible address and option queries may observe the accepted socket.
    /// `Unsupported` keeps the plain `accept` fallback path unchanged.
    fn accept_fast_path(
        &mut self,
        _token: SocketReadinessToken,
        _spec: SocketSpec,
    ) -> Result<SocketAcceptFastPath, HostIoError> {
        Ok(SocketAcceptFastPath::Unsupported)
    }
    fn accept(&mut self) -> Result<(Box<dyn HostSocketHandle>, SocketAddress), HostIoError>;
    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), HostIoError>;
    /// Attempts to submit an adapter-owned `ConnectEx` operation.
    ///
    /// `Pending` means the Linux socket remains `Connecting` until a matching
    /// `Connect` completion is drained through the readiness token and
    /// `complete_connect_fast_path` reports completion. `Unsupported` keeps the
    /// plain `connect` fallback path unchanged.
    fn connect_fast_path(
        &mut self,
        _token: SocketReadinessToken,
        _address: SocketAddress,
    ) -> Result<SocketConnectFastPath, HostIoError> {
        Ok(SocketConnectFastPath::Unsupported)
    }
    fn connect(&mut self, address: SocketAddress) -> Result<(), HostIoError>;
    /// Advances `ConnectEx` completion state before `SO_ERROR`, local address,
    /// or peer address queries are used to complete the Linux state machine.
    fn complete_connect_fast_path(
        &mut self,
    ) -> Result<SocketConnectFastPathCompletion, HostIoError> {
        Ok(SocketConnectFastPathCompletion::Inactive)
    }
    fn rio_capability(&mut self) -> Result<HostRioCapability, HostIoError> {
        Ok(HostRioCapability::unsupported(None))
    }
    fn take_error(&mut self) -> Result<Option<HostIoError>, HostIoError>;
    fn local_addr(&self) -> Result<SocketAddress, HostIoError>;
    fn peer_addr(&self) -> Result<SocketAddress, HostIoError>;
    fn send(&mut self, buffer: &[u8]) -> Result<usize, HostIoError>;
    fn send_vectored(&mut self, buffers: &[IoSlice<'_>]) -> Result<usize, HostIoError> {
        let buffer = flatten_io_slices(buffers)?;
        self.send(&buffer)
    }
    fn send_to(&mut self, buffer: &[u8], address: SocketAddress) -> Result<usize, HostIoError>;
    fn send_to_vectored(
        &mut self,
        buffers: &[IoSlice<'_>],
        address: SocketAddress,
    ) -> Result<usize, HostIoError> {
        let buffer = flatten_io_slices(buffers)?;
        self.send_to(&buffer, address)
    }
    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, HostIoError>;
    fn recv_vectored(&mut self, buffers: &mut [IoSliceMut<'_>]) -> Result<usize, HostIoError> {
        let capacity = checked_iovec_total_len(buffers.iter().map(|buffer| buffer.len()))?;
        let mut buffer = vec![0; capacity];
        let count = self.recv(&mut buffer)?;
        scatter_io_slices(buffers, &buffer, count)?;
        Ok(count)
    }
    fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddress), HostIoError>;
    fn recv_from_vectored(
        &mut self,
        buffers: &mut [IoSliceMut<'_>],
    ) -> Result<(usize, SocketAddress), HostIoError> {
        let capacity = checked_iovec_total_len(buffers.iter().map(|buffer| buffer.len()))?;
        let mut buffer = vec![0; capacity];
        let (count, address) = self.recv_from(&mut buffer)?;
        scatter_io_slices(buffers, &buffer, count)?;
        Ok((count, address))
    }
    fn poll(
        &mut self,
        interest: SocketEvents,
        timeout: Option<Duration>,
    ) -> Result<SocketEvents, HostIoError>;
    fn drain_readiness_completions(
        &mut self,
        _token: SocketReadinessToken,
    ) -> Result<Vec<HostSocketCompletion>, HostIoError> {
        Ok(Vec::new())
    }
    fn shutdown(&mut self, how: ShutdownHow) -> Result<(), HostIoError>;
}

fn flatten_io_slices(buffers: &[IoSlice<'_>]) -> Result<Vec<u8>, HostIoError> {
    let capacity = checked_iovec_total_len(buffers.iter().map(|buffer| buffer.len()))?;
    let mut flattened = Vec::with_capacity(capacity);
    for buffer in buffers {
        flattened.extend_from_slice(buffer.as_ref());
    }
    Ok(flattened)
}

fn scatter_io_slices(
    buffers: &mut [IoSliceMut<'_>],
    bytes: &[u8],
    count: usize,
) -> Result<(), HostIoError> {
    if count > bytes.len() {
        return Err(HostIoError::new(
            LinuxErrno::InvalidArgument,
            "host socket received more bytes than the iovec capacity",
        ));
    }

    let mut consumed = 0usize;
    for buffer in buffers {
        let remaining = count.saturating_sub(consumed);
        if remaining == 0 {
            break;
        }
        let write_len = buffer.len().min(remaining);
        buffer[..write_len].copy_from_slice(&bytes[consumed..consumed + write_len]);
        consumed += write_len;
    }
    Ok(())
}

fn checked_iovec_total_len(lengths: impl IntoIterator<Item = usize>) -> Result<usize, HostIoError> {
    lengths.into_iter().try_fold(0usize, |total, len| {
        total.checked_add(len).ok_or_else(|| {
            HostIoError::new(
                LinuxErrno::InvalidArgument,
                "socket iovec total length overflows usize",
            )
        })
    })
}

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

    fn complete_pending_iocp_packet(
        &mut self,
        packet: mcr_win::HostIoCompletionPacket,
    ) -> Result<SocketEvents, HostIoError> {
        let mut readiness = SocketEvents::default();
        let mut packet = Some(packet);
        if let Some(pending) = self.pending_accept.take() {
            let current = packet.expect("completion packet is present");
            if pending.matches_completion(current) {
                match pending.complete_from_packet(current) {
                    Ok((socket, peer)) => {
                        self.accepted_fast_path = Some((socket, SocketAddress::from(peer)));
                        readiness.readable = true;
                    }
                    Err(error) => {
                        self.accept_error = Some(HostIoError::from(error));
                        readiness.readable = true;
                        readiness.error = true;
                    }
                }
                packet = None;
            } else {
                self.pending_accept = Some(pending);
                packet = Some(current);
            }
        }
        if let Some(current) = packet
            && let Some(pending) = self.pending_connect.take()
        {
            if pending.matches_completion(current) {
                match pending.complete_from_packet(current) {
                    Ok(()) => {
                        self.connect_completed = true;
                        readiness.writable = true;
                    }
                    Err(error) => {
                        self.connect_error = Some(HostIoError::from(error));
                        readiness.writable = true;
                        readiness.error = true;
                    }
                }
                packet = None;
            } else {
                self.pending_connect = Some(pending);
                packet = Some(current);
            }
        }
        if let Some(current) = packet
            && let Some(pending) = self.pending_recv.take()
        {
            if pending.matches_completion(current) {
                let submission = pending.complete_from_packet(current);
                self.apply_recv_submission(submission)?;
                merge_socket_events(&mut readiness, self.recv_completion_kind().readiness());
            } else {
                self.pending_recv = Some(pending);
            }
        }
        Ok(readiness)
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
        if !self.spec.flags.nonblocking
            || self.completion_port.is_none()
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
            || !self.spec.flags.nonblocking
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
        let wait_accept = interest.readable && self.pending_accept.is_some();
        let wait_connect = interest.writable && self.pending_connect.is_some();
        if (wait_accept || wait_connect)
            && let Some(port) = self.completion_port.as_ref().cloned()
        {
            if wait_accept {
                fallback_interest.readable = false;
            }
            if wait_connect {
                fallback_interest.writable = false;
            }
            loop {
                let Some(packet) = port.get(timeout).map_err(HostIoError::from)? else {
                    break;
                };
                let update = self.complete_pending_iocp_packet(packet)?;
                merge_socket_events(&mut readiness, update);
                let accept_ready = !wait_accept || readiness.readable || readiness.error;
                let connect_ready = !wait_connect || readiness.writable || readiness.error;
                if (accept_ready && connect_ready) || timeout.is_some() {
                    break;
                }
            }
        }
        if fallback_interest.readable && self.can_use_iocp_recv() {
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

fn merge_socket_events(target: &mut SocketEvents, update: SocketEvents) {
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

fn address_family_from_socket_domain(domain: SocketDomain) -> AddressFamily {
    match domain {
        SocketDomain::Unix => unreachable!("AF_UNIX sockets do not use host socket transport"),
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

        if matches!(state, SocketState::Created) && self.socket_uses_host_transport(id)? {
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
            && self.socket_uses_host_transport(id)?
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

        if self.socket_uses_host_transport(id)? {
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
        if matches!(self.socket(id)?.state, SocketState::Closed) {
            return Err(SocketError::BadSocket { id });
        }

        if !self.socket_uses_host_transport(id)? {
            return Ok(SocketEvents::default());
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

        if let Some(readiness) = self.readiness_cache.readiness(token, interest) {
            if readiness.writable && matches!(self.socket(id)?.state, SocketState::Connecting(_)) {
                self.finish_nonblocking_connect(id)?;
            }
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
            if spec.domain == SocketDomain::Unix {
                return Err(SocketError::unsupported(
                    operation,
                    LinuxErrno::FunctionNotImplemented,
                    "AF_UNIX sockets do not use host socket transport",
                ));
            }
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

    fn socket_uses_host_transport(&self, id: SocketId) -> Result<bool, SocketError> {
        let socket = self.socket(id)?;
        Ok(socket.domain != SocketDomain::Unix
            && (self.transport.is_some() || self.host_handles.contains_key(&id)))
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
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use mcr_win::SocketFastPathKind;

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

        fn with_acceptex(
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
            self.state.borrow().peer.ok_or_else(|| {
                HostIoError::new(LinuxErrno::NotConnected, "socket is not connected")
            })
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
                    ReadinessCompletionFixture::Current(kind) => {
                        HostSocketCompletion::new(token, kind)
                    }
                    ReadinessCompletionFixture::Stale(kind) => HostSocketCompletion::new(
                        SocketReadinessToken::new(
                            token.socket(),
                            token.generation().saturating_add(1),
                        ),
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

        let unix = SocketSpec::from_linux(LINUX_AF_UNIX, LINUX_SOCK_STREAM, LINUX_IPPROTO_IP)
            .expect("valid unix stream socket");
        assert_eq!(unix.domain, SocketDomain::Unix);
        assert_eq!(unix.socket_type, SocketType::Stream);
        assert_eq!(unix.protocol, SocketProtocol::Default);
        assert_eq!(unix.effective_protocol(), SocketProtocol::Default);
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
    fn unix_stream_bind_listen_stays_guest_local() {
        let mut table = GuestSocketTable::new();
        let stream = table
            .create_socket(
                SocketDomain::Unix,
                SocketType::Stream,
                SocketProtocol::Default,
            )
            .expect("unix stream socket");
        let address = SocketAddress::unix(b"/tmp/mcr-test.sock").expect("unix path");

        assert_eq!(
            table.socket(stream).expect("socket").effective_protocol(),
            SocketProtocol::Default
        );
        table.bind(stream, address).expect("bind unix stream");
        table.listen(stream, 128).expect("listen unix stream");
        assert_eq!(
            table.socket(stream).expect("socket").state(),
            SocketState::Listening(address)
        );
        assert_eq!(
            table
                .poll(stream, SocketEvents::read(), Some(Duration::ZERO))
                .expect("poll unix listener"),
            SocketEvents::default()
        );
        assert_eq!(
            table
                .accept(stream)
                .expect_err("no pending unix connection")
                .linux_errno(),
            LinuxErrno::OperationWouldBlock
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
        let listener_handle = FakeHostSocketHandle::with_counted_accepted(
            peer,
            b"fallback",
            Rc::clone(&accept_calls),
        );
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

        let mut table = GuestSocketTable::with_transport(
            WinHostSocketTransport::new().expect("host transport"),
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
        let (server, _) = listener.accept().unwrap();
        assert_eq!(
            table.peer_address(client).expect("peer address"),
            Some(SocketAddress::from(server.local_addr().unwrap()))
        );
    }

    #[cfg(windows)]
    #[test]
    fn win_host_transport_acceptex_completes_nonblocking_accept() {
        let mut table = GuestSocketTable::with_transport(
            WinHostSocketTransport::new().expect("host transport"),
        );
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

        let mut table = GuestSocketTable::with_transport(
            WinHostSocketTransport::new().expect("host transport"),
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
