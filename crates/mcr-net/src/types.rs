use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

use mcr_win::{SocketCompletionKind, SocketEvents};

use crate::{
    constants::{
        LINUX_AF_INET, LINUX_AF_INET6, LINUX_AF_UNIX, LINUX_IPPROTO_IP, LINUX_IPPROTO_TCP,
        LINUX_IPPROTO_UDP, LINUX_SHUT_RD, LINUX_SHUT_RDWR, LINUX_SHUT_WR, LINUX_SOCK_CLOEXEC,
        LINUX_SOCK_DGRAM, LINUX_SOCK_FLAG_MASK, LINUX_SOCK_NONBLOCK, LINUX_SOCK_RAW,
        LINUX_SOCK_STREAM, LINUX_SOCK_TYPE_MASK,
    },
    error::{LinuxErrno, SocketError, SocketOperation},
    options::SocketOptions,
    transport::HostSocketHandle,
    validation::validate_socket_protocol,
};

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
                panic!("AF_UNIX socket addresses cannot be converted to host IP addresses")
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
    pub(crate) id: SocketId,
    pub(crate) domain: SocketDomain,
    pub(crate) socket_type: SocketType,
    pub(crate) protocol: SocketProtocol,
    pub(crate) flags: SocketCreationFlags,
    pub(crate) state: SocketState,
    pub(crate) shutdown: ShutdownFlags,
    pub(crate) options: SocketOptions,
    pub(crate) last_error: Option<LinuxErrno>,
}

impl GuestSocket {
    pub(crate) fn new(id: SocketId, spec: SocketSpec) -> Self {
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
