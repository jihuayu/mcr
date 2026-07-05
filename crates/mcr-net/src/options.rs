use crate::{
    constants::{
        DEFAULT_SOCKET_BUFFER_SIZE, LINUX_IPPROTO_TCP_LEVEL, LINUX_SO_ERROR, LINUX_SO_KEEPALIVE,
        LINUX_SO_RCVBUF, LINUX_SO_REUSEADDR, LINUX_SO_SNDBUF, LINUX_SO_TYPE, LINUX_SOL_SOCKET,
        LINUX_TCP_NODELAY,
    },
    error::{LinuxErrno, SocketError, SocketOperation},
};

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
pub(crate) const fn bool_to_socket_option(value: bool) -> u32 {
    if value { 1 } else { 0 }
}

pub(crate) const fn socket_option_to_bool(value: u32) -> bool {
    value != 0
}

pub(crate) fn validate_buffer_size(value: u32) -> Result<u32, SocketError> {
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
