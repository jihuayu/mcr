mod constants;
mod dns_cache;
mod error;
mod options;
mod table;
mod transport;
mod types;
mod validation;
mod win_transport;

#[cfg(test)]
mod tests;

pub use constants::*;
pub use dns_cache::{DnsCache, DnsCacheQuery, DnsRecordType, GuestDnsConfig};
pub use error::{HostIoError, LinuxErrno, SocketError, SocketOperation};
pub use options::{SocketOptionName, SocketOptions};
pub use table::GuestSocketTable;
pub use transport::{
    HostSocketBatchPoll, HostSocketHandle, HostSocketTransport, NoopHostSocketTransport,
};
pub use types::{
    GuestSocket, HostSocketCompletion, ShutdownFlags, ShutdownHow, SocketAcceptFastPath,
    SocketAddress, SocketConnectFastPath, SocketConnectFastPathCompletion, SocketCreationFlags,
    SocketDomain, SocketId, SocketProtocol, SocketReadinessToken, SocketSpec, SocketState,
    SocketType,
};
pub use win_transport::WinHostSocketTransport;
