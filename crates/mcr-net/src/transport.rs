use std::{
    fmt,
    io::{IoSlice, IoSliceMut},
    time::Duration,
};

use mcr_win::{HostRioCapability, SocketEvents};

use crate::{
    error::{HostIoError, LinuxErrno},
    options::SocketOptions,
    types::{
        HostSocketCompletion, ShutdownHow, SocketAcceptFastPath, SocketAddress,
        SocketConnectFastPath, SocketConnectFastPathCompletion, SocketReadinessToken, SocketSpec,
    },
};

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
