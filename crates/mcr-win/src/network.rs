mod model;
mod platform;

#[cfg(test)]
mod tests;

pub use model::{
    AddressFamily, HostAcceptExSubmission, HostConnectExSubmission, HostShutdown,
    HostSocketIoCompletion, HostSocketIoDirection, HostSocketIoFailure, HostSocketIoResult,
    HostSocketIoSubmission, HostSocketOptionName, HostSocketOptionValue, SocketCompletionKind,
    SocketEvents, SocketFastPathKind, SocketKind, SocketPoll, SocketProtocol,
};
pub use platform::{
    HostRioCapability, HostSocket, NetworkStack, PendingHostAcceptEx, PendingHostConnectEx,
    PendingHostSocketIo, poll_sockets,
};
