# Network ABI Design

## Boundary

MCR's networking target is Linux/POSIX socket syscall ABI compatibility inside a
Windows userspace runtime. It is not a source-level portability wrapper around
`winsock2.h`.

Guest programs should observe Linux-style `socket`, `accept4`, `connect`,
`sendmsg`, `poll`, `epoll`, `close`, `read`, `write`, `fcntl`, and `ioctl`
semantics. Windows `SOCKET` values and host handles must remain hidden behind
MCR-owned guest file descriptors and open objects.

```text
guest syscall ABI / POSIX API
        |
        v
syscall decoding and guest struct conversion
        |
        v
Linux fd table / open object table
        |
        +--> socket object -> Winsock2 adapter
        +--> epoll object  -> readiness backend
        +--> eventfd/timerfd/pipe/file objects
        |
        v
Windows backend: Winsock2 + WSAPoll/select MVP, later IOCP
```

The first implementation must prioritize semantic correctness with
nonblocking Winsock sockets and a readiness backend. IOCP is a later performance
backend behind the same socket/readiness contracts; it is not an epoll-equivalent
guest model because IOCP is completion-based while Linux epoll is readiness-based.

## Compatibility Slices

The first network ABI slice covers:

- `AF_INET` and `AF_INET6`;
- `SOCK_STREAM` TCP and `SOCK_DGRAM` UDP;
- `socket`, `bind`, `listen`, `accept`, `accept4`, and `connect`;
- `send`, `recv`, `sendto`, `recvfrom`, and basic iovec `sendmsg`/`recvmsg`;
- `getsockname`, `getpeername`, common `getsockopt`/`setsockopt`, and `shutdown`;
- `close`, `read`, and `write` on socket fds;
- `fcntl` for `O_NONBLOCK` and `FD_CLOEXEC`;
- `ioctl` for `FIONBIO` and `FIONREAD`;
- `select`, `poll`, and level-triggered `epoll`.

Deferred or partial areas include `AF_UNIX`, `SCM_RIGHTS`, `SCM_CREDENTIALS`,
`SO_REUSEPORT`, raw sockets, advanced multicast options, `TCP_FASTOPEN`,
`recvmmsg`, `sendmmsg`, io_uring-style APIs, fork-time socket inheritance, and
cross-process fd passing.

## Guest Fd And Object Model

Sockets use the shared MCR guest fd namespace. A guest fd is a small Linux-style
integer allocated by the VFS/fd table, never a Windows `SOCKET`.

```rust
enum FdKind {
    Socket,
    Epoll,
    EventFd,
    TimerFd,
    Pipe,
    File,
}

struct FdEntry {
    kind: FdKind,
    generation: u32,
    fd_flags: u32,
    object: OpenObjectRef,
}

struct SocketObject {
    host_socket: HostSocketRef,
    linux_domain: i32,
    linux_type: i32,
    linux_protocol: i32,
    state: SocketState,
    nonblocking: bool,
}
```

Required fd semantics:

- `FD_CLOEXEC` is fd-entry state; `O_NONBLOCK` is shared open-socket-object
  state and must be visible through `dup`, `dup2`, and `dup3` aliases.
- `dup`, `dup2`, and `dup3` add a reference to the same compatibility object;
  they must not duplicate the Windows socket inside one process.
- `close(fd)` removes only that fd entry; the final object reference closes the
  host socket.
- fd entries carry generation counters so a reused integer fd cannot satisfy an
  old `poll` or `epoll` watch.
- `read` and `write` on socket fds dispatch to socket receive/send paths, not to
  Windows file I/O.

## Winsock Lifecycle

The Windows adapter owns process-level Winsock startup:

```c
WSADATA wsa;
WSAStartup(MAKEWORD(2, 2), &wsa);
```

Successful `WSAStartup` calls must be balanced with `WSACleanup`. Socket
creation should use `WSASocketW` with `WSA_FLAG_OVERLAPPED` so the same objects
can later move behind IOCP, and with `WSA_FLAG_NO_HANDLE_INHERIT` when supported
so host inheritance does not accidentally bypass MCR's `FD_CLOEXEC` policy.

The fd layer still owns `FD_CLOEXEC`; Windows handle inheritance and POSIX
close-on-exec are not the same model.

## Syscall Mapping Rules

| Linux ABI | Windows backend | MCR policy |
|---|---|---|
| `socket` | `WSASocketW` | Strip `SOCK_NONBLOCK`/`SOCK_CLOEXEC`, map domains/types/protocols, preserve Linux metadata. |
| `bind` | `bind` | Convert guest sockaddr to host sockaddr; never pass guest memory directly. |
| `listen` | `listen` | Define backlog and `SOMAXCONN` behavior explicitly. |
| `accept`/`accept4` | `accept` MVP, `AcceptEx` later | Apply `SOCK_NONBLOCK` and `SOCK_CLOEXEC` before returning the guest fd. |
| `connect` | `connect` MVP, `ConnectEx` later | Nonblocking `WSAEWOULDBLOCK` maps to `EINPROGRESS`; readiness completion is verified through `SO_ERROR`. |
| `send`/`recv` | `send`/`recv` or `WSASend`/`WSARecv` | Preserve `MSG_DONTWAIT`; model `MSG_NOSIGNAL`/`SIGPIPE` above Winsock. |
| `sendto`/`recvfrom` | `sendto`/`recvfrom` | Preserve UDP message boundaries and distinguish zero-length datagrams from TCP EOF. |
| `sendmsg`/`recvmsg` | `WSASendMsg`/`WSARecvMsg` where needed | Convert iovecs to `WSABUF`; ancillary data is whitelist-only. |
| `getsockopt`/`setsockopt` | `getsockopt`/`setsockopt` | Translate option level/name/value; never pass Linux constants blindly. |
| `getsockname`/`getpeername` | direct query | Refresh pending nonblocking connect state first. |
| `shutdown` | `shutdown` | Map `SHUT_RD`/`SHUT_WR`/`SHUT_RDWR` to Winsock shutdown modes. |
| `close` | `closesocket` | Close only on final object ref; drain or defer pending overlapped resources. |
| `fcntl` | runtime state plus `ioctlsocket(FIONBIO)` | `F_SETFL O_NONBLOCK` updates the shared socket object; `F_SETFD` updates the fd entry. |
| `ioctl` | `ioctlsocket`/`WSAIoctl` | Whitelist `FIONBIO` and `FIONREAD`; reject unsupported requests intentionally. |
| `select` | fd scan plus readiness backend | Parse Linux fd sets and `nfds`; Windows `select` ignores `nfds` and uses a different `fd_set` layout. |
| `poll` | `WSAPoll` or readiness helper | Merge socket and non-socket readiness; align `POLLERR`, `POLLHUP`, and `POLLNVAL`. |
| `epoll_*` | internal epoll object | MVP builds per-wait readiness snapshots; IOCP may later feed a readiness cache. |

If the IOCP backend later uses `AcceptEx` or `ConnectEx`, successful completions
must apply `SO_UPDATE_ACCEPT_CONTEXT` or `SO_UPDATE_CONNECT_CONTEXT` before
guest-visible address and option queries.

## Blocking And Nonblocking

Host sockets should be kept nonblocking. Blocking Linux syscalls are simulated
by the runtime wait loop:

```text
recv(fd):
    try host recv
    if success: return bytes
    if would-block and guest requested nonblocking: return EAGAIN
    wait_readable(fd, deadline, cancellation)
    retry
```

This keeps interrupt, timeout, close, and cancellation behavior under MCR
control. It also avoids host threads becoming stuck inside blocking Winsock
calls, which do not have POSIX signal interruption semantics.

Nonblocking `connect` uses an explicit state machine:

```text
Initial -> connect succeeds -> Connected
Initial -> WSAEWOULDBLOCK -> Connecting, return EINPROGRESS
Connecting -> connect again -> EALREADY
Connecting -> writable readiness -> getsockopt(SO_ERROR)
SO_ERROR == 0 -> Connected
SO_ERROR != 0 -> Failed
```

Writable readiness alone is not enough to report success; `SO_ERROR` is the
guest-visible completion source of truth.

## Readiness Model

`select`, `poll`, and `epoll` share one readiness policy:

- decode guest fd sets or `pollfd`/`epoll_event` arrays from guest memory;
- look up each fd in the MCR fd table and validate generation/object identity;
- route socket fds to the socket readiness backend;
- route pipes, eventfd, timerfd, stdio, procfs, devfs, and files through runtime
  readiness rules;
- merge results and write only Linux ABI structures back to guest memory.

The Phase 2 epoll subset is level-triggered. `EPOLLONESHOT`, edge-triggered
semantics, `EPOLLEXCLUSIVE`, and signal-mask variants either remain deferred or
return explicit Linux-compatible errors until a task expands the contract.

The IOCP backend feeds this same policy through a socket readiness token owned
by `mcr-net`. Host completions such as accept, connect, receive, send, close,
and error map to readiness bits under the active token generation; stale
completions from a replaced or closed host socket are ignored. The current
Winsock backend still falls back to `WSAPoll` when no completion-backed
readiness is cached, so IOCP remains an implementation backend rather than a new
guest-visible wait model.

`AcceptEx` and `ConnectEx` are optional host fast paths behind that same seam.
The socket adapter may report unsupported and leave the plain `accept` or
`connect` path unchanged, or it may submit an extension operation that later
emits an `Accept` or `Connect` completion for the active readiness token. A
completed `AcceptEx` result must have applied `SO_UPDATE_ACCEPT_CONTEXT` before
returning an accepted host handle to `mcr-net`. A completed `ConnectEx` result
must have applied `SO_UPDATE_CONNECT_CONTEXT` before `SO_ERROR`, local address,
or peer address queries are used to complete the Linux nonblocking connect state
machine.

## MCR-Owned DNS Resolution

Guest-created UDP/TCP sockets keep their normal ownership even when the payload
looks like DNS. MCR may cache DNS results only for an MCR-owned resolver helper
or DNS proxy that performs resolution on behalf of the runtime. That cache lives
behind `mcr-net::DnsCache`, respects response TTLs, normalizes the DNS query
name for cache lookup, and clears entries when the guest-visible resolver
configuration snapshot changes.

## Socket Options

Socket options are a whitelist, not a passthrough. Initial support should focus
on options used by curl, git, libc resolvers, and language package managers:

- `SOL_SOCKET`: `SO_ERROR`, `SO_TYPE`, `SO_REUSEADDR`, `SO_KEEPALIVE`,
  `SO_LINGER`, `SO_RCVBUF`, `SO_SNDBUF`, `SO_RCVTIMEO`, `SO_SNDTIMEO`,
  `SO_BROADCAST`, and `SO_OOBINLINE`;
- `IPPROTO_TCP`: `TCP_NODELAY` and Windows-version-gated keepalive tunables;
- `IPPROTO_IP`: `IP_TTL`, `IP_PKTINFO`, and selected multicast options;
- `IPPROTO_IPV6`: `IPV6_V6ONLY`, `IPV6_PKTINFO`, and selected multicast options.

Known differences must be modeled explicitly:

- Windows `SO_REUSEADDR` and Linux `SO_REUSEADDR`/`SO_REUSEPORT` are not
  equivalent; a runtime bind registry may be needed for Linux-like behavior
  inside one MCR instance.
- `SO_RCVLOWAT` and `SO_SNDLOWAT` must not be reported as supported unless the
  adapter can prove matching behavior.
- timeout options are better enforced by runtime deadlines than by Winsock
  socket timeouts.
- `AF_INET6` sockets should actively set the desired `IPV6_V6ONLY` behavior
  before `bind`, because Windows and common Linux defaults differ.

## Message And Ancillary Data

Basic `sendmsg` and `recvmsg` support converts guest iovecs into host buffers.
Control messages are supported only by explicit whitelist.

The socket transport boundary exposes vectored send/receive entry points for
connected streams and addressed UDP datagrams. These entry points take owned
Rust `IoSlice`/`IoSliceMut` views produced after guest-memory validation, so
host adapters can later map them to `WSABUF` without seeing raw guest pointers.
Until a host adapter overrides them, the fallback flattens or scatters through a
single legacy socket call and preserves the current copy-in/copy-out behavior.

Initial ancillary support may include `IP_PKTINFO`, `IPV6_PKTINFO`, TTL, and hop
limit metadata where Windows exposes compatible information. `SCM_RIGHTS`,
`SCM_CREDENTIALS`, and timestamp families remain deferred.

`SCM_RIGHTS` cannot be faked by placing Windows handles in payload data. If both
peers run inside MCR, it requires a broker that transfers or references MCR open
objects and gives the receiver new guest fd entries. If the peer is outside MCR,
return `EOPNOTSUPP` or `EINVAL` instead of pretending the transfer succeeded.

## AF_UNIX And Raw Socket Policy

`AF_UNIX` has three implementation levels:

- unsupported, returning `EAFNOSUPPORT`;
- Windows native `AF_UNIX` for stream pathname sockets, with socketpair,
  credentials, datagrams, and fd passing still partial;
- fully brokered MCR implementation over named pipes or loopback transport.

The first supported version should use runtime capability detection and document
its Linux mismatches. It must not assume Windows native `AF_UNIX` has Linux
pathname lifetime, permission, abstract namespace, socketpair, or `SCM_RIGHTS`
semantics.

Raw sockets are disabled by default. If a policy allows them, the adapter must
respect Windows administrator requirements and protocol restrictions and map
permission failures to Linux `EPERM`/`EACCES`.

## Process And Close Semantics

`fork`, `execve`, `posix_spawn`, `FD_CLOEXEC`, `dup`, and fd passing all interact
with sockets. Through Phase 2, spawn/exec inheritance is reconstructed from the
MCR fd table; Windows handle inheritance is only a transfer mechanism.

Full Linux `fork` socket state copying is deferred. A future fork-like backend
would need `WSADuplicateSocket` or a broker and still cannot promise identical
pending I/O, epoll interest, and signal behavior without more runtime state.

`close(fd)` must remove the fd entry first, wake runtime waiters, and close the
host socket only on the final object reference. If overlapped I/O is active,
buffers and overlapped records must stay alive until completions have drained.

## Error Mapping

Winsock errors are converted immediately to Linux errno. `WSAGetLastError` is
thread-local host state and must be read immediately after a failed host call.

Representative mappings:

- `WSAEWOULDBLOCK` -> `EAGAIN` or `EWOULDBLOCK`;
- `WSAEINPROGRESS` -> `EINPROGRESS`;
- `WSAEALREADY` -> `EALREADY`;
- `WSAECONNRESET` -> `ECONNRESET`;
- `WSAECONNABORTED` -> `ECONNABORTED`;
- `WSAETIMEDOUT` -> `ETIMEDOUT`;
- `WSAECONNREFUSED` -> `ECONNREFUSED`;
- `WSAEADDRINUSE` -> `EADDRINUSE`;
- `WSAEADDRNOTAVAIL` -> `EADDRNOTAVAIL`;
- `WSAEAFNOSUPPORT` -> `EAFNOSUPPORT`;
- `WSAEPROTONOSUPPORT` -> `EPROTONOSUPPORT`;
- `WSAENOPROTOOPT` -> `ENOPROTOOPT`;
- `WSAEMSGSIZE` -> `EMSGSIZE`;
- `WSAENOTSOCK` -> `ENOTSOCK` or `EBADF`, depending on whether fd table lookup
  or host validation failed;
- `WSA_OPERATION_ABORTED` -> `ECANCELED` or `EINTR`, depending on the runtime
  cancellation source.

## Implementation Phases

1. Foundation: fd table integration, object refcounts, generation checks,
   guest copy-in/copy-out, errno mapping, Winsock startup, and network tracing.
2. TCP/UDP basics: `socket`, `bind`, `listen`, `connect`, `accept`, stream and
   datagram I/O, shutdown, close, address queries, and socket fd `read`/`write`.
3. Nonblocking and waiting: `fcntl(O_NONBLOCK)`, `ioctl(FIONBIO/FIONREAD)`,
   `select`, `poll`, runtime waits, timeouts, cancellation, and nonblocking
   connect completion.
4. Socket options and IPv6: common option whitelist, `TCP_NODELAY`,
   `IPV6_V6ONLY`, dual-stack behavior, and runtime-enforced socket deadlines.
5. `sendmsg`/`recvmsg`: iovec movement, `MSG_PEEK`, `MSG_DONTWAIT`, packet info,
   datagram truncation, and strict control-message bounds checking.
6. `epoll`: internal epoll fd objects, level-trigger watches, close invalidation,
   fd generation checks, and intentionally deferred advanced flags.
7. `AF_UNIX`: stream pathname sockets first, then socketpair and brokered
   `SCM_RIGHTS` if required by workloads.
8. IOCP backend: `AcceptEx`, `ConnectEx`, IOCP worker pool, readiness cache,
   completion drain, and A/B differential tests against the semantic backend.
