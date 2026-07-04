---
id: perf-021
scope: network-performance
status: done
depends-on: [perf-007, perf-020]
---

# perf-021: Implement AcceptEx And ConnectEx Backend

## Objective

Implement `AcceptEx` and `ConnectEx` as host fast paths behind the IOCP socket
lifetime model, including extension lookup, overlapped buffer ownership,
context update calls, cancellation, and fallback comparison tests.

## Context

- `docs/architecture/networking.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-007.md`
- `docs/plan/tasks/perf-020.md`

## Path

- `crates/mcr-win/`
- `crates/mcr-net/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `docs/architecture/networking.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-021.md`

## Verification

```powershell
cargo test -p mcr-win acceptex connectex -- --nocapture
cargo test -p mcr-net acceptex connectex -- --nocapture
cargo test -p mcr-runtime accept connect -- --nocapture
cargo test -p mcr-testkit perf_baseline -- --ignored --nocapture
```

## Notes

- Successful `AcceptEx` completions must apply `SO_UPDATE_ACCEPT_CONTEXT`.
- Successful `ConnectEx` completions must apply `SO_UPDATE_CONNECT_CONTEXT` and
  still report guest completion through Linux readiness and `SO_ERROR`.
- Plain `accept` and nonblocking `connect` remain required fallbacks.

## Checkpoints

- Added the `mcr-win` Winsock extension-function lookup boundary.
  `HostSocket::extension_function` resolves opaque `AcceptEx` and `ConnectEx`
  function pointers with `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` for the
  owning socket. The actual overlapped `AcceptEx`/`ConnectEx` submission,
  context update, cancellation, and `mcr-net` readiness integration remain in
  this task.
- Added the first real `ConnectEx` host submission boundary. `HostSocket`
  can submit a bound, IOCP-associated socket through the resolved `ConnectEx`
  function pointer, keep the `OVERLAPPED` state alive, complete from a matching
  IOCP packet, and apply `SO_UPDATE_CONNECT_CONTEXT`. Wiring this into
  `mcr-net::HostSocketHandle::connect_fast_path` remains in this task.
- Wired `ConnectEx` into the Windows `mcr-net` host transport. New sockets are
  opened with a per-socket IOCP when available, nonblocking TCP connect submits
  `ConnectEx`, readiness draining consumes the matching IOCP packet, and the
  existing Linux `Connecting` -> `Connected` state machine completes through the
  `Connect` readiness class. Plain connect remains the fallback.
- Added the real `AcceptEx` host submission boundary. `HostSocket` can submit
  an IOCP-associated listener through the resolved `AcceptEx` function pointer,
  keep the accepted socket, address buffer, and `OVERLAPPED` state alive, cancel
  unfinished accepts on drop, complete from a matching IOCP packet, and apply
  `SO_UPDATE_ACCEPT_CONTEXT`. Wiring this into `mcr-net` accept readiness
  remains in this task.
- Wired `AcceptEx` into the Windows `mcr-net` host transport. Listening TCP
  sockets submit `AcceptEx` on the nonblocking accept path, readiness draining
  consumes the matching IOCP packet, stores the accepted host socket, and reports
  the normal Linux `Accept` readiness class before registering the accepted
  guest socket. Plain accept remains the fallback.
- Closed as implemented. Targeted verification covered `mcr-win` `AcceptEx` and
  `ConnectEx`, `mcr-net` `AcceptEx` and `ConnectEx`, and runtime accept/connect
  syscall tests.
