---
id: perf-021
scope: network-performance
status: pending
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
