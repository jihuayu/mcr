---
id: perf-007
scope: network-performance
status: pending
depends-on: [perf-006]
---

# perf-007: Add AcceptEx And ConnectEx Fast Paths

## Objective

Add `AcceptEx` and `ConnectEx` paths on top of the IOCP socket backend to reduce
accept/connect round trips while preserving Linux socket state, address queries,
nonblocking connect behavior, and `SO_ERROR` completion semantics.

## Context

- `docs/architecture/networking.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-net/`
- `crates/mcr-win/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo test -p mcr-net acceptex connectex -- --nocapture
cargo test -p mcr-runtime socket_connect socket_accept -- --nocapture
cargo test -p mcr-testkit perf_connect -- --ignored --nocapture
```

## Notes

- Successful `AcceptEx` completions must apply `SO_UPDATE_ACCEPT_CONTEXT` before
  guest-visible address or option queries.
- Successful `ConnectEx` completions must apply `SO_UPDATE_CONNECT_CONTEXT` and
  still drive the Linux nonblocking connect state machine.
- Keep plain accept/connect fallback paths for unsupported sockets.
