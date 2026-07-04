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
