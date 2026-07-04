---
id: perf-020
scope: network-performance
status: pending
depends-on: [perf-006, perf-019]
---

# perf-020: Implement Windows IOCP Socket Backend

## Objective

Implement a real Windows IOCP socket backend behind the existing readiness-token
boundary, preserving Linux `select`, `poll`, and level-trigger `epoll`
readiness semantics while reducing high-concurrency socket overhead.

## Context

- `docs/architecture/networking.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-006.md`
- `docs/plan/tasks/perf-019.md`

## Path

- `crates/mcr-win/`
- `crates/mcr-net/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `docs/architecture/networking.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-020.md`

## Verification

```powershell
cargo test -p mcr-win iocp -- --nocapture
cargo test -p mcr-net readiness iocp -- --nocapture
cargo test -p mcr-runtime socket poll epoll -- --nocapture
cargo test -p mcr-testkit perf_baseline -- --ignored --nocapture
```

## Notes

- IOCP remains a host backend, not a new guest-visible eventing model.
- Preserve fd generation checks, close wakeups, timeout behavior, and Linux errno
  mapping.
- Keep the WSAPoll fallback for unsupported sockets, unsupported host versions,
  and differential testing.

## Checkpoints

- Added the first `mcr-win` IOCP host boundary: `HostIoCompletionPort` can
  create a Windows completion port, associate host handles internally, post
  synthetic completion packets, and poll/wait for packets with timeout mapping.
  Non-Windows builds report explicit unsupported errors, so higher layers can
  retain the WSAPoll fallback while socket integration is added.
- Added the Winsock socket lifetime precondition for the real backend:
  `NetworkStack::open_socket_with_iocp` creates a `WSA_FLAG_OVERLAPPED` socket
  and associates it with a host completion port under an MCR-owned completion
  key. The existing `open_socket`/`WSAPoll` path remains the fallback until
  overlapped `WSARecv`/`WSASend` ownership and readiness-drain integration land.
