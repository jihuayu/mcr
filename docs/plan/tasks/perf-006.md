---
id: perf-006
scope: network-performance
status: pending
depends-on: [perf-001, net-002]
---

# perf-006: Add IOCP Socket Backend Behind Readiness

## Objective

Add an IOCP-backed Winsock implementation that registers overlapped sockets,
drains completion batches, updates MCR socket state, and feeds the existing
level-trigger readiness queue used by `select`, `poll`, and `epoll`.

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
cargo test -p mcr-net iocp readiness -- --nocapture
cargo test -p mcr-runtime epoll_ poll_ -- --nocapture
cargo test -p mcr-testkit perf_network_iocp -- --ignored --nocapture
gh workflow run x86-runtime-smoke.yml -f suite=network
```

## Notes

- IOCP is a host backend, not the guest-visible epoll model.
- Completions must preserve fd generation checks, close wakeups, timeout
  behavior, and Linux errno mapping.
- Keep the semantic WSAPoll/select backend as an A/B comparison and fallback.
