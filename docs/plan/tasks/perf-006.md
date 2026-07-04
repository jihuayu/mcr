---
id: perf-006
scope: network-performance
status: done
depends-on: [perf-001, net-002]
---

# perf-006: Close IOCP Socket Readiness Boundary

## Objective

Close the first IOCP network checkpoint by establishing the safe readiness
boundary that a later Windows completion backend can feed. This checkpoint does
not enable real IOCP sockets. It keeps the semantic Winsock/`WSAPoll` path as
the correctness backend while `mcr-win` and `mcr-net` expose completion classes,
generation-bearing readiness tokens, stale-token filtering, and cached
readiness handoff for `select`, `poll`, and `epoll`.

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
cargo test -p mcr-net readiness -- --nocapture
git diff --check
```

## Notes

- IOCP remains a host backend, not the guest-visible epoll model.
- This task is done as the safe readiness boundary only. It does not claim that
  real `CreateIoCompletionPort` registration, overlapped socket ownership,
  worker draining, cancellation/drain lifecycle, or performance smoke coverage
  exists.
- The real Windows IOCP backend is deferred to `docs/plan/backlog.md` behind a
  measurement gate and must preserve fd generation checks, close wakeups,
  timeout behavior, Linux errno mapping, and the `WSAPoll` fallback comparison.

## Checkpoints

- 2026-07-04: Added the IOCP-readiness seam without replacing the current
  Winsock path. `mcr-win` now defines host socket completion classes and their
  readiness-bit mapping. `mcr-net` assigns generation-bearing readiness tokens
  to host socket handles, drains completion notifications into a readiness
  cache, ignores stale-token completions, and falls back to `WSAPoll` when no
  completion-backed readiness is available. The full IOCP backend, overlapped
  operation ownership, cancellation/drain lifecycle, and ignored testkit
  performance smoke remain follow-up work.
- 2026-07-04 closeout: Closed as safe readiness boundary complete. Real Windows
  IOCP backend work is deferred to backlog and must reopen with overlapped
  ownership, IOCP registration, worker draining, cancellation, differential
  fallback tests, and measurement evidence.
