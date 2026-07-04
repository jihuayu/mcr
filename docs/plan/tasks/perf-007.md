---
id: perf-007
scope: network-performance
status: done
depends-on: [perf-006]
---

# perf-007: Close AcceptEx And ConnectEx Fast-Path Boundary

## Objective

Close the first `AcceptEx`/`ConnectEx` checkpoint by defining the adapter
contract over the readiness-token seam. This checkpoint does not bind to the
real Winsock extension functions. It lets host handles report unsupported,
pending, or completed fast-path work while `mcr-net` keeps plain accept/connect
fallbacks, Linux socket state, address queries, nonblocking connect behavior,
and `SO_ERROR` completion semantics.

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
cargo test -p mcr-net acceptex -- --nocapture
cargo test -p mcr-net connectex -- --nocapture
git diff --check
```

## Notes

- Successful `AcceptEx` completions must apply `SO_UPDATE_ACCEPT_CONTEXT` before
  guest-visible address or option queries.
- Successful `ConnectEx` completions must apply `SO_UPDATE_CONNECT_CONTEXT` and
  still drive the Linux nonblocking connect state machine.
- Keep plain accept/connect fallback paths for unsupported sockets.
- This task is done as the safe fast-path boundary only. Real Windows extension
  lookup, overlapped buffer ownership, context update calls, cancellation, and
  performance smoke coverage are deferred to `docs/plan/backlog.md` behind the
  IOCP backend lifetime model and measurement gate.

## Checkpoints

- 2026-07-04: Added the fast-path adapter contract over the existing
  readiness-token seam without replacing the plain Winsock fallback. `mcr-win`
  now names `AcceptEx`/`ConnectEx` fast-path kinds and their completion classes.
  `mcr-net` host handles can report unsupported, pending, or completed
  accept/connect fast paths; pending operations feed `Accept`/`Connect`
  completions into the readiness cache while Linux accept/connect state and
  `SO_ERROR` completion semantics stay in `mcr-net`. Real Windows extension
  function lookup, overlapped ownership, context update calls, cancellation, and
  performance smoke remain follow-up work.
- 2026-07-04 closeout: Closed as safe fast-path boundary complete. Real
  `AcceptEx`/`ConnectEx` backend work is deferred to backlog and must reopen
  with Windows extension lookup, overlapped ownership, context updates,
  cancellation, differential fallback tests, and measurement evidence.
