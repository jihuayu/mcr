---
id: perf-004
scope: io-performance
status: done
depends-on: [perf-001, fd-001, net-001]
---

# perf-004: Add Scatter/Gather I/O Fast Paths

## Objective

Use host vector I/O where safe for Linux `readv`, `writev`, `sendmsg`, and
`recvmsg`, reducing per-buffer host calls and extra copies while preserving
Linux iovec, message boundary, and ancillary-data behavior.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/networking.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-vfs/`
- `crates/mcr-net/`
- `crates/mcr-sys/`
- `crates/mcr-win/`
- `crates/mcr-runtime/`

## Verification

```powershell
cargo test -p mcr-vfs readv writev -- --nocapture
cargo test -p mcr-net sendmsg recvmsg -- --nocapture
cargo test -p mcr-runtime iovec_ -- --nocapture
cargo test -p mcr-testkit perf_iovec -- --ignored --nocapture
```

## Notes

- Socket paths should prefer `WSABUF` with `WSASend`, `WSARecv`, `WSASendMsg`,
  and `WSARecvMsg` where the semantics match.
- File scatter/gather paths must prove alignment, handle, and buffer-lifetime
  constraints before bypassing the existing copy fallback.
- Unsupported control messages remain whitelist-only and must fail intentionally.

## Checkpoints

- 2026-07-04: Added the `mcr-net` socket/message-vector boundary:
  `HostSocketHandle` now has vectored send/receive entry points for connected
  streams and addressed UDP datagrams, and `GuestSocketTable` exposes matching
  `sendmsg`/`recvmsg`-oriented helpers. Focused tests prove stream scatter/gather
  routing uses one vectored host entry point and UDP keeps a single datagram
  message. The current fallback still copies through a temporary buffer; direct
  Windows `WSABUF` wiring and runtime syscall use of the new helpers remain
  follow-up work.
- 2026-07-04: Closed as safe boundary complete. The committed scope preserves
  Linux iovec and message-boundary behavior behind the existing copy fallback,
  while direct host-vector execution is deferred until runtime syscall routing,
  Windows `WSABUF` socket adapters, and file scatter/gather alignment/lifetime
  gates are wired together.
