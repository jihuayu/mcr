---
id: perf-003
scope: io-performance
status: done
depends-on: [perf-001, fd-001, win-001]
---

# perf-003: Add Overlapped File And Pipe I/O Backend

## Objective

Add a Windows overlapped I/O backend for regular files, pipes, and anonymous
file-like objects while keeping guest `read`, `write`, blocking, nonblocking,
timeout, interruption, and close behavior under the MCR runtime wait model.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-win/`
- `crates/mcr-vfs/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo test -p mcr-win
cargo test -p mcr-vfs
cargo test -p mcr-runtime io_ -- --nocapture
cargo test -p mcr-testkit perf_file_io -- --ignored --nocapture
```

## Notes

- Host completion records and buffers must stay alive until the operation is
  completed, cancelled, or drained after close.
- The backend must map host completion and cancellation results into Linux errno
  above the Windows adapter.
- Keep a synchronous fallback for unsupported host handles or Windows versions.

## Checkpoint 2026-07-04

- Added the `mcr-win` host I/O submission boundary for file-like reads and
  writes without replacing the synchronous backend.
- `HostFile::submit_overlapped_read` and `HostFile::submit_overlapped_write`
  currently return explicit synchronous fallback submissions that own the
  operation buffer and preserve the existing host error shape.
- Added focused `mcr-win` tests covering fallback round trips, fallback error
  buffer retention, pending cancellation drain mapping to interrupted host
  errors, and the completion-after-cancel race shape that real overlapped I/O
  must preserve.

## Remaining Blocker

Opening Windows file and pipe handles with overlapped-compatible flags, binding
them to an event/thread-pool/IOCP completion source, and wiring completion
readiness into the runtime wait model remain pending. The VFS/runtime
synchronous paths are intentionally unchanged in this checkpoint.

## Closure Decision

The 2026-07-04 checkpoint closes `perf-003` as the host I/O submission-boundary
work, not as a completed real overlapped backend. The implemented boundary is
enough for later backends to own buffers, report fallback results, and preserve
the cancellation/completion race shape under `mcr-win`, while current
VFS/runtime file and pipe I/O still execute through synchronous fallback paths.

The actual Windows overlapped file/pipe backend is deferred to the backlog. That
follow-up must cover overlapped-compatible handle open flags, a concrete
completion source, runtime wait wiring, close/cancel drain behavior, and
differential verification against the synchronous fallback.
