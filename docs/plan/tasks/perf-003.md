---
id: perf-003
scope: io-performance
status: pending
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
