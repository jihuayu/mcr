---
id: perf-016
scope: io-performance
status: ready
depends-on: [perf-003, perf-015]
---

# perf-016: Implement Real Overlapped File And Pipe Backend

## Objective

Replace the file/pipe synchronous fallback with a real Windows overlapped I/O
backend where handle type and host support allow it, while preserving guest
`read`, `write`, blocking, nonblocking, timeout, interruption, and close
semantics.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-003.md`

## Path

- `crates/mcr-win/`
- `crates/mcr-vfs/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-016.md`

## Verification

```powershell
cargo test -p mcr-win overlapped -- --nocapture
cargo test -p mcr-vfs pipe file -- --nocapture
cargo test -p mcr-runtime io_ pipe poll epoll -- --nocapture
cargo test -p mcr-testkit perf_file_io -- --ignored --nocapture
```

## Notes

- Keep the existing synchronous fallback for unsupported file kinds, Windows
  versions, and failure cases.
- Completion buffers and host records must outlive completion, cancellation, and
  close-drain paths.
- Runtime readiness must be event driven; do not add timer polling as the normal
  overlapped completion path.
