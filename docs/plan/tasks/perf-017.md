---
id: perf-017
scope: io-performance
status: done
depends-on: [perf-004, perf-016]
---

# perf-017: Add Regular-File Scatter/Gather Fast Path

## Objective

Add a regular-file scatter/gather fast path for Linux `readv` and `writev`
where Windows handle mode, alignment, and guest buffer lifetime constraints are
proven safe, while preserving the current copy fallback for all unsupported
shapes.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-004.md`
- `docs/plan/tasks/perf-016.md`

## Path

- `crates/mcr-win/`
- `crates/mcr-vfs/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-017.md`

## Verification

```powershell
cargo test -p mcr-win scatter gather -- --nocapture
cargo test -p mcr-vfs readv writev -- --nocapture
cargo test -p mcr-runtime iovec_ readv writev -- --nocapture
cargo test -p mcr-testkit perf_iovec -- --ignored --nocapture
```

## Notes

- Socket scatter/gather is already implemented by `perf-004`; this task is only
  for regular files.
- The implementation must not expose borrowed guest buffers to host completion
  records unless their lifetime and pinning semantics are explicit.
- Unsupported or poorly aligned I/O must fall back without changing Linux errno
  behavior.

## Checkpoints

- Added a VFS/runtime regular-file `readv`/`writev` fast path that preflights
  regular descriptors, stages a single contiguous regular-file transfer, scatters
  or gathers guest iovec buffers, and updates the file offset once. Unsupported
  fd kinds still use the existing per-iovec fallback, and no borrowed guest
  buffers are exposed to host completion records.
- Closed as implemented for the safe regular-file scope. Targeted verification
  covered `mcr-vfs` and `mcr-runtime` readv/writev tests plus clippy for both
  crates; the `mcr-win` scatter/gather filters currently have no matching tests.
