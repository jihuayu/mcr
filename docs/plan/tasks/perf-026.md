---
id: perf-026
scope: syscall-performance
status: ready
depends-on: [arch-001]
---

# perf-026: Zero-Copy Guest I/O Through Borrowed Guest Memory Slices

## Objective

Eliminate the per-call temporary buffer allocation and double copy in guest I/O
syscalls by letting subsystems borrow guest memory directly as host slices,
with the existing copy path as the cross-VMA fallback, and replace
byte-at-a-time guest C-string reads with VMA-bounded chunked scans.

## Context

- `docs/architecture/performance.md` (Hot-Path Constant-Cost Debt)
- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/plan/tasks/arch-001.md`

## Path

- `crates/mcr-memory/`
- `crates/mcr-runtime/`
- `crates/mcr-vfs/`
- `crates/mcr-net/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
cargo test -p mcr-vfs perf_baseline -- --ignored --nocapture
```

## Notes

- Today `sys_read`, `sys_write`, `sys_pread64`, `sys_readv`, `sys_writev`, and
  the readlink paths allocate `vec![0; len]` and copy
  guest -> Vec -> backend -> Vec -> guest on every call
  (`crates/mcr-runtime/src/filesystem.rs`). Guest memory is host memory inside
  the same process, so contiguous ranges need no intermediate buffer at all.
- Add safe borrow APIs in `mcr-memory` (for example
  `GuestMemory::slice(addr, len, AccessKind)` and `slice_mut`) that return a
  direct slice when the range is contiguous inside one VMA with the required
  protection, and `None` for cross-VMA ranges so callers fall back to the
  existing copy path. No `unsafe` is required: allocations are owned slices and
  the single-threaded guest execution model guarantees exclusive borrows.
- `read_c_string` performs one full VMA BTreeMap lookup per byte
  (`crates/mcr-memory/src/access.rs`); scan for the NUL terminator in
  VMA-bounded chunks so a path read costs one or two lookups.
- Guest-visible semantics must not change: EFAULT boundaries, protection
  checks, and partial-copy behavior must match the copy path exactly.
  Differential tests should cover ranges spanning VMA boundaries and
  protection edges.
- Socket send/recv and VFS read/write should accept borrowed slices without an
  intermediate Vec where the backend already takes `&[u8]`/`&mut [u8]`.
