---
id: perf-018
scope: memory-performance
status: done
depends-on: [perf-005, perf-012, perf-015]
---

# perf-018: Implement Host-Backed Mapping And COW Page Reuse

## Objective

Move beyond immutable payload caching by adding host-backed executable/read-only
mapping reuse and copy-on-write page reuse where Linux VMA permissions,
`mprotect`, EOF zero-fill, private writable mappings, and invalidation semantics
are proven together.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-005.md`
- `docs/plan/tasks/perf-012.md`

## Path

- `crates/mcr-runtime/src/memory.rs`
- `crates/mcr-runtime/src/lib.rs`
- `crates/mcr-vfs/`
- `crates/mcr-win/`
- `crates/mcr-testkit/`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-018.md`

## Verification

```powershell
cargo test -p mcr-runtime file_backed mmap mprotect clone native_patch -- --nocapture
cargo test -p mcr-vfs cache metadata -- --nocapture
cargo test -p mcr-testkit perf_baseline -- --ignored --nocapture
```

## Notes

- Guest VMA identity and permissions remain runtime-owned; host paths and
  handles must not leak into guest-visible state.
- Private writable mappings must preserve Linux copy-on-write behavior and
  fault isolation between parent and child processes.
- Cache invalidation must include VFS generation changes, truncation, writes,
  metadata changes, and exec rematerialization.

## Checkpoints

- Added the first host-backed read-only file mapping primitive in `mcr-win`.
  `HostFile::map_readonly_at` returns `HostFileMapping`, which uses
  `CreateFileMappingW` / `MapViewOfFile` on Windows with allocation-granularity
  offset alignment and a non-Windows read-backed fallback. This is still a host
  adapter boundary; runtime VMA/COW integration remains in this task.
- VFS now exposes deferred host-file read-only mappings without materializing
  file contents into the in-memory tree, and runtime file-backed mmap population
  tries that host mapping path before falling back to `pread`. The guest VMA is
  still runtime-owned and copied into guest memory; page-level VMA/COW reuse is
  the remaining integration step.
- Runtime process-memory clones now reuse non-writable guest allocations by
  sharing their host allocation owner in flexible-address mode. The first
  write/protection mutation detaches the allocation into a private copy before
  updating bytes or host protections, so read-only executable/library pages can
  be reused across fork snapshots while writable mappings keep private process
  semantics.
- Closed 2026-07-04: shared read-only clone allocations now detach at guest
  page granularity when a write, `mprotect`, or native patch mutates a shared
  range in flexible-address mode. Untouched pages keep using the original host
  allocation, while fixed-address native memory keeps the conservative
  allocation-level copy path because those mappings must preserve guest VA
  placement. Targeted verification covered clone COW, `mprotect`, and native
  patch cache tests.
