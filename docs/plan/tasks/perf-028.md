---
id: perf-028
scope: vfs-performance
status: ready
depends-on: [perf-002]
---

# perf-028: Per-Inode VFS Cache Invalidation And Directory Index

## Objective

Make VFS cache invalidation per-inode instead of global, index directory
children instead of scanning the whole path table, cache host file handles,
and stop materializing deferred host-backed files on read-only access.

## Context

- `docs/architecture/performance.md` (Hot-Path Constant-Cost Debt, Metadata
  And Directory Caches, Rootfs Startup)
- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/plan/tasks/perf-002.md`

## Path

- `crates/mcr-vfs/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
cargo test -p mcr-vfs perf_baseline -- --ignored --nocapture
cargo test -p mcr-testkit --test perf_baseline perf_baseline_guest_smoke_workloads -- --ignored --nocapture
```

## Notes

- Any successful regular-file write of more than zero bytes calls
  `invalidate_all()` and clears every metadata, directory-listing, and
  small-read cache entry (`crates/mcr-vfs/src/filesystem.rs`,
  `crates/mcr-vfs/src/cache.rs`). Mixed read/write workloads (git writing
  objects while reading config, package managers) get almost no cache value.
  Move to per-inode generations plus targeted parent-directory listing
  invalidation; keep global invalidation only for structural changes such as
  mounts, rename exchanges, and raw `tree_mut` escapes.
- `static_children` iterates every path in the filesystem to list one
  directory (`crates/mcr-vfs/src/path.rs`), making `getdents64` O(total
  files). Add per-directory child maps; an ordered prefix range scan over the
  existing `BTreeMap<GuestPath, InodeId>` is an acceptable transition step.
- `read_host_file_at` opens and closes the host file on every read
  (`crates/mcr-vfs/src/io_helpers.rs`); add a bounded per-inode host handle
  cache with invalidation on unlink/rename/truncate.
- `materialize_deferred_content` reads the entire file into a resident
  `Vec<u8>` on first read (`crates/mcr-vfs/src/path.rs`), so reading one byte
  of a large rootfs binary pins the whole file in memory. Read-only access to
  deferred files should pass through offset reads against the host path and
  materialize only on write or truncate, matching the documented rootfs
  copy-on-write semantics.
- Linux-visible inode identity, readdir ordering, metadata, and unlink/rename
  semantics must not change; the existing VFS and guest small-file/directory
  baselines are the measurement.
