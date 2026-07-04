---
id: perf-002
scope: vfs-performance
status: done
depends-on: [perf-001, vfs-004]
---

# perf-002: Cache VFS Metadata, Directory Iteration, And Small Reads

## Objective

Add VFS caches for Linux inode attributes, batched directory iteration, and
small immutable reads so repeated `statx`, `newfstatat`, `getdents64`, and
configuration-file reads avoid redundant host metadata and file I/O.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-vfs/`
- `crates/mcr-runtime/`
- `crates/mcr-win/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo test -p mcr-vfs
cargo test -p mcr-runtime vfs_ -- --nocapture
cargo test -p mcr-vfs perf_baseline_vfs_file_and_directory_paths -- --ignored --nocapture
```

## Notes

- Cache keys must use guest inode identity and VFS generation state, not raw host
  paths alone.
- Invalidate affected entries on write-open, unlink, rename, truncate,
  metadata-sidecar updates, and any syscall that can change visible attributes.
- Preserve Linux delete-while-open and directory iteration behavior.
- Initial checkpoint: `mcr-vfs` has an inode-and-generation keyed metadata cache
  and small regular-file read cache with generation invalidation on successful
  write opens, writes, truncates, link/path mutations, mount changes, and
  metadata updates.
- Directory-iteration checkpoint: `mcr-vfs` caches complete directory entry
  batches by directory inode and VFS generation, then consumes those batches
  through the existing per-fd directory cursor. Dynamic `/proc/self/fd` listings
  are intentionally uncached because they depend on the live fd table.
- Completed 2026-07-04: focused VFS/runtime verification and the ignored
  `mcr-vfs` VFS performance baseline passed. The original `mcr-testkit
  perf_vfs_cache` filter has no matching committed test; the committed baseline
  lives in `crates/mcr-vfs/tests/perf_baseline.rs`.
