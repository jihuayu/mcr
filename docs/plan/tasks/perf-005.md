---
id: perf-005
scope: memory-performance
status: done
depends-on: [perf-001, elf-003, vfs-004]
---

# perf-005: Optimize File-Backed Mapping Reuse

## Objective

Use host-backed mappings and lazy population for executable files, shared
libraries, and read-only data where this preserves MCR's guest VMA model and
Linux `mmap`, `munmap`, `mprotect`, and copy-on-write behavior.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-elf/`
- `crates/mcr-vfs/`
- `crates/mcr-runtime/`
- `crates/mcr-win/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo test -p mcr-elf
cargo test -p mcr-runtime mmap_ -- --nocapture
git diff --check
```

## Notes

- Preserve guest VMA permissions, zero-fill behavior, and private writable
  mapping semantics.
- Shared read-only mapping reuse must not leak host paths or handles into
  guest-visible diagnostics.
- This task is closed at the safe immutable private payload-cache boundary.
  Lower-level host-backed page mapping, copy-on-write page sharing, and
  exec-heavy before/after measurement are deferred to backlog work.

## Checkpoints

- 2026-07-04: Added a runtime file-backed mapping payload cache for immutable
  private mappings. Cache keys use `mcr-vfs` regular-file inode identity plus
  VFS generation, mapping offset, and requested length, so guest mutations move
  future lookups onto a new generation without exposing host paths or handles.
  The focused runtime mmap test proves read-only mappings reuse the cache while
  preserving VMA permissions, EOF zero-fill, isolated guest VMAs after
  `mprotect`, and uncached private writable mappings. Host-backed page mapping,
  copy-on-write page sharing, and the exec-heavy benchmark remain follow-up
  work.
- 2026-07-04: Closed `perf-005` as the safe payload-cache boundary. Reopen
  lower-level mapping work only when a host-backed page mapping or COW design can
  preserve guest VMA, `mprotect`, EOF zero-fill, and private-write semantics and
  includes exec-heavy benchmark evidence.
