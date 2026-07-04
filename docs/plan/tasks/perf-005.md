---
id: perf-005
scope: memory-performance
status: pending
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
cargo test -p mcr-testkit perf_mmap -- --ignored --nocapture
```

## Notes

- Preserve guest VMA permissions, zero-fill behavior, and private writable
  mapping semantics.
- Shared read-only mapping reuse must not leak host paths or handles into
  guest-visible diagnostics.
- Include an exec-heavy benchmark that shows repeated dynamic image startup
  before and after the change.
