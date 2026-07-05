---
id: arch-001
scope: architecture
status: ready
depends-on: [mem-001]
---

# arch-001: Extract Guest Memory Manager Into mcr-memory

## Objective

Move the guest memory manager (`GuestMemory`, VMA model, mmap/mprotect/brk,
COW clone strategies, and memory access traits) out of `mcr-runtime` into a
new `mcr-memory` crate so runtime returns toward lifecycle and wiring.

## Context

- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/architecture/runtime.md`

## Path

- `crates/mcr-memory/` (new)
- `crates/mcr-runtime/`
- `Cargo.toml`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
```

## Notes

- Source modules: `crates/mcr-runtime/src/memory.rs` and
  `crates/mcr-runtime/src/access.rs` plus their unit tests.
- This is a mechanical extraction: no guest-visible mmap/brk/mprotect behavior
  change, no new features. Existing runtime memory tests move with the code.
- `mcr-runtime` keeps only thin syscall routing into the extracted manager.
- Update the workspace module map in `docs/architecture/README.md` when the
  crate lands.
