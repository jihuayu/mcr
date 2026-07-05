---
id: arch-002
scope: architecture
status: pending
depends-on: [arch-001]
---

# arch-002: Split RuntimeSubsystems Into Cohesive State Groups

## Objective

Replace the `RuntimeSubsystems` god-object (20+ unrelated fields) with
cohesive state groups: a per-process table (memory, fd tables, pending
fork-exec), native-execution state (patch caches, floating-point state,
image patch maps), and event state (futex, epoll, signal alt stacks).

## Context

- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/architecture/runtime.md`

## Path

- `crates/mcr-runtime/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
```

## Notes

- Current shape: `crates/mcr-runtime/src/subsystems/mod.rs` mixes task,
  memory, fd, futex, epoll, native patch, and perf state in one struct.
- Pure structural refactor: no syscall behavior change, no new locks, no
  scheduling change. Existing tests must pass unchanged.
- Group boundaries should anticipate `arch-003` (per-process context
  ownership) so process-scoped state lands in one place.
- Do not fold subsystem business logic moves into this task; that is tracked
  separately (`arch-004`, `arch-007`).
