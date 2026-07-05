---
id: arch-003
scope: architecture
status: pending
depends-on: [arch-002]
---

# arch-003: Per-Process Context Ownership Without Memory Swap

## Objective

Eliminate the single "selected" process context so each guest process owns its
`GuestMemory` and fd table directly and scheduling switches references instead
of cloning, swapping, or remapping memory contents on every cross-process
switch.

## Context

- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/architecture/performance.md` (Performance-First Viability Gate)
- `docs/architecture/runtime.md`

## Path

- `crates/mcr-runtime/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
```

## Notes

- Current cost: `select_memory_for_process` clones the outgoing process
  memory via `try_clone_runtime()` and, in native mode,
  `select_native_memory_for_process` drops and remaps allocations at guest
  addresses on every switch. Pipe-heavy cross-process protocols (`git` with
  `git-remote-https`) pay this repeatedly; perf traces already show remap
  cost.
- Native fixed-address mode may still require exclusive commitment of one
  process's fixed mappings at a time; manage that as a narrow native-mode
  constraint instead of cloning in flexible mode.
- This is a performance-relevant architecture task: record before/after
  measurements for the shell pipeline and `git ls-remote` paths per the plan
  rules for promoted performance work.
- Guest-visible fork/exec/wait, fd inheritance, and close-on-exec semantics
  must not change.
