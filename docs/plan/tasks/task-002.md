---
id: task-002
scope: task
status: done
depends-on: [elf-003, fd-001]
---

# task-002: Implement Fork-Exec-Wait Shell Path

## Objective

Implement guest child process lifecycle for common shell execution: `fork`/`vfork` fast path into `execve`, child exit state, `wait4`, file descriptor inheritance, and close-on-exec behavior.

## Context

- `docs/architecture/runtime.md`
- `docs/product/README.md`

## Path

- `crates/mcr-task/`
- `crates/mcr-runtime/`
- `crates/mcr-sys/`
- `crates/mcr-vfs/`
- `crates/mcr-elf/`

## Verification

```powershell
cargo test -p mcr-task
cargo test -p mcr-runtime
```

## Notes

- Optimize and validate the fork-then-immediate-exec path.
- Full memory-copying `fork` without exec remains deferred unless a Phase 2 smoke command requires a constrained implementation.
