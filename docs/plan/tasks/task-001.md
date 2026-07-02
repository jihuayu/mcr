---
id: task-001
scope: task
status: ready
depends-on: [elf-002, sys-001, vfs-001]
---

# task-001: Implement MVP Guest Task Lifecycle

## Objective

Implement guest PID/TID allocation, initial process state, `getpid`, `gettid`, `exit`, `exit_group`, `uname`, `arch_prctl`, and minimal `execve` replacement for MVP.

## Context

- `docs/architecture/runtime.md`

## Path

- `crates/mcr-task/`
- `crates/mcr-runtime/`
- `crates/mcr-sys/`
- `crates/mcr-elf/`

## Verification

```powershell
cargo test -p mcr-task
cargo test -p mcr-runtime
```

## Notes

- `execve` should reload guest executable state and apply close-on-exec semantics.
- Full child process behavior belongs to `task-002`.
