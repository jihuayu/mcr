---
id: task-001
scope: task
status: done
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
- `arch_prctl` support is limited to `ARCH_SET_FS` and `ARCH_GET_FS` for per-task guest FS-base state. Other operations must return explicit Linux-compatible errors.
- Guest FS-base state must be visible to guest execution; host Rust TLS or host thread-local APIs cannot stand in for guest TLS semantics.
- Full child process behavior belongs to `task-002`.
