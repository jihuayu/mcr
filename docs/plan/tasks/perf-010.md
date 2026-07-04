---
id: perf-010
scope: task-performance
status: pending
depends-on: [perf-001, task-002]
---

# perf-010: Optimize Fork-Exec And Spawn Fast Path

## Objective

Optimize the common guest `fork`/`vfork` followed by immediate `execve` path so
shell command startup avoids unnecessary parent memory copies while preserving
guest PID/TID, wait state, fd inheritance, close-on-exec, and exec failure
behavior.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-task/`
- `crates/mcr-runtime/`
- `crates/mcr-sys/`
- `crates/mcr-vfs/`
- `crates/mcr-elf/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo test -p mcr-task
cargo test -p mcr-runtime fork exec wait4 -- --nocapture
cargo test -p mcr-testkit perf_fork_exec -- --ignored --nocapture
```

## Notes

- The fast path must fall back to the existing semantic path when the child can
  observe divergent parent memory before exec.
- Preserve `execve` error behavior: failed exec must report to the child path
  with Linux-compatible errno and not corrupt parent state.
- Treat `posix_spawn`-like behavior as the same direct-exec optimization when it
  is represented by supported guest syscalls.
