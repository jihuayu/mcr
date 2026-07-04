---
id: perf-010
scope: task-performance
status: done
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

- 2026-07-04 checkpoint: `mcr-runtime` now creates fork-like child task and fd
  state immediately but defers the child memory clone while the child remains on
  the fork+exec path. A child `execve` can read its filename, argv, and envp
  from parent memory while the deferred snapshot invariant still holds and
  replace the child image directly; parent memory mutation, child pre-exec
  writes, child non-exec syscalls, or exec failure materialize the child memory
  first so the existing fork semantics are preserved.
- The checkpoint covers syscall-dispatch and same-ISA interpreted child startup
  paths. Native child execution that cannot be proven read-only still falls back
  to materializing child memory before continuing.
- The fast path must fall back to the existing semantic path when the child can
  observe divergent parent memory before exec.
- Preserve `execve` error behavior: failed exec must report to the child path
  with Linux-compatible errno and not corrupt parent state.
- Treat `posix_spawn`-like behavior as the same direct-exec optimization when it
  is represented by supported guest syscalls.
- Completed 2026-07-04: the deferred fork+exec runtime checkpoint now has
  focused fork, exec, and wait4 verification plus an ignored `mcr-testkit`
  `perf_fork_exec_baseline` that measures the guest shell startup path when
  `MCR_BIN` and a materialized Alpine rootfs are available.
