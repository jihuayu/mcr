---
id: perf-027
scope: runtime-performance
status: done
depends-on: [perf-015]
---

# perf-027: Constant-Time Scheduler Iterations And Event-Driven Fd Wakeups

## Objective

Remove the per-iteration full fd-table clones and O(all-tasks) scans from the
scheduler loop, and wake fd-blocked tasks through readiness events recorded at
the mutation site instead of re-polling every waiter on every iteration.

## Context

- `docs/architecture/performance.md` (Hot-Path Constant-Cost Debt)
- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/plan/tasks/arch-003.md`

## Path

- `crates/mcr-runtime/`
- `crates/mcr-task/`
- `crates/mcr-vfs/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
```

## Notes

- `resume_fd_waiters` clones the selected process `FdTable` plus the entire
  `process_fds` map on every scheduler iteration
  (`crates/mcr-runtime/src/subsystems/task.rs`). A `git ls-remote` run does
  thousands of pipe-blocked iterations, each paying a full deep clone. The
  first checkpoint is a split-borrow refactor that drops both clones without
  changing wakeup semantics; it must not wait for the rest of this task.
- `runnable_tids()` and `resume_waiting_tasks()` scan all tasks and allocate a
  fresh Vec per iteration (`crates/mcr-task/src/kernel/wait.rs`); maintain an
  incrementally updated runnable queue and a waiting-task index keyed by what
  each task waits on.
- Pipe writes and closes already notify per-node condvars
  (`crates/mcr-vfs/src/node.rs`), but the scheduler never consumes those
  events. Register `(pid, fd, direction)` waiters with the owning subsystem
  and mark them ready at the mutation site (pipe write/close, socket
  completion, fd close), so the scheduler consumes a ready set instead of
  polling every blocked task each iteration.
- Guest-visible blocking, poll/select/epoll, EINTR, and fd-lifetime semantics
  must not change. Coordinate ownership moves with `arch-003` per-process
  state so the waiter registry is not rebuilt twice.
- Record before/after `MCR_TRACE_PERF_SUMMARY=1` runs for the shell pipeline
  and `git ls-remote` workloads per the promoted-performance-task rules.

## Result

- `GuestKernel` now maintains runnable, child-wait, fd-wait, and futex-wait
  indexes as task states change, so scheduler readiness queries no longer scan
  every task.
- Runtime fd waiter resume now uses split borrows over selected and parked
  process fd tables instead of cloning fd tables on each scheduler iteration.
