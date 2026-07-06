---
id: task-005
scope: task
status: pending
depends-on: [task-004]
---

# task-005: Complete Interruptible Futex And Thread Exit Semantics

## Objective

Make futex waits, thread exit, and process exit-group behavior match the Linux
thread lifecycle used by pthreads, Node/V8 compiler threads, and shell
workloads. This task closes the `no runnable guest tasks remain` class where
tasks are stuck in futex join or exit cleanup after guest work has already
completed.

## Context

- `docs/architecture/runtime.md`
- `docs/plan/backlog.md`
- `docs/plan/tasks/task-004.md`

## Path

- `crates/mcr-task/`
- `crates/mcr-runtime/`
- `crates/mcr-sys/`
- `crates/mcr-testkit/`
- `docs/plan/backlog.md`
- `docs/plan/tasks/task-005.md`

## Verification

```powershell
cargo test -p mcr-task --lib -- --test-threads=1
cargo test -p mcr-runtime --lib -- --test-threads=1
cargo test -p mcr-testkit --test extended_support_smoke_contract extended_support_smoke_contract_nodejs_run -- --ignored --nocapture --test-threads=1
```

## Notes

- `exit` terminates the current thread; `exit_group` terminates the full guest
  process and wakes tasks that must run exit cleanup.
- Thread exit with `clear_child_tid` writes zero to guest memory and performs
  the matching private futex wake used by pthread join.
- Futex waits must be interruptible by deliverable signals and must return
  Linux-compatible `EINTR`, `ETIMEDOUT`, or `EAGAIN` behavior.
- Private futex keys are `(guest address-space identity, uaddr)`. Shared futex
  keys remain deferred and must fail intentionally until mapping identity is
  implemented.
- Scheduler diagnostics must distinguish normal all-threads-dead exit, valid
  blocked waits with wake sources, and true deadlock/stall cases.
