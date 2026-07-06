---
id: task-004
scope: task
status: done
depends-on: [task-003, workload-001]
---

# task-004: Deliver Pending Signals At Return-To-User

## Objective

Replace the current signal-skeleton behavior with a unified return-to-user
signal delivery path. `kill`, `tkill`, `tgkill`, native guest faults, and
unblocked pending signals must enqueue Linux signals and deliver them before a
task resumes guest execution.

## Context

- `docs/architecture/runtime.md`
- `docs/plan/backlog.md`
- `docs/plan/tasks/task-003.md`
- `docs/plan/tasks/workload-001.md`

## Path

- `crates/mcr-task/`
- `crates/mcr-runtime/`
- `crates/mcr-sys/`
- `crates/mcr-testkit/`
- `docs/plan/backlog.md`
- `docs/plan/tasks/task-004.md`

## Verification

```powershell
cargo test -p mcr-task --lib -- --test-threads=1
cargo test -p mcr-runtime --lib -- --test-threads=1
cargo test -p mcr-testkit --test extended_support_smoke_contract extended_support_smoke_contract_nodejs_run -- --ignored --nocapture --test-threads=1
```

## Notes

- Signal dispositions are process-shared; signal masks and thread-pending
  queues are per task.
- Thread-pending signals from `tkill`/`tgkill` take precedence over
  process-pending signals and can only be delivered to the target task.
- Fatal default actions for `SIGABRT`, `SIGSEGV`, `SIGILL`, `SIGBUS`, and
  `SIGFPE` must terminate the guest process instead of allowing guest code to
  continue into V8/Node `hlt` abort instructions.
- Handler delivery must build an `rt_sigframe`, update the guest registers,
  honor `SA_RESTORER`, `SA_NODEFER`, `SA_ONSTACK`, and restore state through
  `rt_sigreturn`.
- Blocking waits only need enough restart semantics for current workloads in
  this task; deeper wait/futex restructuring belongs to `task-005`.
