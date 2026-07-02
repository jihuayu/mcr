---
id: task-003
scope: task
status: pending
depends-on: [task-002, win-001]
---

# task-003: Implement Signals Skeleton And Private Futex

## Objective

Implement Phase 2 signal and synchronization support: `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `kill`, `tgkill`, `set_tid_address`, `set_robust_list`, and process-private futex `WAIT`/`WAKE`.

## Context

- `docs/architecture/runtime.md`

## Path

- `crates/mcr-task/`
- `crates/mcr-sys/`
- `crates/mcr-runtime/`
- `crates/mcr-win/`

## Verification

```powershell
cargo test -p mcr-task
cargo test -p mcr-sys
```

## Notes

- Futex must check the guest memory value before sleeping and handle timeout/interruption.
- Process-shared futex must return explicit unsupported behavior.
