---
id: perf-011
scope: task-performance
status: in-progress
depends-on: [perf-001, task-003, net-002]
---

# perf-011: Add Bounded Host Worker Pools

## Objective

Use bounded host worker pools for guest task execution and I/O completions so
high-concurrency workloads do not repeatedly create and destroy Windows threads.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-task/`
- `crates/mcr-runtime/`
- `crates/mcr-win/`
- `crates/mcr-net/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo test -p mcr-task
cargo test -p mcr-task perf_worker_pool -- --ignored --nocapture
cargo test -p mcr-runtime task_ wait_ -- --nocapture
cargo test -p mcr-net readiness -- --nocapture
cargo test -p mcr-testkit perf_worker_pool -- --ignored --nocapture
```

## Notes

- Worker pools need cancellation, teardown, and exit semantics compatible with
  guest wait and signal behavior.
- Do not introduce prestarted process workers in this task; that requires a
  separate design if MCR changes the one-host-process-per-container boundary.
- Pool sizing must be bounded and observable in diagnostics.

## Checkpoints

- Added the first diagnostics-visible boundary in `mcr-task`: bounded pool
  records for guest task execution and I/O completions, exposed through runtime
  diagnostics without changing guest scheduling or process semantics.
- Added ignored worker-pool diagnostics baseline reports under `mcr-task` and
  the `mcr-testkit perf_worker_pool` filter so the active perf gate captures
  diagnostics snapshot overhead before real submissions are routed through the
  boundary.
