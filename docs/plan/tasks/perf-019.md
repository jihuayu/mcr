---
id: perf-019
scope: task-performance
status: ready
depends-on: [perf-011, perf-015]
---

# perf-019: Route Runtime And Network Work Through Worker Pools

## Objective

Use the bounded host worker-pool contract for real runtime guest task work and
network/I/O completion work without breaking guest wait, exit, cancellation,
teardown, or diagnostics behavior.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/networking.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-011.md`

## Path

- `crates/mcr-task/`
- `crates/mcr-runtime/`
- `crates/mcr-net/`
- `crates/mcr-win/`
- `crates/mcr-testkit/`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-019.md`

## Verification

```powershell
cargo test -p mcr-task worker_pool -- --nocapture
cargo test -p mcr-runtime task_ wait_ poll epoll -- --nocapture
cargo test -p mcr-net readiness -- --nocapture
cargo test -p mcr-testkit perf_worker_pool -- --ignored --nocapture
```

## Notes

- Pool routing must be bounded and observable through diagnostics.
- Cancellation and shutdown must drain queued and active work deterministically.
- Guest process/thread IDs remain MCR state; host worker identity must not leak
  into guest-visible APIs.

## Checkpoints

- Added a real bounded `HostWorkerPoolExecutor` next to the existing diagnostic
  boundary. It starts a fixed worker set per role, accepts `Send + 'static`
  jobs through a capacity-limited queue, reports active/queued/submitted/
  completed/rejected counts through `HostWorkerPoolDiagnostics`, catches job
  panics so counters are drained, and joins workers on explicit shutdown or
  drop.
