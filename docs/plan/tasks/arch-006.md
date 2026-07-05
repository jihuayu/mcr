---
id: arch-006
scope: architecture
status: ready
depends-on: [perf-019]
---

# arch-006: Move Host Worker Pool Below Subsystem Policy

## Objective

Move the bounded host worker pool executor out of `mcr-task` into `mcr-win`
so `mcr-net` no longer depends on `mcr-task`, keeping host thread capability
below Linux subsystem policy.

## Context

- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/architecture/performance.md` (Worker Pools)

## Path

- `crates/mcr-win/`
- `crates/mcr-task/`
- `crates/mcr-net/`
- `crates/mcr-runtime/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
```

## Notes

- Today `mcr-net/src/win_transport.rs` imports
  `HostWorkerPoolExecutor`/`HostWorkerPoolConfig`/`HostWorkerPoolRole` from
  `mcr-task` only to wait on IOCP completions; worker threads are host
  capability, not guest task semantics.
- `mcr-task` keeps guest-facing scheduling policy and pool role configuration
  semantics that are genuinely task-model state; the executor mechanism moves
  down.
- Remove the `mcr-task` dependency from `crates/mcr-net/Cargo.toml` and keep
  the dependency graph acyclic: `mcr-net -> mcr-win` only.
- Pool diagnostics counters must remain visible through the existing runtime
  diagnostics shape.
