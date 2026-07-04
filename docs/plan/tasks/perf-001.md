---
id: perf-001
scope: performance
status: pending
depends-on: [workload-001]
---

# perf-001: Add Performance Baseline Harness

## Objective

Add repeatable performance baselines for syscall dispatch, small file I/O,
directory metadata walks, shell `fork+exec+wait4`, network smoke workloads, and
high-concurrency loopback sockets before changing performance backends.

## Context

- `docs/architecture/performance.md`
- `docs/development/README.md`

## Path

- `crates/mcr-testkit/`
- `crates/mcr-runtime/`
- `crates/mcr-vfs/`
- `crates/mcr-net/`
- `.github/workflows/x86-runtime-smoke.yml`
- `docs/architecture/performance.md`
- `docs/development/README.md`

## Verification

```powershell
cargo test -p mcr-testkit perf_baseline -- --ignored --nocapture
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
cargo test -p mcr-vfs perf_baseline -- --ignored --nocapture
cargo test -p mcr-net perf_baseline -- --ignored --nocapture
gh workflow run x86-runtime-smoke.yml -f suite=performance
```

## Notes

- Capture wall time, operation counts, and enough environment metadata to compare
  Windows local runs with the x86-64 smoke workflow.
- Include before/after reporting for `curl`, `git ls-remote`, and shell command
  startup paths.
- Do not tune subsystem code in this task except where required to expose
  measurements.
- Preparatory harness checkpoint: add ignored baseline suites for runtime
  syscall/process paths, VFS small-file and metadata walks, loopback sockets,
  and guest shell/network workloads. Keep this task `pending` until
  `workload-001` is done and the performance verification succeeds.
