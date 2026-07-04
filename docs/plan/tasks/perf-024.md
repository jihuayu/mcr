---
id: perf-024
scope: performance
status: pending
depends-on: [perf-016, perf-017, perf-018, perf-020, perf-021, perf-022, perf-023]
---

# perf-024: Promote Performance Baselines To Regression Gates

## Objective

Convert selected release-mode performance baselines into enforceable regression
gates with stored before/after evidence for shell startup, file I/O,
directory metadata, socket latency/throughput, `curl`, `git ls-remote`, shallow
clone, native patching, and intrinsic replacement.

## Context

- `docs/architecture/performance.md`
- `docs/development/README.md`
- `docs/plan/tasks/perf-001.md`
- `docs/plan/tasks/perf-015.md`

## Path

- `crates/mcr-testkit/`
- `crates/mcr-runtime/`
- `crates/mcr-vfs/`
- `crates/mcr-net/`
- `.github/workflows/x86-runtime-smoke.yml`
- `docs/architecture/performance.md`
- `docs/development/README.md`
- `docs/plan/tasks/perf-024.md`

## Verification

```powershell
cargo test -p mcr-testkit perf_baseline -- --ignored --nocapture
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
cargo test -p mcr-vfs perf_baseline -- --ignored --nocapture
cargo test -p mcr-net perf_baseline -- --ignored --nocapture
gh workflow run x86-runtime-smoke.yml -f suite=performance
```

## Notes

- Gates must run in release mode for guest workloads.
- Thresholds must include enough environment metadata to distinguish runtime
  regressions from public-network or runner variance.
- Start with local command-specific gates before requiring centralized trend
  storage.

## Checkpoints

- Added opt-in wall-time regression gates to the `mcr-testkit` guest workload
  baseline. Setting `MCR_PERF_ENFORCE_GATES=1` enforces stored local thresholds
  for shell startup, small-file I/O, and directory metadata; public-network
  `curl` and `git ls-remote` thresholds are enforced only when
  `MCR_PERF_ENFORCE_PUBLIC_NETWORK=1` is also set. Each workload can be
  overridden with `MCR_PERF_MAX_WALL_MS_<WORKLOAD_NAME>`.
- Added an ignored host-only libc intrinsic dispatch baseline. It exercises the
  runtime `GuestLibcIntrinsic` dispatch contract for `memcpy`, `memchr`,
  `memcmp`, `memset`, and `strlen`, emits normal `mcr_perf_baseline` output, and
  participates in `MCR_PERF_ENFORCE_GATES=1` through
  `MCR_PERF_MAX_WALL_MS_LIBC_INTRINSIC_DISPATCH`.
