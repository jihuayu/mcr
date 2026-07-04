---
id: perf-015
scope: product-performance
status: ready
depends-on: [perf-001, perf-010, perf-013, integ-003]
---

# perf-015: Prove Shell And Network Metadata Performance Viability

## Objective

Turn the current public-network baseline into a product viability gate for
shell and network metadata workloads. Classify why `git ls-remote` is orders of
magnitude slower than host execution, fix the dominant runtime handoff cost, and
record before/after release measurements.

## Context

- `docs/product/README.md`
- `docs/development/README.md`
- `docs/architecture/performance.md`
- `docs/plan/backlog.md`
- `docs/plan/tasks/perf-001.md`
- `docs/plan/tasks/perf-010.md`
- `docs/plan/tasks/perf-013.md`

## Path

- `crates/mcr-runtime/`
- `crates/mcr-task/`
- `crates/mcr-sys/`
- `crates/mcr-vfs/`
- `crates/mcr-testkit/`
- `docs/architecture/performance.md`
- `docs/development/README.md`
- `docs/plan/tasks/perf-015.md`

## Verification

```powershell
cargo fmt --check
cargo test -p mcr-sys maps_linux_x86_64_syscall_numbers
cargo test -p mcr-task -- --test-threads=1
cargo test -p mcr-runtime -- --test-threads=1
cargo build --release -p mcr-cli
$env:MCR_TRACE_PERF_SUMMARY='1'
target\release\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /bin/sh -c "GIT_TERMINAL_PROMPT=0 git ls-remote https://github.com/octocat/Hello-World.git HEAD >/dev/null"
$env:MCR_BIN='target\release\mcr.exe'
$env:MCR_PERF_PUBLIC_NETWORK='1'
cargo test -p mcr-testkit --test perf_baseline perf_baseline_guest_smoke_workloads -- --ignored --nocapture
```

## Notes

- Current `main` public-network baseline: `curl https://example.com` about
  `1947ms`; `git ls-remote https://github.com/octocat/Hello-World.git HEAD`
  about `114131ms`. This is too slow to treat as a late backend optimization.
- Start with an opt-in summary trace that records wall time, guest syscall
  count, same-pid and cross-pid switches, remap count and total/p50/p95 time,
  scheduler sleep and no-runnable counts, clone-to-exec time, pipe
  read/write/wakeup counts, and poll/select/wait/futex counts.
- Prioritize the measured dominant cost in scheduler handoff, address-space
  remap, clone/exec, or pipe IPC before broad IOCP or regular-file backend
  rewrites.
- The first accepted result must include release before/after measurements for
  `git ls-remote`; microbenchmarks alone are not sufficient.
- Unsafe shortcuts must stay narrow and opt-in. Sharing fork/vfork memory until
  exec is a candidate experiment; globally sharing guest virtual address space
  across execed processes is not an accepted design.
