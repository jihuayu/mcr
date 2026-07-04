---
id: perf-015
scope: product-performance
status: done
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

## Checkpoints

- Added `MCR_TRACE_PERF_SUMMARY=1`, which reports wall time, guest syscall
  count, scheduler enter/sleep/no-runnable counts, same-pid and cross-pid
  switches, remap count and latency distribution, clone/exec counts,
  clone-to-exec time, pipe I/O counts, fd wakeups, poll/select/wait/futex
  counts, and fork-like syscall shape.
- Added `MCR_SCHED_STICKY=1`, so the scheduler keeps running the current guest
  task while it remains runnable and only rotates when the task blocks, exits,
  yields, or another explicit wait boundary requires a handoff.
- Added narrow spawn-path fixes needed by the measured workload: clone3
  fork-like exec support, vfork child-stack handling, opt-in
  `MCR_UNSAFE_SHARE_UNTIL_EXEC=1`, and guest futex wait scheduling.
- Verified 2026-07-04 on current `main` with:

```powershell
cargo fmt --check
cargo test -p mcr-sys maps_linux_x86_64_syscall_numbers
cargo test -p mcr-task -- --test-threads=1
cargo test -p mcr-runtime -- --test-threads=1
cargo build --release -p mcr-cli
$env:MCR_TRACE_PERF_SUMMARY='1'
$env:MCR_SCHED_STICKY='1'
target\release\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /bin/sh -c "GIT_TERMINAL_PROMPT=0 git ls-remote https://github.com/octocat/Hello-World.git HEAD >/dev/null"
$env:MCR_BIN='target\release\mcr.exe'
$env:MCR_PERF_PUBLIC_NETWORK='1'
cargo test -p mcr-testkit --test perf_baseline perf_baseline_guest_smoke_workloads -- --ignored --nocapture
```

- Direct release `git ls-remote` returned exit `0`; host-observed wall time was
  `3341.323ms`. The runtime summary reported `2173ms`, `9568` guest syscalls,
  `0` scheduler sleeps, `30` PID switches, `29` remaps, `276470us` total remap
  time, `6567` pipe reads, `184` pipe writes, and `19` fd wakeups.
- Release public-network baseline with `MCR_SCHED_STICKY=1`: shell startup
  `167.507ms`, guest small-file loop `1430.149ms`, directory metadata walk
  `3800.368ms`, `curl https://example.com` `485.074ms`, and `git ls-remote`
  `1872.576ms`.
- 2026-07-04 follow-up: sticky scheduling is now the default runtime policy,
  because the release public-network gate regressed to the scheduler latency
  cliff when the environment variable was omitted. Set `MCR_SCHED_STICKY=0`
  only for differential fairness/debug comparisons.
