---
id: perf-029
scope: syscall-performance
status: ready
depends-on: [perf-025]
---

# perf-029: Native Trap And Dispatch Constant Overhead

## Objective

Remove fixed per-syscall and per-execution-slice host costs: install the
native-execution vectored exception handler once per process, index the
syscall dispatch table by number, cache epoll interest lists, and batch
poll/select socket readiness into one host poll where semantics allow.

## Context

- `docs/architecture/performance.md` (Hot-Path Constant-Cost Debt, Fast
  Syscalls, Caches And Reuse)
- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)

## Path

- `crates/mcr-win/`
- `crates/mcr-sys/`
- `crates/mcr-runtime/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
```

## Notes

- `execute_x86_64_until_trap` calls `AddVectoredExceptionHandler` and
  `RemoveVectoredExceptionHandler` on every guest execution slice
  (`crates/mcr-win/src/native_exec.rs`), so every syscall round trip mutates
  the process-global handler chain. Install the handler once for the process
  lifetime; the handler already filters on the active thread and state, so
  guest fault semantics stay unchanged.
- `syscall_descriptor` linearly scans the 212-entry `SYSCALL_DISPATCH_TABLE`
  for every syscall (`crates/mcr-sys/src/dispatcher.rs`). Build a
  direct-indexed static array keyed by syscall number; the table remains the
  source of truth for number, name, argument, trace, and unsupported behavior.
- `epoll_wait` clones the full watch map into a Vec on every call
  (`crates/mcr-runtime/src/subsystems/event.rs`); cache the interest list and
  bump a generation on `epoll_ctl` mutations.
- `poll`/`select` check each socket fd's readiness individually, which can
  issue one host poll per fd; aggregate socket fds into a single `WSAPoll`
  call per invocation where the level-trigger contract allows.
- No guest-visible behavior change is allowed; the runtime syscall baseline
  and `mcr_perf_baseline` gates are the measurement.
- Completed 2026-07-05: the `mcr-sys`/`mcr-win` checkpoint is implemented.
  `syscall_descriptor_by_number` now direct-indexes a static descriptor index
  built from `SYSCALL_DISPATCH_TABLE`, and Windows native execution installs
  the VEH once per process while retaining the active-thread/state filter.
  Runtime epoll interest-list caching and poll/select batching remain in
  scope for a later checkpoint.
