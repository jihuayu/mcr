---
id: perf-013
scope: syscall-performance
status: done
depends-on: [perf-001, sys-001]
---

# perf-013: Add Simple Syscall Fast Paths

## Objective

Add fast dispatcher paths for small, frequent syscalls with no guest memory side
effects, reducing trampoline-to-dispatch overhead while preserving tracing,
diagnostics, and Linux ABI return behavior.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-sys/`
- `crates/mcr-runtime/`
- `crates/mcr-jit/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo test -p mcr-sys
cargo test -p mcr-runtime getpid gettid clock -- --nocapture
cargo test -p mcr-runtime perf_baseline_runtime_syscall_and_process_paths -- --ignored --nocapture
```

## Notes

- 2026-07-04 checkpoint: `getpid` and `gettid` now use a no-memory-side-effect
  dispatcher fast path in `mcr-sys`/`mcr-runtime`, with the same enter/exit trace
  event shape and `SyscallReturn` Linux ABI encoding as the regular path.
- Initial candidates are `getpid`, `gettid`, selected clock queries, `uname`,
  and other compatibility queries backed entirely by MCR-owned state.
- Preserve structured trace events or document any reduced trace mode as an
  explicit diagnostic tradeoff.
- I/O syscalls may get lighter decode helpers later, but still need safe guest
  memory copy-in/copy-out and subsystem routing.
- Remaining candidates such as `uname` and clock queries that copy structures
  into guest memory stay on the regular dispatcher path until their memory
  semantics have focused coverage.
- Completed 2026-07-04: the committed fast path remains intentionally narrow to
  `getpid`/`gettid`, with runtime coverage proving trace and return-value
  parity. Clock and structure-copying candidates stay on the regular dispatcher
  until their guest-memory semantics have focused coverage; the committed
  ignored runtime baseline covers synthetic getpid dispatch timing.
