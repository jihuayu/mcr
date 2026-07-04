---
id: perf-013
scope: syscall-performance
status: pending
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
cargo test -p mcr-testkit perf_syscall_fast_path -- --ignored --nocapture
```

## Notes

- Initial candidates are `getpid`, `gettid`, selected clock queries, `uname`,
  and other compatibility queries backed entirely by MCR-owned state.
- Preserve structured trace events or document any reduced trace mode as an
  explicit diagnostic tradeoff.
- I/O syscalls may get lighter decode helpers later, but still need safe guest
  memory copy-in/copy-out and subsystem routing.
