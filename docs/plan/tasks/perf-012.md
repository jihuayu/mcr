---
id: perf-012
scope: jit-performance
status: in-progress
depends-on: [perf-001, jit-001]
---

# perf-012: Cache Native Blocks And Executable Ranges

## Objective

Expand native same-ISA execution caching so hot executable ranges and patched or
re-emitted basic blocks are reused across compatible guest tasks without
rescanning or retranslating immutable code.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-jit/`
- `crates/mcr-runtime/`
- `crates/mcr-elf/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo fmt --check
cargo test -p mcr-jit
cargo test -p mcr-runtime native_patch_cache -- --nocapture
cargo test -p mcr-runtime native_execution -- --nocapture
cargo test -p mcr-testkit perf_native_execution -- --ignored --nocapture
```

## Notes

- Cache invalidation must honor `mprotect`, executable mapping changes, `munmap`,
  and private writable mappings.
- Same-ISA paths must preserve guest FS-base/TLS behavior and crash diagnostics.
- Do not add a broad x86 interpreter for non-x86 hosts.
- 2026-07-04 checkpoint: native syscall patch discovery now filters for `0f 05`
  candidates before decoding, stops after the last candidate, and has the
  runtime derive syscall and Windows FS-relative patch plans from one read of
  each new executable range. This reduces first-dispatch work for large package
  binaries without changing the per-process invalidation boundary.
- Remaining blocker: rerun a bounded package-backed `node -v` or `go version`
  smoke with materialized language rootfs fixtures and capture whether the next
  stall is guest wait/futex, readiness, scheduling, or native execution.
