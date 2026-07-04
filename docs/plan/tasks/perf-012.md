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
- 2026-07-04 checkpoint: Windows FS-relative TLS candidates are now recorded
  without materializing no-op rewrites when the guest FS base is zero, and
  unchanged nonzero bases only materialize newly discovered executable-range
  candidates. Real FS-base transitions still rewrite the full candidate set so
  syscall patching and TLS semantics remain intact. Fixed-width code patching
  is also batched by host allocation to avoid per-candidate protection toggles
  when large Node or Rust executable ranges need thousands of rewrites.
- Remaining blocker: after the FS-relative patch apply checkpoint, local
  package-rootfs `node -v` and `cargo --version` no longer time out in native
  patch application. They return guest runtime errors from native execution
  faults at null address instead (`node`: RIP `0x700357c6`; `cargo`: RIP
  `0x7006680a`), so follow-up work should diagnose the faulting native
  instruction/register state rather than patch-cache throughput.
