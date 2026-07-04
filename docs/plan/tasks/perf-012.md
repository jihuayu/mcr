---
id: perf-012
scope: jit-performance
status: done
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
- Post-cache validation: after the FS-relative patch apply checkpoint, local
  package-rootfs `node -v` and `cargo --version` no longer time out in native
  patch application. They return guest runtime errors from native execution
  faults at null address instead (`node`: RIP `0x700357c6`; `cargo`: RIP
  `0x7006680a`), so follow-up work should diagnose the faulting native
  instruction/register state rather than patch-cache throughput.
- 2026-07-04 checkpoint: native fault reporting now includes the faulting
  instruction bytes, a decoded instruction summary, and the guest FS base beside
  the existing register and stack snapshot. Rerunning package rootfs checks
  shows the next blocker is unmaterialized FS-relative TLS loads whose guest
  FS bases are above the current fixed-width absolute rewrite range: `node -v`
  faulted on `64 48 8b 04 25 28 00 00 00` (`mov rax, fs:[0x28]`) at RIP
  `0x700000751bd6` with FS base `0x700000277c90`; `cargo --version` faulted on
  `64 48 8b 04 25 00 00 00 00` (`mov rax, fs:[0]`) at RIP `0x7006680a` with
  FS base `0x700010ba1140`.
- 2026-07-04 closure: the native cache/range work for this task is complete:
  executable scan filtering, single-read syscall and FS/TLS patch planning,
  zero-FS no-op skip, unchanged-base new-candidate materialization, and batched
  fixed-width patch writes are implemented. The remaining Node/Cargo package
  workload blocker is outside cache throughput: high-address guest FS-base TLS
  loads cannot be represented by the current fixed-width absolute rewrite, so
  `workload-001` and the backlog track the native execution or JIT fallback
  boundary for those accesses.
