---
id: perf-012
scope: jit-performance
status: pending
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
cargo test -p mcr-jit
cargo test -p mcr-runtime native_patch_cache native_execution -- --nocapture
cargo test -p mcr-testkit perf_native_execution -- --ignored --nocapture
```

## Notes

- Cache invalidation must honor `mprotect`, executable mapping changes, `munmap`,
  and private writable mappings.
- Same-ISA paths must preserve guest FS-base/TLS behavior and crash diagnostics.
- Do not add a broad x86 interpreter for non-x86 hosts.
