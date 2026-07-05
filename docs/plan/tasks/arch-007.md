---
id: arch-007
scope: architecture
status: done
depends-on: [arch-002]
---

# arch-007: Consolidate Native Patch Pipeline Behind mcr-jit

## Objective

Move native patch scanning, plan derivation, persistent metadata caching, and
patch application out of `mcr-runtime` so the instruction-analysis and
code-patching pipeline lives behind one `mcr-jit` boundary, with runtime
keeping only per-process cache wiring and policy toggles.

## Context

- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/architecture/performance.md` (Caches And Reuse)
- `docs/architecture/runtime.md`

## Path

- `crates/mcr-jit/`
- `crates/mcr-runtime/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
```

## Notes

- Today `crates/mcr-runtime/src/native_patch.rs` (~1.5k lines) owns scan
  ranges, syscall/FS-TLS patch candidates, persistent metadata load/store, and
  batched patch writes, while calling `mcr_jit::syscall_instruction_sites` for
  the actual instruction analysis. Two crates co-own one pipeline.
- Preserve the perf-012 behaviors exactly: `0f 05` prefilter before decode,
  single range read for syscall and TLS plans, zero-FS candidate recording
  without materialization, incremental candidate materialization, and batched
  patch writes per host allocation.
- Guest-visible trap behavior, native fault diagnostics, and patch cache hit
  semantics must not change; this is an ownership move, not a redesign.
- Persistent cache file format may stay as-is; document it where it lands.

## Result

- Native patch scan/metadata/key/cache primitives now live in
  `mcr-jit::native_patch`; runtime keeps process cache orchestration, memory
  access, worker-pool fallback, and host-step trace policy.
- Persistent cache format remains version 2 and is documented next to the
  `mcr-jit` cache constants.
