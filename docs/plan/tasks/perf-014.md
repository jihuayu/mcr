---
id: perf-014
scope: jit-performance
status: blocked
depends-on: [perf-012]
---

# perf-014: Evaluate Libc Intrinsic Replacement

## Objective

Evaluate replacing safe, pure libc routines such as `memcpy`, `memset`,
`memchr`, `memcmp`, and `strlen` with host implementations when the runtime can
identify the target and preserve guest memory, overlap, and fault semantics.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-jit/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `docs/plan/backlog.md`

## Verification

```powershell
cargo test -p mcr-jit libc_intrinsic -- --nocapture
cargo test -p mcr-runtime guest_memory_fault -- --nocapture
cargo test -p mcr-testkit perf_libc_intrinsic -- --ignored --nocapture
```

## Notes

- This remains blocked until native block caching is stable and measurements show
  string or memory routines are a material hotspot.
- Replacement must preserve overlap behavior and guest memory fault reporting.
- If symbol identification is fragile for static or stripped binaries, document
  the limitation and leave the optimization disabled by default.
