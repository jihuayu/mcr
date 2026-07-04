---
id: perf-014
scope: jit-performance
status: done
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
git diff --check
```

## Notes

- 2026-07-04 decision checkpoint: do not implement libc intrinsic replacement
  now. `perf-012` is still in progress, native block caching is not yet a
  stable foundation, and current package-rootfs diagnostics point at native
  execution faults and block-cache or patch-application behavior rather than
  measured libc string or memory routine hotspots.
- Keep this optimization in the backlog behind a measurement gate. Reopen only
  after `perf-012` stabilizes native block caching, an ignored perf benchmark
  shows `memcpy`, `memset`, `memchr`, `memcmp`, `strlen`, or adjacent libc
  string/memory routines are a material hotspot, and the implementation can
  prove Linux-visible guest memory fault reporting and overlap semantics.
- The risk remains high until target identification is robust for static and
  stripped binaries and replacement paths can preserve guest memory checks
  without hiding native faults.
- Future implementation validation should include:

```powershell
cargo test -p mcr-jit libc_intrinsic -- --nocapture
cargo test -p mcr-runtime guest_memory_fault -- --nocapture
cargo test -p mcr-testkit perf_libc_intrinsic -- --ignored --nocapture
```
