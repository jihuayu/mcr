---
id: perf-023
scope: jit-performance
status: ready
depends-on: [perf-012, perf-014, perf-015]
---

# perf-023: Implement Libc Intrinsic Replacement

## Objective

Replace measured hot libc memory/string routines such as `memcpy`, `memset`,
`memchr`, `memcmp`, and `strlen` with host-assisted implementations only when
target identification, guest memory validation, fault reporting, and overlap
semantics match the Linux-visible contract.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-014.md`

## Path

- `crates/mcr-jit/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-023.md`

## Verification

```powershell
cargo test -p mcr-jit libc_intrinsic -- --nocapture
cargo test -p mcr-runtime guest_memory_fault native -- --nocapture
cargo test -p mcr-testkit perf_libc_intrinsic -- --ignored --nocapture
```

## Notes

- Replacement requires measurement evidence; do not add speculative rewrites
  for routines that are not hot in ignored performance baselines.
- Faulting guest memory must still report the same guest-visible failure shape
  as native/JIT execution.
- Overlap semantics must match the specific target routine, especially
  `memcpy` versus `memmove`-like behavior.
