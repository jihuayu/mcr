---
id: perf-023
scope: jit-performance
status: done
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

## Checkpoints

- Added runtime-owned guest-memory intrinsic primitives for `memset`,
  overlap-safe `memmove`, `memchr`, and bounded `strlen`. They reuse the normal
  guest memory access checks, so unmapped ranges and read/write permissions keep
  returning the same Linux-facing memory errors. Native symbol/patch dispatch is
  still the remaining replacement step.
- Added the runtime intrinsic dispatch contract for already-identified libc
  targets. `GuestLibcIntrinsic` executes SysV register-shaped arguments for
  `memcpy`, `memmove`, `memset`, `memchr`, `memcmp`, and bounded `strlen`,
  preserves guest memory checks, returns ABI-shaped values, and rejects
  overlapping `memcpy` instead of silently applying `memmove` semantics. Loader
  dynsym/PLT target discovery remains separate from this safe execution
  boundary.
- Added a libc symbol-name classifier for unversioned and glibc-versioned names
  (`name`, `name@VERSION`, and `name@@VERSION`) so future native patch or loader
  discovery can map resolved targets to the safe dispatch contract without
  duplicating string matching.
- Added the native trap dispatch side of libc intrinsic replacement. Runtime can
  register a process-local intrinsic target, patch the target entry with the
  same native trap shape used by syscall patches, execute the safe
  `GuestLibcIntrinsic` contract from SysV argument registers, pop the guest
  return address, and resume the caller with ABI-shaped `rax`. Automatic dynsym
  / PLT discovery is still the remaining target-identification step.
- Closed 2026-07-04: executable file-backed `mmap` in native mode now scans
  ELF64 `.dynsym` entries, classifies hot libc memory/string symbols, computes
  the mapped object load bias from `PT_LOAD`, and registers process-local trap
  patches when the symbol lands inside the executable mapping. Invalid,
  unsupported, or oversized ELF files skip replacement and keep normal mmap
  semantics. Targeted verification covers symbol parsing, automatic mmap patch
  registration, native trap dispatch, and the ignored intrinsic baseline.
