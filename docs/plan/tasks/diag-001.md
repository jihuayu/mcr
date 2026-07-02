---
id: diag-001
scope: diagnostics
status: pending
depends-on: [sys-001, elf-002, jit-001]
---

# diag-001: Add Runtime Diagnostics And Crash Reports

## Objective

Implement structured syscall tracing and guest crash diagnostics with guest registers, VMAs, executable path, argv, and last syscall.

## Context

- `docs/architecture/runtime.md`
- `docs/development/README.md`

## Path

- `crates/mcr-runtime/`
- `crates/mcr-sys/`
- `crates/mcr-jit/`
- `crates/mcr-cli/`

## Verification

```powershell
cargo test -p mcr-runtime
cargo test -p mcr-sys
```

## Notes

- Diagnostics must avoid exposing host handles as guest-visible identifiers.
- Include at least one synthetic crash test.
