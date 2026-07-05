---
id: arch-005
scope: architecture
status: ready
depends-on: [abi-001]
---

# arch-005: Unify Linux Errno Mapping In mcr-sys

## Objective

Make `mcr-sys` the single owner of Linux errno values and of the shared
host-error-to-errno mapping, replacing the two independent mappings maintained
in `mcr-vfs` and `mcr-net`.

## Context

- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/architecture/runtime.md`
- `docs/architecture/networking.md`

## Path

- `crates/mcr-sys/`
- `crates/mcr-vfs/`
- `crates/mcr-net/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
```

## Notes

- Duplication today: `mcr-vfs` maps `VfsError::linux_errno()` with hand-written
  numeric values while `mcr-net` owns its own `LinuxErrno` enum plus
  `host_error_errno()` for `HostErrorKind` conversion. The two can drift.
- Subsystems keep their domain error enums; only errno numbering and the
  shared `HostErrorKind -> errno` table move to `mcr-sys`.
- `mcr-win` continues to return platform-neutral host errors and never assigns
  Linux errno; this task does not move policy below the adapter boundary.
- Add a differential test asserting the unified mapping matches the previous
  per-crate mappings for every covered `HostErrorKind`.
