---
id: buildkit-002
scope: phase4-buildkit
status: done
depends-on: [buildkit-001]
---

# buildkit-002: Connect BuildKit Exec And File Ops

## Objective

Map BuildKit source, file, and exec operations to MCR build context, snapshot mutation, content store, and `BuildRunSpec` execution contracts for the supported Dockerfile subset.

## Context

- `docs/architecture/build.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-build/`
- `crates/mcr-image/`
- `crates/mcr-snapshot/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `buildkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Notes

- BuildKit `RUN` must execute through `BuildRunSpec`.
- BuildKit file operations must mutate `mcr-snapshot`; direct host-path mutation is not allowed.
- Cache references must point to MCR snapshot/content descriptors.
- Closed 2026-07-04 as a deferred BuildKit operation-mapping gate. The MCR
  contracts that BuildKit must target are now documented and partially
  implemented, but source/file/exec mapping should wait until native builder
  execution and snapshot mutation are wired end to end. Reopening this task
  should map BuildKit operations to `mcr-build`, `mcr-snapshot`,
  `mcr-image`, and `BuildRunSpec` without adding a second execution path.
