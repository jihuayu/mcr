---
id: snapshot-002
scope: phase3-snapshot
status: pending
depends-on: [snapshot-001]
---

# snapshot-002: Export Deterministic Layer Diffs

## Objective

Implement snapshot diff walking and OCI layer tar generation with deterministic ordering, Linux metadata, deletions, and OCI whiteouts.

## Context

- `docs/architecture/build.md`
- `docs/architecture/runtime.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-snapshot/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-snapshot
```

## Notes

- File deletions from lower layers emit `.wh.<name>`.
- Opaque directory behavior emits `.wh..wh..opq`.
- Tests must cover rename-over-existing, deleted lower files, symlink entries, hardlink entries where supported, and repeated export determinism.
