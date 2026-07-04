---
id: snapshot-002
scope: phase3-snapshot
status: done
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
- Initial checkpoint: added deterministic layer-entry planning in
  `mcr-snapshot` for filesystem entries, deleted-lower whiteouts, and opaque
  directory markers. Tar stream emission and content bytes remain follow-up
  work.
- 2026-07-04 checkpoint: added deterministic uncompressed tar export for the
  layer plan, including regular file content validation, Linux metadata,
  hardlinks, symlinks, devices, FIFOs, whiteouts, and opaque directory markers.
- 2026-07-04 completion: `SnapshotSpec::export_upper_layer_tar` now walks the
  deterministic layer plan, reads regular file content from the writable upper
  root, and emits the OCI layer tar stream used by image export checkpoints.
