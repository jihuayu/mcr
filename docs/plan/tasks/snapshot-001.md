---
id: snapshot-001
scope: phase3-snapshot
status: in-progress
depends-on: [workload-001]
---

# snapshot-001: Add Build Snapshot Model

## Objective

Create the `mcr-snapshot` crate with snapshot IDs, lower layer references, writable upper roots, metadata sidecar records, and deterministic snapshot view APIs.

## Context

- `docs/architecture/build.md`
- `docs/architecture/runtime.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `Cargo.toml`
- `crates/mcr-snapshot/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-snapshot
```

## Notes

- A snapshot is explicit build state, not only a host directory.
- Linux mode, uid, gid, symlink, hardlink, and timestamp metadata must have a stable representation even when the host filesystem cannot represent them directly.
- Do not implement diff export in this task.
- Initial checkpoint: added the `mcr-snapshot` crate with snapshot IDs, lower
  layer references, writable upper root records, Linux metadata sidecar records,
  and deterministic path-ordered snapshot views. Diff export remains separate in
  `snapshot-002`.
