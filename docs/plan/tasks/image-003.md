---
id: image-003
scope: phase3-image
status: done
depends-on: [image-001, snapshot-002]
---

# image-003: Write OCI Layout And Docker Tar Exporters

## Objective

Implement image config, manifest, OCI image layout, and Docker-compatible tar export using descriptors and layer diffs produced by `mcr-image` and `mcr-snapshot`.

## Context

- `docs/architecture/build.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-image/`
- `crates/mcr-snapshot/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-image
cargo test -p mcr-snapshot
```

## Notes

- Include environment, working directory, entrypoint, command, history, rootfs diff IDs, and platform metadata.
- Output must be deterministic for identical inputs.
- External `docker load` validation belongs to `integ-004`.
- Initial config checkpoint: added deterministic hand-written OCI image config
  and manifest JSON serialization in `mcr-image`, covering platform metadata,
  environment, working directory, entrypoint, command, history, rootfs diff IDs,
  descriptor ordering, and annotation key ordering. OCI layout and
  Docker-compatible tar writers remain follow-up work.
- 2026-07-04 checkpoint: `LocalContentStore::write_oci_layout` now writes
  deterministic `oci-layout`, `index.json`, and manifest blobs after verifying
  referenced config and layer blobs.
- 2026-07-04 checkpoint: `LocalContentStore::docker_tar_bytes` and
  `write_docker_tar` now write deterministic Docker-compatible archives with
  `manifest.json`, the config JSON file, layer `layer.tar` entries in manifest
  order, and optional `repositories` tag metadata. External `docker load`
  validation remains covered by `integ-004`.
