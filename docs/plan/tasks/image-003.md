---
id: image-003
scope: phase3-image
status: pending
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
