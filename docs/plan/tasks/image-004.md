---
id: image-004
scope: phase3-image
status: pending
depends-on: [image-003]
---

# image-004: Add Registry Push Round Trip

## Objective

Implement registry push for MCR-built images by uploading missing blobs before manifests, then add a pull/push round-trip test against a deterministic registry endpoint.

## Context

- `docs/architecture/build.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-image/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-image
```

## Notes

- Tests should prefer a local registry fixture or deterministic fake registry.
- Full credential helper support is deferred.
- Manifest push must happen after required blobs are present.
