---
id: image-004
scope: phase3-image
status: done
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
- Checkpoint 2026-07-04: `mcr-image` now has a registry push planner that validates
  config/layer media types, skips remote-present blobs, deduplicates repeated
  layer descriptors, and always orders the manifest upload after required blobs.
  A deterministic fake registry transport remains before marking this task done.
- Completed 2026-07-04: `LocalContentStore::push_to_registry` now queries a
  `RegistryPushTarget`, uploads only missing verified local blobs, and writes the
  manifest last. The deterministic fake registry test covers push ordering plus
  a pull-plan round trip over the pushed manifest and blobs.
