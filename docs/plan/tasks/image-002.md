---
id: image-002
scope: phase3-image
status: pending
depends-on: [image-001, snapshot-001]
---

# image-002: Pull And Unpack Linux Amd64 Base Images

## Objective

Implement OCI registry pull for `linux/amd64` image references, platform manifest selection, digest verification, and base layer unpack into `mcr-snapshot`.

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

- Reject image indexes without a compatible `linux/amd64` manifest.
- Use deterministic fixture images or a local registry for tests.
- This task does not write final image outputs.
