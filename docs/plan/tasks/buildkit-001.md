---
id: buildkit-001
scope: phase4-buildkit
status: pending
depends-on: [integ-004]
---

# buildkit-001: Prototype BuildKit Worker Boundary

## Objective

Create the first BuildKit worker adapter boundary that advertises MCR worker capabilities and maps BuildKit lifecycle, cancellation, progress, and worker identity concepts onto MCR contracts without executing builds yet.

## Context

- `docs/architecture/build.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-build/`
- `crates/mcr-image/`
- `crates/mcr-snapshot/`
- `crates/mcr-testkit/`
- `buildkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Notes

- If BuildKit integration requires a Go sidecar to use BuildKit worker APIs, introduce it under `buildkit/` with an explicit Rust boundary contract.
- Do not duplicate MCR image, snapshot, or runtime execution semantics in the adapter.
- Unsupported capabilities must be advertised as unsupported, not silently ignored.
