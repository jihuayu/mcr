---
id: buildkit-003
scope: phase4-buildkit
status: pending
depends-on: [buildkit-002]
---

# buildkit-003: Deliver BuildKit Buildctl Smoke

## Objective

Run the supported Dockerfile fixture matrix through BuildKit using the MCR worker and export OCI output with `buildctl`.

## Context

- `docs/product/README.md`
- `docs/architecture/build.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-build/`
- `crates/mcr-image/`
- `crates/mcr-snapshot/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `buildkit/`
- `tests/fixtures/build/`
- `docs/plan/backlog.md`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
buildctl --addr npipe:////./pipe/mcr-buildkit build --frontend dockerfile.v0 --local context=tests/fixtures/build/single-stage --local dockerfile=tests/fixtures/build/single-stage --output type=oci,dest=out-single.tar
buildctl --addr npipe:////./pipe/mcr-buildkit build --frontend dockerfile.v0 --local context=tests/fixtures/build/multistage --local dockerfile=tests/fixtures/build/multistage --output type=oci,dest=out-multistage.tar
```

## Notes

- Compare supported fixture outputs with native `mcr build` outputs, allowing only documented metadata differences.
- Record unsupported BuildKit features in backlog with the BuildKit operation and intended error.
- Docker Engine API compatibility remains outside this task.
