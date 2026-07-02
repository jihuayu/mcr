---
id: build-003
scope: phase3-build
status: pending
depends-on: [image-002, image-003, build-002, buildrun-001]
---

# build-003: Execute Native Dockerfile Build

## Objective

Connect `mcr build` to image resolution, snapshot mutation, `RUN` execution, layer diffing, and final OCI/Docker output for single-stage Dockerfiles.

## Context

- `docs/architecture/build.md`
- `docs/architecture/README.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-cli/`
- `crates/mcr-build/`
- `crates/mcr-image/`
- `crates/mcr-snapshot/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `tests/fixtures/build/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mcr build -t mcr-fixture-single tests/fixtures/build/single-stage
```

## Notes

- This task covers single-stage `FROM`, metadata instructions, `COPY`, and shell/exec form `RUN`.
- Build failures must include Dockerfile instruction index, stage, snapshot ID, and runtime trace ID for failed `RUN`.
- Multi-stage support remains in `build-004`.
