---
id: build-002
scope: phase3-build
status: pending
depends-on: [build-001, snapshot-001]
---

# build-002: Apply Build Context And Metadata Instructions

## Objective

Implement build context loading, basic `.dockerignore`, `ARG`, `ENV`, `WORKDIR`, `COPY`, and local-file `ADD` application against `mcr-snapshot`.

## Context

- `docs/architecture/build.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-build/`
- `crates/mcr-snapshot/`
- `tests/fixtures/build/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-build
cargo test -p mcr-snapshot
```

## Notes

- `COPY` and `ADD` must not escape the build context.
- Preserve deterministic file ordering and metadata sidecar behavior.
- Remote URL `ADD` and tar auto-extract remain unsupported.
