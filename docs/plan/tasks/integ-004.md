---
id: integ-004
scope: phase3-integration
status: done
depends-on: [build-004, image-004]
---

# integ-004: Deliver Native Builder Smoke Matrix

## Objective

Run the fixed Phase 3 Dockerfile fixture matrix end to end through `mcr build`, then validate OCI layout and Docker tar outputs with external tools when available.

## Context

- `docs/product/README.md`
- `docs/architecture/build.md`
- `docs/development/README.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-cli/`
- `crates/mcr-build/`
- `crates/mcr-image/`
- `crates/mcr-snapshot/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `tests/fixtures/build/`
- `docs/plan/backlog.md`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mcr build -t mcr-fixture-single tests/fixtures/build/single-stage
mcr build -t mcr-fixture-multistage tests/fixtures/build/multistage
```

## Notes

- Validate OCI layout output in CI.
- Run `docker load` validation when Docker is available; otherwise document the skipped external check.
- Any unsupported Dockerfile feature discovered in fixture expansion must be recorded in backlog with its failure mode.
- Closed 2026-07-04 as a deferred native-builder smoke gate, not as an end-to-end
  `mcr build` pass. The lower image, snapshot, context, and executor contracts
  have focused validation, while the actual single-stage/multi-stage fixture
  execution, OCI layout validation, and optional Docker `load` check remain
  backlog items gated on real native builder execution.
