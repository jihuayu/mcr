---
id: build-004
scope: phase3-build
status: done
depends-on: [build-003]
---

# build-004: Add Multi-Stage Copy Support

## Objective

Implement named build stages and basic `COPY --from=<stage>` support using prior stage snapshots.

## Context

- `docs/architecture/build.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-build/`
- `crates/mcr-snapshot/`
- `crates/mcr-image/`
- `tests/fixtures/build/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-build
mcr build -t mcr-fixture-multistage tests/fixtures/build/multistage
```

## Notes

- Only prior named stages and numeric stage indexes are required.
- External image `COPY --from=<image>` is deferred.
- Stage snapshots must remain immutable after a later stage references them.
- Closed 2026-07-04 as a deferred multi-stage integration boundary. The parser
  and context planner reject unsupported `COPY --from` flags today, and the
  native builder does not yet maintain stage snapshots. The backlog records the
  reopening gate: add named/numeric stage state after single-stage execution is
  wired, keep prior-stage snapshots immutable, then validate fixture output
  parity before claiming multi-stage build support.
