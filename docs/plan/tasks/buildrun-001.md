---
id: buildrun-001
scope: phase3-build-executor
status: in-progress
depends-on: [workload-001, snapshot-001]
---

# buildrun-001: Expose Build RUN Executor

## Objective

Expose a build-oriented `BuildRunSpec` and `BuildRunResult` in `mcr-runtime` that executes shell and exec form `RUN` commands against a snapshot rootfs through the normal guest runtime path.

## Context

- `docs/architecture/build.md`
- `docs/architecture/runtime.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-runtime/`
- `crates/mcr-snapshot/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-runtime
cargo test -p mcr-testkit
```

## Notes

- Host shell execution is forbidden.
- Preserve exit code, stdout/stderr routing, trace ID, cwd, env, argv, and cancellation behavior.
- Shell form defaults to `/bin/sh -c` unless the image config later supplies a different shell.
- 2026-07-04 checkpoint: `mcr-runtime` now exposes `BuildRunSpec`,
  `BuildRunCommand`, and `BuildRunResult` as the build executor boundary. Shell
  form maps to guest `/bin/sh -c`, exec form preserves argv, env is passed
  deterministically into `run-rootfs`, and results preserve status,
  stdout/stderr, snapshot ID, and trace ID. Snapshot-rootfs mounting, working
  directory application, cancellation, and end-to-end `RUN` mutation remain
  follow-up work.
