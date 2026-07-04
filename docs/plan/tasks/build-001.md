---
id: build-001
scope: phase3-build
status: done
depends-on: [workload-001]
---

# build-001: Add Native Build CLI And Dockerfile Plan Model

## Objective

Create the `mcr-build` crate and add a `mcr build` CLI entrypoint that parses the supported Dockerfile subset into a typed build plan without executing steps.

## Context

- `docs/architecture/build.md`
- `docs/architecture/README.md`
- `docs/development/README.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `Cargo.toml`
- `crates/mcr-cli/`
- `crates/mcr-build/`
- `tests/fixtures/build/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-build
cargo test -p mcr-cli
```

## Notes

- Supported instructions are `FROM`, `ARG`, `ENV`, `WORKDIR`, `COPY`, local `ADD`, `RUN`, `CMD`, and `ENTRYPOINT`.
- Unsupported instructions must fail with a typed error naming the instruction and subset boundary.
- This task must not pull images, mutate snapshots, or run commands.
- Initial checkpoint: added the `mcr-build` crate with a typed Dockerfile plan
  parser for the supported subset plus `mcr build [--file <Dockerfile>]
  <context>` CLI parsing. The CLI parses and reports instruction count only; it
  does not pull images, mutate snapshots, or execute build steps.
- 2026-07-04: verified complete for the parser and CLI plan boundary. Build
  context application and execution remain tracked by later build tasks.
