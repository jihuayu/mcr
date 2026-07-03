# Repository Guidelines

## Project Structure & Module Organization

This is a Rust 2024 workspace for a userspace Linux ABI runtime. Workspace crates live under `crates/`: `mcr-cli` provides the `mcr` binary, `mcr-runtime` wires sessions, `mcr-elf` loads ELF files, `mcr-jit` handles syscall interception, `mcr-sys` owns ABI/syscall dispatch, `mcr-vfs`, `mcr-task`, `mcr-net`, and `mcr-win` own subsystem behavior, and `mcr-testkit` owns smoke-test helpers. Integration fixtures live in `tests/fixtures`, with golden output in `tests/fixtures/golden`. Design and task planning live in `docs/architecture`, `docs/development`, and `docs/plan/tasks`.

## Build, Test, and Development Commands

- `cargo build --workspace`: build all crates.
- `cargo build -p mcr-cli`: build the local `mcr` executable.
- `cargo ci-fmt`: run `cargo fmt --check` via `.cargo/config.toml`.
- `cargo ci-clippy`: run Clippy across all targets with warnings denied.
- `cargo ci-test`: run the full workspace test suite.
- `python3 scripts/materialize-alpine-rootfs.py --force`: refresh the Alpine rootfs fixture for ignored smoke tests.

## Coding Style & Naming Conventions

Use standard `rustfmt` formatting and Rust 2024 idioms. Keep module and file names in `snake_case`; crate names use the existing `mcr-*` pattern. Workspace lints forbid unsafe code except in `mcr-win`, where host-adapter unsafe blocks must stay narrow and documented by clear wrapper boundaries. Model guest-visible Linux semantics explicitly; do not leak host paths, handles, or IDs into guest-facing APIs.

## Testing Guidelines

Place unit tests near the code they cover and crate-level integration tests under each crate's `tests/` directory. Smoke contracts and golden assertions belong in `mcr-testkit` and `tests/fixtures`. Normal validation is `cargo ci-fmt`, `cargo ci-clippy`, and `cargo ci-test`. Ignored shell and network smokes require a materialized rootfs and `MCR_BIN`, for example: `MCR_BIN=target/debug/mcr cargo test -p mcr-testkit -- --ignored shell_smoke_contract`.

## Commit & Pull Request Guidelines

History uses Conventional Commits such as `docs(net-002): record readiness gate` and `ci(runtime): add x86 smoke workflow`. Keep commits narrowly scoped to one completed task, stage only related files, and update design docs when behavior or contracts change. Pull requests should describe the task, list validation commands and results, link relevant `docs/plan/tasks/*` files or issues, and include screenshots only for user-visible output changes.

## Agent-Specific Instructions

Before non-trivial implementation, split work into reviewable checkpoints and commit each completed checkpoint before starting the next. Do not combine unrelated tasks or revert user changes. Keep progress messages minimal and actionable.
