---
id: boot-001
scope: bootstrap
status: in-progress
depends-on: []
---

# boot-001: Initialize Rust Workspace

## Objective

Create the Rust workspace, crate skeletons, formatting/lint configuration, and minimal CI-ready test command structure required by the runtime plan.

## Context

- `docs/INDEX.md`
- `docs/development/README.md`
- `docs/architecture/README.md`

## Path

- `Cargo.toml`
- `crates/`
- `.gitignore`
- `.cargo/`
- `.github/workflows/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Notes

- Crates should compile with empty or placeholder APIs only where later tasks will fill contracts.
- Do not implement runtime behavior in this task.
