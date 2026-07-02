---
id: testkit-002
scope: testkit
status: pending
depends-on: [testkit-001]
---

# testkit-002: Add Opt-In Network Smoke Contracts

## Objective

Add ignored or environment-gated `mcr-testkit` smoke contracts for public-network Phase 2 commands so `curl` and `git clone` can be proved at the owning network milestones without making normal workspace tests depend on internet access or large rootfs payloads.

## Context

- `docs/development/README.md`
- `docs/product/README.md`
- `docs/architecture/runtime.md`

## Path

- `crates/mcr-testkit/`
- `tests/fixtures/`
- `docs/development/README.md`

## Verification

```powershell
cargo test -p mcr-testkit
MCR_BIN=mcr cargo test -p mcr-testkit -- --ignored network_smoke_contract
```

## Notes

- Normal `cargo test --workspace` must not require internet access, GitHub access, CA certificates, or materialized rootfs payloads.
- The opt-in smokes must run through `mcr run-rootfs alpine-rootfs /bin/sh -c ...`, not the host shell.
- The public-network smoke set must include `curl --version`, `curl -fsSL https://example.com >/dev/null`, `git --version`, and `git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hello-world`.
- The implementation must not check in rootfs archives, extracted rootfs directories, or cloned repositories.
