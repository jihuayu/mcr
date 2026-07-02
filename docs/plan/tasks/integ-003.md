---
id: integ-003
scope: phase2-integration
status: pending
depends-on: [integ-002, net-002]
---

# integ-003: Deliver Network Tool Smoke

## Objective

Connect guest socket syscalls, DNS, socket fd integration, and poll/epoll readiness into shell-driven `curl` and `git` smoke tests.

## Context

- `docs/product/README.md`
- `docs/architecture/runtime.md`
- `docs/development/README.md`

## Path

- `crates/mcr-cli/`
- `crates/mcr-runtime/`
- `crates/mcr-net/`
- `crates/mcr-vfs/`
- `crates/mcr-sys/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mcr run-rootfs alpine-rootfs /bin/sh -c "curl --version"
mcr run-rootfs alpine-rootfs /bin/sh -c "git --version"
mcr run-rootfs alpine-rootfs /bin/sh -c "curl -fsSL https://example.com >/dev/null"
```

## Notes

- External-network tests should have a local deterministic fallback in CI.
- Network namespaces, port publishing, and raw sockets remain unsupported.
