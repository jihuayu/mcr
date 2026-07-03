---
id: integ-003
scope: phase2-integration
status: pending
depends-on: [integ-002, net-002]
---

# integ-003: Deliver Network Tool Smoke

## Objective

Connect the Phase 2 TCP-client socket subset, bounded DNS, socket fd integration, and level-trigger poll/epoll readiness into shell-driven `curl` and `git` smoke tests.

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
mcr run-rootfs alpine-rootfs /bin/sh -c "git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hello-world"
```

## Notes

- External-network tests are intentional acceptance gates for this task; keep normal workspace tests deterministic by making the corresponding testkit contracts ignored or environment-gated.
- `alpine-rootfs` must include `curl`, `git`, CA certificates, and writable `/tmp` before this task is marked done.
- The smoke success criteria must stay within AF_INET/AF_INET6 TCP client flows plus the documented DNS path.
- Network namespaces, port publishing, raw sockets, packet sockets, and general UDP behavior remain unsupported.
- Any unsupported epoll flags encountered by curl/git must be rejected or documented with Linux-compatible errno behavior before the smoke is considered stable.
