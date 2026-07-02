---
id: integ-002
scope: phase2-integration
status: blocked
depends-on: [task-002, task-003, vfs-004]
---

# integ-002: Deliver Shell And Procfs Smoke

## Objective

Connect dynamic execution, `fork+exec+wait4`, fd inheritance, pipes, signals skeleton, futex, writable VFS, procfs, and devfs into real Alpine shell smoke tests.

## Context

- `docs/product/README.md`
- `docs/architecture/runtime.md`
- `docs/development/README.md`

## Path

- `crates/mcr-cli/`
- `crates/mcr-runtime/`
- `crates/mcr-elf/`
- `crates/mcr-task/`
- `crates/mcr-vfs/`
- `crates/mcr-sys/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mcr run-rootfs alpine-rootfs /bin/sh -c "echo hi"
mcr run-rootfs alpine-rootfs /bin/sh -c "echo hi | cat"
mcr run-rootfs alpine-rootfs /bin/sh -c "cat /proc/self/cmdline >/dev/null && head -c 4 /dev/zero >/dev/null"
```

## Notes

- No task/process/VFS mock may remain on this path.
- This task does not require outbound network.
