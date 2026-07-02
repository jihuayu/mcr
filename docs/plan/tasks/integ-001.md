---
id: integ-001
scope: mvp-integration
status: pending
depends-on: [testkit-001, jit-001, sys-001, mem-001, vfs-002, task-001, diag-001]
---

# integ-001: Deliver MVP Run-Rootfs Smoke

## Objective

Connect CLI, runtime, ELF loader, JIT, syscall dispatcher, VFS, memory, and task lifecycle into a real `mcr run-rootfs` path that runs BusyBox MVP smoke commands.

## Context

- `docs/product/README.md`
- `docs/architecture/README.md`
- `docs/architecture/runtime.md`
- `docs/development/README.md`

## Path

- `crates/mcr-cli/`
- `crates/mcr-runtime/`
- `crates/mcr-elf/`
- `crates/mcr-jit/`
- `crates/mcr-sys/`
- `crates/mcr-vfs/`
- `crates/mcr-task/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mcr run-rootfs alpine-rootfs /bin/busybox echo hello
mcr run-rootfs alpine-rootfs /bin/busybox ls /
mcr run-rootfs alpine-rootfs /bin/busybox cat /etc/os-release
```

## Notes

- This task is the MVP gate.
- No subsystem mock may remain on this execution path.
