---
id: workload-001
scope: phase2-workloads
status: blocked
depends-on: [integ-003]
---

# workload-001: Stabilize Phase 2 Development Workload Matrix

## Objective

Add and pass fixed Phase 2 smoke tests for Node.js, Python, Go, and Rust runtime discovery commands, then document any unsupported syscall gaps encountered during stabilization.

## Context

- `docs/product/README.md`
- `docs/architecture/runtime.md`
- `docs/development/README.md`
- `docs/plan/backlog.md`

## Path

- `crates/mcr-testkit/`
- `crates/mcr-runtime/`
- `crates/mcr-sys/`
- `crates/mcr-vfs/`
- `crates/mcr-task/`
- `crates/mcr-net/`
- `docs/plan/backlog.md`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mcr run-rootfs node-rootfs /bin/sh -c "node -v"
mcr run-rootfs python-rootfs /bin/sh -c "python -V"
mcr run-rootfs go-rootfs /bin/sh -c "go version"
mcr run-rootfs rust-rootfs /bin/sh -c "cargo --version"
```

## Notes

- This task is the Phase 2 completion gate.
- The workload matrix must remain inside the documented ABI subset: TCP-client networking, bounded DNS, level-trigger readiness, MCR-managed rootfs semantics, and per-task FS-base TLS.
- If a workload exposes a non-essential syscall gap, document the gap in backlog with the command and Linux errno behavior.
- If a workload requires unsupported network/event behavior such as general UDP, edge-trigger epoll, tty/pty completeness, or process-shared futex, keep that behavior out of Phase 2 unless the product scope is explicitly revised.
- Fixed ignored `mcr-testkit` workload contracts now model the four required
  guest shell commands and skip unless `MCR_BIN` plus the matching materialized
  rootfs are available.
- Local package-backed rootfs validation on Windows passed `python -V`
  (`Python 3.14.5`) but did not clear the matrix: `sigaltstack` support and
  instruction-aware syscall patching moved `go version` past the native
  execution fault and Go `newosproc` clone failure, but it still did not
  complete within a bounded local run. `node -v` and `cargo --version` also did
  not complete within several minutes and were stopped. These are runtime
  execution blockers, not fixture-contract gaps.
