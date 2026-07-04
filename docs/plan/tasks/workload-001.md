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
- Added a deterministic runtime stall diagnostic for bounded language workload
  runs. `RuntimeWithTracer<RuntimeDiagnosticsTracer>::run_guest_until_exit_with_step_limit`
  and `RunRootfsConfig::with_guest_step_limit` now return a `GuestRunError`
  timeout diagnostic that classifies the snapshot as guest wait/futex,
  readiness, scheduling, native execution, or unknown, without changing normal
  unbounded runtime behavior. Focused runtime tests cover futex, fd readiness,
  wait4 scheduling, native execution, and step-limit timeout reporting.
- Follow-up package-rootfs validation with `mcr run-rootfs --guest-step-limit`
  confirmed that `python -V` completes, while `go version`, `node -v`, and
  `cargo --version` each exceeded a 30s process timeout without returning a
  guest step-limit diagnostic. That means the remaining blocker is likely inside
  a single native/host-side execution window, patch/materialization path, or
  equivalent long operation rather than repeated guest-step progress.
- Host-step tracing can be enabled with `MCR_HOSTSTEP_TRACE=1` when running
  package-rootfs workloads. The first trace checkpoint showed that `go version`
  does not reach guest execution within 30s because eager rootfs materialization
  is still copying package files; `node -v` reaches native execution and times
  out inside a large FS-relative patch apply (`45171` patches with `fs_base=0`);
  `cargo --version` reaches native execution and times out during repeated
  native patch scan/apply work for Rust-sized executable ranges.
- 2026-07-04 checkpoint: `run-rootfs` now registers regular package-rootfs
  files as host-backed VFS entries and reads file bytes when the guest opens a
  file instead of copying every file before guest execution. This moves the Go
  rootfs bulk copy out of the pre-guest critical path; `go version` still needs
  a package-rootfs rerun to identify the next runtime blocker after guest entry.
