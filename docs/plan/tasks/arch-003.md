---
id: arch-003
scope: architecture
status: done
depends-on: [arch-002]
---

# arch-003: Per-Process Context Ownership Without Memory Swap

## Objective

Eliminate the single "selected" process context so each guest process owns its
`GuestMemory` and fd table directly and scheduling switches references instead
of cloning, swapping, or remapping memory contents on every cross-process
switch.

## Context

- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/architecture/performance.md` (Performance-First Viability Gate)
- `docs/architecture/runtime.md`

## Path

- `crates/mcr-runtime/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
```

## Notes

- Current cost: `select_memory_for_process` clones the outgoing process
  memory via `try_clone_runtime()` and, in native mode,
  `select_native_memory_for_process` drops and remaps allocations at guest
  addresses on every switch. Pipe-heavy cross-process protocols (`git` with
  `git-remote-https`) pay this repeatedly; perf traces already show remap
  cost.
- Native fixed-address mode may still require exclusive commitment of one
  process's fixed mappings at a time; manage that as a narrow native-mode
  constraint instead of cloning in flexible mode.
- This is a performance-relevant architecture task: record before/after
  measurements for the shell pipeline and `git ls-remote` paths per the plan
  rules for promoted performance work.
- Guest-visible fork/exec/wait, fd inheritance, and close-on-exec semantics
  must not change.

## Results

- Flexible-address process switches now move the selected memory and fd table
  back into their owning process slots instead of cloning `GuestMemory` or
  cloning the selected `FdTable` on every cross-process switch.
- Native fixed-address execution still materializes the selected process at
  guest addresses and records that narrow remap/clone constraint separately.
- Runtime diagnostics now expose context switch counters so flexible-mode
  switches can assert zero selected-memory clones.

## Validation

```powershell
cargo fmt -p mcr-runtime --check
cargo test -p mcr-runtime --lib -- --test-threads=1
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
cargo ci-test
```

- Focused runtime tests passed: `173 passed`.
- Runtime perf baseline passed:
  - `runtime_native_patch_scan`: `6.597ms` for 512 syscall sites.
  - `runtime_syscall_dispatch_getpid`: `44.305ms` for 512 operations.
  - `runtime_fork_exec_wait4`: `30.355ms` for 1 operation.
- Workspace `cargo ci-test` passed in a clean validation worktree with this
  checkpoint applied. On the shared branch after the parallel native-patch
  checkpoint landed, a full `cargo ci-test` rerun reached `mcr-win` and failed
  once in `host_worker_pool::tests::executor_result_job_reports_panic_as_disconnected`;
  rerunning that exact test immediately passed.

## Measurements

Measured with the patched release binary and the materialized Alpine rootfs at
`D:\oss\mcr\tests\fixtures\rootfs\alpine-rootfs`.

- Shell pipeline:
  `mcr.exe run-rootfs ... /bin/sh -c "printf 'a\nb\n' | grep b | wc -l >/dev/null"`
  - exit status: `0`
  - host wall time: `330.184ms`
  - runtime perf summary: `pid_switch_count=12`,
    `context_memory_switch_count=0`, `context_memory_clone_count=9`,
    `context_fd_switch_count=8`, `remap_count=9`,
    `remap_total_us=20282`
- `git ls-remote`:
  `mcr.exe run-rootfs ... /bin/sh -c "GIT_TERMINAL_PROMPT=0 git ls-remote https://github.com/octocat/Hello-World.git HEAD >/dev/null"`
  - exit status: `0`
  - host wall time: `1768.884ms`
  - runtime perf summary: `pid_switch_count=30`,
    `context_memory_switch_count=0`, `context_memory_clone_count=29`,
    `context_fd_switch_count=29`, `remap_count=29`,
    `remap_total_us=201738`

The guest workload measurements run through `run-rootfs`, which enables native
execution on Windows; the remaining context memory clones are the fixed-address
native remap constraint called out above, not flexible-mode scheduler switches.
