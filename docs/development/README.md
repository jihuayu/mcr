# Development Plan

## Current Milestone Boundary

Development is split into two required stages.

| Stage | Goal | Exit criteria |
|---|---|---|
| MVP | Run static Linux x86-64 ELF and BusyBox/Alpine commands from a rootfs. | BusyBox smoke suite passes with P0 syscall coverage and deterministic crash diagnostics. |
| Phase 2 | Run shell commands, common `fork+exec`, networking, and minimal `/proc`/`/dev`. | Alpine shell, curl/git networking, and language runtime smoke tests pass. |

Work after Phase 2 is tracked as backlog. It must not be implemented inside MVP/Phase 2 tasks unless a task explicitly moves the boundary.

## Repository Layout

```text
crates/
  mcr-cli/       # CLI entrypoints and smoke commands
  mcr-runtime/   # session lifecycle and subsystem wiring
  mcr-elf/       # ELF loader and initial stack
  mcr-jit/       # instruction decode, rewrite, trampoline
  mcr-sys/       # syscall ABI table, dispatcher, errno
  mcr-vfs/       # VFS, fd table, procfs/devfs
  mcr-task/      # guest processes, tasks, futex, signals
  mcr-net/       # sockets, DNS, poll/epoll
  mcr-win/       # Windows host adapters
  mcr-testkit/   # fixtures and smoke harness
docs/
  product/
  architecture/
  development/
  plan/
```

The first bootstrap task creates this layout and the workspace manifests.

## Milestone Detail

### MVP

The MVP must prove the core runtime path:

```text
mcr-cli -> mcr-runtime -> mcr-elf -> mcr-jit -> mcr-sys -> mcr-vfs/mcr-task/mcr-win
```

Required capabilities:

- Linux x86-64 ELF parsing and load mapping;
- Linux initial stack and minimal auxv;
- syscall instruction interception;
- P0 syscall dispatcher;
- rootfs jail and Linux path normalization;
- fd table for stdin/stdout/stderr and regular files;
- static BusyBox smoke tests;
- crash report with registers, VMAs, executable path, argv, and last syscall.

MVP may start with static binaries and a constrained rootfs. Dynamic linking must be designed but does not need to be complete until Phase 2.

### Phase 2

Phase 2 turns the runtime into a useful development command runner.

Required capabilities:

- dynamic Alpine shell path if MVP used static binaries only;
- `execve` replacement and common `fork+exec+wait4` shell path;
- guest PID/TID lifecycle and child exit tracking;
- `pipe`, `dup`, `fcntl`, and selected `ioctl`;
- process-private futex `WAIT`/`WAKE`;
- signals skeleton for install, mask, interrupt, and termination behavior;
- `/proc/self` and `/dev` nodes listed in runtime design;
- AF_INET/AF_INET6 TCP client sockets, DNS, selected server socket behavior;
- `poll` and `epoll` compatibility over a shared readiness queue;
- smoke tests for shell, curl/git, and language runtimes.

## Validation Policy

Every task must define verification in its task file. The common validation stack is:

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Windows-only integration tasks also run the relevant smoke command through `mcr-testkit`.

## Testkit Fixture Contract

`mcr-testkit` discovers fixture metadata from `tests/fixtures` by default, or
from `MCR_FIXTURES_DIR` when a local cache is used. The crate owns three fixture
surfaces:

- `guest-binaries/manifest.mcr` declares Linux x86-64 guest binaries by name,
  relative path, ABI, format, linkage, milestone stage, and whether the payload
  is required for the current test.
- `rootfs/manifest.mcr` declares rootfs names, extracted paths, optional archive
  paths, architecture, distro/version metadata, source URL, milestone stage, and
  whether the payload is required.
- `golden/` stores exact stdout/stderr files for smoke assertions.

Rootfs archives and extracted rootfs directories are fixture payloads, not source
files. Keep them out of git and materialize them in a local fixture cache before
running ignored integration smokes. Metadata-only fixtures use `required=false`
so normal unit tests can validate the contract without downloading large rootfs
archives.

Smoke tests use `SmokeCommand` plus `GoldenOutput` assertions. A smoke remains
`#[ignore]` until the owning runtime integration task enables the corresponding
command from the table below.

Smoke commands become required as soon as their owning task lands:

| Smoke | Introduced by |
|---|---|
| `mcr run-rootfs alpine-rootfs /bin/busybox echo hello` | MVP runtime integration |
| `mcr run-rootfs alpine-rootfs /bin/busybox ls /` | VFS P0 |
| `mcr run-rootfs alpine-rootfs /bin/busybox cat /etc/os-release` | VFS P0 |
| `mcr run-rootfs alpine-rootfs /bin/sh -c "echo hi"` | Phase 2 shell |
| `mcr run-rootfs alpine-rootfs /bin/sh -c "curl --version"` | Phase 2 networking |
| `mcr run-rootfs alpine-rootfs /bin/sh -c "git --version"` | Phase 2 networking |
| `mcr run-rootfs node-rootfs /bin/sh -c "node -v"` | Phase 2 workload matrix |
| `mcr run-rootfs python-rootfs /bin/sh -c "python -V"` | Phase 2 workload matrix |
| `mcr run-rootfs go-rootfs /bin/sh -c "go version"` | Phase 2 workload matrix |
| `mcr run-rootfs rust-rootfs /bin/sh -c "cargo --version"` | Phase 2 workload matrix |

## Task And Commit Policy

Implementation work follows task files in `docs/plan/tasks/`.

- Each task is a reviewable checkpoint and receives its own Conventional Commit.
- Stage only files listed in the task `path`.
- Do not combine two completed tasks into one commit.
- A task is done only after its verification commands pass or the task file explicitly documents why a check cannot run.
- Design docs are source of truth. If implementation needs a contract change, update the design doc in the same task.

## Checkpoint Order

The delivery order is:

1. documentation and task planning;
2. workspace/bootstrap;
3. ABI/syscall foundation;
4. ELF loader and memory map;
5. JIT/trampoline syscall interception;
6. VFS/fd P0;
7. MVP integration smoke;
8. Phase 2 task/process/futex/signals;
9. Phase 2 procfs/devfs;
10. Phase 2 network/eventing;
11. Phase 2 workload smoke matrix.

Tasks with no path overlap may be parallelized in separate worktrees, but dependent integration tasks wait for predecessor tasks to land.

## Deferred Work

The following are intentionally outside the current plan:

- Dockerfile parser and builder;
- OCI image writer, layer diff, and registry interactions;
- BuildKit worker/executor;
- Docker Engine API facade;
- overlay lower/upper layer implementation beyond VFS design compatibility;
- IOCP performance rewrite;
- full `fork` without exec;
- process-shared futex;
- pty/tty completeness;
- strong sandboxing.
