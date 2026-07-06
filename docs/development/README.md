# Development Plan

## Current Milestone Boundary

Development is split into two required runtime stages. Build work starts only
after Phase 2 exits. Performance validation is not a post-Phase-2 activity: it
is a front-loaded product gate for deciding whether the runtime path is worth
expanding.

| Stage | Goal | Exit criteria |
|---|---|---|
| MVP | Run static Linux x86-64 ELF and BusyBox/Alpine commands from a rootfs. | BusyBox smoke suite passes with P0 syscall coverage, deterministic crash diagnostics, and no known startup-path performance cliff. |
| Phase 2 | Run shell commands, common `fork+exec`, TCP-client networking, bounded DNS, and minimal `/proc`/`/dev`. | Alpine shell, curl/git networking, and language runtime smoke tests pass under the documented ABI subset, with shell/network metadata latency passing the active performance viability gate. |
| Phase 3 | Build constrained Dockerfile images with native MCR builder and OCI/Docker output. | `mcr build` produces valid OCI layout and Docker tar for fixed Dockerfile fixtures. |
| Phase 4 | Adapt stable build contracts to BuildKit worker/executor. | `buildctl` drives the supported Dockerfile subset through the MCR worker. |

Phase 3 and Phase 4 work is tracked in `docs/architecture/build.md`, `docs/plan/analysis/buildkit.md`, and `docs/plan/tasks/`. It must not be implemented inside MVP/Phase 2 tasks unless a task explicitly moves the boundary.

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
  mcr-net/       # TCP sockets, bounded DNS, level-trigger poll/epoll
  mcr-win/       # Windows host adapters
  mcr-testkit/   # fixtures and smoke harness
  mcr-image/     # post-Phase 2 OCI content, image, registry, and exporter contracts
  mcr-snapshot/  # post-Phase 2 build snapshot and layer diff contracts
  mcr-build/     # post-Phase 2 native builder and future BuildKit adapter
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
- AF_INET/AF_INET6 TCP client sockets, bounded DNS, and selected loopback server socket behavior only when a smoke requires it;
- level-trigger `poll` and `epoll` compatibility over a shared readiness queue;
- per-task guest FS-base TLS through `ARCH_SET_FS` and `ARCH_GET_FS`;
- smoke tests for shell, curl/git, and language runtimes.
- performance proof for the high-risk user-visible paths before broadening the
  workload matrix: shell startup, `curl`, `git ls-remote`, shallow `git clone`,
  native execution patching, and cross-process pipe handoff.

### Performance Viability Gate

Performance work is allowed to move ahead of broader compatibility when a
measured path threatens product value. The pre-gate public-network baseline had
`curl https://example.com` at about `1947ms` and `git ls-remote
https://github.com/octocat/Hello-World.git HEAD` at about `114131ms`, which was
too large to treat as a late backend optimization.

`perf-015` closed the first viability gate by adding opt-in summary tracing and
sticky scheduling for the shell/network metadata path. The 2026-07-04 release
rerun with `MCR_SCHED_STICKY=1` measured `curl https://example.com` at
`485.074ms` and `git ls-remote` at `1872.576ms`; the direct
`MCR_TRACE_PERF_SUMMARY=1` run reported zero scheduler sleeps and showed remap
plus pipe IPC as the remaining visible costs.

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

Materialize the default local Alpine fixture with:

```powershell
python3 scripts/materialize-alpine-rootfs.py
```

The materializer downloads the latest stable Alpine minirootfs, verifies the
release SHA-256 digest, extracts it to `tests/fixtures/rootfs/alpine-rootfs`,
and adds `curl`, `git`, and CA certificates without requiring Docker, Podman, or
a host `apk` binary. Rebuild an existing ignored fixture with:

```powershell
python3 scripts/materialize-alpine-rootfs.py --force
```

When the script runs inside a linked git worktree, it treats the main workspace
as the rootfs cache. If the main workspace already has
`tests/fixtures/rootfs/alpine-rootfs`, the current worktree gets a symlink to
that payload. If not, the script materializes the payload in the main workspace
first and then links to it. Use `--no-worktree-cache` to keep the payload local
to the current checkout.

Named package rootfs fixtures use the same materializer and manifest. Build
only the extended-support payloads you need:

```powershell
python3 scripts/materialize-alpine-rootfs.py --rootfs-name gcc-rootfs --package build-base --force
python3 scripts/materialize-alpine-rootfs.py --rootfs-name node-rootfs --package nodejs --force
python3 scripts/materialize-alpine-rootfs.py --rootfs-name jdk-rootfs --package openjdk21-jdk --force
python3 scripts/materialize-alpine-rootfs.py --rootfs-name mysql-rootfs --package mariadb --package mariadb-client --force
python3 scripts/materialize-alpine-rootfs.py --rootfs-name redis-rootfs --package redis --force
```

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
| `mcr run-rootfs alpine-rootfs /bin/sh -c "<common filesystem/text/process command>"` | Phase 2 shell command matrix |
| `mcr run-rootfs alpine-rootfs /bin/sh -c "curl --version"` | Phase 2 networking |
| `mcr run-rootfs alpine-rootfs /bin/sh -c "curl -fsSL https://example.com >/dev/null"` | Phase 2 networking |
| `mcr run-rootfs alpine-rootfs /bin/sh -c "git --version"` | Phase 2 networking |
| `mcr run-rootfs alpine-rootfs /bin/sh -c "git ls-remote https://github.com/octocat/Hello-World.git HEAD >/dev/null"` | Phase 2 networking |
| `mcr run-rootfs alpine-rootfs /bin/sh -c "git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hello-world-shallow"` | Phase 2 networking |
| `mcr run-rootfs alpine-rootfs /bin/sh -c "git clone https://github.com/octocat/Hello-World.git /tmp/hello-world-full"` | Phase 2 networking |
| `mcr run-rootfs node-rootfs /bin/sh -c "node -v"` | Phase 2 workload matrix |
| `mcr run-rootfs python-rootfs /bin/sh -c "python -V"` | Phase 2 workload matrix |
| `mcr run-rootfs go-rootfs /bin/sh -c "go version"` | Phase 2 workload matrix |
| `mcr run-rootfs rust-rootfs /bin/sh -c "cargo --version"` | Phase 2 workload matrix |
| `mcr run-rootfs gcc-rootfs /bin/sh -c "<write C source, gcc, run binary>"` | Extended support matrix |
| `mcr run-rootfs node-rootfs /bin/sh -c "<run optimized JavaScript with default Node/V8 JIT>"` | Extended support matrix |
| `mcr run-rootfs node-rootfs /bin/sh -c "<require next/dist/server/config from prepared app>"` | `jit-003` FS/TLS coverage gate |
| `mcr run-rootfs jdk-rootfs /bin/sh -c "<compile Java source with javac, run class with java>"` | Extended support matrix |
| `mcr run-rootfs mysql-rootfs /bin/sh -c "<bootstrap mariadbd and run query matrix>"` | Extended support matrix |
| `mcr run-rootfs redis-rootfs /bin/sh -c "redis-server --test-memory 1"` | Extended support matrix |

Phase 2 shell and network contracts are opt-in. Normal `cargo test -p
mcr-testkit` must not require network access, GitHub access, CA certificates, or
a materialized rootfs. The ignored shell tests additionally skip unless
`MCR_BIN` is set and `alpine-rootfs` is extracted in the fixture root. Run them
explicitly with:

```powershell
MCR_BIN=mcr cargo test -p mcr-testkit -- --ignored shell_smoke_contract
```

The ignored common command matrix uses the same `MCR_BIN` and
materialized-rootfs gate, and covers the guest shell path for `cat`, `mkdir`,
`ls`, `rmdir`, `rm`, `cp`, `mv`, `ln`, `readlink`, `touch`, `echo`, `grep`,
`head`, `tail`, `sed`, `chmod`, `chown`, and `ps`. Run it explicitly with:

```powershell
MCR_BIN=mcr cargo test -p mcr-testkit -- --ignored common_command_matrix_contract
```

The ignored network matrix tests use the same `MCR_BIN` and
materialized-rootfs gate, plus public network access. The matrix covers `curl`
version/HTTPS fetch and `git` version/remote query/shallow clone/full HTTPS
clone. They intentionally stay inside the Phase 2 TCP-client and bounded-DNS
subset. Run them explicitly with:

```powershell
MCR_BIN=mcr cargo test -p mcr-testkit -- --ignored network_smoke_contract
```

Those tests invoke `mcr` directly as `run-rootfs`, the `alpine-rootfs` fixture,
`/bin/sh`, `-c`, and the guest command. They do not execute the command string
through the host shell.

The ignored extended support matrix uses `MCR_BIN` plus the matching
materialized package rootfs fixture. It covers GCC compile-and-run, Node.js
JavaScript execution on the default V8 JIT path, unpinned `javac -version` plus
JDK compile-and-run, MariaDB bootstrap ordinary/index/JOIN/range queries, and
Redis server execution. Run it explicitly with:

```powershell
MCR_BIN=mcr cargo test -p mcr-testkit --test extended_support_smoke_contract -- --ignored --nocapture
```

Ignored performance baselines print `mcr_perf_baseline.version=1` reports with
environment metadata, wall time, operation counts, and derived throughput.
Setting `MCR_PERF_ENFORCE_GATES=1` turns the stored local thresholds into
assertions for the selected runtime, VFS, network, worker-pool, native patch,
intrinsic, and guest workload paths. Run local subsystem baselines with:

```powershell
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
cargo test -p mcr-vfs perf_baseline -- --ignored --nocapture
cargo test -p mcr-net perf_baseline -- --ignored --nocapture
cargo test -p mcr-testkit perf_worker_pool -- --ignored --nocapture
```

The task-specific DNS cache and worker-pool gates are host-only reports that
keep the active perf task filters non-empty:

```powershell
cargo test -p mcr-testkit perf_dns -- --ignored --nocapture
cargo test -p mcr-testkit perf_worker_pool -- --ignored --nocapture
```

The guest workload baseline additionally requires `MCR_BIN` and a materialized
`alpine-rootfs`. Public-network `curl`, `git ls-remote`, and shallow `git
clone` measurements run only when `MCR_PERF_PUBLIC_NETWORK=1` is set. Public
network thresholds are enforced only when
`MCR_PERF_ENFORCE_PUBLIC_NETWORK=1` is also set:

```powershell
MCR_BIN=target/debug/mcr cargo test -p mcr-testkit --test perf_baseline -- --ignored --nocapture
MCR_BIN=target/debug/mcr MCR_PERF_PUBLIC_NETWORK=1 cargo test -p mcr-testkit --test perf_baseline -- --ignored --nocapture
```

For active performance viability work, run the release binary as well as the
ignored baseline harness so debug-build overhead does not hide the runtime
shape:

```powershell
cargo build --release -p mcr-cli
$env:MCR_BIN = (Resolve-Path target\release\mcr.exe).Path
$env:MCR_PERF_ENFORCE_GATES = '1'
cargo test -p mcr-testkit --test perf_baseline -- --ignored --nocapture
```

Linux x86-64 guest smokes must be treated as x86_64-host validation. Do not
expand `mcr-jit` into a broad x86 interpreter to make those smokes pass on an
ARM developer machine. Use the manual `x86_64 Runtime Smokes` GitHub Actions
workflow for the required proof:

```powershell
gh workflow run x86-runtime-smoke.yml -f suite=shell
gh workflow run x86-runtime-smoke.yml -f suite=network
gh workflow run x86-runtime-smoke.yml -f suite=performance
```

For local ARM development, run the same commands inside an x86_64 VM/container.
On Docker Desktop or another QEMU-enabled runtime, this shape is sufficient:

```sh
docker run --rm --platform linux/amd64 -v "$PWD":/work -w /work \
  -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  rust:1-bookworm \
  bash -c 'python3 scripts/materialize-alpine-rootfs.py --force && cargo build -p mcr-cli && MCR_BIN=target/debug/mcr cargo test -p mcr-testkit --test shell_procfs_smoke_contract -- --ignored shell_smoke_contract --nocapture'
```

If an x86_64 runner or QEMU container still reports `guest block did not
terminate at syscall` for an Alpine smoke, treat it as an execution-layer gap.
The fix is native same-ISA execution/re-emission on x86_64, not adding enough
decoded instruction cases to approximate a full CPU.

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
11. performance viability for shell/network metadata paths;
12. promoted performance backend gates:
    `perf-016` through `perf-024`;
13. Phase 2 workload smoke matrix.

Tasks with no path overlap may be parallelized in separate worktrees, but dependent integration tasks wait for predecessor tasks to land.

## Deferred Or Later Work

The following are intentionally outside MVP and Phase 2:

- Dockerfile parser and builder before Phase 3;
- OCI image writer, layer diff, and registry interactions before Phase 3;
- BuildKit worker/executor before Phase 4;
- Docker Engine API facade;
- overlay lower/upper layer implementation beyond VFS design compatibility;
- broad IOCP performance rewrite after the current viability gate is solved;
- general UDP socket semantics outside the DNS path;
- AF_UNIX compatibility;
- edge-triggered epoll and one-shot/exclusive epoll watches;
- full `fork` without exec;
- process-shared futex;
- pty/tty completeness;
- strong sandboxing.
