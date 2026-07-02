# Product Scope

## Product Definition

MCR is a Windows-native Linux userspace runtime for trusted development workloads. It runs selected Linux x86-64 programs on Windows x86-64 by loading ELF binaries, intercepting Linux syscalls in userspace, and mapping a constrained Linux ABI surface onto Windows host APIs.

The first planned delivery is not a Docker Desktop replacement. It is the runtime foundation needed before any Dockerfile builder, OCI image writer, BuildKit worker, or Docker Engine API facade is worth building.

## Target User

The target user is a developer who wants to run lightweight Linux CLI and build tools on Windows without starting WSL2 or a VM. The expected workload is trusted code owned by the user or their team.

## Goal Through Current Plan

The current plan completes two stages:

| Stage | Product result | Required user-visible proof |
|---|---|---|
| MVP | Static ELF and BusyBox/Alpine commands run from a Linux rootfs. | `mcr run-rootfs alpine-rootfs /bin/busybox echo hello`, `ls /`, and `cat /etc/os-release` succeed. |
| Phase 2 | Shell, common `fork+exec`, networking, and minimal `/proc` make common development tools usable. | `alpine sh -c`, `curl`, `git clone`, `node -v`, `python -V`, `go version`, and `cargo --version` smoke tests succeed. |

## Supported Workloads

MVP workloads:

- static Linux x86-64 binaries;
- BusyBox commands that depend on basic file, directory, memory, time, random, and process-exit syscalls;
- read-only or simple writable rootfs operations inside an MCR-managed workspace.

Phase 2 workloads:

- Alpine shell command execution with pipes and fd duplication;
- outbound TCP clients such as `curl`, `wget`, and `git`;
- language runtime discovery and package fetch paths for Node.js, Python, Go, and Rust;
- basic local development tools that do not require privileged kernel features.

## Non-Goals

These are not part of the current delivery plan:

| Area | Deferred or unsupported |
|---|---|
| Build pipeline | Dockerfile builder, OCI/Docker tar output, registry push/pull, BuildKit worker, build cache. |
| Docker compatibility | Docker Engine API, Compose, volumes, full logs/stats/events/inspect behavior. |
| Security | Strong isolation, hostile-code sandboxing, multi-tenant execution, seccomp-equivalent policy. |
| Kernel features | systemd, kernel modules, eBPF, KVM, full cgroup v2, full mount namespaces, netns, iptables/nftables. |
| Device and IO | raw block devices, TUN/TAP, GPU, raw sockets, database-grade fsync and mmap consistency guarantees. |
| Architecture | Linux arm64 guest, transparent cross-architecture execution, Windows containers. |

## Success Criteria

MVP is complete when:

- the runtime loads Linux x86-64 ELF binaries and constructs `argc`, `argv`, `envp`, and `auxv`;
- the runtime intercepts guest Linux `syscall` instructions before they reach the Windows kernel;
- P0 syscalls needed by BusyBox succeed or return Linux-compatible errors;
- fd table, rootfs path resolution, and basic process exit behavior are deterministic;
- the BusyBox smoke suite passes on Windows x86-64.

Phase 2 is complete when:

- shell form execution works through the common `fork+exec+wait4` path;
- `pipe`, `dup`, `fcntl`, process-private `futex`, and a usable signals skeleton are present;
- outbound TCP, DNS, and `poll`/`epoll` compatibility cover `curl`, `git`, and package-manager fetch paths;
- `/proc/self/exe`, `/proc/self/cmdline`, `/proc/self/environ`, `/proc/self/fd`, `/dev/null`, `/dev/zero`, and `/dev/urandom` exist;
- fixed smoke tests for Alpine shell, network tools, and language runtimes pass.

## Product Decisions

| Decision | Chosen default | Reason |
|---|---|---|
| Host and guest architecture | Windows x86-64 host, Linux x86-64 guest | Same-ISA execution avoids cross-architecture CPU emulation during the first runtime milestone. |
| Trust model | Trusted development workloads | Strong sandboxing would dominate the design and block the runtime proof. |
| Process model | One host process per guest container through Phase 2 | This keeps guest IDs, fd tables, futex keys, signals, and `/proc` under one runtime authority. |
| gVisor reuse | Reference only | gVisor's syscall tables, tests, and architecture are useful, but its platform layer depends on Linux mechanisms. |
| BuildKit reuse | Deferred | Runtime correctness must exist before a BuildKit executor can be meaningful. |
