# MCR Documentation Index

MCR is a Rust runtime project for running selected Linux x86-64 development workloads on Windows x86-64 without WSL2, Hyper-V, or a Linux kernel.

## Product And Architecture

| Doc | Purpose |
|---|---|
| [Product scope](product/README.md) | Goal, non-goals, supported workloads, and MVP + Phase 2 acceptance criteria. |
| [Architecture overview](architecture/README.md) | Runtime boundary, subsystem ownership, module map, and cross-module flows. |
| [Runtime design](architecture/runtime.md) | ELF execution, syscall dispatch, guest task model, VFS, `/proc`, networking, futex, and Windows host adapters. |
| [Build, OCI, and BuildKit design](architecture/build.md) | Post-Phase 2 Dockerfile build, OCI image, snapshot, registry, and BuildKit worker boundaries. |

## Delivery

| Doc | Purpose |
|---|---|
| [Development plan](development/README.md) | Milestones, validation policy, source layout, and engineering workflow. |
| [Plan workflow](plan/README.md) | Task status model and execution rules. |
| [MVP + Phase 2 analysis](plan/analysis/mvp-phase2.md) | Module decomposition and integration map used to create task files. |
| [Build + BuildKit analysis](plan/analysis/buildkit.md) | Phase 3/4 module decomposition and integration map for builder, OCI, and BuildKit work. |
| [Task backlog](plan/backlog.md) | Deferred work and non-blocking follow-up items. |
| [Tasks](plan/tasks/) | Small implementation tasks through MVP + Phase 2. |

## Current Delivery Scope

The active plan ends when MCR can:

- run static Linux x86-64 ELF and BusyBox/Alpine commands from a rootfs;
- run shell form commands through the common `fork+exec+wait4` path;
- support basic pipes, fd duplication, private futex, signals skeleton, and guest task IDs;
- support outbound TCP networking, DNS, and enough `poll`/`epoll` behavior for `curl`, `git`, and language package managers;
- expose minimal `/proc` and `/dev` nodes required by development tooling.

Dockerfile builder, OCI image export, BuildKit integration, Docker Engine API compatibility, strong sandboxing, and cross-architecture execution are intentionally deferred until the Phase 2 runtime contract is stable.
