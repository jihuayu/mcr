# Architecture Overview

## Purpose And Boundary

The architecture centers on a userspace Linux ABI runtime. The runtime owns guest execution, guest kernel-like state, and translation between Linux ABI calls and Windows host APIs.

Through Phase 2 it does not own Dockerfile solving, OCI image creation, Docker Engine API compatibility, or strong security isolation. Post-Phase 2 build work is defined separately in [Build, OCI, and BuildKit design](build.md).

## System Shape

```text
CLI / smoke harness
        |
        v
Runtime manager
        |
        +--> ELF loader ---------+
        |                        |
        +--> JIT / trampoline ---+--> Guest task execution
        |                        |
        +--> Syscall dispatcher -+
                 |
                 +--> VFS / fd table / procfs / devfs
                 +--> Process, signal, futex, timer state
                 +--> Network and poll/epoll compatibility
                 +--> Windows host adapters
```

## Scope Ownership

| Scope | Owns | Delegates |
|---|---|---|
| Runtime manager | Container lifetime, rootfs mount, initial process creation, smoke harness entrypoints. | ELF loading, syscall dispatch, subsystem state. |
| ELF and memory | ELF64 parsing, segment mapping, initial stack, auxv, guest TLS inputs, guest VMAs. | Host memory allocation and protection to Windows adapter. |
| JIT and trampoline | Basic block decode, same-ISA re-emission, syscall interception, register context bridge. | Linux syscall behavior to syscall dispatcher. |
| Syscall dispatcher | Syscall table, Linux ABI structs, errno mapping, argument validation, dispatch tracing. | File, process, network, and sync behavior to owned subsystems. |
| VFS | Linux path semantics, rootfs jail, virtual inode model, fd table, metadata sidecar, procfs/devfs nodes. | Host file operations to Windows file adapter. |
| Process and sync | Guest PID/TID, task lifecycle, `fork+exec` fast path, `wait4`, signals skeleton, process-private futex. | Host threads and wait primitives to Windows sync adapter. |
| Network and eventing | Linux/POSIX socket syscall ABI compatibility, guest socket fd objects, socket readiness, and level-trigger `poll`/`epoll` compatibility. | Winsock, `std::net` only where it preserves ABI semantics, WSAPoll, and later IOCP to Windows net adapter. |
| Windows adapters | Narrow wrappers over Win32/NT capabilities. | Nothing upward; adapters expose host capability, not Linux policy. |

## Module Map

The planned Rust workspace uses package names that match subsystem boundaries.

| Package | Responsibility |
|---|---|
| `mcr-cli` | User-facing `mcr run-rootfs` and smoke commands. |
| `mcr-runtime` | Container/session lifecycle and subsystem wiring. |
| `mcr-elf` | ELF loader, initial stack, auxv, guest TLS setup inputs, and guest memory map setup. |
| `mcr-jit` | x86-64 decode/rewrite, syscall trampoline, register context bridge. |
| `mcr-sys` | Syscall table, ABI structs, errno, dispatcher traits, syscall trace events. |
| `mcr-vfs` | VFS, fd table, procfs, devfs, rootfs jail, Linux metadata model. |
| `mcr-task` | Guest process/task model, `fork+exec`, `wait4`, signals skeleton, futex. |
| `mcr-net` | TCP sockets, bounded DNS, readiness, and level-trigger `poll`/`epoll` compatibility for Phase 2. |
| `mcr-win` | Windows-specific host adapters. |
| `mcr-testkit` | Rootfs fixtures, guest test binaries, smoke runner, golden output assertions. |
| `mcr-image` | Post-Phase 2 OCI content store, image metadata, registry pull/push, layout and tar exporters. |
| `mcr-snapshot` | Post-Phase 2 build snapshot roots, lower/upper views, diff walking, and OCI whiteout export. |
| `mcr-build` | Post-Phase 2 Dockerfile subset execution and later BuildKit worker bridge. |

## Cross-Module Creation Flow

```text
mcr-cli
  creates RuntimeConfig
  calls mcr-runtime::run_rootfs

mcr-runtime
  creates GuestKernel
  creates RootFs mount through mcr-vfs
  calls mcr-elf to load init executable
  calls mcr-jit to enter guest code

mcr-jit
  intercepts syscall
  calls mcr-sys dispatcher with GuestContext

mcr-sys
  routes file syscalls to mcr-vfs
  routes task syscalls to mcr-task
  routes socket/event syscalls to mcr-net
  returns Linux ABI result to mcr-jit
```

Integration tasks must prove these creation and call chains with real implementations, not mocks.

Post-Phase 2 build flow:

```text
mcr-cli
  parses build command
  calls mcr-build

mcr-build
  parses the supported Dockerfile subset
  resolves base images through mcr-image
  creates build snapshots through mcr-snapshot
  executes RUN steps through mcr-runtime
  exports image metadata and layers through mcr-image
```

The BuildKit adapter must use the same `mcr-runtime`, `mcr-snapshot`, and `mcr-image` contracts. It must not introduce a second runtime execution path.

## State Ownership

| State | Owner | Notes |
|---|---|---|
| Guest PID/TID namespace | `mcr-task` | Host process IDs are never exposed as guest IDs. |
| Guest fd table | `mcr-vfs` | File, pipe, socket, proc, and dev descriptors share one guest fd namespace. |
| Guest inode IDs | `mcr-vfs` | Host paths are storage backends, not inode identity. |
| Guest memory map | `mcr-elf` initially, then runtime memory manager | VMAs are Linux concepts mapped onto host memory allocations. |
| Guest FS base | `mcr-task` and execution core | `arch_prctl` updates per-task guest TLS state; host Rust TLS is not guest truth. |
| Syscall ABI table | `mcr-sys` | Syscall numbers, argument decoding, and errno conversion live here. |
| Socket readiness | `mcr-net` | Exposes the documented level-trigger readiness subset over host Winsock/readiness helpers; IOCP is a later performance backend, not the guest-visible model. |
| Host handles | `mcr-win` adapters | Handles must not leak into Linux-facing types. |
| OCI blobs and descriptors | `mcr-image` | Content-addressed blobs are keyed by digest and never by mutable tags. |
| Build snapshot roots | `mcr-snapshot` | Build layers are derived from explicit lower/upper state, not host directory diffs alone. |
| Dockerfile build graph | `mcr-build` first, BuildKit later | Native builder owns the first constrained graph; BuildKit owns LLB solving after the worker exists. |

## Architecture Constraints

- Guest-visible semantics must be modeled explicitly; do not use host IDs or host paths as guest truth.
- Every syscall returns a Linux ABI result, including Linux errno values.
- Windows adapters stay below subsystem policy; they do not decide guest path, pid, signal, or fd semantics.
- Through Phase 2, process-private futex relies on the one-host-process-per-container model.
- The networking architecture targets Linux/POSIX socket syscall ABI compatibility, not a source-level Winsock wrapper. Phase 2 still gates on the smaller TCP/DNS subset unless a task explicitly expands it.
- Detailed networking rules live in [Network ABI design](networking.md), including
  the guest fd/object model, Winsock lifecycle, syscall mappings, readiness
  strategy, socket options, close semantics, and deferred IOCP backend.
- Performance goals and backend optimization boundaries live in
  [Performance optimization design](performance.md). Performance work must keep
  guest-visible syscall, fd, task, VFS, and socket contracts stable.
- Through Phase 2, `poll` and `epoll` are level-trigger only; unsupported flags must fail intentionally instead of being accepted silently.
- Unsupported syscalls must be tracked and tested as unsupported behavior, not silently ignored.
- Build steps must call the same runtime executor as user-visible `run-rootfs` workloads.
- BuildKit integration must be an adapter over MCR executor, snapshot, content, and image contracts, not a forked implementation of those contracts.
