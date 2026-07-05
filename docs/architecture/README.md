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
| ELF loader | ELF64 parsing, segment mapping plan, initial stack, auxv, guest TLS inputs. | Guest memory mapping to `mcr-memory`; host memory allocation and protection to Windows adapter. |
| Guest memory | Guest VMAs, mmap/mprotect/brk, memory access, libc intrinsic memory routines, runtime clone/COW strategies. | Host memory allocation and protection to Windows adapter. |
| JIT and trampoline | Basic block decode, same-ISA re-emission, syscall interception, register context bridge. | Linux syscall behavior to syscall dispatcher. |
| Syscall dispatcher | Syscall table, Linux ABI structs, errno mapping, argument validation, dispatch tracing. | File, process, network, and sync behavior to owned subsystems. |
| VFS | Linux path semantics, rootfs jail, virtual inode model, fd table, metadata sidecar, procfs/devfs nodes. | Host file operations to Windows file adapter. |
| Process and sync | Guest PID/TID, task lifecycle, `fork+exec` fast path, `wait4`, signals skeleton, process-private futex. | Host threads and wait primitives to Windows sync adapter. |
| Network and eventing | Linux/POSIX socket syscall ABI compatibility, guest socket fd objects, socket readiness, and level-trigger `poll`/`epoll` compatibility. | Winsock, `std::net` only where it preserves ABI semantics, WSAPoll, and later IOCP to Windows net adapter. |
| Windows adapters | Narrow wrappers over Win32/NT capabilities. | Nothing upward; adapters expose host capability, not Linux policy. |

## Module Map

The planned Rust workspace uses package names that match subsystem boundaries.
Current deviations from this map are tracked in
[Architecture debt and planned fixes](#architecture-debt-and-planned-fixes).

| Package | Responsibility |
|---|---|
| `mcr-cli` | User-facing `mcr run-rootfs` and smoke commands. |
| `mcr-runtime` | Container/session lifecycle and subsystem wiring. |
| `mcr-memory` | Guest memory manager, VMAs, mmap/mprotect/brk, COW clone strategies, and guest memory access traits. |
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
| Guest memory map | `mcr-memory` | VMAs are Linux concepts mapped onto host memory allocations; `mcr-elf` supplies the initial image plan. |
| Guest FS base | `mcr-task` and execution core | `arch_prctl` updates per-task guest TLS state; host Rust TLS is not guest truth. |
| Syscall ABI table | `mcr-sys` | Syscall numbers, argument decoding, and errno conversion live here. |
| Socket readiness | `mcr-net` | Exposes the documented level-trigger readiness subset over host Winsock/readiness helpers; IOCP is a later performance backend, not the guest-visible model. |
| Host handles | `mcr-win` adapters | Handles must not leak into Linux-facing types. |
| OCI blobs and descriptors | `mcr-image` | Content-addressed blobs are keyed by digest and never by mutable tags. |
| Build snapshot roots | `mcr-snapshot` | Build layers are derived from explicit lower/upper state, not host directory diffs alone. |
| Dockerfile build graph | `mcr-build` first, BuildKit later | Native builder owns the first constrained graph; BuildKit owns LLB solving after the worker exists. |

## Architecture Debt And Planned Fixes

A 2026-07-05 architecture review confirmed that the subsystem boundary
discipline holds (no Linux errno or host handles leak through `mcr-win`, no
`unsafe` or direct Windows API use outside `mcr-win`), but recorded the
following structural debt. Each item has an explicit task in
`docs/plan/tasks/`; fixes must keep guest-visible syscall, fd, task, VFS, and
socket contracts stable.

| Debt | Planned fix | Task |
|---|---|---|
| `mcr-runtime` owns subsystem internals (native patch pipeline, file/network syscall bodies, poll/select decode) instead of only lifecycle and wiring. | Guest memory manager extracted to `mcr-memory`; continue thinning runtime modules back to wiring. | `arch-001` |
| `RuntimeSubsystems` aggregates 20+ unrelated state fields as one god-object. | Split into cohesive process-table, native-execution, and event state groups. | `arch-002` |
| One global "selected" process context; switching guest processes clones or remaps the whole `GuestMemory` and fd table. | Per-process state ownership so scheduling switches references, not memory contents. | `arch-003` |
| Guest ABI struct codecs (`pollfd`, iovec, sockaddr, `timespec`) are duplicated across runtime modules, and runtime re-implements ELF program-header parsing next to `mcr-elf`. | One guest ABI codec layer owned by `mcr-sys`; runtime reuses `mcr-elf` for ELF views. | `arch-004` |
| Two independent Linux errno mappings exist (`mcr-vfs` `VfsError::linux_errno`, `mcr-net` `LinuxErrno` + host-error mapping). | Single host-error-to-errno mapping owned by `mcr-sys`. | `arch-005` |
| `mcr-net` depends on `mcr-task` only for the host worker pool executor. | Move the host worker pool below subsystem policy into `mcr-win`. | `arch-006` |
| Native patch scanning, caching, and application live in `mcr-runtime` while instruction analysis lives in `mcr-jit`. | Consolidate the native patch pipeline behind the `mcr-jit` boundary. | `arch-007` |
| `mcr-win` carries mistakenly added non-Windows backends and stubs (including a Linux `libc` backend). | Windows x86-64 is the only supported host; delete non-Windows backends. | `win-002` |
| Syscall trace decoding allocates on every syscall even when tracing is off, and interpreter-fallback frequency is unmeasured. | Zero-cost disabled tracing plus fallback counters before deciding on a decoded-block cache. | `perf-025` |
| Guest I/O syscalls copy through per-call temporary buffers and read guest C-strings one byte per VMA lookup, even though guest memory is same-process host memory. | Safe borrowed guest-memory slice boundary in `mcr-memory` with the copy path as cross-VMA fallback. | `perf-026` |
| The scheduler clones full fd tables and rescans all tasks every iteration, and fd-blocked tasks are re-polled instead of event-woken. | Split-borrow the waiter check, incremental runnable/waiter tracking, and mutation-site fd readiness events. | `perf-027` |
| Any VFS write invalidates the whole cache via one global generation, directory listing scans every filesystem path, and deferred rootfs files fully materialize on first read. | Per-inode generations, per-directory child indexes, host handle cache, and read-through deferred files. | `perf-028` |
| Native execution reinstalls the vectored exception handler per execution slice, syscall descriptor lookup is a linear table scan, and `epoll_wait` rebuilds its watch list per call. | Process-lifetime handler install, direct-indexed dispatch table, cached epoll interest lists, batched `WSAPoll`. | `perf-029` |

The hot-path fixed costs are described in more detail in
[Performance optimization design](performance.md) under "Hot-Path
Constant-Cost Debt".

## Architecture Constraints

- The only supported host platform is Windows x86-64. Host adapter code must
  not grow non-Windows production backends or stubs; the remaining non-Windows
  compile-time branches in `mcr-win` were added by mistake and are scheduled
  for removal in `win-002`.
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
  guest-visible syscall, fd, task, VFS, and socket contracts stable. Selected
  shell/network latency paths are active milestone gates when they decide
  product viability, not only post-Phase-2 backend tuning.
- Through Phase 2, `poll` and `epoll` are level-trigger only; unsupported flags must fail intentionally instead of being accepted silently.
- Unsupported syscalls must be tracked and tested as unsupported behavior, not silently ignored.
- Build steps must call the same runtime executor as user-visible `run-rootfs` workloads.
- BuildKit integration must be an adapter over MCR executor, snapshot, content, and image contracts, not a forked implementation of those contracts.
