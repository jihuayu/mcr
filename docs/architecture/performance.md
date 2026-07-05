# Performance Optimization Design

## Purpose And Boundary

MCR's first performance goal is to prove that the Windows userspace Linux ABI
runtime can be valuable before the project broadens compatibility. This is not
a late tuning phase. Startup latency, cross-process pipe protocols, public
network metadata fetches, and native execution handoff costs must be measured
and fixed early when they threaten product value.

Performance backends remain implementation details behind the same syscall, fd,
task, memory, and readiness contracts documented in [Runtime design](runtime.md)
and [Network ABI design](networking.md).

The design targets trusted development workloads that are syscall-heavy,
I/O-heavy, or network-heavy, especially shell pipelines, `curl`, `git`, package
manager metadata fetches, and language runtime startup checks.

## Baseline Cost Model

The runtime pays overhead in four main places:

- every guest Linux `syscall` crosses the JIT/trampoline boundary, saves guest
  register state, decodes arguments, calls the Rust syscall dispatcher, maps the
  result back to Linux ABI registers, and resumes guest execution;
- file and network calls repeatedly copy Linux data structures into Windows
  structures and copy results back into guest memory;
- Phase 2 networking uses nonblocking Winsock plus `WSAPoll`/select-style
  readiness, which is correct but does not scale like a completion backend under
  high connection counts;
- process and thread creation on Windows is relatively expensive, so naive
  guest `fork`, `vfork`, `clone`, and shell command fan-out can dominate short
  workloads.

Fuse/WinFsp-style filesystem bridging is not treated as a primary performance
solution. It can help development convenience, but small-block forwarding,
extra copies, and context switching make it a poor substitute for an MCR-owned
VFS and Windows file adapter.

## Design Goals

1. Preserve Linux ABI behavior before optimizing host calls.
2. Keep host handles, Windows errors, and Winsock-specific state below MCR-owned
   fd, socket, process, and syscall abstractions.
3. Add measurements before and after each optimization so regressions are
   visible in smoke workloads and microbenchmarks.
4. Prefer backend swaps that keep existing guest contracts stable, such as
   replacing a readiness implementation with IOCP-fed readiness state.
5. Avoid optimizations that silently weaken fork, fd lifetime, close-on-exec,
   errno, path, or socket semantics.
6. Treat product-critical latency cliffs as milestone blockers, not as generic
   backlog items.

## Performance-First Viability Gate

Correctness remains mandatory, but a correct runtime that makes common
development commands feel unusable is not a viable product. The plan therefore
front-loads performance validation for the smallest workloads that expose the
highest-risk overhead:

- shell startup and short `sh -c` commands;
- cross-process pipe protocols such as `git` talking to `git-remote-https`;
- public-network metadata fetches with small payloads, especially `git
  ls-remote`;
- shallow clone and package-manager metadata paths;
- native execution patch/cache behavior for language runtime startup.

The initial public-network baseline proved why this gate exists: `curl
https://example.com` was about `1947ms`, while `git ls-remote
https://github.com/octocat/Hello-World.git HEAD` was about `114131ms`. That
shape pointed to runtime handoff overhead rather than network throughput alone.
`perf-015` closed the first product-value proof with opt-in summary tracing and
sticky scheduling. Sticky scheduling is now the default policy, with
`MCR_SCHED_STICKY=0` reserved for differential debugging. The 2026-07-04
release rerun measured `curl https://example.com` at `485.074ms` and
`git ls-remote` at `1872.576ms`; the direct trace reported zero scheduler
sleeps, with remap and pipe IPC still visible for later backend work. The
remap cost is now tracked as architecture debt: the single selected process
context clones or remaps guest memory on every cross-process switch, and
`arch-003` replaces it with per-process state ownership so scheduling switches
references instead of memory contents.

## Hot-Path Constant-Cost Debt

A 2026-07-05 hot-path review measured where the runtime pays fixed costs on
every syscall, every scheduler iteration, or every VFS operation regardless of
workload size. These are recorded as performance debt with owning tasks; fixes
must keep guest-visible syscall, fd, task, VFS, and socket contracts stable.

| Fixed cost | Where | Task |
|---|---|---|
| Guest I/O syscalls allocate a temporary `Vec` per call and copy guest -> buffer -> backend -> buffer -> guest, even though guest memory is same-process host memory. | `mcr-runtime` filesystem syscall bodies | `perf-026` |
| Guest C-string reads do one full VMA lookup per byte for every path-taking syscall. | `mcr-memory` access trait | `perf-026` |
| Every scheduler iteration clones the selected process `FdTable` plus the whole per-process fd-table map to poll fd waiters, and rescans all tasks into fresh `Vec`s. | `mcr-runtime` scheduler loop, `mcr-task` wait kernel | `perf-027` |
| Fd-blocked tasks are re-polled each iteration instead of being woken by pipe/socket mutation events that the VFS already signals internally. | `mcr-runtime`, `mcr-vfs` | `perf-027` |
| Any regular-file write invalidates the entire VFS metadata/directory/small-read cache through one global generation. | `mcr-vfs` cache | `perf-028` |
| Listing one directory scans every path in the filesystem; host-backed reads reopen the host file per call; deferred rootfs files fully materialize into resident memory on first read. | `mcr-vfs` path tree and I/O helpers | `perf-028` |
| Native execution installs and removes the vectored exception handler on every execution slice, and syscall descriptor lookup linearly scans the dispatch table per syscall. | `mcr-win` native execution, `mcr-sys` dispatcher | `perf-029` |
| `epoll_wait` clones the watch list per call, and poll/select can issue one host poll per socket fd instead of one batched `WSAPoll`. | `mcr-runtime` event subsystem | `perf-029` |

The zero-copy borrow boundary in `perf-026` is the widest lever: it converts
the dominant read/write shape from one allocation plus two copies into direct
slice access for contiguous VMA ranges, with the existing copy path kept as
the cross-VMA and permission-fault fallback.

## File And I/O Optimization

### Async Host I/O

Regular files, pipes, and anonymous file-like objects should gain a Windows
overlapped I/O backend after the synchronous VFS semantics are stable. The
adapter may use `ReadFile`, `WriteFile`, events, thread-pool I/O, or IOCP, but
guest `read`, `write`, blocking, nonblocking, timeout, interruption, and close
behavior remains owned by the runtime wait loop.

The immediate objective is to avoid parking host worker threads inside blocking
Windows I/O calls when the guest operation can be represented as a pending MCR
waitable operation.

The first checkpoint keeps the synchronous backend in place and introduces the
`mcr-win` host submission boundary. `HostFile::submit_overlapped_read` and
`HostFile::submit_overlapped_write` return an owned submission that is either
completed, pending, or explicitly routed through a synchronous fallback. Pending
records own their buffer until completion or cancellation drain, and fallback
failures return the same host adapter error shape that the existing synchronous
file adapter uses. A later checkpoint can open compatible Windows handles with
overlapped flags and attach events, thread-pool I/O, or IOCP without changing
the VFS/runtime errno boundary.

### Vector And Scatter/Gather I/O

Linux `readv`, `writev`, `sendmsg`, and `recvmsg` should avoid per-buffer host
calls where Windows exposes a compatible vector interface:

- file paths can use scatter/gather-capable Windows APIs only when alignment,
  lifetime, and file-handle constraints are satisfied;
- socket paths should use `WSABUF` with `WSASend`, `WSARecv`, `WSASendMsg`, and
  `WSARecvMsg` where this preserves Linux message and ancillary-data behavior;
- fallbacks must keep the current copy-in/copy-out behavior rather than exposing
  host buffers directly to guest memory.

The socket scatter/gather path is implemented through the `mcr-net` vectored
transport boundary and the Windows socket adapter. Runtime socket `readv`,
`writev`, `sendmsg`, and `recvmsg` route guest iovecs into a single vectored
socket-table operation. The default host-handle fallback still copies through a
temporary buffer for non-Windows or test handles, while `WinHostSocketHandle`
uses `WSASend`, `WSARecv`, `WSASendTo`, and `WSARecvFrom` with `WSABUF`
vectors under the same Linux message and errno contract.

### Metadata And Directory Caches

The VFS should cache Linux inode attributes, directory iteration state, and
small immutable reads where invalidation is well-defined. This targets repeated
`statx`, `newfstatat`, `getdents64`, and config-file reads during process and
package-manager startup.

Cache entries must use guest inode identity and VFS generation state, not host
path strings alone. Mutating syscalls such as `openat` with write intent,
`unlinkat`, `renameat2`, `ftruncate`, chmod/chown-like changes, and metadata
sidecar writes must invalidate affected entries.

The first VFS cache checkpoint keeps this boundary narrow: `mcr-vfs` maintains
an inode-and-generation keyed metadata cache plus a small regular-file read
cache. Any successful VFS mutation that can affect attributes, links, paths, or
file contents advances the generation and drops cached entries. Directory
listing cache entries are also keyed by inode and generation, store immutable
listing snapshots, and hand shared entries back to callers on cache hits.

### File Mapping

Executable files, shared libraries, and read-only data should prefer host-backed
file mappings where that preserves MCR's guest VMA model. The runtime should use
lazy population and copy-on-write for private writable mappings so repeated
`execve` and supported `fork+exec` paths avoid unnecessary copies.

The first reusable boundary caches immutable private file-mapping payloads by
regular-file inode, VFS generation, file offset, and requested mapping length.
The cache lives above the VFS and below guest memory materialization: it never
exposes host paths or handles, writes cached bytes into each guest VMA with the
requested permissions restored afterward, and bypasses reuse for initially
writable private mappings.

Process-memory clones reuse non-writable host allocations in flexible-address
mode. When a later write, `mprotect`, or native patch mutates a shared range,
the runtime splits the affected guest VMA range at page boundaries, copies only
the touched pages into a private host allocation, and leaves untouched pages
shared. Fixed-address native memory keeps the conservative allocation-level
copy path because those allocations must preserve guest virtual address
placement.

### Rootfs Startup

`run-rootfs` must not copy every regular file in a package rootfs before the
initial guest executable can run. Rootfs loading should register directory,
symlink, metadata, and host-backed regular-file nodes first, then materialize
regular-file bytes only when a readable fd is opened. The initial checkpoint
keeps writes isolated by materializing a deferred file into the in-memory VFS
before truncation or write paths mutate it.

## Network Optimization

### IOCP Backend

The long-term network backend should use overlapped Winsock sockets registered
with IOCP through `CreateIoCompletionPort`. Worker threads can drain batches via
`GetQueuedCompletionStatusEx`, translate completions into socket state changes,
and feed MCR's readiness queue.

IOCP remains a backend, not the guest model. Guest `select`, `poll`, and
level-trigger `epoll` must continue to observe Linux readiness semantics,
including fd generation checks, close wakeups, timeout behavior, and
Linux-compatible errno mapping.

The first readiness checkpoint establishes the backend contract without
switching sockets to IOCP yet: host completion classes map to `SocketEvents`,
`mcr-net` associates completions with a socket readiness token and generation,
and the semantic `WSAPoll` path remains the fallback when no completion-backed
readiness is available. The full backend still needs overlapped operation
ownership, IOCP registration, worker draining, cancellation, and differential
tests against the fallback path.

### AcceptEx And ConnectEx

`AcceptEx` and `ConnectEx` should be added after the IOCP socket lifetime model
is in place. They can reduce accept/connect round trips and prepare buffers or
addresses in one operation. Successful completions must apply
`SO_UPDATE_ACCEPT_CONTEXT` or `SO_UPDATE_CONNECT_CONTEXT` before guest-visible
address and option queries.

The nonblocking `connect` state machine still reports guest success through the
Linux socket state and `SO_ERROR` equivalent, even if IOCP completion is the
host notification source.

The first checkpoint adds the adapter boundary without binding to the real
Windows extension functions. Host socket handles can return unsupported and keep
the plain fallback paths, or submit pending `AcceptEx`/`ConnectEx` work that
feeds the existing readiness-token cache with accept/connect completions. The
actual Winsock function lookup, overlapped buffer ownership, IOCP registration,
context update calls, cancellation, and A/B measurement remain separate backend
work.

### Registered I/O

Registered I/O (RIO) is a later optional backend for small-message workloads.
It should not be mixed into the first IOCP pass. A future RIO task must prove
that registered buffer ownership, cancellation, and completion semantics can be
hidden behind MCR's socket object and Linux errno model.

The 2026-07-04 `perf-008` decision closes RIO as backlog-only until IOCP
measurements show a small-message datagram bottleneck and a RIO prototype proves
enough benefit to justify Windows-only buffer and lifetime complexity.

### DNS And Connection Reuse

DNS caching is allowed only where MCR owns the resolution path, such as a
runtime DNS proxy or resolver helper. Entries must respect TTLs and be scoped to
the guest network configuration represented by `/etc/hosts`, `/etc/resolv.conf`,
and `/etc/nsswitch.conf`.

Generic TCP or TLS connection pooling is not a transparent socket ABI
optimization. The guest owns socket creation, TLS state, shutdown, and fd
lifetime, so MCR must not silently reuse connections between unrelated guest
sockets. Reuse can be considered only for future MCR-owned helper protocols, not
for arbitrary guest sockets.

## Fork, Exec, And Task Optimization

### Fork+Exec Fast Path

The common shell path should optimize guest `fork`/`vfork` followed immediately
by `execve`. When the runtime can prove the child will replace its image before
observing divergent parent memory, it should create or reuse the target guest
process state directly, load the new ELF, reconstruct inherited fd state from
the MCR fd table, and avoid copying parent memory.

The fast path must preserve guest PID/TID behavior, parent/child wait state,
close-on-exec, inherited cwd/root/env where applicable, and error reporting when
`execve` fails.

The first checkpoint keeps that optimization narrow. Fork-like syscalls create
the child task, wait state, and cloned fd table immediately, but the runtime
marks the child memory as deferred instead of copying the parent address space.
If the child reaches `execve` through read-only setup code, the runtime reads
the exec arguments from parent memory while the deferred snapshot invariant still
holds, loads the new image directly into the child process, and applies
close-on-exec to the child fd table. If the parent is about to mutate memory, if
the child writes memory before exec, if the child uses a non-exec syscall, or if
`execve` fails, the runtime materializes the child memory from the parent before
continuing. This keeps parent memory
uncorrupted and preserves the existing wait/exit fallback behavior.

### Posix-Spawn-Like Path

Where libc or toolchains express process creation as `posix_spawn`-like
behavior, MCR should map it to the same direct exec path rather than forcing a
full fork emulation. This is a semantic optimization of the supported process
contract, not a new guest-visible API.

### Clone And Vfork Fast Paths

Thread-like `clone` should reuse a host worker thread where the flags describe
the supported shared-memory, shared-fd task subset. Guest PID/TID, TLS, robust
list, clear-child-tid, and exit semantics remain MCR state.

Full copy-on-write fork without immediate exec stays a later compatibility item
unless a required smoke workload proves it is necessary. Manual copy-on-write
guest address spaces are a long-term memory-manager optimization, not a Phase 2
performance shortcut.

### Worker Pools

MCR should use bounded host worker pools for guest tasks and I/O completions so
high-concurrency workloads do not repeatedly call `CreateThread`. Worker pools
need cancellation, teardown, and priority rules compatible with guest wait and
exit behavior.

The first checkpoints add the diagnostics-visible boundary without changing
guest scheduling. `mcr-task` owns bounded pool configuration records for guest
task execution and I/O completion work. Runtime diagnostics capture each pool's
role, maximum workers, queue capacity, active workers, queued jobs, and
submission/completion/rejection counters.

`mcr-task` also owns a bounded submission boundary that starts work while a role
has idle worker slots, queues accepted work up to the configured capacity, and
rejects later submissions with observable counters. This is still a synchronous
host-side boundary; guest scheduling and I/O are not routed through the pool
until a later checkpoint wires cancellation, teardown, and wait semantics.

Prestarted process workers are a speculative later optimization. They must not
break the current one-host-process-per-container boundary unless a separate
design changes that boundary.

## Syscall Translation And JIT Optimization

### Native Same-ISA Execution

For Windows x86-64 hosts running Linux x86-64 guests, hot basic blocks that do
not need syscall or fault intervention should run through same-ISA native
execution or re-emission rather than instruction-by-instruction interpretation.
The execution core returns to the runtime at syscalls, unsupported instructions,
guard pages, faults, and cross-page control-flow boundaries that require MCR
policy.

Hot-path selection must be measurement-driven and guarded by correctness checks
for guest memory permissions, FS-base/TLS behavior, and crash diagnostics.

### Libc Intrinsics

Common pure functions such as `memcpy`, `memset`, `memchr`, `memcmp`, and
`strlen` may be replaced with host implementations only after the runtime can
identify the target safely and prove that guest memory access checks, signal or
fault behavior, and overlap semantics match the Linux-visible contract.

This is optional and should follow native execution and syscall fast paths.

The native-mode implementation uses the same trap shape as syscall patching.
For executable file-backed mappings, runtime scans ELF64 `.dynsym` metadata,
maps recognized libc symbols through the `PT_LOAD` load bias, and registers
process-local intrinsic traps only when the target address falls inside the
new executable mapping. The trap handler validates guest memory through the
normal runtime paths and preserves routine-specific overlap behavior.

### Fast Syscalls

Small, frequent syscalls with no guest memory side effects should gain a fast
dispatcher path after tracing and diagnostics are preserved. Candidates include
`getpid`, `gettid`, selected clock queries, `uname`, and other compatibility
queries that return MCR-owned state.

The first fast path is deliberately narrow: `getpid` and `gettid` bypass the
general subsystem routing path, but still emit the normal structured enter and
exit trace events and encode Linux ABI return values through `SyscallReturn`.
Guest-memory-copying calls, including clock queries that write `timespec`
structures, stay on the regular dispatcher path.

I/O syscalls may get lighter argument decode and errno mapping paths, but they
must still copy guest structures safely and route through the owning subsystem.

### Caches And Reuse

The JIT should cache translated or patched executable ranges and share immutable
entries across tasks running the same mapped code where invalidation is clear.
The syscall layer should avoid repeated dynamic allocation and table lookups on
hot paths, but the syscall table remains the source of truth for number, name,
argument, trace, and unsupported behavior.

Native same-ISA syscall patching keeps a per-process record of executable ranges
already scanned. New ranges are read once to derive both syscall trap patches and
Windows FS-relative TLS patch candidates. The syscall scanner first checks for
the `0f 05` byte pair and skips the decoder entirely for candidate-free ranges;
when candidates exist, decoding stops after the last candidate so large package
binary tails are not walked after the final possible `syscall`.

Windows FS-relative TLS patching records candidates separately from materializing
rewrites. When the guest FS base is zero, newly discovered candidates stay in the
cache but are not rewritten back to their original bytes, avoiding no-op patch
work for large binaries. When the FS base is unchanged and only new executable
ranges appear, only the new candidates are materialized; a real FS-base change
still rewrites the full candidate set to preserve guest TLS semantics. Batched
code patching groups fixed-width rewrites by host allocation so large syscall or
TLS patch sets do not repeatedly toggle the same executable mapping's
protection for each candidate.

Native fault diagnostics include the faulting instruction bytes, a decoded
instruction summary, the guest FS base, registers, and stack words. These
diagnostics are part of the performance boundary because they distinguish
patch-cache throughput regressions from same-ISA execution correctness blockers,
such as FS-relative TLS instructions whose guest FS base cannot be encoded by
the current fixed-width absolute rewrite.

When Windows native execution faults on an original FS-relative instruction that
could not be rewritten into the fixed-width absolute form, the runtime now uses
a narrow interpreted fallback. It preserves native floating-point state, seeds
the same-ISA execution core with the guest FS base, executes the current block
until the next syscall through the JIT memory operand path, and then resumes the
normal syscall return flow. This keeps high-address TLS loads correct without
turning unsupported native execution faults into a broad interpreter escape.

## Measurement Gates

Each performance task must add or update an observable benchmark or smoke gate.
At minimum, the plan needs:

- syscall microbenchmarks for fast-path candidates;
- file metadata, directory iteration, small-read, and vector-I/O microbenchmarks;
- shell `fork+exec+wait4` startup measurements;
- network throughput and latency checks for `curl`, `git ls-remote`, package
  manager metadata fetches, and high-concurrency loopback sockets;
- before/after reporting that can run locally where possible and in the
  x86-64 smoke workflow where guest execution requires it.

Correctness tests remain required. A faster backend that fails Linux ABI
compatibility is not acceptable.

## Repeatable Baseline Harness

`perf-001` introduces a baseline harness before any backend tuning. The harness
prints a line-oriented `mcr_perf_baseline.version=1` report with environment
metadata, wall-clock milliseconds, operation counts, and derived operations per
second for each measured path.

The first baseline suites are intentionally split by subsystem boundary:

- `mcr-runtime` measures synthetic guest syscall dispatch and
  `fork+execve+wait4` process startup paths through `run_rootfs`;
- `mcr-vfs` measures local small-file create/write/read/close loops and
  directory `getdents64` plus per-entry `statx` walks;
- `mcr-net` measures high-concurrency loopback accept/recv/send behavior through
  `WinHostSocketTransport` plus DNS cache insert, lookup-hit, and expiry-purge
  costs for the MCR-owned resolver boundary;
- `mcr-task` measures bounded worker-pool diagnostics snapshots without routing
  real guest scheduling or I/O submissions through the pool boundary;
- `mcr-testkit` measures guest shell startup, small-file I/O, directory
  metadata walks through the materialized Alpine rootfs and `MCR_BIN`; the
  public-network `curl` and `git ls-remote` measurements are opt-in with
  `MCR_PERF_PUBLIC_NETWORK=1`, while the `perf_dns`, `perf_worker_pool`, and
  intrinsic filters provide task-specific host-only reports for active perf
  checkpoints.

These suites started as baselines, not performance assertions. For
product-critical paths, that is no longer enough. `perf-015` promoted selected
shell/network metadata measurements into a viability gate: the benchmark still
reports raw wall time and operation counts, but the task may block milestone
progress when the runtime remains orders of magnitude slower than the host for
small payloads. `perf-024` extends that model across the local subsystem
baselines and release guest workloads. `MCR_PERF_ENFORCE_GATES=1` enforces the
stored local thresholds, and public-network thresholds for `curl`,
`git ls-remote`, and shallow `git clone` are opt-in with
`MCR_PERF_ENFORCE_PUBLIC_NETWORK=1` to avoid failing normal runs on network
variance.
