# Performance Optimization Design

## Purpose And Boundary

MCR's first performance goal is to reduce the overhead of the Windows userspace
Linux ABI runtime without changing guest-visible Linux semantics. Performance
backends are implementation details behind the same syscall, fd, task, memory,
and readiness contracts documented in [Runtime design](runtime.md) and
[Network ABI design](networking.md).

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

The first socket checkpoint establishes the `mcr-net` vectored transport
boundary before binding it to Winsock-specific calls. Connected stream and
addressed UDP paths can now route one message through a single vectored host
entry point; the default host-handle fallback still copies into or out of a
temporary buffer, while a future Windows adapter can replace that fallback with
`WSABUF` plumbing under the same socket contract.

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
iteration batching remains a later `perf-002` step.

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
writable private mappings until a real copy-on-write page backend exists.

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

### Registered I/O

Registered I/O (RIO) is a later optional backend for small-message workloads.
It should not be mixed into the first IOCP pass. A future RIO task must prove
that registered buffer ownership, cancellation, and completion semantics can be
hidden behind MCR's socket object and Linux errno model.

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
  `WinHostSocketTransport`;
- `mcr-testkit` measures guest shell startup, small-file I/O, directory
  metadata walks through the materialized Alpine rootfs and `MCR_BIN`; the
  public-network `curl` and `git ls-remote` measurements are opt-in with
  `MCR_PERF_PUBLIC_NETWORK=1`.

These suites are baselines, not performance assertions. They should fail only
when the measured workload itself fails. Thresholds, trend storage, and
regression budgets belong in later performance tasks after `workload-001` makes
the Phase 2 workload matrix stable.
