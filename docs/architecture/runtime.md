# Runtime Design

## Execution Model

MCR runs Linux x86-64 guest code inside a Windows x86-64 host process. Guest code must not execute a Linux `syscall` instruction directly against the Windows kernel. The JIT/trampoline layer owns the guest instruction stream and diverts syscalls into the MCR syscall dispatcher.

```text
ELF file
  -> map PT_LOAD segments
  -> build Linux initial stack
  -> enter translated/re-emitted basic block
  -> intercept syscall
  -> dispatch Linux syscall
  -> return Linux ABI result to guest registers
```

## ELF Loader

The loader owns:

- ELF64 header and program-header validation;
- `PT_LOAD` mapping with Linux-like permissions;
- interpreter detection for dynamic binaries, with MVP allowed to start on static BusyBox first;
- Linux initial stack layout: `argc`, `argv`, `envp`, and `auxv`;
- `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_ENTRY`, `AT_RANDOM`, `AT_EXECFN`, and architecture entries needed by musl/glibc paths;
- initial `brk`, stack, and VMA registration.

MVP acceptance can use static BusyBox first. Dynamic Alpine support becomes required before Phase 2 completion because shell and language toolchains need it.

## JIT And Syscall Interception

The first implementation should prefer same-ISA re-emission over cross-architecture emulation.
The runtime is not expected to grow into a full x86-64 instruction interpreter
to make x86 guests pass on non-x86 hosts. When a smoke requires Linux x86-64
guest execution, validate it on a Windows x86-64 runner or in an x86-64
VM/container, including QEMU-backed environments when the developer host is
ARM.

Required behavior:

- decode x86-64 guest basic blocks with `iced-x86`;
- identify `syscall` instructions;
- replace syscall entry with a trampoline that saves guest register state;
- call the Rust syscall dispatcher with a typed `GuestContext`;
- restore guest registers with Linux ABI return conventions;
- report unsupported or invalid instruction paths with crash diagnostics.

The JIT layer does not implement syscall semantics. It only controls execution and preserves guest CPU state.
Small decoded-instruction helpers may exist for unit coverage and trampoline
bookkeeping, but adding broad instruction semantics as a cross-architecture
emulation strategy is outside this plan.

## Syscall Dispatcher

The dispatcher owns syscall number routing, argument decoding, result encoding, and tracing.

P0 syscalls for MVP:

| Group | Syscalls |
|---|---|
| Exit | `exit`, `exit_group` |
| Basic IO | `read`, `write`, `readv`, `writev`, `close`, `lseek` |
| File open/stat | `openat`, `fstat`, `newfstatat`, `statx`, `access`, `readlink` |
| Directory | `getdents64` |
| Memory | `mmap`, `munmap`, `mprotect`, `brk` |
| Time/random | `clock_gettime`, `nanosleep`, `getrandom` |
| Identity | `getpid`, `gettid`, `uname`, `arch_prctl` |
| Exec | `execve` |

Phase 2 syscalls:

| Group | Syscalls |
|---|---|
| fd management | `dup`, `dup2`, `dup3`, `fcntl`, selected `ioctl` |
| Pipes | `pipe`, `pipe2` |
| Task lifecycle | `clone` thread subset, `fork`/`vfork` fast-path behavior, `wait4`, `set_tid_address`, `set_robust_list` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `kill`, `tgkill` |
| Sync | `futex` `WAIT`/`WAKE` for process-private futexes |
| Network | TCP-first `socket`, `connect`, selected `bind`/`listen`/`accept`, stream `sendmsg`/`recvmsg`, `getsockopt`, `setsockopt`, `shutdown` |
| Events | `poll`, `ppoll`, `epoll_create1`, `epoll_ctl`, `epoll_wait` |
| File mutation | `mkdirat`, `unlinkat`, `renameat2`, `symlinkat`, `linkat`, `ftruncate`, `getcwd`, `chdir`, `umask` |

Unsupported syscalls must return intentional Linux errors such as `ENOSYS` or documented compatible fakes.

## Guest Process And Task Model

Through Phase 2, one Windows host process owns one guest container. Guest processes and threads are runtime objects.

```rust
type GuestPid = u32;
type GuestTid = u32;

struct GuestProcess {
    pid: GuestPid,
    parent: Option<GuestPid>,
    pgid: GuestPid,
    sid: GuestPid,
    mm: MmSpace,
    files: Arc<FdTable>,
    fs: FsContext,
    signals: SignalState,
    children: BTreeSet<GuestPid>,
    exit_state: ExitState,
}

struct GuestTask {
    tid: GuestTid,
    pid: GuestPid,
    regs: GprState,
    tls: TlsState,
    state: TaskState,
    host_thread: Option<HostThreadId>,
    robust_list: Option<u64>,
    clear_child_tid: Option<u64>,
}
```

Required semantics:

- `getpid` and `gettid` return guest IDs;
- fd tables are guest state and support `CLOEXEC`;
- `execve` replaces guest memory and argv/env while preserving process identity;
- `fork+exec` is optimized as a common shell path;
- full copy-on-write `fork` without immediate exec is explicitly not required for Phase 2 unless needed by a smoke workload;
- `wait4` observes guest child exit state;
- signals can be skeletal but must support common install, mask, interrupt, and termination paths.

## Guest TLS And `arch_prctl`

Guest thread-local storage is Linux ABI state, not host Rust TLS.

Required Phase 2 behavior:

- support `ARCH_SET_FS` and `ARCH_GET_FS` for per-task FS base state;
- preserve FS base across syscall dispatch and task scheduling;
- reset FS base on `execve` according to the newly loaded image and dynamic linker path;
- copy or initialize FS base intentionally for the supported `fork`/`vfork`/`clone` paths;
- make same-ISA native execution and any re-emitted guest code observe guest FS-relative memory accesses;
- return explicit Linux errors for unsupported `arch_prctl` operations.

Rust `thread_local!`, host thread-local APIs, and host TLS slots may be used only as implementation details. They must not become guest-visible TLS semantics.

## Futex And Synchronization

Phase 2 supports process-private futex behavior only.

Required behavior:

- `FUTEX_WAIT` checks the guest memory value before sleeping;
- `FUTEX_WAKE` wakes up to the requested number of waiters;
- timeout and interrupt paths produce Linux-compatible results;
- implementation maps to `WaitOnAddress` and `WakeByAddress*` only while all guest tasks share one host process;
- process-shared futex is deferred and must not be accidentally advertised.

## VFS And File Descriptor Model

The VFS owns Linux path and inode semantics. Host paths are backend storage, not guest identity.

```rust
type Fd = i32;
type InodeId = u64;

struct FdTable {
    entries: BTreeMap<Fd, FileRef>,
    cloexec: BitSet,
}

struct Inode {
    id: InodeId,
    attr: LinuxStat,
    backend: InodeBackend,
    link_count: u32,
}

enum InodeBackend {
    HostPath(HostPathRef),
    ProcVirtual(ProcNode),
    DevVirtual(DevNode),
    Pipe(PipeNode),
    Socket(SocketNode),
}
```

Required semantics:

- Linux path canonicalization for `/`, `.`, `..`, symlink traversal, cwd, and rootfs jail;
- Linux errno mapping for missing, denied, not-directory, loop, and invalid path cases;
- fd allocation, `dup`, `dup2`, `dup3`, `CLOEXEC`, and close-on-exec;
- metadata sidecar for guest mode, uid, gid, and timestamps when host metadata cannot represent Linux semantics;
- delayed unlink and rename behavior for Linux delete-while-open compatibility;
- `getdents64` produces Linux directory entries.

Overlay and OCI whiteout are deferred to the builder phase, but VFS must not choose designs that block lower/upper layer support.

## Minimal Procfs And Devfs

Phase 2 requires:

| Node | Behavior |
|---|---|
| `/proc/self/exe` | Symlink-like view of the current guest executable. |
| `/proc/self/cmdline` | NUL-separated argv bytes. |
| `/proc/self/environ` | NUL-separated environment bytes. |
| `/proc/self/fd` | Directory exposing guest fd entries. |
| `/proc/self/fd/<n>` | Symlink-like target for files, pipes, sockets, and virtual nodes. |
| `/dev/null` | Discards writes and returns EOF on reads. |
| `/dev/zero` | Returns zero bytes. |
| `/dev/urandom` | Returns cryptographic random bytes from Windows RNG. |

`/proc`, `/sys`, tty, pty, and full device models are not required beyond these nodes.

## Networking And Eventing

MCR uses host networking and virtualizes the guest socket ABI.

The detailed network architecture is documented in
[Network ABI design](networking.md). This runtime section records only the
Phase 2 contract and subsystem placement.

The long-term networking boundary is Linux/POSIX socket syscall ABI
compatibility on top of Windows user-mode networking. It is not a thin
`winsock2.h` portability wrapper. Guest code sees Linux-style
`socket`/`accept4`/`connect`/`sendmsg`/`poll`/`epoll`/`close`/`read`/`write`
semantics, while Windows `SOCKET` values remain hidden behind MCR-owned guest fd
objects.

```text
guest syscall ABI
        |
        v
syscall decoding and guest struct conversion
        |
        v
Linux fd table and open object table
        |
        +--> socket object -> Winsock adapter
        +--> epoll object  -> readiness backend
        +--> pipe/eventfd/timerfd objects as they land
        |
        v
Windows backends: Winsock + WSAPoll/select MVP, later IOCP
```

Required design rules:

- guest fd allocation stays in the shared MCR fd namespace; never return a
  Windows `SOCKET` or host handle as a guest fd;
- `FD_CLOEXEC` is fd-entry state, while `O_NONBLOCK` belongs to the shared open
  socket object so `dup` aliases observe the same nonblocking mode;
- syscall handlers must copy guest socket structs and iovecs into host structs,
  validate lengths and flags, call the host adapter, then copy translated
  results back to guest memory;
- errno mapping is owned above Winsock, and `WSAGetLastError` values must never
  leak into guest-visible results;
- close, poll, epoll, and fd reuse paths need object lifetime and generation
  checks so a reused integer fd cannot satisfy an old readiness watch;
- the semantic-first backend uses nonblocking Winsock sockets plus runtime wait
  loops and `WSAPoll`/select-style readiness. IOCP, `AcceptEx`, and `ConnectEx`
  are deferred performance backends behind the same socket/readiness contracts.

Phase 2 networking includes:

- AF_INET and AF_INET6 `SOCK_STREAM` TCP client sockets;
- connected stream `sendto`, `recvfrom`, `sendmsg`, and `recvmsg` behavior over the MCR fd table;
- selected loopback `bind`, `listen`, and `accept` behavior only when needed by smoke tests;
- DNS resolution compatible with common libc resolver flows by exposing guest-visible
  `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, and UDP datagram sockets;
  Phase 2 does not add a separate runtime-only host resolver ABI;
- AF_UNIX if available on the target Windows version;
- `getsockopt` and `setsockopt` cases required by curl/git/language runtimes;
- explicit unsupported results for raw sockets, packet sockets, network namespaces, and UDP behavior outside the DNS path.

Rust `std::net` and Windows networking APIs are valid host backends, but Linux-visible fd allocation, socket flags, sockaddr layout, errno mapping, nonblocking behavior, and close-on-exec state remain owned by MCR.

`poll` and `epoll` expose a level-trigger Linux readiness subset over Windows host mechanisms.

Deferred or partial areas include AF_UNIX fidelity, `SCM_RIGHTS`, raw sockets,
advanced multicast options, `SO_REUSEPORT`, `recvmmsg`/`sendmmsg`, fork-time
socket inheritance, cross-process fd passing, and IOCP-backed high-concurrency
readiness. Unsupported pieces must fail intentionally with Linux-compatible
errors rather than silently accepting flags or options.

Phase 2 eventing includes:

- readiness for TCP sockets, pipes, stdio, proc/dev virtual nodes, and internal runtime wakeups;
- `POLLIN`, `POLLOUT`, `POLLERR`, `POLLHUP`, and matching epoll event bits needed by the smoke matrix;
- timeout behavior for `poll`, `ppoll`, and `epoll_wait`;
- explicit `EINVAL` or documented Linux-compatible errors for edge-triggered epoll, one-shot watches, exclusive watches, signal-mask waits beyond the supported subset, and unsupported fd types.

Implementation order:

1. Build a simple level-trigger readiness model with Winsock/`std::net` helpers and `WSAPoll` where useful.
2. Feed socket, pipe, procfs/devfs, stdio, and internal wakeups into one runtime ready queue.
3. Implement `epoll_create1`, `epoll_ctl`, and `epoll_wait` over that ready queue.
4. Defer IOCP optimization until after Phase 2 smoke tests are stable.

## Windows Host Adapters

Windows-specific APIs stay in `mcr-win`.

Windows x86-64 is the only supported host platform. `mcr-win` must contain
Windows backends only: the non-Windows compile-time stubs and the Linux `libc`
backend that accumulated in this crate were added by mistake, are not a
supported execution or test path, and are scheduled for removal in `win-002`.
CI and smoke validation run on Windows x86-64 runners.

| Adapter | Host APIs |
|---|---|
| Memory | `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, exception handling hooks. |
| File | `CreateFileW`, `ReadFile`, `WriteFile`, `SetFileInformationByHandle`, `ReplaceFileW`, symlink/hardlink helpers. |
| Sync | `WaitOnAddress`, `WakeByAddressSingle`, `WakeByAddressAll`, waitable timers. |
| Network | Winsock, `std::net` where useful, `WSAPoll`, later IOCP. |
| Process control | Host thread creation, Job Objects for cleanup and coarse resource handling. |

Adapters return host-level errors to callers; Linux errno conversion happens above them in owning subsystems.

## Diagnostics

Every smoke failure must be debuggable from structured logs.

Required trace fields:

- guest pid/tid;
- syscall name and number;
- raw arguments and decoded path/fd/socket details;
- Linux result or errno;
- host adapter error when one exists;
- guest instruction pointer for syscall and crash paths.

The crash report must include guest registers, mapped VMAs, current executable, argv, and last syscall.
