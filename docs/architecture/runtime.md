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

## Runtime Layering

The runtime is a userspace Linux kernel model, not a set of direct Windows API
shortcuts. The implementation is split across four layers:

| Layer | Responsibility |
|---|---|
| Host | Windows threads, memory protection, timers, files, sockets, and exception hooks as infrastructure only. |
| MCR runtime | Guest scheduler, syscall dispatch, signal delivery, futexes, VFS, memory, native patching, and diagnostics. |
| Guest kernel model | Linux process/thread state, address spaces, fd tables, signal dispositions, pending signals, and wait queues. |
| Guest application | Linux ELF code such as BusyBox, Node/V8, JDK, MySQL, Redis, and build tools. |

Linux-visible semantics must be owned by the runtime and guest-kernel model.
Windows thread, signal, and handle behavior may back an implementation detail,
but must not leak into guest-visible IDs, signal results, futex wakeups, fd
numbers, or errno values.

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
    signal_dispositions: Arc<SignalDispositions>,
    signal_mask_process_defaults: SignalState,
    process_pending_signals: SignalQueue,
    children: BTreeSet<GuestPid>,
    exit_state: ExitState,
    exit_group_state: Option<ExitStatus>,
}

struct GuestTask {
    tid: GuestTid,
    pid: GuestPid,
    regs: GprState,
    tls: TlsState,
    signal_mask: SigSet,
    thread_pending_signals: SignalQueue,
    state: TaskState,
    host_thread: Option<HostThreadId>,
    robust_list: Option<u64>,
    clear_child_tid: Option<u64>,
    waiting_on: Option<WaitObject>,
    interrupt_pending: bool,
}
```

Required semantics:

- `getpid` and `gettid` return guest IDs;
- fd tables are guest state and support `CLOEXEC`;
- `execve` replaces guest memory and argv/env while preserving process identity;
- `fork+exec` is optimized as a common shell path;
- full copy-on-write `fork` without immediate exec is explicitly not required for Phase 2 unless needed by a smoke workload;
- `wait4` observes guest child exit state;
- signal dispositions are process-shared, while signal masks and thread-pending signals are per task;
- `exit` terminates the current task, while `exit_group` terminates every task in the guest process;
- `set_tid_address` and `CLONE_CHILD_CLEARTID` write zero to `clear_child_tid` and wake the matching futex when a thread exits;
- robust-list cleanup must remain a first-class task-exit hook even when the first implementation supports only the subset needed by current workloads.

## Guest TLS And `arch_prctl`

Guest thread-local storage is Linux ABI state, not host Rust TLS.
On Linux x86-64, FS-relative memory operands are the normal TLS access path for
libc, libstdc++, V8, and language runtimes. Every guest task therefore owns an
FS base, and every instruction with an FS segment override must resolve through
that task's guest FS base. Host segment registers, host thread-local storage,
and Windows TEB/PEB state are implementation details only.

Required Phase 2 behavior:

- support `ARCH_SET_FS` and `ARCH_GET_FS` for per-task FS base state;
- preserve FS base across syscall dispatch and task scheduling;
- reset FS base on `execve` according to the newly loaded image and dynamic linker path;
- copy or initialize FS base intentionally for the supported `fork`/`vfork`/`clone` paths;
- classify every executable instruction whose memory operand uses the FS
  segment before same-ISA native execution can run that range;
- materialize only FS-relative forms whose replacement is proven correct for
  the current FS base and instruction length constraints;
- force every unmaterialized FS-relative site through a trap, marker, or
  interpreted execution path before the host CPU can execute it;
- make same-ISA native execution and any re-emitted guest code observe guest
  FS-relative memory accesses for loads, register stores, immediate stores,
  comparisons, tests, and arithmetic/logical memory operations;
- return explicit Linux errors for unsupported `arch_prctl` operations.

The native-patch pipeline may keep fast fixed-width absolute rewrites for common
forms such as `mov r64, fs:[disp32]`, but that optimization is not the semantic
boundary. The semantic boundary is: no unclassified or unhandled FS-relative
guest instruction may fall through to host native execution. Relying on a host
fault is not sufficient because an invalid guest TLS access may be a valid host
FS/GS address, or may read host TLS data before MCR can intervene. Native fault
fallback remains a diagnostic and recovery path for unexpected gaps, not the
primary FS/TLS interception mechanism.

The interpreter and any re-emitted block must compute FS-relative effective
addresses as `task.fs_base + signed_displacement`, then apply normal guest
memory permissions and Linux fault mapping. If a Windows host adapter can safely
install a zero or sentinel host FS/GS base for the native-execution window
without breaking the host thread runtime, it may do so as a hardening measure;
correctness must not depend on that guard.

Node/V8 is the gating workload for this boundary. V8 uses TLS slots to remember
per-thread executable-code write scopes and the JIT page mutex currently held by
that thread. A stale, host-routed, or partially emulated FS slot can make V8
attempt to unlock a mutex that the guest thread does not hold. The runtime must
preserve the full lock -> TLS slot nonzero -> unlock -> TLS slot clear lifecycle
before larger Node package workloads can be considered stable.

Rust `thread_local!`, host thread-local APIs, and host TLS slots may be used
only as implementation details. They must not become guest-visible TLS
semantics.

## Signal Delivery And Return-To-User

Signal handling is the primary compatibility boundary for language runtimes such
as Node/V8. The runtime must not treat `kill`, `tkill`, or `tgkill` as direct
host process actions. They enqueue Linux signals into process-level or
thread-level pending queues, then the runtime delivers them at Linux return
points.

Required signal model:

- signal dispositions from `rt_sigaction` are shared by the guest process;
- each task owns its signal mask, alternate signal stack state, and
  thread-pending signal queue;
- process-pending signals from `kill(pid, sig)` may be delivered to any
  unmasked task in the process;
- thread-pending signals from `tkill`, `tgkill`, `pthread_kill`, or native
  guest faults may be delivered only to the target task;
- standard signals coalesce while pending; real-time signal queuing is deferred
  until a workload requires it;
- fatal default actions such as `SIGABRT`, `SIGSEGV`, `SIGILL`, `SIGBUS`, and
  `SIGFPE` terminate the guest process unless a guest handler overrides them;
- stop/continue job-control signals may stay explicitly unsupported until pty
  and job-control support enter scope.

All paths that can enter guest code must call a single return-to-user delivery
hook before native execution or interpreted execution resumes:

- normal syscall return;
- syscall return after blocking wait wakeup;
- scheduler task switch to a runnable task;
- `rt_sigprocmask` changes that unblock pending signals;
- `rt_sigreturn` after restoring the saved context;
- first user entry of a newly cloned task.

The delivery hook selects a deliverable signal by checking thread-pending
signals before process-pending signals and by skipping signals blocked by the
task mask. When a handler is installed, the runtime builds an `rt_sigframe` on
the guest stack or signal alt stack, writes `siginfo_t` and `ucontext_t`, sets
`rdi/rsi/rdx` to Linux handler arguments, updates the task mask using the
action mask and `SA_NODEFER`, and jumps to the guest handler. `rt_sigreturn`
restores the saved registers and mask from the frame.

Blocking syscalls that Linux can interrupt must be represented as
interruptible waits. When a deliverable signal arrives, the runtime removes the
task from the wait queue, marks it runnable, returns `EINTR` or arranges a
restart according to the installed action and `SA_RESTART`, then lets the
return-to-user hook deliver the signal frame.

## Futex And Synchronization

Phase 2 supports process-private futex behavior first. The long-term futex
table must still have a shape that can represent process-shared futexes later.

Required behavior:

- `FUTEX_WAIT` checks the guest memory value before sleeping;
- `FUTEX_WAKE` wakes up to the requested number of waiters;
- timeout and interrupt paths produce Linux-compatible results such as
  `ETIMEDOUT`, `EAGAIN`, and `EINTR`;
- private futex keys include the guest address-space identity plus the guest
  address, so same-process threads synchronize on `(mm_id, uaddr)`;
- shared futex keys will need mapping identity plus offset; until implemented,
  process-shared futex behavior must fail intentionally rather than sharing on
  host virtual addresses;
- thread exit performs `clear_child_tid` zeroing and wakes the matching futex
  as part of the task-exit path used by pthread join;
- implementation may use `WaitOnAddress` and `WakeByAddress*` only while all
  guest tasks share one host process and the runtime still owns the Linux
  keying and wake semantics.

## Scheduler And Wait Loop

The scheduler owns guest task state transitions. A lack of runnable tasks is
not automatically a runtime crash.

Required scheduler behavior:

- if all tasks are dead, return the guest process exit status;
- if the process is in `exit_group`, wake all tasks that can be woken so they
  can run task-exit cleanup and release futex waiters;
- if tasks are blocked on interruptible waits and the runtime has timers,
  fd-readiness, futex, signal, or child-exit wake sources, wait for or poll the
  next source;
- if blocked tasks have no possible wake source, report a deadlock or stalled
  wait diagnostic rather than a native execution fault;
- diagnostics for stalls must include runnable count, futex waiters, fd waiters,
  child waiters, signal waiters, task states, last syscall, and recent syscalls.

`no runnable guest tasks remain` should be reserved for diagnostics where the
runtime has proven there are no runnable tasks and no event source that can make
forward progress. It must not be emitted while the process is still completing
valid Linux thread-exit or signal-delivery work.

## Dynamic Executable Pages And Native Faults

V8 and other JIT runtimes generate executable code after process startup. MCR
must track those pages with the same Linux ABI discipline used for file-backed
ELF mappings.

Required behavior:

- `mmap` or `mprotect` that grants `PROT_EXEC` invalidates native patch metadata
  for the affected range and increments an executable-generation marker;
- writes to executable or RWX pages must conservatively invalidate the affected
  translated/native patch range before it can run again;
- native entry checks the executable-generation metadata and scans newly
  executable ranges for syscall traps, supported intrinsic patches, and the
  complete FS/TLS classification described above;
- Windows `FlushInstructionCache` is required after host-side code patching or
  guest writes that can affect host-executed instructions;
- host SEH/VEH exceptions from guest-owned addresses map to Linux signals such
  as `SIGSEGV`, `SIGBUS`, `SIGILL`, and `SIGFPE`, enqueue thread-pending
  `siginfo`, and return through the normal signal-delivery hook.

Node/V8 JIT stability depends more on signal/futex/thread lifecycle semantics
than on the raw ability to execute generated machine code. A JIT-generated code
page may execute successfully while the process still fails during concurrent
compiler-thread shutdown or fatal-signal delivery; those are task/signal/futex
bugs, not proof that dynamic executable tracking is complete.

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
