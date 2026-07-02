1. Findings

- P1 blocking — `docs/architecture/README.md:80-82` says runtime dispatch routes file syscalls to `mcr-vfs` and socket/event syscalls to `mcr-net`, but the production `RuntimeSubsystems` still uses the default unsupported implementations for both file and network syscalls. `RuntimeFileSystem<M>` contains the new VFS/socket control syscall implementation, but `Runtime::new` builds `SyscallDispatcher<RuntimeSubsystems>` and `RuntimeSubsystems` has no VFS or socket table fields, so production `socket`, `bind`, `connect`, `listen`, `shutdown`, `getsockopt`, `setsockopt`, `accept`, `accept4`, `getsockname`, and `getpeername` remain `ENOSYS`. Code: `crates/mcr-runtime/src/lib.rs:1240-1248`, `crates/mcr-runtime/src/lib.rs:1347-1368`, `crates/mcr-runtime/src/lib.rs:1401-1408`, implemented-but-detached path at `crates/mcr-runtime/src/lib.rs:360-644`.

- P2 non-blocking — `docs/architecture/runtime.md:71` and `docs/plan/tasks/net-001.md:38` include socket control coverage, but `getsockname` currently returns `ENOTCONN` for a successfully connected but unbound socket because `SocketState::local_address()` only returns an address for `Bound`/`Listening`. Linux `getsockname` on a connected socket should return the local endpoint. This is not enough to block the runtime/VFS control-syscall foundation because the current placeholder model does not allocate real local endpoints yet, but it is a follow-up compatibility gap before net-001 can be called complete. Code: `crates/mcr-runtime/src/lib.rs:626-637`, `crates/mcr-net/src/lib.rs:226-241`.

- P2 non-blocking — `docs/plan/analysis/mvp-phase2.md:75` says an implemented syscall needs success and at least one failure-path test. The focused `RuntimeFileSystem` tests cover success paths for `socket`, `bind`, `listen`, `connect`, `shutdown`, `getsockopt`, `setsockopt`, `getsockname`, and `getpeername`, plus several failures, but they do not exercise the production `Runtime::dispatch_syscall` path for any network syscall. That gap allowed the detached `RuntimeSubsystems` integration above to pass tests. Code: tests at `crates/mcr-runtime/src/lib.rs:2228-2537`; production dispatch at `crates/mcr-runtime/src/lib.rs:1290-1292` and `crates/mcr-sys/src/dispatcher.rs:413-419`.

- P3 non-blocking — `docs/architecture/runtime.md:182` expects `/proc/self/fd/<n>` to handle socket descriptors, and the VFS helper itself does not expose `FIRST_SOCKET_INODE_ID` or derive ids from inode constants. `VirtualFileSystem::socket_id_for_fd` delegates through `FdTable::socket_id_for_fd`, reads `InodeBackend::Socket(SocketNode)`, returns `ENOTSOCK` for non-socket fds and `EBADF` for closed/bad fds, with tests for dup and close behavior. Code: `crates/mcr-vfs/src/lib.rs:84`, `crates/mcr-vfs/src/lib.rs:1468-1479`, `crates/mcr-vfs/src/lib.rs:1810-1837`, `crates/mcr-vfs/src/lib.rs:2441-2447`, `crates/mcr-vfs/src/lib.rs:3077-3081`, tests at `crates/mcr-vfs/src/lib.rs:3316-3382`.

Scope note: the reviewed commits are a runtime/VFS control-syscall foundation only. Lack of real TCP I/O, DNS, `sendmsg`, and `recvmsg` is expected for this slice and is not counted as a blocking finding for this review.

Verification:

- `cargo fmt --check` — pass
- `cargo test -p mcr-vfs` — pass
- `cargo clippy -p mcr-vfs --all-targets -- -D warnings` — pass
- `cargo test -p mcr-runtime` — pass
- `cargo clippy -p mcr-runtime --all-targets -- -D warnings` — pass

2. 结论：blocked
