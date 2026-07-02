1. Findings

- Blocking findings: none.

- The prior P1 production-dispatch blocker is fixed by `de7d8bd`. `Runtime::new` now builds `RuntimeSubsystems::new`, which owns `RuntimeFileSystem<GuestMemory>`; that wrapper contains both the `VirtualFileSystem` and `GuestSocketTable`. Production `Runtime::dispatch_syscall` reaches `SyscallDispatcher::dispatch`, the `Network` branch calls `RuntimeSubsystems::dispatch_network`, and that forwards to `RuntimeFileSystem::dispatch_network`. The network dispatcher handles `socket`, `bind`, `connect`, `listen`, `shutdown`, `getsockopt`, `setsockopt`, `accept`, `accept4`, `getsockname`, and `getpeername` instead of falling through to the default unsupported implementation. Code: `crates/mcr-runtime/src/lib.rs:1241-1249`, `crates/mcr-runtime/src/lib.rs:1368-1393`, `crates/mcr-runtime/src/lib.rs:1432-1447`, `crates/mcr-runtime/src/lib.rs:456-476`, `crates/mcr-sys/src/dispatcher.rs:413-419`.

- Production dispatcher coverage now exists. `runtime_dispatch_routes_socket_control_syscalls_through_vfs` instantiates `Runtime::new`, calls production `Runtime::dispatch_syscall(Syscall::Socket)`, and proves the returned fd is a VFS socket by `fcntl` and `fstat`. `runtime_dispatch_routes_socket_address_and_option_controls` also uses production dispatch and covers address/control/option paths including `bind`, `listen`, `accept4`, `accept`, `getsockname`, `connect`, `getpeername`, `shutdown`, `setsockopt`, and `getsockopt`. Code: `crates/mcr-runtime/src/lib.rs:1875-2081`.

- Scope note remains appropriate for this slice: real send/recv data I/O and DNS are still not implemented here, but that is not a blocker for the reviewed runtime/VFS control-syscall foundation. The production dispatcher test `runtime_dispatch_keeps_unsupported_network_io_unsupported` explicitly preserves unsupported network I/O as `ENOSYS` for `sendto`; `sendmsg`, `recvmsg`, and DNS completion remain follow-up net-001/integ-003 work rather than a blocker for this review. Code: `crates/mcr-runtime/src/lib.rs:2083-2093`; task scope references: `docs/plan/tasks/net-001.md:8-12`, `docs/plan/tasks/integ-003.md:12`.

Verification:

- `cargo fmt --check` — pass
- `cargo test -p mcr-runtime` — pass
- `cargo clippy -p mcr-runtime --all-targets -- -D warnings` — pass
- `cargo test -p mcr-vfs` — pass
- `cargo clippy -p mcr-vfs --all-targets -- -D warnings` — pass

2. 结论：pass
