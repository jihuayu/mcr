# net-002 Readiness Review 1

## Findings

- Blocking findings inside the audited `poll`/`ppoll`/`epoll` implementation: none.

- The current runtime and VFS tests satisfy the non-smoke contract described in `docs/plan/tasks/net-002.md`. The audited cases cover pipe readiness, socket readiness, `ppoll` timeout parsing, `epoll_create1`, add/mod/del watch behavior, closed-fd hangup/error reporting, and timeout handoff to the socket transport. This gives good unit-level evidence for the shared readiness queue behavior without changing JIT execution semantics or adding instruction emulation.

- `net-002` should still stay `blocked` at the task-file level because the final gate is no longer a local host-shell smoke. End-to-end proof must run through native x86 guest execution via `x86-runtime-smoke.yml` or an equivalent x86_64/QEMU environment, and that proof still depends on `net-001` reaching DNS-complete network integration.

## Verification

- `cargo test -p mcr-net`: pass
- `cargo test -p mcr-vfs`: pass
- `cargo test -p mcr-runtime poll_ -- --nocapture`: pass
- `cargo test -p mcr-runtime epoll_ -- --nocapture`: pass

## Conclusion

blocked
