# net-001-io Review 1

## Findings

No blocking or non-blocking findings.

Reviewed scope:

- `crates/mcr-net/src/lib.rs` host socket transport abstraction, Windows host adapter bridge, connected TCP socket table handles, shutdown behavior, and host error to Linux errno mapping.
- `crates/mcr-runtime/src/lib.rs` `sendto`, `recvfrom`, `sendmsg`, and `recvmsg` wiring for connected stream sockets.
- Unit coverage for host handle send/recv behavior and runtime guest-buffer/iovec movement.

Out of scope for this slice:

- DNS.
- Datagram/addressed socket I/O.
- Complete Alpine rootfs network smoke.

Verification:

- `cargo fmt --check`: pass.
- `cargo test -p mcr-net -p mcr-runtime connected_socket -- --nocapture`: pass.
- `cargo test -p mcr-net -p mcr-runtime`: pass.
- `cargo clippy -p mcr-net -p mcr-runtime --all-targets -- -D warnings`: pass.

## Conclusion

pass
