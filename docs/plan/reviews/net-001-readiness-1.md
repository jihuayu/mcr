# net-001 Readiness Review 1

## Findings

- Blocking findings for the audited TCP socket slices: none.

- `mcr-net`, `mcr-vfs`, and `mcr-runtime` now cover the unit-level TCP socket contract called out by `docs/plan/tasks/net-001.md`: socket creation, bind/listen/accept, connect/shutdown, send/recv via guest buffers and iovecs, and socket option round-trips. The audited tests also prove socket fd metadata and production runtime dispatch wiring. Representative coverage lives in `crates/mcr-net/src/lib.rs`, `crates/mcr-vfs/src/lib.rs`, and `crates/mcr-runtime/src/lib.rs`.

- The earlier DNS concern was overstated: the documented runtime contract is compatibility with
  common guest libc resolver flows, not a separate runtime-host `getaddrinfo` API. The audited
  code already materializes `/etc/hosts`, `/etc/resolv.conf`, and `/etc/nsswitch.conf` in
  `crates/mcr-runtime/src/run_rootfs.rs`, and it covers guest-visible UDP datagram socket I/O for
  `sendto`/`recvfrom` and `sendmsg`/`recvmsg` in `crates/mcr-runtime/src/lib.rs` plus
  `crates/mcr-net/src/lib.rs`. Those pieces cover the non-smoke DNS prerequisites.

- `net-001` therefore remains `pending` only because the final libc-resolution proof for
  `example.com` and `github.com` still belongs to native x86 guest execution smoke
  (`curl`/`git clone`), not because a separate DNS proxy or host resolver shim is missing from the
  audited networking stack.

- Final proof for this task must use native x86 guest execution. The old direct Alpine shell smoke commands are no longer the correct gate on an ARM host; the required end-to-end evidence now runs through `x86-runtime-smoke.yml` or an equivalent x86_64/QEMU environment, and should stay separate from unit-level readiness claims.

## Verification

- `cargo test -p mcr-net`: pass
- `cargo test -p mcr-vfs`: pass
- `cargo test -p mcr-runtime connected_socket -- --nocapture`: pass
- `cargo test -p mcr-runtime socket_ -- --nocapture`: pass
- `cargo test -p mcr-runtime run_rootfs_materializes_minimal_dns_config -- --nocapture`: pass
- `cargo test -p mcr-runtime datagram -- --nocapture`: pass

## Conclusion

pending
