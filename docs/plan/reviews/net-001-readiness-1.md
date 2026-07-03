# net-001 Readiness Review 1

## Findings

- Blocking findings for the audited TCP socket slices: none.

- `mcr-net`, `mcr-vfs`, and `mcr-runtime` now cover the unit-level TCP socket contract called out by `docs/plan/tasks/net-001.md`: socket creation, bind/listen/accept, connect/shutdown, send/recv via guest buffers and iovecs, and socket option round-trips. The audited tests also prove socket fd metadata and production runtime dispatch wiring. Representative coverage lives in `crates/mcr-net/src/lib.rs`, `crates/mcr-vfs/src/lib.rs`, and `crates/mcr-runtime/src/lib.rs`.

- The task is still not complete because guest-visible DNS resolution is not implemented in the audited networking stack yet. A repo-wide search for `getaddrinfo`, resolver plumbing, or equivalent DNS-specific handling in `mcr-net`/`mcr-runtime` does not turn up an implementation path, while the remaining public-network smoke contracts still require resolving `example.com` and `github.com`. This keeps `net-001` in `pending` even though the non-smoke TCP/socket pieces are largely covered.

- Final proof for this task must use native x86 guest execution. The old direct Alpine shell smoke commands are no longer the correct gate on an ARM host; the required end-to-end evidence now runs through `x86-runtime-smoke.yml` or an equivalent x86_64/QEMU environment, and should stay separate from unit-level readiness claims.

## Verification

- `cargo test -p mcr-net`: pass
- `cargo test -p mcr-vfs`: pass
- `cargo test -p mcr-runtime connected_socket -- --nocapture`: pass
- `cargo test -p mcr-runtime socket_ -- --nocapture`: pass

## Conclusion

pending
