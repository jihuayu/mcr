# net-001 Curl Smoke Review 1

Date: 2026-07-03

## Scope

- Native MCR execution of Alpine `curl` through the materialized rootfs.
- Follow-up evidence after socket fd `read`/`write` routing, `recvmsg` compatibility fixes,
  host I/O `SO_ERROR` recording, and socket `F_SETFL O_NONBLOCK` propagation.

## Findings

- `curl --version` now completes under native execution instead of hanging in guest cleanup.
- `curl -fsSL https://example.com` no longer times out after socket nonblocking propagation, but
  it still fails DNS resolution with curl exit code 6.
- The current failing stderr is:

```text
curl: (6) Could not resolve host: example.com (Could not contact DNS servers)
```

- A DNS-bypassed probe reported by the parallel worker using
  `--resolve example.com:443:93.184.216.34` reaches the TCP connect path but exits 7 with an
  immediate connect failure. That means net-001 still has at least two remaining integration
  risks: libc DNS server contact and outbound TCP connect completion for the smoke target.

## Validation

```powershell
cargo fmt --check
cargo test -p mcr-net -- --nocapture
cargo test -p mcr-runtime fcntl_setfl_propagates_socket_nonblocking_to_host_handle -- --nocapture
cargo build -p mcr-cli
target\debug\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /usr/bin/curl --version
target\debug\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /usr/bin/curl -fsSL https://example.com -o NUL
```

Observed local smoke results:

```text
curl --version: EXIT=0 elapsed=00:00:01.7393748
curl example.com: EXIT=6 elapsed=00:00:01.7535207
```

## Next

- Trace the guest DNS UDP path from libc/c-ares through `sendto`/`poll`/`recvfrom` and verify the
  runtime actually contacts the configured resolver from `/etc/resolv.conf`.
- After DNS returns an address, trace the TCP client connect path for the public smoke endpoint,
  including nonblocking `connect`, readiness, and `SO_ERROR` consumption.
