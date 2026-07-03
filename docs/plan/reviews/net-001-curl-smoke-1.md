# net-001 Curl Smoke Review 1

Date: 2026-07-03

## Scope

- Native MCR execution of Alpine `curl` through the materialized rootfs.
- Follow-up evidence after socket fd `read`/`write` routing, `recvmsg` compatibility fixes,
  host I/O `SO_ERROR` recording, and socket `F_SETFL O_NONBLOCK` propagation.

## Findings

- `curl --version` now completes under native execution instead of hanging in guest cleanup.
- After the connected UDP and nonblocking Winsock fixes, guest DNS now reaches an
  address for `example.com` instead of failing with exit code 6.
- `curl -v https://example.com -o NUL` and the DNS-bypassed
  `--resolve example.com:443:93.184.216.34` path now reach TCP connect
  readiness but still exit 7.
- The current failing stderr shape is:

```text
*   Trying 198.18.0.94:443...
* connect to 198.18.0.94 port 443 failed: No error information
curl: (7) Failed to connect to example.com port 443 after ... ms: Could not connect to server
```

- Temporary diagnostics showed `poll(fd, POLLOUT)` returning `POLLOUT` and
  `getsockopt(SO_ERROR)` returning `0`, so the next risk is the exact
  guest-visible connect/readiness/address-query sequence curl uses after the
  socket becomes writable.

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
curl example.com: EXIT=7
```

## Next

- Trace the TCP client path after writable readiness, especially `connect`
  retry, `getsockopt(SO_ERROR)`, `getsockname`, `getpeername`, returned
  `pollfd.revents`, and socket state transitions.
- Keep DNS regression coverage for connected UDP `connect` plus `sendto(NULL)`,
  but the active blocker is now outbound TCP connect completion as observed by
  curl.
