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
- Linux poll write aliases and priority-interest handling fixed the later TCP
  connect exit 7. The guest now sees writable readiness, `SO_ERROR=0`, completes
  TLS, verifies the certificate, and receives HTTP/2 200 from `example.com`.
- A follow-up HTTPS failure without `-k` was not a socket bug. `curl -k -vvv`
  reported `OpenSSL verify result: 14`, and default verification faulted at
  musl `hlt` instructions.
- Offline diagnostics with an openssl-enabled temporary rootfs showed
  `openssl asn1parse` could parse the leaf certificate, while
  `openssl x509 -noout` hit `ld-musl-x86_64.so.1` offset `0x46b25`.
  Disassembly maps that `hlt` to musl mallocng's tail overflow-byte check,
  i.e. an intentional allocator invariant trap rather than a random RIP jump.
- The allocator trap was caused by MCR reusing previously unmapped anonymous
  memory without zero-filling it when the underlying Windows host allocation was
  still shared with adjacent VMAs. Linux requires a fresh anonymous `mmap` to
  return zeroed pages.
- The current successful stderr shape is:

```text
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / id-ecPublicKey
* subjectAltName: "example.com" matches cert's "example.com"
* OpenSSL verify result: 0
* SSL certificate verified via OpenSSL.
< HTTP/2 200
```

- The DNS-bypassed `--resolve example.com:443:93.184.216.34` path is not a good
  regression proof in this environment: host curl to that fixed IP also returns
  an empty/no-TLS response, while the DNS path resolves to `198.18.0.94` and
  succeeds.
- Standalone `openssl verify -CAfile ... -untrusted ... leaf.pem` still showed a
  separate native segfault in local diagnostics. It is not blocking the curl
  gate because curl's OpenSSL verification now returns 0, but it remains useful
  evidence for later native-execution hardening.

## Validation

```powershell
cargo fmt --check
cargo test -p mcr-net -- --nocapture
cargo test -p mcr-runtime fcntl_setfl_propagates_socket_nonblocking_to_host_handle -- --nocapture
cargo test -p mcr-runtime memory::tests:: -- --nocapture
cargo test -p mcr-runtime runtime_file_backed_mmap_populates_private_mapping_from_vfs_fd -- --nocapture
cargo build -p mcr-cli
target\debug\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /usr/bin/curl --version
target\debug\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /usr/bin/curl -fsSL https://example.com -o NUL
target\debug\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /usr/bin/curl -v --connect-timeout 15 https://example.com/ -o NUL
```

Observed local smoke results:

```text
curl --version: EXIT=0
curl -fsSL https://example.com: EXIT=0
curl -v https://example.com: EXIT=0, OpenSSL verify result 0, HTTP/2 200
```

## Next

- Extend the same network smoke confidence to `git clone` through the
  materialized rootfs.
- Keep the connected UDP DNS, poll alias, and anonymous mmap zero-fill tests as
  regressions for the curl path.
- Track the remaining standalone `openssl verify` CLI segfault separately from
  `net-001` socket readiness unless it reappears in curl/git smoke paths.
