---
id: perf-009
scope: network-performance
status: done
depends-on: [perf-001, net-001]
---

# perf-009: Add DNS Cache For MCR-Owned Resolution

## Objective

Add a small TTL-respecting DNS cache only where MCR owns the resolution path,
such as a runtime resolver helper or DNS proxy, reducing repeated resolver
latency without changing guest socket ownership or TLS behavior.

## Context

- `docs/architecture/networking.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-net/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo test -p mcr-net dns_cache -- --nocapture
cargo test -p mcr-net perf_baseline_dns -- --ignored --nocapture
cargo test -p mcr-runtime dns_ -- --nocapture
cargo test -p mcr-testkit perf_dns -- --ignored --nocapture
```

## Checkpoint

- Added `mcr-net::DnsCache` as the boundary for MCR-owned resolver helpers and
  DNS proxies. It caches positive address answers by normalized query name and
  record type, expires them at the TTL boundary, skips zero-TTL answers, and
  clears entries when the guest-visible resolver configuration snapshot changes.
- This checkpoint does not intercept guest DNS datagrams, does not add TCP/TLS
  pooling, and does not change guest socket ownership.
- Added ignored DNS cache baseline reports under `mcr-net` and the
  `mcr-testkit perf_dns` filter so the active DNS cache perf gate captures
  insert, lookup-hit, and expiry-purge costs without requiring guest network
  execution.
- Completed 2026-07-04: focused DNS cache, runtime resolver-file materialization,
  and ignored `mcr-net`/`mcr-testkit` DNS performance baselines passed. This
  remains scoped to MCR-owned resolver helpers and DNS proxies; guest DNS
  datagram interception and generic TCP/TLS pooling stay out of this task.

## Notes

- Respect TTLs and scope entries to the guest network configuration represented
  by `/etc/hosts`, `/etc/resolv.conf`, and `/etc/nsswitch.conf`.
- Do not add generic TCP or TLS connection pooling for arbitrary guest sockets.
- Invalidate cache entries when the guest-visible resolver configuration changes.
