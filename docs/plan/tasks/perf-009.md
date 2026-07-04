---
id: perf-009
scope: network-performance
status: pending
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
cargo test -p mcr-runtime dns_ -- --nocapture
cargo test -p mcr-testkit perf_dns -- --ignored --nocapture
```

## Notes

- Respect TTLs and scope entries to the guest network configuration represented
  by `/etc/hosts`, `/etc/resolv.conf`, and `/etc/nsswitch.conf`.
- Do not add generic TCP or TLS connection pooling for arbitrary guest sockets.
- Invalidate cache entries when the guest-visible resolver configuration changes.
