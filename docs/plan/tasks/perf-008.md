---
id: perf-008
scope: network-performance
status: blocked
depends-on: [perf-006]
---

# perf-008: Evaluate Registered I/O Datagram Backend

## Objective

Prototype a Registered I/O backend for small-message datagram workloads and land
it only if measurement proves a meaningful improvement over the IOCP backend
without weakening MCR socket lifetime, buffer ownership, cancellation, or Linux
errno semantics.

## Context

- `docs/architecture/networking.md`
- `docs/architecture/performance.md`

## Path

- `crates/mcr-net/`
- `crates/mcr-win/`
- `crates/mcr-testkit/`
- `docs/plan/backlog.md`

## Verification

```powershell
cargo test -p mcr-net rio -- --nocapture
cargo test -p mcr-testkit perf_rio_datagram -- --ignored --nocapture
```

## Notes

- This remains blocked until IOCP measurements identify a datagram bottleneck
  that RIO can plausibly address.
- Registered buffers must never expose host memory ownership to guest code.
- If RIO support is unavailable or not better than IOCP for target workloads,
  close this task by documenting that decision instead of keeping a partial
  backend.
