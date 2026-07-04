---
id: perf-008
scope: network-performance
status: done
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
git diff --check
```

## Decision

Closed on 2026-07-04 as a documentation decision checkpoint. MCR will not land a
Registered I/O datagram backend in this phase.

The current repository does not contain checked-in benchmark output, smoke-test
evidence, or IOCP-vs-RIO measurements proving that RIO improves a target
small-message datagram workload. Without that bottleneck evidence, a RIO backend
would add Windows-only registered-buffer ownership, completion, cancellation,
and socket-lifetime complexity that still must be hidden behind MCR's Linux ABI
socket semantics.

## Notes

- Reopen only after IOCP measurements identify a datagram bottleneck that RIO
  can plausibly address.
- Reopen work must include an observable measurement gate comparing RIO against
  the IOCP backend for the target datagram workload.
- Registered buffers must never expose host memory ownership to guest code.
- A reopened prototype must preserve MCR socket lifetime, buffer ownership,
  cancellation, readiness, and Linux errno semantics before it can land.
