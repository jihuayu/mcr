---
id: perf-022
scope: network-performance
status: pending
depends-on: [perf-020]
---

# perf-022: Add Registered I/O Network Backend Gate

## Objective

Add an opt-in Registered I/O backend for the measured socket workload where it
beats the IOCP backend and can preserve MCR-owned buffer lifetime, cancellation,
readiness, and Linux errno semantics.

## Context

- `docs/architecture/networking.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-008.md`
- `docs/plan/tasks/perf-020.md`

## Path

- `crates/mcr-win/`
- `crates/mcr-net/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `docs/architecture/networking.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-022.md`

## Verification

```powershell
cargo test -p mcr-win rio -- --nocapture
cargo test -p mcr-net rio -- --nocapture
cargo test -p mcr-testkit perf_baseline -- --ignored --nocapture
```

## Notes

- RIO must stay opt-in until measurement proves it improves a target workload.
- If the host does not support RIO, tests must prove explicit fallback behavior.
- Registered buffers must not bypass guest memory validation or outlive their
  owning runtime state.

## Checkpoints

- Added the `mcr-win` Registered I/O capability gate. `HostSocket::rio_capability`
  probes `WSAID_MULTIPLE_RIO` with `WSAIoctl` and reports either a supported
  RIO function-table shape or an explicit unsupported fallback. No RIO data path
  is enabled yet; future work must still provide opt-in measurement evidence,
  registered-buffer lifetime proofs, and comparison against the IOCP backend.
- Exposed the RIO capability gate through `mcr-net::HostSocketHandle` and
  `GuestSocketTable`. Non-RIO handles default to an explicit unsupported
  capability, while the Windows host handle delegates to `mcr-win`.
