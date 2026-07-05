---
id: perf-025
scope: syscall-performance
status: done
depends-on: [perf-015]
---

# perf-025: Zero-Cost Disabled Tracing And Interpreter Fallback Counters

## Objective

Make syscall trace field decoding cost nothing when tracing is disabled, and
add counters for interpreted-block execution (fallback frequency, bytes read,
blocks decoded) so a future decoded-block cache decision is measurement-driven
instead of speculative.

## Context

- `docs/architecture/performance.md` (Fast Syscalls, Caches And Reuse)
- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)

## Path

- `crates/mcr-sys/`
- `crates/mcr-jit/`
- `crates/mcr-runtime/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
cargo test -p mcr-runtime perf_baseline -- --ignored --nocapture
```

## Notes

- Today `decode_syscall_fields` builds a `Vec<TraceField>` for every syscall
  even when no tracer consumes it; the dispatcher should skip field decoding
  entirely (or use an inline small-buffer type) when tracing is off, while
  keeping the enter/exit event shape identical when tracing is on.
- The interpreted path re-reads up to `MAX_GUEST_BLOCK_BYTES` of guest memory
  and re-decodes with iced-x86 every time it runs; since native execution is
  the primary path, record how often and where the interpreter fallback
  actually executes before building any block cache.
- Counters ride the existing perf summary/diagnostics shape; no new
  guest-visible behavior.
- A decoded-block cache itself is out of scope; open a follow-up task only if
  the counters prove the fallback is hot on real workloads.
