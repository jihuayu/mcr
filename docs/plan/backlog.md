# Backlog

## Deferred Or Later Than Phase 2

| Item | Target | Reason |
|---|---|
| Dockerfile builder | Phase 3 | Runtime must first support shell, process, network, and filesystem behavior used by `RUN`. |
| OCI/Docker image output | Phase 3 | Requires reliable snapshot diff and overlay semantics, which build on VFS after Phase 2. |
| Registry pull/push | Phase 3 | Not needed to prove runtime execution; rootfs fixtures are enough for MVP and Phase 2. |
| BuildKit worker/executor | Phase 4 | Needs a stable runtime executor contract, snapshot diff boundary, and native builder proof first. |
| Docker Engine API subset | Later than Phase 4 | CLI compatibility is not useful until the runtime and builder can run meaningful workloads. |
| Full overlay lower/upper layer implementation | Phase 3 | VFS must remain compatible with it, but export semantics belong to builder work. |
| Overlapped file and pipe backend | Later optimization | `perf-003` closed with the `mcr-win` submission boundary and synchronous fallback only. Reopen for real backend work covering overlapped handle flags, event/thread-pool/IOCP completion source, runtime wait wiring, close/cancel drain semantics, and fallback comparison tests. |
| IOCP event backend | Later optimization | Tracked by `perf-006`; WSAPoll plus runtime readiness queue remains the Phase 2 correctness backend. |
| Registered I/O network backend | Measurement gate | `perf-008` closed without implementation; reopen only if IOCP measurements expose a small-message datagram bottleneck and a RIO prototype proves benefit without Windows-only buffer or lifetime leakage. |
| General UDP socket semantics | Later compatibility | Phase 2 only needs UDP if it is the chosen implementation detail for DNS. |
| Edge-triggered epoll and one-shot/exclusive watches | Later compatibility | Phase 2 readiness is level-triggered for CLI/network tool smoke tests. |
| AF_UNIX compatibility | Later compatibility | TCP client behavior is the Phase 2 networking proof. |
| Full `fork` without immediate exec | Later compatibility | Common shell and build paths can start with `fork+exec` fast path. |
| Process-shared futex | Later compatibility | Current model intentionally keeps one host process per container. |
| Strong sandboxing | Later product line | Current product trust model is trusted development workloads. |
| Cross-architecture guest execution | Later product line | Same-ISA x86-64 is required to keep MVP feasible. |
| Libc intrinsic replacement | Measurement gate | `perf-014` closed as a decision checkpoint without implementation. Reopen only after `perf-012` stabilizes native block caching, ignored perf benchmarks prove libc string or memory routines are a material hotspot, and fault/overlap semantics can be proven. |

## Phase 2 Workload Blockers

2026-07-04 perf-012 reduced native executable patch startup work by avoiding
decoder passes for candidate-free ranges and deriving syscall and FS/TLS patch
plans from one range read. workload-001 now has a deterministic runtime step
limit diagnostic that classifies timeout snapshots as guest wait/futex,
readiness, scheduling, or native execution. A package-rootfs rerun with
`mcr run-rootfs --guest-step-limit` confirmed `python -V` completes, while Go,
Node, and Cargo each exceeded a 30s process timeout without returning a guest
step-limit diagnostic. The remaining blocker is therefore likely inside a single
native/host-side execution window, patch/materialization path, or equivalent
long operation rather than repeated guest-step progress. `MCR_HOSTSTEP_TRACE=1`
now emits opt-in host-side timing for rootfs loading, program loading, native
entry/return, native patch scanning, and fork-exec memory materialization to
pinpoint that window.

2026-07-04 host-step tracing with `MCR_HOSTSTEP_TRACE=1` narrowed the no-output
timeouts. `go version` did not reach guest execution within 30s because
`run-rootfs` was still eagerly materializing the package rootfs
(`5120/7782` files and `362243289/417985720` bytes after `27364ms`). `node -v`
and `cargo --version` reached native execution, but the 30s timeout landed in
host patch work: Node was applying `45171` FS-relative patches with
`fs_base=0`, while Cargo was rescanning/reapplying the Rust executable ranges
and was killed while applying `1942` FS-relative patches.

| Command | Current result | Required follow-up |
|---|---|---|
| `mcr run-rootfs go-rootfs /bin/sh -c "go version"` | `sigaltstack` support cleared the previous native execution fault, and instruction-aware syscall patching cleared the Go `newosproc` clone failure caused by rewriting the `0x50f00` clone-flags immediate. Host-step tracing shows the 30s timeout happens before runtime execution: eager rootfs materialization had reached `5120/7782` files at `27364ms` and had not emitted `run-rootfs rootfs-loaded`. | Replace or bypass eager rootfs materialization for large package fixtures before using guest-step diagnostics as the workload gate. |
| `mcr run-rootfs node-rootfs /bin/sh -c "node -v"` | Host-step tracing shows the rootfs and interpreter startup complete, then native patching scans a `31363072` byte Node executable range and the timeout lands while applying `45171` FS-relative patches with `fs_base=0`. | Reduce or defer Windows FS-relative patch application for large executable ranges; avoid treating this as guest scheduler progress. |
| `mcr run-rootfs rust-rootfs /bin/sh -c "cargo --version"` | Host-step tracing shows repeated native patch cache work after startup: the Rust executable range is rescanned and FS-relative patches are reapplied, with the timeout landing while applying `1942` FS-relative patches after a fresh scan. | Stabilize native patch cache invalidation/reuse and reduce repeated FS-relative patch application for Rust-sized executable mappings. |

## Resolved Build Direction

- Phase 3 is the native MCR builder plus OCI/Docker image output.
- Phase 4 is the BuildKit worker/executor adapter.
- Docker Engine API compatibility is later than BuildKit integration.
- OCI image layer diff belongs in `mcr-snapshot` and feeds `mcr-image` through content-addressed descriptors.

## Open Questions For Later Milestones

- Whether pty/tty completeness is needed before the first public preview.
- Whether host process mapping is needed for selected workloads after Phase 2.
