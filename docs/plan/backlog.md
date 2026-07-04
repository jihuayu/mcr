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
| IOCP event backend | Later optimization | Tracked by `perf-006`; WSAPoll plus runtime readiness queue remains the Phase 2 correctness backend. |
| Registered I/O network backend | Later optimization | Tracked by `perf-008`; only useful if IOCP measurements expose a small-message datagram bottleneck. |
| General UDP socket semantics | Later compatibility | Phase 2 only needs UDP if it is the chosen implementation detail for DNS. |
| Edge-triggered epoll and one-shot/exclusive watches | Later compatibility | Phase 2 readiness is level-triggered for CLI/network tool smoke tests. |
| AF_UNIX compatibility | Later compatibility | TCP client behavior is the Phase 2 networking proof. |
| Full `fork` without immediate exec | Later compatibility | Common shell and build paths can start with `fork+exec` fast path. |
| Process-shared futex | Later compatibility | Current model intentionally keeps one host process per container. |
| Strong sandboxing | Later product line | Current product trust model is trusted development workloads. |
| Cross-architecture guest execution | Later product line | Same-ISA x86-64 is required to keep MVP feasible. |

## Phase 2 Workload Blockers

| Command | Current result | Required follow-up |
|---|---|---|
| `mcr run-rootfs go-rootfs /bin/sh -c "go version"` | Native execution faulted on local Windows x86-64 with access violation at guest RIP `0x8931db` while running the package-backed Alpine Go rootfs. | Diagnose the native execution path around the faulting Go startup block before `workload-001` can be marked done. |
| `mcr run-rootfs node-rootfs /bin/sh -c "node -v"` | Did not complete within several minutes on local Windows x86-64 with a package-backed Alpine Node rootfs. | Add a bounded timeout diagnostic and identify whether startup is blocked in guest wait/futex, epoll/readiness, or native execution. |
| `mcr run-rootfs rust-rootfs /bin/sh -c "cargo --version"` | Did not complete within several minutes on local Windows x86-64 with a package-backed Alpine Cargo rootfs. | Add a bounded timeout diagnostic and identify whether startup is blocked in guest wait/futex, filesystem metadata, or native execution. |

## Resolved Build Direction

- Phase 3 is the native MCR builder plus OCI/Docker image output.
- Phase 4 is the BuildKit worker/executor adapter.
- Docker Engine API compatibility is later than BuildKit integration.
- OCI image layer diff belongs in `mcr-snapshot` and feeds `mcr-image` through content-addressed descriptors.

## Open Questions For Later Milestones

- Whether pty/tty completeness is needed before the first public preview.
- Whether host process mapping is needed for selected workloads after Phase 2.
