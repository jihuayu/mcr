# Backlog

## Deferred Until After Phase 2

| Item | Reason deferred |
|---|---|
| Dockerfile builder | Runtime must first support shell, process, network, and filesystem behavior used by `RUN`. |
| OCI/Docker image output | Requires reliable snapshot diff and overlay semantics, which build on VFS after Phase 2. |
| Registry pull/push | Not needed to prove runtime execution; rootfs fixtures are enough for MVP and Phase 2. |
| BuildKit worker/executor | Needs a stable runtime executor contract and snapshot diff boundary first. |
| Docker Engine API subset | CLI compatibility is not useful until the runtime can run meaningful workloads. |
| Full overlay lower/upper layer implementation | VFS must remain compatible with it, but export semantics belong to builder work. |
| IOCP event backend | WSAPoll plus runtime readiness queue is simpler for Phase 2 correctness. |
| Full `fork` without immediate exec | Common shell and build paths can start with `fork+exec` fast path. |
| Process-shared futex | Current model intentionally keeps one host process per container. |
| Strong sandboxing | Current product trust model is trusted development workloads. |
| Cross-architecture guest execution | Same-ISA x86-64 is required to keep MVP feasible. |

## Open Questions For Later Milestones

- Whether BuildKit worker integration or Docker Engine API compatibility should be Phase 3.
- Whether OCI image layer diff should use a custom VFS walker or integrate with a content store abstraction.
- Whether pty/tty completeness is needed before the first public preview.
- Whether host process mapping is needed for selected workloads after Phase 2.
