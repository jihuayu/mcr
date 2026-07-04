# Backlog

Targeted shell/network metadata performance is no longer a later backlog item.
`perf-015` is the active front-loaded gate for classifying and reducing the
current `git ls-remote` latency cliff before Phase 2 broadens the workload
matrix or Phase 3 build work starts. Broad IOCP, overlapped file/pipe, worker
pool routing, and memory-manager backend rewrites remain deferred unless
`perf-015` measurements prove one of them is the dominant blocker.

## Deferred Or Later Than Phase 2

| Item | Target | Reason |
|---|---|
| Dockerfile builder | Phase 3 | Runtime must first support shell, process, network, and filesystem behavior used by `RUN`. |
| Native builder execution gate | Phase 3 | `build-003` is closed only as the single-stage planning and contract boundary. Reopen for real `mcr build` execution after snapshot-rootfs mutation, `BuildRunSpec` execution, layer diffing, image output selection, and build diagnostics can be wired end to end. |
| Multi-stage builder wiring | Phase 3 | `build-004` is closed as a deferred integration boundary. Reopen after native single-stage execution exists, then add named/numeric stage state, immutable prior-stage snapshot references, `COPY --from=<stage>` path resolution, and fixture smoke output comparison. |
| Native builder smoke matrix | Phase 3 | `integ-004` is closed as a deferred external-validation gate. Reopen after real `mcr build` execution exists, then run single-stage and multi-stage fixtures, OCI layout validation, and `docker load` when Docker is available. |
| OCI/Docker image output | Phase 3 | Requires reliable snapshot diff and overlay semantics, which build on VFS after Phase 2. |
| Registry pull/push | Phase 3 | Not needed to prove runtime execution; rootfs fixtures are enough for MVP and Phase 2. |
| Registry transport/auth/gzip gate | Phase 3 | `image-002` closed only the pull/unpack contract boundary. Reopen for real OCI registry HTTP transport, auth/token handling, remote manifest/blob fetch, gzip layer decompression, and local-registry integration proof before claiming remote image pull support. |
| Build RUN snapshot mutation and cancellation gate | build-003 | `buildrun-001` closed only the `mcr-runtime` executor API boundary. Follow-up must mount snapshot rootfs views, route `RUN` writes into snapshot mutation and layer diffing, and wire build cancellation before claiming end-to-end Dockerfile `RUN` mutation. |
| BuildKit worker/executor | Phase 4 | Needs a stable runtime executor contract, snapshot diff boundary, and native builder proof first. |
| BuildKit adapter implementation gates | Phase 4 | `buildkit-001` through `buildkit-003` are closed as deferred adapter gates. Reopen after native builder execution exists, then add worker capability advertisement, source/file/exec mapping to MCR contracts, cache reference mapping, cancellation/progress translation, and `buildctl` smoke output comparison. |
| Docker Engine API subset | Later than Phase 4 | CLI compatibility is not useful until the runtime and builder can run meaningful workloads. |
| Full overlay lower/upper layer implementation | Phase 3 | VFS must remain compatible with it, but export semantics belong to builder work. |
| Overlapped file and pipe backend | Later optimization | `perf-003` closed with the `mcr-win` submission boundary and synchronous fallback only. Reopen for real backend work covering overlapped handle flags, event/thread-pool/IOCP completion source, runtime wait wiring, close/cancel drain semantics, and fallback comparison tests. |
| File scatter/gather backend | Later optimization | `perf-004` now routes socket `readv`/`writev`/`sendmsg`/`recvmsg` through vectored runtime helpers and Windows `WSABUF` socket calls. Reopen only for regular-file scatter/gather after alignment, handle-mode, and guest-buffer lifetime constraints are modeled safely. |
| Host-backed file mapping and COW page reuse | Measurement gate | `perf-005` closed with the safe immutable private payload-cache boundary only. Reopen for real host-backed page mapping or COW page sharing when guest VMA permissions, `mprotect`, EOF zero-fill, private writable mapping semantics, cache invalidation, and exec-heavy benchmark evidence can be proven together. |
| Windows IOCP socket backend | Measurement gate | `perf-006` closed only the safe readiness-token boundary. Reopen real backend work for `CreateIoCompletionPort` registration, overlapped operation ownership, worker draining, cancellation/drain lifecycle, fallback comparison tests, and network perf smoke evidence; `WSAPoll` plus runtime readiness queue remains the Phase 2 correctness backend. |
| AcceptEx/ConnectEx backend | Measurement gate | `perf-007` closed only the adapter contract over readiness tokens. Reopen real fast-path work for Winsock extension lookup, overlapped buffer ownership, `SO_UPDATE_ACCEPT_CONTEXT`/`SO_UPDATE_CONNECT_CONTEXT`, cancellation, fallback comparison tests, and accept/connect perf smoke evidence after the IOCP lifetime model is ready. |
| Registered I/O network backend | Measurement gate | `perf-008` closed without implementation; reopen only if IOCP measurements expose a small-message datagram bottleneck and a RIO prototype proves benefit without Windows-only buffer or lifetime leakage. |
| General UDP socket semantics | Later compatibility | Phase 2 only needs UDP if it is the chosen implementation detail for DNS. |
| Edge-triggered epoll and one-shot/exclusive watches | Later compatibility | Phase 2 readiness is level-triggered for CLI/network tool smoke tests. |
| AF_UNIX compatibility | Later compatibility | TCP client behavior is the Phase 2 networking proof. |
| Full `fork` without immediate exec | Later compatibility | Common shell and build paths can start with `fork+exec` fast path. |
| Process-shared futex | Later compatibility | Current model intentionally keeps one host process per container. |
| Strong sandboxing | Later product line | Current product trust model is trusted development workloads. |
| Cross-architecture guest execution | Later product line | Same-ISA x86-64 is required to keep MVP feasible. |
| Libc intrinsic replacement | Measurement gate | `perf-014` closed as a decision checkpoint without implementation. Reopen only after `perf-012` stabilizes native block caching, ignored perf benchmarks prove libc string or memory routines are a material hotspot, and fault/overlap semantics can be proven. |
| Runtime and network worker-pool routing | Measurement gate | `perf-011` closed with the bounded `mcr-task` pool contract only. Reopen for routing real guest task execution and I/O completions through worker pools after cancellation, teardown, wait/exit semantics, runtime scheduling integration, network completion integration, and differential fallback tests are defined. |

## Phase 2 Workload Blockers

2026-07-04 perf-012 closed the native executable cache/range throughput work:
syscall scanning filters `0f 05` before decode, derives syscall and FS/TLS plans
from one range read, records zero-FS TLS candidates without no-op
materialization, materializes only new candidates when FS base is unchanged, and
batches fixed-width patch writes by host allocation. Native fault diagnostics
now render instruction bytes, a decoded instruction summary, FS base, registers,
and stack words. Package-rootfs reruns no longer show Node/Cargo blocked in
patch-cache scan/apply. The high-address FS/TLS fallback has since landed in
the runtime and JIT, so current package-rootfs follow-up is workload-native
execution stability after that fallback, not perf-012 cache throughput.

`MCR_HOSTSTEP_TRACE=1` remains the opt-in host-side timing path for rootfs
loading, program loading, native entry/return, native patch scanning, and
fork-exec memory materialization when a workload stalls inside a single
host/native window instead of returning a guest step-limit diagnostic.

| Command | Current result | Required follow-up |
|---|---|---|
| `mcr run-rootfs go-rootfs /bin/sh -c "go version"` | After the FS/TLS fallback checkpoint, the latest bounded local rerun still exceeded a 90s process timeout without output. | Rerun with host-step and native-fault diagnostics to classify the current native-window blocker now that high-address FS/TLS fallback is no longer the known missing boundary. |
| `mcr run-rootfs node-rootfs /bin/sh -c "node -v"` | The FS/TLS fallback removes the previous native null-address fault; local reruns include successful `v24.17.0` output around 11-12s, but a repeated normal run also failed with `guest block did not terminate at syscall: Invalid { rip: 1879212813 }`. | Stabilize the remaining native/JIT block execution path and add repeatable workload smoke evidence before claiming Node is fully green. |
| `mcr run-rootfs rust-rootfs /bin/sh -c "cargo --version"` | The FS/TLS fallback now handles the prior `mov rax, fs:[0]` native fault and advances execution to `guest block terminated with x86 exception before syscall at guest rip 0x000000007006681e`. | Classify the new x86 exception terminator and decide whether it is an unsupported instruction, signal/exception semantic gap, or workload-specific runtime blocker. |

## Resolved Build Direction

- Phase 3 is the native MCR builder plus OCI/Docker image output.
- Phase 4 is the BuildKit worker/executor adapter.
- Docker Engine API compatibility is later than BuildKit integration.
- OCI image layer diff belongs in `mcr-snapshot` and feeds `mcr-image` through content-addressed descriptors.

## Open Questions For Later Milestones

- Whether pty/tty completeness is needed before the first public preview.
- Whether host process mapping is needed for selected workloads after Phase 2.
