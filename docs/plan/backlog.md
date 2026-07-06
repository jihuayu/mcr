# Backlog

Targeted shell/network metadata performance is no longer a later backlog item.
`perf-015` closed the first front-loaded gate by reducing the `git ls-remote`
latency cliff with opt-in summary tracing and sticky scheduling.

## Completed Promoted Performance Track

These items were promoted from backlog into the front-loaded performance goal
and are now closed as narrow task commits with measurements and correctness
checks. Future work should reopen a new task with fresh evidence rather than
treating these as open backlog.

| Item | Active task | Gate |
|---|---|---|
| Real overlapped file and pipe backend | `perf-016` | Prove Windows overlapped handle mode, completion source, cancellation/drain, and runtime readiness integration against the synchronous fallback. |
| Regular-file scatter/gather | `perf-017` | Bypass the copy fallback only when alignment, handle mode, and guest buffer lifetime are proven safe; keep fallback for unsupported shapes. |
| Host-backed mapping and COW page reuse | `perf-018` | Prove VMA permissions, EOF zero-fill, private writable semantics, invalidation, and exec-heavy benchmark benefit. |
| Runtime and network worker-pool routing | `perf-019` | Route real guest task and I/O completion work through bounded pools without breaking wait, exit, cancellation, or teardown semantics. |
| Windows IOCP socket backend | `perf-020` | Replace the WSAPoll-only backend where supported while preserving Linux readiness, timeout, close wakeup, and errno behavior. |
| AcceptEx/ConnectEx backend | `perf-021` | Use host accept/connect fast paths behind the IOCP lifetime model with context update and fallback comparison tests. |
| Registered I/O network backend | `perf-022` | Add an opt-in RIO path only with measurement evidence and buffer/lifetime proof against the IOCP backend. |
| Libc intrinsic replacement | `perf-023` | Replace measured hot libc memory/string routines only when target identification, guest memory faults, and overlap semantics are proven. |
| Performance regression gates | `perf-024` | Convert the selected local baselines into enforceable release-mode gates with stored before/after evidence. |

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
| General UDP socket semantics | Later compatibility | Phase 2 only needs UDP if it is the chosen implementation detail for DNS. |
| Edge-triggered epoll and one-shot/exclusive watches | Later compatibility | Phase 2 readiness is level-triggered for CLI/network tool smoke tests. |
| AF_UNIX compatibility | Later compatibility | TCP client behavior is the Phase 2 networking proof. |
| Full `fork` without immediate exec | Later compatibility | Common shell and build paths can start with `fork+exec` fast path. |
| Process-shared futex | Later compatibility | Current model intentionally keeps one host process per container. |
| Strong sandboxing | Later product line | Current product trust model is trusted development workloads. |
| Cross-architecture guest execution | Later product line | Same-ISA x86-64 is required to keep MVP feasible. |

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
| `mcr run-rootfs node-rootfs /bin/sh -c "<run JavaScript with node --jitless>"` | Node.js JavaScript execution is green locally when the extended smoke runs real JS through `node --jitless`. The unpinned V8 native/JIT path can still fault on the `hlt` terminator. | Keep broader Node package-manager/build and V8 native/JIT workloads on the workload backlog; the extended-support JavaScript smoke is restored on the interpreter path. |
| `mcr run-rootfs jdk-rootfs /bin/sh -c "<javac then java>"` | JDK compile-and-run is repeatably green locally when the smoke pins the compile/run step to interpreted mode with `javac -J-Xint` and `java -Xint`. Unpinned `javac -version` is now covered after nanosleep stopped blocking the whole guest scheduler. | Keep broader unpinned Java compilation workloads on the workload backlog, but the extended-support javac version and compile-and-run smoke is restored. |
| `mcr run-rootfs mysql-rootfs /bin/sh -c "<bootstrap mariadbd and run query matrix>"` | MariaDB bootstrap mode now initializes InnoDB, creates customer/item/order tables, bulk-inserts 128 rows, and verifies ordinary lookup, forced-index aggregate, JOIN aggregate, and range aggregate query results through `SELECT ... INTO OUTFILE`. Full install-db plus background daemon/client query remains broader than the restored smoke; the latest bounded install-db probe still did not complete. | Keep full local server startup plus client query coverage on the workload backlog; the extended-support bootstrap query matrix is restored. |
| `mcr run-rootfs rust-rootfs /bin/sh -c "cargo --version"` | The FS/TLS fallback now handles the prior `mov rax, fs:[0]` native fault and advances execution to `guest block terminated with x86 exception before syscall at guest rip 0x000000007006681e`. | Classify the new x86 exception terminator and decide whether it is an unsupported instruction, signal/exception semantic gap, or workload-specific runtime blocker. |

## Resolved Build Direction

- Phase 3 is the native MCR builder plus OCI/Docker image output.
- Phase 4 is the BuildKit worker/executor adapter.
- Docker Engine API compatibility is later than BuildKit integration.
- OCI image layer diff belongs in `mcr-snapshot` and feeds `mcr-image` through content-addressed descriptors.

## Open Questions For Later Milestones

- Whether pty/tty completeness is needed before the first public preview.
- Whether host process mapping is needed for selected workloads after Phase 2.
