# Build + BuildKit Delivery Analysis

## Objective

This analysis decomposes post-Phase 2 build work into independently reviewable implementation tasks.

The target order is:

1. Phase 3 native builder: image/content contracts, snapshot/layer diff, constrained Dockerfile execution, OCI/Docker output.
2. Phase 4 BuildKit worker: adapt the stable MCR executor, snapshot, content, and image contracts to BuildKit.
3. Docker Engine API compatibility remains outside this task graph.

Phase 3 and Phase 4 depend on `workload-001`, the Phase 2 completion gate.

## Module Decomposition

| Module | Inputs | Outputs | Depends on | Delivery tasks |
|---|---|---|---|---|
| `mcr-image` | Registry refs, descriptors, blobs, image metadata | OCI descriptors, local content blobs, image configs, manifests, layout/tar outputs, push/pull results | `mcr-net`, host HTTP/TLS, snapshot unpack | `image-001`, `image-002`, `image-003`, `image-004` |
| `mcr-snapshot` | Base layers, build writes, metadata sidecars | snapshot views, upper roots, deterministic layer diffs, whiteout tar entries | `mcr-vfs` semantics | `snapshot-001`, `snapshot-002` |
| `mcr-build` | Dockerfile, build context, build args, target tag | build plan, stage graph, image output, CLI progress and errors | image, snapshot, runtime executor | `build-001`, `build-002`, `build-003`, `build-004`, `integ-004` |
| `mcr-runtime` build executor | snapshot rootfs, argv/env/cwd/stdio/network mode | exit code, traces, stdout/stderr stream, cancellation result | Phase 2 runtime | `buildrun-001` |
| `mcr-cli` build command | CLI args, build context path, output flags | calls native builder and exits with build result | build | `build-001`, `build-003`, `integ-004` |
| BuildKit adapter | BuildKit worker requests, source/file/exec ops, cache refs | BuildKit worker capability, MCR snapshots, progress, output refs | native builder contracts | `buildkit-001`, `buildkit-002`, `buildkit-003` |
| `mcr-testkit` build fixtures | Dockerfile fixtures, expected image contents, registry test endpoints | reproducible build smoke matrix and external validation helpers | image, snapshot, build, optional Docker/OCI tools | `integ-004`, `buildkit-003` |

## Integration Enumeration

Each integration task must connect real modules instead of leaving stubs.

| Integration | Required real path | Proved by |
|---|---|---|
| CLI to native builder | `mcr-cli` parses `build`, creates build options, calls `mcr-build`. | `build-003`, `integ-004` |
| Builder to image resolver | `mcr-build` resolves `FROM` through `mcr-image`, including platform selection. | `image-002`, `build-003` |
| Image to snapshot | `mcr-image` unpacks pulled layers through `mcr-snapshot` in descriptor order. | `image-002` |
| Builder to snapshot mutation | `COPY`, `ADD`, `WORKDIR`, and metadata instructions mutate snapshot state through `mcr-snapshot`, not host paths directly. | `build-002` |
| Builder to runtime executor | `RUN` creates `BuildRunSpec` and executes through `mcr-runtime`. | `buildrun-001`, `build-003` |
| Runtime executor to snapshot rootfs | Runtime sees the snapshot rootfs as guest filesystem state and writes build outputs into the upper layer. | `buildrun-001`, `build-003` |
| Snapshot to image layer | `mcr-snapshot` emits deterministic tar diff and OCI whiteouts. | `snapshot-002`, `image-003` |
| Image metadata to exporters | `mcr-image` writes config, manifest, OCI layout, and Docker tar. | `image-003`, `integ-004` |
| Multi-stage graph | Later stages reference previous stage snapshots by name and copy files through snapshot APIs. | `build-004` |
| Registry push | `mcr-image` uploads missing blobs before manifest push. | `image-004` |
| Native builder E2E | `mcr build -t demo .` runs fixed fixtures and produces externally valid output. | `integ-004` |
| BuildKit to MCR worker | BuildKit worker requests map to MCR source/file/exec/snapshot/content contracts. | `buildkit-001`, `buildkit-002` |
| BuildKit E2E | `buildctl` drives the supported Dockerfile subset through MCR and exports OCI output. | `buildkit-003` |

## Dependency Graph

```text
workload-001
  -> image-001
      -> image-002
      -> image-003
          -> image-004
  -> snapshot-001
      -> snapshot-002
          -> image-003
  -> build-001
      -> build-002
  -> buildrun-001

image-002
snapshot-002
build-002
buildrun-001
  -> build-003
      -> build-004
          -> integ-004
              -> buildkit-001
                  -> buildkit-002
                      -> buildkit-003

image-004
  -> integ-004
```

`image-001`, `snapshot-001`, `build-001`, and `buildrun-001` may be implemented in parallel after `workload-001` if separate worktrees are available and their paths do not overlap.

## Phase 3 Acceptance

Phase 3 is complete when:

- `mcr build -t demo .` supports the documented Dockerfile subset;
- fixed Dockerfile fixtures cover `FROM`, `ARG`, `ENV`, `WORKDIR`, `COPY`, local `ADD`, shell and exec form `RUN`, `CMD`, `ENTRYPOINT`, and basic multi-stage `COPY --from`;
- `RUN` execution uses the same runtime path as `mcr run-rootfs`;
- snapshot diff emits deterministic OCI layers with whiteout support;
- OCI layout validation passes;
- Docker tar output is accepted by `docker load` where Docker is available;
- registry push/pull round-trip succeeds against a deterministic local or test registry.

## Phase 4 Acceptance

Phase 4 is complete when:

- a BuildKit worker can advertise the supported MCR capabilities;
- BuildKit source/file/exec operations map to MCR build context, snapshot, and runtime executor contracts;
- `buildctl --frontend dockerfile.v0 --output type=oci` drives the same supported fixture set as the native builder;
- cache metadata is stable enough for repeated local builds to reuse unchanged source and exec results;
- unsupported BuildKit features fail with named, intentional errors.

## Task Boundary Rules

- Native builder tasks must not execute `RUN` through the host shell.
- Snapshot tasks must represent Linux metadata and whiteouts explicitly; host directory state is not the source of truth.
- Image tasks must validate digests on read and write.
- BuildKit tasks must be adapters over MCR contracts. They must not introduce a second image store, snapshot diff, or runtime execution path.
- Docker Engine API work is not part of these tasks.
