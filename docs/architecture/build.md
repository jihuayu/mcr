# Build, OCI, And BuildKit Design

## Purpose And Boundary

This document defines the post-Phase 2 build plane for MCR.

The build plane turns a Linux rootfs-capable runtime into a constrained image builder:

- pull and unpack OCI/Docker base images for `linux/amd64`;
- execute a documented Dockerfile subset;
- run every `RUN` step through the MCR Linux userspace runtime;
- capture filesystem changes as deterministic OCI layers;
- export OCI layout and Docker-compatible tar outputs;
- expose the same executor, snapshot, content, and image contracts to a later BuildKit worker.

The build plane is not part of MVP or Phase 2. Runtime correctness remains the prerequisite.

## Product Boundary

| Area | In first build release | Deferred |
|---|---|---|
| Platform | `linux/amd64` images on Windows x86-64. | `linux/arm64`, cross-architecture builds, Windows containers. |
| Dockerfile | `FROM`, `ARG`, `ENV`, `WORKDIR`, `COPY`, `ADD` local files, `RUN`, `CMD`, `ENTRYPOINT`, basic multi-stage `COPY --from`. | Full Dockerfile feature parity, heredoc edge cases, advanced mount/cache/secret/ssh syntax. |
| Execution | Shell and exec form `RUN` through `mcr-runtime`. | Alternative executors and host shell fallbacks. |
| Image output | OCI image layout and Docker-compatible tarball. | Full Docker Engine image store compatibility. |
| Registry | Basic OCI pull/push and auth hooks. | Complete credential helper and mirror policy surface. |
| Cache | Deterministic local content and snapshot keys. | Distributed cache, inline cache parity, remote cache import/export. |
| BuildKit | Worker/executor adapter after native builder contracts are stable. | Treating existing Windows container BuildKit worker as sufficient. |
| Docker API | None in first build release. | Docker Engine API facade, Compose, volumes, stats, events. |

## System Shape

```text
CLI / future BuildKit worker
        |
        v
mcr-build
        |
        +--> Dockerfile subset model
        +--> Build context and ignore rules
        +--> Step planner
        |
        +--> mcr-image
        |       +--> registry pull/push
        |       +--> content-addressed blob store
        |       +--> OCI config/manifest/layout writer
        |
        +--> mcr-snapshot
        |       +--> base rootfs unpack
        |       +--> lower/upper build views
        |       +--> diff and OCI whiteout export
        |
        +--> mcr-runtime
                +--> executes RUN through the normal guest path
```

BuildKit integration enters at the top of this shape. It replaces the native Dockerfile planner with BuildKit LLB solving, but it must reuse the lower contracts.

## Module Ownership

| Package | Owns | Delegates |
|---|---|---|
| `mcr-build` | Native Dockerfile subset, build graph, step ordering, build args, env, workdir, tags, user-facing build command. | Image pull/export to `mcr-image`, snapshots to `mcr-snapshot`, `RUN` to `mcr-runtime`. |
| `mcr-image` | OCI descriptors, digest validation, blob storage, image config, manifests, indexes, registry transfer, layout and tar export. | Filesystem unpack to `mcr-snapshot`; network transport to host adapters or HTTP clients. |
| `mcr-snapshot` | Snapshot IDs, lower layer chain, writable upper roots, diff walking, metadata sidecar, whiteout generation, layer tar stream. | Linux path and metadata semantics to `mcr-vfs` concepts where shared. |
| `mcr-runtime` | Linux process execution for `RUN`, stdout/stderr, exit status, cancellation, diagnostic traces. | Filesystem backing to `mcr-snapshot`; syscalls to existing runtime modules. |
| BuildKit adapter | Worker capability advertisement, BuildKit exec/source/file result wiring, cache metadata mapping. | Actual execution, snapshotting, content, and image output to MCR contracts. |

## Core Contracts

### Run Executor

`mcr-runtime` exposes a build-oriented executor over the same execution path used by `mcr run-rootfs`.

```rust
struct BuildRunSpec {
    rootfs: SnapshotMount,
    argv: Vec<String>,
    env: BTreeMap<String, String>,
    cwd: GuestPath,
    user: Option<GuestUser>,
    stdin: RunInput,
    stdout: RunOutput,
    stderr: RunOutput,
    network: BuildNetworkMode,
    timeout: Option<Duration>,
}

struct BuildRunResult {
    exit_code: i32,
    stdout_digest: Option<Digest>,
    stderr_digest: Option<Digest>,
    trace_id: TraceId,
}
```

Required behavior:

- shell form `RUN` resolves through the image's configured shell, defaulting to `/bin/sh -c`;
- exec form `RUN` bypasses shell parsing;
- `cwd`, environment, argv, and user are guest-visible state;
- exit code is preserved exactly;
- stdout/stderr can be streamed to CLI and captured for diagnostics;
- cancellation terminates the guest process tree tracked by MCR;
- unsupported runtime behavior returns a typed build error with the runtime trace ID.

Host shell execution is forbidden for Dockerfile `RUN`.

### Snapshot

Snapshots are explicit build state. A snapshot is not just a host directory.

```rust
struct SnapshotId(String);

struct SnapshotView {
    id: SnapshotId,
    lower: Vec<LayerRef>,
    upper: UpperRoot,
    metadata: SnapshotMetadata,
}

struct SnapshotDiff {
    entries: Vec<DiffEntry>,
    layer_digest: Digest,
    uncompressed_digest: Digest,
}
```

Required behavior:

- base image layers unpack into read-only lower state;
- each mutable build step receives a new writable upper;
- `COPY`/`ADD` and `RUN` write through the same snapshot mutation path;
- diff walking emits deterministic path order, metadata, file contents, symlinks, hardlinks where supported, and directory entries;
- deletions of lower files emit OCI whiteouts using `.wh.<name>`;
- opaque lower directory removal emits `.wh..wh..opq`;
- Linux metadata that cannot be represented by NTFS is stored in MCR metadata sidecars;
- case handling is guest-defined, not inherited blindly from the host filesystem.

### Content Store

`mcr-image` stores image blobs by digest.

```rust
struct Descriptor {
    media_type: String,
    digest: Digest,
    size: u64,
    annotations: BTreeMap<String, String>,
}

trait ContentStore {
    fn has(&self, digest: &Digest) -> Result<bool, ContentError>;
    fn write_blob(&self, media_type: &str, bytes: BlobReader) -> Result<Descriptor, ContentError>;
    fn read_blob(&self, digest: &Digest) -> Result<BlobReader, ContentError>;
}
```

Required behavior:

- digest verification happens on every pull, import, and local write;
- descriptors carry OCI media types;
- tag resolution is separate from blob storage;
- cache keys use descriptors and build inputs, not mutable paths or tags alone.

### Image Store And Export

`mcr-image` owns image metadata and output.

Required behavior:

- pull a `linux/amd64` image manifest or image index from a registry;
- reject an image when no compatible platform manifest exists;
- unpack layers into snapshots in descriptor order;
- write image config with environment, working directory, entrypoint, command, history, diff IDs, and rootfs metadata;
- write OCI image layout output;
- write Docker-compatible tar output for `docker load`;
- push images by uploading missing blobs before manifests.

The first exporter should be deterministic for the same inputs.

## Native Builder Flow

```text
mcr build -t demo .
  -> read Dockerfile and .dockerignore
  -> parse supported instructions into BuildPlan
  -> resolve FROM image through mcr-image
  -> unpack base layers into mcr-snapshot
  -> apply ENV / ARG / WORKDIR metadata
  -> apply COPY / ADD into snapshot upper
  -> execute RUN through mcr-runtime
  -> diff snapshot into OCI layer
  -> write config, manifest, image layout or docker tar
```

Every build step produces either metadata changes or a snapshot result. The builder must never mutate a previous immutable result.

## Dockerfile Subset

| Instruction | First behavior |
|---|---|
| `FROM` | Registry reference or local image reference, optional `AS name`, `linux/amd64` only. |
| `ARG` | Build-time variable with default and CLI override. |
| `ENV` | Image environment metadata and runtime environment for later `RUN`. |
| `WORKDIR` | Creates directory when needed and sets cwd for later `RUN`, `COPY`, and metadata. |
| `COPY` | Local context copy, directory copy, metadata preservation through MCR sidecar, basic `--from`. |
| `ADD` | Same as `COPY` for local files first; remote URL and tar auto-extract are deferred. |
| `RUN` | Shell and exec form through `BuildRunSpec`. |
| `CMD` | Image config only. |
| `ENTRYPOINT` | Image config only. |

Unsupported instructions fail with a clear build error that names the instruction and the current subset.

## BuildKit Worker Boundary

BuildKit integration starts only after the native builder proves executor, snapshot, content, and image contracts.

The adapter owns:

- worker registration and capability advertisement;
- mapping BuildKit source/file/exec requests to MCR contracts;
- mapping MCR snapshot descriptors back to BuildKit cache references;
- translating BuildKit cancellation and progress events;
- exposing the local content store to BuildKit.

The adapter does not own:

- Linux syscall behavior;
- snapshot diff semantics;
- OCI whiteout semantics;
- image descriptor validation;
- Dockerfile parsing for the native builder.

First BuildKit acceptance:

```text
buildctl --addr npipe:////./pipe/mcr-buildkit build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --output type=oci,dest=out.tar
```

The output must match the native builder for the same supported Dockerfile subset, allowing only documented metadata differences.

## Diagnostics

Build failures must report:

- Dockerfile path and instruction index;
- build stage name or number;
- snapshot ID;
- content descriptor when a blob is involved;
- runtime trace ID for `RUN`;
- stdout/stderr tail for failed `RUN`;
- unsupported feature name for subset failures.

## Validation Matrix

| Capability | Required proof |
|---|---|
| Base image pull | Pull `alpine:latest` or a pinned digest for `linux/amd64` and verify descriptors. |
| Snapshot unpack | Read files from unpacked layers through MCR VFS-compatible paths. |
| COPY | Copy a local context directory and preserve deterministic output. |
| RUN | `RUN echo hello > /hello.txt` creates a layer containing `/hello.txt`. |
| Package manager | `RUN apk add --no-cache build-base` completes or fails with runtime trace diagnostics. |
| Multi-stage | `COPY --from=build` copies a file from a previous stage snapshot. |
| OCI layout | External OCI validation accepts the output. |
| Docker tar | `docker load` accepts the output where Docker is available. |
| BuildKit adapter | `buildctl` can drive the same supported build subset. |

## Deferred Work

- Docker Engine API facade;
- Compose compatibility;
- Docker volume semantics;
- complete BuildKit frontend feature parity;
- remote and inline cache parity;
- secret, ssh, cache, tmpfs, and bind mount flags for `RUN`;
- cross-architecture builds;
- strong hostile-code sandboxing;
- Windows container builds.
