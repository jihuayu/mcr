---
id: image-002
scope: phase3-image
status: done
depends-on: [image-001, snapshot-001]
---

# image-002: Pull And Unpack Linux Amd64 Base Images

## Objective

Close the pull/unpack contract boundary for `linux/amd64` image references:
typed reference parsing, platform manifest selection, manifest-to-pull planning,
digest and size verification for layer blobs, and uncompressed base layer unpack
into `mcr-snapshot`. Real registry HTTP transport, auth/token handling, remote
blob fetching, and gzip decompression are deferred.

## Context

- `docs/architecture/build.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `crates/mcr-image/`
- `crates/mcr-snapshot/`
- `crates/mcr-testkit/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-image
cargo test -p mcr-snapshot
```

## Notes

- Reject image indexes without a compatible `linux/amd64` manifest.
- Use deterministic fixture images or a local registry for tests.
- This task does not write final image outputs.
- Initial pull-boundary checkpoint: added typed OCI reference parsing,
  `linux/amd64` image-index manifest selection, manifest-to-pull planning, and
  digest/size-verified layer blobs. Uncompressed OCI tar layers can now cross
  into `mcr-snapshot` as read-only base-layer snapshots through deterministic
  in-memory tests.
- Completed 2026-07-04: pull/unpack contract boundary is complete. The code
  covers typed OCI references, `linux/amd64` index manifest selection,
  manifest-to-pull planning, descriptor digest/size verification, and
  uncompressed layer handoff into `mcr-snapshot`.
- This does not claim support for real remote image pulls. Registry HTTP
  transport, auth/token handling, remote blob fetching, and gzip layer
  decompression are deferred to backlog work.
