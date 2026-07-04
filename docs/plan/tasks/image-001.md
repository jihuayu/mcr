---
id: image-001
scope: phase3-image
status: done
depends-on: [workload-001]
---

# image-001: Add OCI Descriptor And Content Store Foundation

## Objective

Create the `mcr-image` crate with OCI descriptor types, digest validation, media type constants, and a local content-addressed blob store contract.

## Context

- `docs/architecture/build.md`
- `docs/architecture/README.md`
- `docs/development/README.md`
- `docs/plan/analysis/buildkit.md`

## Path

- `Cargo.toml`
- `crates/mcr-image/`

## Verification

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p mcr-image
```

## Notes

- Store blobs by digest, not tag or mutable path.
- Verify digest on every blob write and read path that crosses a trust boundary.
- Do not implement registry pull or image export in this task.
- Initial checkpoint: added the `mcr-image` crate with OCI media type constants,
  SHA-256 descriptor digest parsing/normalization, and a local content-addressed
  blob store that writes and reads under `blobs/sha256/<digest>` with size and
  digest verification.
- 2026-07-04: verified complete for the OCI descriptor and local content-store
  foundation. Registry pull and image export remain tracked under later image
  tasks.
