---
id: perf-016
scope: io-performance
status: ready
depends-on: [perf-003, perf-015]
---

# perf-016: Implement Real Overlapped File And Pipe Backend

## Objective

Replace the file/pipe synchronous fallback with a real Windows overlapped I/O
backend where handle type and host support allow it, while preserving guest
`read`, `write`, blocking, nonblocking, timeout, interruption, and close
semantics.

## Context

- `docs/architecture/runtime.md`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-003.md`

## Path

- `crates/mcr-win/`
- `crates/mcr-vfs/`
- `crates/mcr-runtime/`
- `crates/mcr-testkit/`
- `docs/architecture/performance.md`
- `docs/plan/tasks/perf-016.md`

## Verification

```powershell
cargo test -p mcr-win overlapped -- --nocapture
cargo test -p mcr-vfs pipe file -- --nocapture
cargo test -p mcr-runtime io_ pipe poll epoll -- --nocapture
cargo test -p mcr-testkit perf_file_io -- --ignored --nocapture
```

## Notes

- Keep the existing synchronous fallback for unsupported file kinds, Windows
  versions, and failure cases.
- Completion buffers and host records must outlive completion, cancellation, and
  close-drain paths.
- Runtime readiness must be event driven; do not add timer polling as the normal
  overlapped completion path.

## Checkpoints

- Added the first real Windows overlapped regular-file operation boundary in
  `mcr-win`: `FileOptions::with_overlapped_io()` opens a handle with
  `FILE_FLAG_OVERLAPPED`, and `HostFile::submit_overlapped_read_at` /
  `submit_overlapped_write_at` issue offset-based `ReadFile` / `WriteFile`
  requests with an owned event and `GetOverlappedResult`.
- Existing `submit_overlapped_read` / `submit_overlapped_write` keep returning
  the synchronous fallback because they do not carry an offset and therefore
  cannot safely preserve regular-file position on an overlapped handle.
- This checkpoint proves the Windows adapter can execute real overlapped
  operations and return owned buffers through `HostIoSubmission::Completed` or
  `HostIoSubmission::Failed`. VFS/runtime readiness integration and pipe handle
  wiring remain in this task.
- VFS deferred rootfs regular-file reads now keep host-backed file content
  unmaterialized on open and read through the host adapter's offset-based
  overlapped boundary. Writes, truncation, and other mutations still
  materialize the file into VFS-owned memory before changing contents.
- The read path treats overlapped EOF as a zero-byte Linux read, so ELF segment
  tail probes and other offset reads past the host file end do not surface as
  guest `EINVAL`.
