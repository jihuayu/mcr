# integ-002 Review 1

## Findings

1. **P1 blocking** - `run-rootfs /bin/sh -c ...` is still a host-side command emulator, not real guest dynamic execution through the runtime.
   - Design: `docs/product/README.md:68`, `docs/architecture/runtime.md:3`, `docs/architecture/runtime.md:62`, `docs/architecture/runtime.md:110`, `docs/development/README.md:69`, `docs/plan/tasks/integ-002.md:10`
   - Code: `crates/mcr-runtime/src/run_rootfs.rs:196`, `crates/mcr-runtime/src/run_rootfs.rs:227`, `crates/mcr-runtime/src/run_rootfs.rs:290`, `crates/mcr-runtime/src/run_rootfs.rs:437`, `crates/mcr-runtime/src/run_rootfs.rs:462`, `crates/mcr-runtime/src/run_rootfs.rs:480`, `crates/mcr-cli/tests/run_rootfs.rs:58`
   - Evidence: `run_rootfs` loads the ELF and creates a `RuntimeWithTracer`, but then calls `dispatch_mvp_program` against a separate host-populated `VirtualFileSystem`. `/bin/sh -c` is parsed by `lex_shell` and executed by Rust helpers for `echo`, `cat`, `head`, `true`, and `false`. The shell tests create a synthetic static ELF at `/bin/sh`. This path never enters guest code, never runs Alpine `/bin/sh`, and never exercises the common `fork+exec+wait4` shell path.

2. **P1 blocking** - The main runtime dispatcher is not wired to the VFS/fd/proc/dev implementation for guest syscalls.
   - Design: `docs/architecture/runtime.md:45`, `docs/architecture/runtime.md:62`, `docs/architecture/runtime.md:132`, `docs/architecture/runtime.md:172`, `docs/plan/tasks/integ-002.md:12`
   - Code: `crates/mcr-runtime/src/lib.rs:386`, `crates/mcr-runtime/src/lib.rs:1039`, `crates/mcr-runtime/src/lib.rs:1093`, `crates/mcr-sys/src/dispatcher.rs:294`
   - Evidence: file syscall handling exists on the separate `RuntimeFileSystem<M>` helper, but `RuntimeSubsystems` only owns `GuestKernel`, `GuestMemory`, and futex waiter counters. Its `impl FileSyscalls for RuntimeSubsystems {}` uses the default unsupported implementation, so a real guest `openat`, `read`, `write`, `pipe`, `dup`, `fcntl`, procfs, devfs, or writable-VFS syscall would return `ENOSYS` instead of reaching `mcr-vfs`.

3. **P1 blocking** - `execve` ignores the guest syscall path, argv, and envp, so the runtime cannot execute child programs from a shell.
   - Design: `docs/architecture/runtime.md:110`, `docs/development/README.md:71`, `docs/plan/tasks/integ-002.md:12`
   - Code: `crates/mcr-task/src/lib.rs:686`, `crates/mcr-task/src/lib.rs:774`, `crates/mcr-task/src/lib.rs:1262`
   - Evidence: the `Syscall::Execve` arm rebuilds a `GuestProgram` from the current process image and interpreter, then calls `execve_current`. It does not read the syscall's filename, argv, or envp pointers, does not resolve the target executable through the rootfs VFS, and cannot load `/bin/cat`, `/bin/head`, or other shell children selected by Alpine `/bin/sh`.

4. **P2 blocking** - `/proc/self` is mounted as static nodes, but the required process-backed contents and fd links are missing.
   - Design: `docs/architecture/runtime.md:172`, `docs/product/README.md:68`, `docs/plan/tasks/integ-002.md:12`
   - Code: `crates/mcr-vfs/src/lib.rs:414`, `crates/mcr-vfs/src/lib.rs:797`, `crates/mcr-vfs/src/lib.rs:2016`, `crates/mcr-vfs/src/lib.rs:2522`, `crates/mcr-runtime/src/run_rootfs.rs:705`
   - Evidence: `mount_minimal_procfs` creates `/proc/self/exe`, `/proc/self/cmdline`, `/proc/self/environ`, and `/proc/self/fd`, but `cmdline` and `environ` have no process-backed data, `readlink` only handles `PathNodeKind::Symlink` rather than `ProcNodeKind::Exe` or `FdLink`, and no `/proc/self/fd/<n>` entries are materialized from the current fd table. The current proc/dev smoke only proves that `cat /proc/self/cmdline` can read an empty regular node and discard it to `/dev/null`.

5. **P2 blocking** - Futex support is a counter stub, not process-private `WAIT`/`WAKE` synchronization.
   - Design: `docs/architecture/runtime.md:120`, `docs/development/README.md:75`, `docs/plan/tasks/integ-002.md:12`
   - Code: `crates/mcr-runtime/src/lib.rs:1043`, `crates/mcr-runtime/src/lib.rs:1124`
   - Evidence: `FUTEX_WAIT` checks the memory value, but with a null timeout it increments a waiter count and returns success immediately instead of blocking. With a non-null timeout pointer it returns `ETIMEDOUT` without reading the requested timeout. There is no real sleep/wake handoff, no interrupt path, and no host sync adapter integration, so this does not satisfy the Phase 2 futex contract.

6. **P2 blocking** - The required real Alpine shell smoke tests are not enabled as integration proof.
   - Design: `docs/development/README.md:114`, `docs/development/README.md:118`, `docs/plan/tasks/integ-002.md:30`
   - Code: `crates/mcr-cli/tests/run_rootfs.rs:58`, `crates/mcr-runtime/src/run_rootfs.rs:898`, `crates/mcr-testkit/src/lib.rs:1081`, `tests/fixtures/rootfs/manifest.mcr:3`
   - Evidence: committed shell tests use temporary rootfs directories with synthetic static ELF fixtures, while `mcr-testkit` still only has an ignored MVP BusyBox smoke contract. `alpine-rootfs` is metadata-only and `required=false`. In this checkout, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` pass, but `target/debug/mcr run-rootfs alpine-rootfs /bin/sh -c "echo hi"` fails with `rootfs does not exist: alpine-rootfs` before any real Alpine shell can run.

## Conclusion

blocked
