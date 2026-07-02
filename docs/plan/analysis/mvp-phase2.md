# MVP + Phase 2 Delivery Analysis

## Objective

This analysis decomposes the runtime plan into independently reviewable implementation tasks ending at Phase 2 completion: BusyBox/Alpine MVP, shell `fork+exec`, networking, and minimal `/proc`/`/dev`.

Dockerfile builder, OCI output, BuildKit, and Docker Engine API are outside this task graph.

## Module Decomposition

| Module | Inputs | Outputs | Depends on | Delivery tasks |
|---|---|---|---|---|
| `mcr-cli` | CLI args, rootfs path, argv | exit code, stdout/stderr wiring, diagnostics | runtime | `boot-001`, `integ-001`, `integ-002`, `integ-003`, `workload-001` |
| `mcr-runtime` | `RuntimeConfig`, rootfs, argv/env | guest session lifecycle | elf, jit, sys, vfs, task, net | `boot-001`, `diag-001`, integration tasks |
| `mcr-elf` | ELF bytes, argv/env, rootfs context | memory map, entrypoint, initial stack | win memory, ABI | `elf-001`, `elf-002`, `elf-003` |
| `mcr-jit` | entrypoint, guest blocks, guest register state | controlled guest execution and syscall traps | ABI, win memory | `jit-001` |
| `mcr-sys` | syscall number, guest registers | Linux ABI return value | vfs, task, net, win adapters | `abi-001`, `sys-001` |
| `mcr-vfs` | guest paths, fd ops, rootfs | Linux file, directory, proc, dev behavior | win file adapter, ABI | `vfs-001`, `vfs-002`, `vfs-003`, `vfs-004`, `fd-001` |
| `mcr-task` | guest task syscalls, process events | PID/TID, exit, exec, wait, futex, signals | elf, vfs, win sync | `task-001`, `task-002`, `task-003` |
| `mcr-net` | socket syscalls and readiness waits | Linux socket and event compatibility | win net adapter, vfs fd table | `net-001`, `net-002` |
| `mcr-win` | host requests | typed Windows capability wrappers | none | `win-001` |
| `mcr-testkit` | fixtures, expected outputs | unit and opt-in smoke harnesses | CLI/runtime milestones | `testkit-001`, `testkit-002`, integration tasks |

## Integration Enumeration

Each integration task must connect real modules instead of leaving stubs.

| Integration | Required real path | Proved by |
|---|---|---|
| CLI to runtime | `mcr-cli` parses `run-rootfs`, builds `RuntimeConfig`, calls `mcr-runtime`. | `integ-001` |
| Runtime to ELF | Runtime opens guest executable through VFS and passes bytes/context to `mcr-elf`. | `integ-001` |
| ELF to JIT | Loaded entrypoint and memory map are executable through `mcr-jit`. | `integ-001` |
| JIT to syscall dispatcher | Guest `syscall` reaches `mcr-sys` with correct registers. | `jit-001`, `integ-001` |
| Syscall to VFS | P0 file and directory syscalls operate on real rootfs/fd table. | `vfs-002`, `integ-001` |
| Syscall to task | `exit_group`, `getpid`, `gettid`, and `execve` use real guest task state. | `task-001`, `integ-001` |
| Runtime diagnostics | Failed guest execution reports last syscall, registers, VMAs, argv. | `diag-001`, `integ-001` |
| Shell process path | `sh -c` drives `fork+exec+wait4`, pipes, and fd duplication. | `task-002`, `fd-001`, `integ-002` |
| Proc/dev path | Shell and language runtimes read `/proc/self/*` and `/dev/*` through VFS. | `vfs-004`, `integ-002`, `workload-001` |
| Network path | Guest socket syscalls reach Winsock and DNS through `mcr-net`/`mcr-win`. | `net-001`, `integ-003` |
| Event path | Guest `poll`/`epoll` consumes socket, pipe, and internal readiness. | `net-002`, `integ-003` |
| Workload matrix | Runtime executes fixed Node/Python/Go/Rust discovery commands. | `workload-001` |

## Dependency Graph

```text
boot-001
  -> testkit-001
      -> testkit-002
  -> abi-001 -> sys-001
  -> win-001
  -> elf-001 -> elf-002
  -> jit-001
  -> vfs-001 -> vfs-002
  -> mem-001
  -> task-001
  -> diag-001
  -> integ-001
      -> elf-003
      -> vfs-003
      -> fd-001
      -> task-002
      -> task-003
      -> vfs-004
      -> net-001 -> net-002
      -> integ-002
      -> integ-003
      -> workload-001
```

Some module tasks can run in parallel after `boot-001` if separate worktrees are available and their paths do not overlap. Integration tasks are serial gates.

## Task Boundary Rules

- Module tasks may introduce internal mocks only when the task objective is a local contract; integration tasks must replace those mocks for their path.
- A syscall is not considered implemented until it has Linux errno behavior and a test for success and at least one failure path.
- A smoke test is not considered passing if it relies on host shell execution instead of guest execution.
- Unsupported behavior must be explicit and traceable as `ENOSYS`, documented fake behavior, or a documented Phase 2 exclusion.
