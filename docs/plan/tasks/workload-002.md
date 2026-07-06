---
id: workload-002
scope: phase2-workloads
status: ready
depends-on: [task-004, task-005, jit-002]
---

# workload-002: Close Node V8 Default JIT Contract

## Objective

Promote Node.js from the restored `--jitless` extended-support smoke to a
default V8 native/JIT workload that can execute optimized JavaScript and exit
cleanly with concurrent compiler threads enabled.

## Context

- `docs/product/README.md`
- `docs/architecture/runtime.md`
- `docs/development/README.md`
- `docs/plan/backlog.md`
- `docs/plan/tasks/task-004.md`
- `docs/plan/tasks/task-005.md`
- `docs/plan/tasks/jit-002.md`

## Path

- `crates/mcr-testkit/`
- `crates/mcr-runtime/`
- `crates/mcr-task/`
- `crates/mcr-jit/`
- `crates/mcr-win/`
- `docs/development/README.md`
- `docs/plan/backlog.md`
- `docs/plan/tasks/workload-002.md`

## Verification

```powershell
$env:MCR_BIN='target\debug\mcr.exe'
cargo build -p mcr-cli
cargo test -p mcr-testkit --test extended_support_smoke_contract extended_support_smoke_contract_nodejs_run -- --ignored --nocapture --test-threads=1
target\debug\mcr.exe run-rootfs --guest-step-limit 160000 tests\fixtures\rootfs\node-rootfs /bin/sh -c '/usr/bin/node --allow-natives-syntax --trace-opt --no-concurrent-recompilation -e "function f(x){return x+1}; for(let i=0;i<10000;i++) f(i); %PrepareFunctionForOptimization(f); %OptimizeFunctionOnNextCall(f); let y=f(41); require(\"fs\").writeSync(1, \"opt=\"+y+\"\n\")"'
target\debug\mcr.exe run-rootfs --guest-step-limit 160000 tests\fixtures\rootfs\node-rootfs /bin/sh -c '/usr/bin/node --allow-natives-syntax --trace-opt -e "function f(x){return x+1}; for(let i=0;i<10000;i++) f(i); %PrepareFunctionForOptimization(f); %OptimizeFunctionOnNextCall(f); let y=f(41); require(\"fs\").writeSync(1, \"opt-concurrent=\"+y+\"\n\")"'
```

## Notes

- Current evidence shows synchronous Maglev/Turbofan optimized code can run and
  print the expected result, so this is not primarily a "V8 cannot emit machine
  code" problem.
- The open blockers are Linux signal delivery, fatal default actions,
  interruptible futex waits, `clear_child_tid`/pthread join, and concurrent
  compiler-thread shutdown.
- Keep the `--jitless` smoke until this contract is green; only then promote
  the default-JIT Node command into the extended-support matrix.
- The final contract must preserve real failures. It should not special-case
  Node or suppress V8 fatal signals to get a green smoke.
