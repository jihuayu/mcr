---
id: workload-002
scope: phase2-workloads
status: done
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
target\debug\mcr.exe run-rootfs --guest-step-limit 160000 tests\fixtures\rootfs\node-rootfs /bin/sh -c '/usr/bin/node --allow-natives-syntax -e "function f(x){return x+1}; for(let i=0;i<10000;i++) f(i); %PrepareFunctionForOptimization(f); %OptimizeFunctionOnNextCall(f); let y=f(41); require(\"fs\").writeSync(1, \"opt-concurrent=\"+y+\"\n\")"'
```

## Notes

- Closed by promoting the extended-support Node smoke from `--jitless` to the
  default V8 JIT path. The contract now warms a JavaScript function, requests
  optimization through V8 native syntax, verifies the optimized result, and
  exits only after writing `node-ok`.
- The default probe prints `opt-concurrent=42` with V8 optimization enabled.
- The smoke does not special-case Node or suppress V8 fatal signals.
- V8 diagnostic modes such as `--trace-opt` and forced
  `--no-concurrent-recompilation` still exercise broader mutex/logging paths
  than this default-JIT contract and remain outside this task.
