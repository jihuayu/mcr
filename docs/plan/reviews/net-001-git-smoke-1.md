# net-001 Git Smoke Review 1

Date: 2026-07-04

## Scope

- Native MCR execution of Alpine `git` through the materialized rootfs.
- HTTPS clone with normal certificate verification enabled.
- Follow-up evidence after curl HTTPS, connected UDP DNS, TCP readiness,
  file-backed mmap population, `fsync`/`pread64`, and VFS created-file access
  fixes.

## Findings

- `git ls-remote https://github.com/octocat/Hello-World.git HEAD` succeeds and
  returns the expected HEAD object id, proving the HTTPS transport, DNS path,
  CA bundle, and remote helper execution path are usable.
- `git clone --depth 1 https://github.com/octocat/Hello-World.git ...` succeeds
  without `http.sslVerify=false`.
- Full `git clone https://github.com/octocat/Hello-World.git ...` also succeeds.
- The full clone initially failed after `index-pack` spawned
  `git rev-list --objects --stdin --not --all --quiet --alternate-refs`. The
  child process reported `Error loading shared library libpcre2-8.so.0: Bad file
  descriptor`.
- That failure was not a certificate or socket issue. The dynamic linker opened
  `libpcre2-8.so.0` successfully, then failed while mapping it because
  file-backed `mmap(fd, ...)` selected only the calling process memory. If
  another runnable process's fd table was currently selected, mmap population
  read from the wrong fd table and returned `EBADF`.
- `mmap` now selects full process context for file-backed mappings before
  reading from the mapped fd, so memory and fd tables remain aligned for nested
  fork/exec workloads.

## Validation

```powershell
cargo fmt --check
cargo test -p mcr-runtime runtime_file_backed_mmap_uses_calling_process_fd_table -- --nocapture
cargo build -p mcr-cli
target\debug\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /usr/bin/git ls-remote https://github.com/octocat/Hello-World.git HEAD
target\debug\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /usr/bin/git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/mcr-hello-https-*
target\debug\mcr.exe run-rootfs tests\fixtures\rootfs\alpine-rootfs /usr/bin/git clone https://github.com/octocat/Hello-World.git /tmp/mcr-hello-full-https-fixed-*
$env:MCR_BIN=(Resolve-Path target\debug\mcr.exe).Path; cargo test -p mcr-testkit --test network_smoke_contract -- --ignored network_smoke_contract --nocapture
```

Observed local smoke results:

```text
git ls-remote HEAD: EXIT=0, 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d HEAD
git clone --depth 1: EXIT=0
git clone full HTTPS: EXIT=0
mcr-testkit network_smoke_contract: 4 passed
```

## Next

- If the GitHub Actions x86 network suite is available, run
  `gh workflow run x86-runtime-smoke.yml -f suite=network` as the remote
  integration gate. Local Windows x86-64 native guest execution has already
  covered the equivalent `curl`/`git` network contract path.
