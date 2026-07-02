# testkit-002 Review 1

## 1. Findings

无阻塞 findings。

Reviewed design positions:

- `docs/plan/tasks/testkit-002.md:11` - objective for opt-in public-network smoke contracts.
- `docs/plan/tasks/testkit-002.md:32` - normal tests must not require network, GitHub, CA certificates, or rootfs payloads.
- `docs/plan/tasks/testkit-002.md:36` - network smokes must run through `mcr run-rootfs alpine-rootfs /bin/sh -c ...`.
- `docs/development/README.md:135` - Phase 2 network contracts are opt-in and normal `cargo test -p mcr-testkit` must stay offline/rootfs-free.
- `docs/development/README.md:144` - tests invoke `mcr` as `run-rootfs`, the `alpine-rootfs` fixture, `/bin/sh`, `-c`, and the public network command.
- `docs/product/README.md:68` - Phase 2 completion requires fixed smoke tests for network tools.
- `docs/architecture/runtime.md:189` - Phase 2 networking/eventing design requires host networking and guest socket ABI virtualization.

Reviewed code positions:

- `crates/mcr-testkit/tests/network_smoke_contract.rs:16` - `curl --version` contract.
- `crates/mcr-testkit/tests/network_smoke_contract.rs:21` - `curl -fsSL https://example.com >/dev/null` contract.
- `crates/mcr-testkit/tests/network_smoke_contract.rs:26` - `git --version` contract.
- `crates/mcr-testkit/tests/network_smoke_contract.rs:31` - `git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hello-world` contract.
- `crates/mcr-testkit/tests/network_smoke_contract.rs:51` - `MCR_BIN` and materialized `alpine-rootfs` opt-in gating.
- `crates/mcr-testkit/tests/network_smoke_contract.rs:80` - `SmokeCommand` models `mcr run-rootfs <alpine-rootfs> /bin/sh -c <script>` without host-shell execution.
- `crates/mcr-testkit/tests/network_smoke_contract.rs:120` - ignored network smoke tests.
- `tests/fixtures/rootfs/README.md:9` - network smoke rootfs payload expectations.

Verification:

- `cargo fmt --check`: pass.
- `cargo test -p mcr-testkit`: pass.
- `MCR_BIN=mcr cargo test -p mcr-testkit -- --ignored network_smoke_contract --nocapture`: pass. The four ignored network tests ran and self-skipped because `tests/fixtures/rootfs/alpine-rootfs` is not materialized in this worktree, matching the documented opt-in gate; no live `curl`/`git clone` network proof was performed in this review environment.

## 2. 结论

pass
