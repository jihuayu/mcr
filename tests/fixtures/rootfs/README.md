# Rootfs Fixture Contract

Rootfs fixtures are declared in `manifest.mcr`. The manifest may reference local
archives or extracted rootfs directories, but those payloads are ignored by git.

Use `MCR_FIXTURES_DIR=/path/to/tests/fixtures` when keeping fixture payloads
outside the repository checkout.

Materialize the default local Alpine fixture with:

```sh
python3 scripts/materialize-alpine-rootfs.py
```

The script downloads the latest stable Alpine minirootfs, verifies its SHA-256
digest, extracts it to `tests/fixtures/rootfs/alpine-rootfs`, and adds the
`curl`, `git`, and CA-certificate packages needed by the Phase 2 network smoke
contracts. Use `--force` to rebuild an existing ignored fixture payload.

When run from a linked git worktree, the script uses the main workspace as the
fixture cache. It reuses `tests/fixtures/rootfs/alpine-rootfs` from the main
workspace when present, otherwise it materializes the payload there first, then
creates a symlink from the current worktree to the cached rootfs. Use
`--no-worktree-cache` to force a local materialization in the current checkout.

Phase 2 network smokes use `alpine-rootfs` and expect the extracted payload to
provide `/bin/sh`, `curl`, `git`, CA certificates, and a writable `/tmp`.

Extended support smokes use named Alpine package rootfs fixtures. Materialize
only the payloads you need:

```sh
python3 scripts/materialize-alpine-rootfs.py --rootfs-name gcc-rootfs --package build-base --force
python3 scripts/materialize-alpine-rootfs.py --rootfs-name node-rootfs --package nodejs --force
python3 scripts/materialize-alpine-rootfs.py --rootfs-name jdk-rootfs --package openjdk21-jdk --force
python3 scripts/materialize-alpine-rootfs.py --rootfs-name mysql-rootfs --package mariadb --package mariadb-client --force
python3 scripts/materialize-alpine-rootfs.py --rootfs-name redis-rootfs --package redis --force
```

These fixture payloads remain local and ignored by git.
