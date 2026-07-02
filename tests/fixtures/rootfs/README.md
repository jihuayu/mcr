# Rootfs Fixture Contract

Rootfs fixtures are declared in `manifest.mcr`. The manifest may reference local
archives or extracted rootfs directories, but those payloads are ignored by git.

Use `MCR_FIXTURES_DIR=/path/to/tests/fixtures` when keeping fixture payloads
outside the repository checkout.

Phase 2 network smokes use `alpine-rootfs` and expect the extracted payload to
provide `/bin/sh`, `curl`, `git`, CA certificates, and a writable `/tmp`.
