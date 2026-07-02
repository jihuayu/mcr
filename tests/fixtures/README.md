# MCR Test Fixtures

This directory contains small fixture contracts for `mcr-testkit`.

- `guest-binaries/manifest.mcr` describes guest ELF binaries that later tasks can materialize.
- `rootfs/manifest.mcr` describes rootfs fixtures and their archive/download contract.
- `golden/` stores exact stdout/stderr files used by smoke assertions.

Large rootfs archives and extracted rootfs directories must stay out of git. Use
`MCR_FIXTURES_DIR` to point `mcr-testkit` at a local fixture cache when running
ignored integration smoke tests.
