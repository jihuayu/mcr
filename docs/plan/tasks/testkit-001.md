---
id: testkit-001
scope: testkit
status: pending
depends-on: [boot-001]
---

# testkit-001: Add Runtime Fixtures And Smoke Harness

## Objective

Create `mcr-testkit` support for guest binary fixtures, rootfs fixture metadata, golden stdout/stderr assertions, and smoke command execution.

## Context

- `docs/development/README.md`
- `docs/product/README.md`

## Path

- `crates/mcr-testkit/`
- `tests/fixtures/`
- `docs/development/README.md`

## Verification

```powershell
cargo test -p mcr-testkit
```

## Notes

- The task may define fixture download/extraction contracts, but should avoid checking large rootfs archives into git.
- Smoke tests may be marked ignored until the owning runtime integration task enables them.
