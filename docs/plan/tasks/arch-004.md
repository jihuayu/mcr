---
id: arch-004
scope: architecture
status: ready
depends-on: [abi-001]
---

# arch-004: Consolidate Guest ABI Struct Codecs In mcr-sys

## Objective

Create one guest ABI codec layer owned by `mcr-sys` for Linux struct
copy-in/copy-out (`pollfd`, select bitsets, iovec vectors, sockaddr,
`timespec`, C strings, argv/env vectors) and remove the duplicated decoders
and the redundant ELF program-header parsing from `mcr-runtime`.

## Context

- `docs/architecture/README.md` (Architecture Debt And Planned Fixes)
- `docs/architecture/runtime.md`

## Path

- `crates/mcr-sys/`
- `crates/mcr-runtime/`
- `crates/mcr-elf/`

## Verification

```powershell
cargo ci-fmt
cargo ci-clippy
cargo ci-test
```

## Notes

- Duplication today: `crates/mcr-runtime/src/lib.rs` carries `read_pollfd`,
  select-bitset decode, `read_guest_*` helpers, and a private
  `read_elf64_program_headers`; `linux_abi.rs` and `filesystem.rs` carry
  further per-syscall struct parsing.
- The codec layer operates through the guest memory access trait; it must not
  give `mcr-sys` a dependency on the memory manager implementation.
- Replace runtime-local ELF program-header parsing with an `mcr-elf` view API
  instead of keeping two ELF parsers in the workspace.
- Byte-for-byte behavior preservation: existing golden and smoke outputs must
  not change.
