# Guest Binary Fixture Contract

`manifest.mcr` is metadata-first. Runtime integration tasks may place generated
or downloaded Linux x86-64 ELF binaries at the declared relative paths. Fixtures
with `required=false` are allowed to be missing during normal unit test runs.
