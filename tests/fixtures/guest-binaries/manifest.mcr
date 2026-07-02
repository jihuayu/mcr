# mcr-testkit guest binary manifest v1

[[guest_binary]]
name=busybox-static
path=guest-binaries/busybox-x86_64-linux-static
architecture=x86_64
abi=linux
format=elf
linkage=static
stage=mvp
source=busybox-static-download-or-build-output
required=false

[[guest_binary]]
name=static-hello
path=guest-binaries/static-hello.x86_64-linux.elf
architecture=x86_64
abi=linux
format=elf
linkage=static
stage=mvp
source=generated-by-elf-loader-fixtures
required=false
