# mcr-testkit rootfs manifest v1

[[rootfs]]
name=alpine-rootfs
path=rootfs/alpine-rootfs
archive_path=rootfs/alpine-minirootfs-x86_64.tar.gz
architecture=x86_64
distro=alpine
version=contract
stage=mvp
source_url=https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/
required=false

[[rootfs]]
name=node-rootfs
path=rootfs/node-rootfs
archive_path=rootfs/node-rootfs.tar.gz
architecture=x86_64
distro=alpine
version=contract
stage=phase2
source_url=external-fixture-cache
required=false

[[rootfs]]
name=python-rootfs
path=rootfs/python-rootfs
archive_path=rootfs/python-rootfs.tar.gz
architecture=x86_64
distro=alpine
version=contract
stage=phase2
source_url=external-fixture-cache
required=false

[[rootfs]]
name=go-rootfs
path=rootfs/go-rootfs
archive_path=rootfs/go-rootfs.tar.gz
architecture=x86_64
distro=alpine
version=contract
stage=phase2
source_url=external-fixture-cache
required=false

[[rootfs]]
name=rust-rootfs
path=rootfs/rust-rootfs
archive_path=rootfs/rust-rootfs.tar.gz
architecture=x86_64
distro=alpine
version=contract
stage=phase2
source_url=external-fixture-cache
required=false
