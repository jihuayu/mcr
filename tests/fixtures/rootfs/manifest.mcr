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
name=gcc-rootfs
path=rootfs/gcc-rootfs
archive_path=rootfs/gcc-rootfs.tar.gz
architecture=x86_64
distro=alpine
version=contract
stage=extended
source_url=external-fixture-cache
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
name=jdk-rootfs
path=rootfs/jdk-rootfs
archive_path=rootfs/jdk-rootfs.tar.gz
architecture=x86_64
distro=alpine
version=contract
stage=extended
source_url=external-fixture-cache
required=false

[[rootfs]]
name=mysql-rootfs
path=rootfs/mysql-rootfs
archive_path=rootfs/mysql-rootfs.tar.gz
architecture=x86_64
distro=alpine
version=contract
stage=extended
source_url=external-fixture-cache
required=false

[[rootfs]]
name=redis-rootfs
path=rootfs/redis-rootfs
archive_path=rootfs/redis-rootfs.tar.gz
architecture=x86_64
distro=alpine
version=contract
stage=extended
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
