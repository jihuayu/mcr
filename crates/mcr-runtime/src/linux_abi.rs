#[allow(unused_imports)]
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinuxOpenHow {
    pub(crate) flags: u64,
    pub(crate) mode: u64,
    pub(crate) resolve: u64,
}

pub(crate) fn io_slices(buffers: &[Vec<u8>]) -> Vec<IoSlice<'_>> {
    buffers.iter().map(|buffer| IoSlice::new(buffer)).collect()
}

pub(crate) fn io_slices_mut(buffers: &mut [Vec<u8>]) -> Vec<IoSliceMut<'_>> {
    buffers
        .iter_mut()
        .map(|buffer| IoSliceMut::new(buffer))
        .collect()
}

pub(crate) fn outcome(result: Result<u64, LinuxErrno>) -> SyscallOutcome {
    match result {
        Ok(value) => SyscallOutcome::success(value),
        Err(errno) => SyscallOutcome::errno(errno),
    }
}

pub(crate) fn arg(request: &SyscallRequest, index: usize) -> u64 {
    request.arg(index).unwrap_or_default()
}

pub(crate) fn arg_i32(request: &SyscallRequest, index: usize) -> Fd {
    arg(request, index) as i32
}

pub(crate) fn arg_u32(request: &SyscallRequest, index: usize) -> u32 {
    arg(request, index) as u32
}

pub(crate) fn clone_args_from_request(request: &SyscallRequest) -> CloneSyscallArgs {
    CloneSyscallArgs::new(
        arg(request, 0),
        arg(request, 1),
        arg(request, 2),
        arg(request, 3),
        arg(request, 4),
    )
}

pub(crate) fn clone3_args_from_memory(
    memory: &impl GuestMemoryAccess,
    addr: u64,
    size: u64,
) -> Result<CloneSyscallArgs, LinuxErrno> {
    const CLONE_ARGS_MIN_SIZE: u64 = 64;
    const CLONE_ARGS_FULL_SIZE: u64 = 88;
    if addr == 0 {
        return Err(LinuxErrno::EFAULT);
    }
    if !(CLONE_ARGS_MIN_SIZE..=CLONE_ARGS_FULL_SIZE).contains(&size) {
        return Err(LinuxErrno::EINVAL);
    }
    let flags = read_guest_u64(memory, clone3_field_addr(addr, 0)?)?;
    let pidfd = read_guest_u64(memory, clone3_field_addr(addr, 8)?)?;
    let child_tid = read_guest_u64(memory, clone3_field_addr(addr, 16)?)?;
    let parent_tid = read_guest_u64(memory, clone3_field_addr(addr, 24)?)?;
    let exit_signal = read_guest_u64(memory, clone3_field_addr(addr, 32)?)?;
    let stack = read_guest_u64(memory, clone3_field_addr(addr, 40)?)?;
    let stack_size = read_guest_u64(memory, clone3_field_addr(addr, 48)?)?;
    let tls = read_guest_u64(memory, clone3_field_addr(addr, 56)?)?;
    let set_tid = if size >= 72 {
        read_guest_u64(memory, clone3_field_addr(addr, 64)?)?
    } else {
        0
    };
    let set_tid_size = if size >= 80 {
        read_guest_u64(memory, clone3_field_addr(addr, 72)?)?
    } else {
        0
    };
    let cgroup = if size >= CLONE_ARGS_FULL_SIZE {
        read_guest_u64(memory, clone3_field_addr(addr, 80)?)?
    } else {
        0
    };
    if pidfd != 0 || set_tid != 0 || set_tid_size != 0 || cgroup != 0 {
        return Err(LinuxErrno::EINVAL);
    }
    let child_stack = if stack == 0 || stack_size == 0 {
        stack
    } else {
        stack.checked_add(stack_size).ok_or(LinuxErrno::EINVAL)?
    };
    Ok(CloneSyscallArgs::new(
        flags | exit_signal,
        child_stack,
        parent_tid,
        child_tid,
        tls,
    ))
}

pub(crate) fn clone3_field_addr(addr: u64, offset: u64) -> Result<u64, LinuxErrno> {
    addr.checked_add(offset).ok_or(LinuxErrno::EFAULT)
}

pub(crate) fn optional_linux_id(value: u32) -> Option<u32> {
    (value != u32::MAX).then_some(value)
}

pub(crate) fn usize_arg(request: &SyscallRequest, index: usize) -> Result<usize, LinuxErrno> {
    usize::try_from(arg(request, index)).map_err(|_| LinuxErrno::EINVAL)
}

pub(crate) fn fd_range_bounds(first: u32, last: u32) -> Result<Option<(Fd, Fd)>, LinuxErrno> {
    if first > last {
        return Err(LinuxErrno::EINVAL);
    }
    if first > i32::MAX as u32 {
        return Ok(None);
    }
    let first = Fd::try_from(first).map_err(|_| LinuxErrno::EINVAL)?;
    let last = Fd::try_from(last.min(i32::MAX as u32)).map_err(|_| LinuxErrno::EINVAL)?;
    Ok(Some((first, last)))
}

pub(crate) fn vfs_errno(error: VfsError) -> LinuxErrno {
    LinuxErrno::new(error.linux_errno()).unwrap_or(LinuxErrno::EINVAL)
}

pub(crate) fn time_errno(error: mcr_win::HostError) -> LinuxErrno {
    host_sync_errno(error.kind())
}

pub(crate) fn validate_send_message_flags(
    flags: u32,
    operation: SocketOperation,
) -> Result<(), LinuxErrno> {
    if flags & !(LINUX_MSG_NOSIGNAL | LINUX_MSG_DONTWAIT) == 0 {
        Ok(())
    } else {
        Err(net_errno(GuestSocketTable::unsupported_socket_flags(
            operation,
        )))
    }
}

pub(crate) fn validate_recv_message_flags(
    flags: u32,
    operation: SocketOperation,
) -> Result<(), LinuxErrno> {
    if flags & !(LINUX_MSG_DONTWAIT | LINUX_MSG_CMSG_CLOEXEC) == 0 {
        Ok(())
    } else {
        Err(net_errno(GuestSocketTable::unsupported_socket_flags(
            operation,
        )))
    }
}

pub(crate) fn net_errno(error: mcr_net::SocketError) -> LinuxErrno {
    LinuxErrno::new(error.linux_errno().code() as u16).unwrap_or(LinuxErrno::EINVAL)
}

pub(crate) fn sync_proc_self(
    vfs: &mut VirtualFileSystem,
    kernel: &GuestKernel,
    pid: mcr_sys::GuestPid,
) {
    if let Some(process) = kernel.process(pid) {
        let image = process.image();
        vfs.set_proc_self(ProcSelfData::new(
            image.executable().path().to_vec(),
            image.argv().to_vec(),
            image.envp().to_vec(),
        ));
    }
}

pub(crate) fn encode_dirents(entries: &[DirectoryEntry]) -> Result<Vec<u8>, LinuxErrno> {
    let mut bytes = Vec::new();
    for entry in entries {
        entry.encode_linux_dirent64(&mut bytes).map_err(vfs_errno)?;
    }
    Ok(bytes)
}

pub(crate) fn read_socket_address(
    memory: &impl GuestMemoryAccess,
    sockaddr: u64,
    addrlen: u32,
) -> Result<SocketAddress, LinuxErrno> {
    mcr_sys::read_socket_address(memory, sockaddr, addrlen).map(socket_address_from_linux)
}

pub(crate) fn write_socket_address(
    memory: &mut impl GuestMemoryAccess,
    sockaddr: u64,
    addrlen_addr: u64,
    address: SocketAddress,
) -> Result<(), LinuxErrno> {
    mcr_sys::write_socket_address(
        memory,
        sockaddr,
        addrlen_addr,
        socket_address_to_linux(address),
    )
}

pub(crate) fn write_optional_socket_address(
    memory: &mut impl GuestMemoryAccess,
    sockaddr: u64,
    addrlen_addr: u64,
    address: SocketAddress,
) -> Result<(), LinuxErrno> {
    if sockaddr == 0 {
        return Ok(());
    }
    if addrlen_addr == 0 {
        return Err(LinuxErrno::EFAULT);
    }
    mcr_sys::write_optional_socket_address(
        memory,
        sockaddr,
        addrlen_addr,
        socket_address_to_linux(address),
    )
}

pub(crate) fn write_socket_address_to_msghdr_name(
    memory: &mut impl GuestMemoryAccess,
    msghdr: u64,
    sockaddr: u64,
    addrlen: u32,
    address: SocketAddress,
) -> Result<(), LinuxErrno> {
    mcr_sys::write_socket_address_to_msghdr_name(
        memory,
        msghdr,
        sockaddr,
        addrlen,
        socket_address_to_linux(address),
    )
}

fn socket_address_from_linux(address: LinuxSocketAddress) -> SocketAddress {
    match address {
        LinuxSocketAddress::Inet { address, port } => SocketAddress::inet(address, port),
        LinuxSocketAddress::Inet6 {
            address,
            port,
            flowinfo,
            scope_id,
        } => SocketAddress::inet6(address, port, flowinfo, scope_id),
    }
}

fn socket_address_to_linux(address: SocketAddress) -> LinuxSocketAddress {
    match address {
        SocketAddress::Inet { address, port } => LinuxSocketAddress::inet(address, port),
        SocketAddress::Inet6 {
            address,
            port,
            flowinfo,
            scope_id,
        } => LinuxSocketAddress::inet6(address, port, flowinfo, scope_id),
    }
}

pub(crate) fn encode_linux_stat(attr: LinuxFileAttr) -> [u8; 144] {
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: attr.inode,
        st_nlink: attr.nlink,
        st_mode: attr.mode,
        st_uid: attr.uid,
        st_gid: attr.gid,
        st_size: attr.size as i64,
        st_blksize: attr.blksize as i64,
        st_blocks: attr.blocks as i64,
        st_atime: attr.atime_sec,
        st_atime_nsec: attr.atime_nsec,
        st_mtime: attr.mtime_sec,
        st_mtime_nsec: attr.mtime_nsec,
        st_ctime: attr.ctime_sec,
        st_ctime_nsec: attr.ctime_nsec,
        ..LinuxStat::default()
    };
    let mut bytes = [0; 144];
    bytes[0..8].copy_from_slice(&stat.st_dev.to_le_bytes());
    bytes[8..16].copy_from_slice(&stat.st_ino.to_le_bytes());
    bytes[16..24].copy_from_slice(&stat.st_nlink.to_le_bytes());
    bytes[24..28].copy_from_slice(&stat.st_mode.to_le_bytes());
    bytes[28..32].copy_from_slice(&stat.st_uid.to_le_bytes());
    bytes[32..36].copy_from_slice(&stat.st_gid.to_le_bytes());
    bytes[40..48].copy_from_slice(&stat.st_rdev.to_le_bytes());
    bytes[48..56].copy_from_slice(&stat.st_size.to_le_bytes());
    bytes[56..64].copy_from_slice(&stat.st_blksize.to_le_bytes());
    bytes[64..72].copy_from_slice(&stat.st_blocks.to_le_bytes());
    bytes[72..80].copy_from_slice(&stat.st_atime.to_le_bytes());
    bytes[80..88].copy_from_slice(&stat.st_atime_nsec.to_le_bytes());
    bytes[88..96].copy_from_slice(&stat.st_mtime.to_le_bytes());
    bytes[96..104].copy_from_slice(&stat.st_mtime_nsec.to_le_bytes());
    bytes[104..112].copy_from_slice(&stat.st_ctime.to_le_bytes());
    bytes[112..120].copy_from_slice(&stat.st_ctime_nsec.to_le_bytes());
    bytes
}

pub(crate) fn encode_linux_statfs(statfs: LinuxStatfs) -> [u8; LINUX_STATFS_SIZE] {
    let mut bytes = [0; LINUX_STATFS_SIZE];
    let magic = match statfs.kind {
        LinuxFsKind::ExtLike => LINUX_EXT_SUPER_MAGIC,
        LinuxFsKind::TmpfsLike => LINUX_TMPFS_MAGIC,
    };
    bytes[0..8].copy_from_slice(&magic.to_le_bytes());
    bytes[8..8 + 8].copy_from_slice(&statfs.block_size.to_le_bytes());
    bytes[16..24].copy_from_slice(&statfs.blocks.to_le_bytes());
    bytes[24..32].copy_from_slice(&statfs.blocks_free.to_le_bytes());
    bytes[32..40].copy_from_slice(&statfs.blocks_available.to_le_bytes());
    bytes[40..48].copy_from_slice(&statfs.files.to_le_bytes());
    bytes[48..56].copy_from_slice(&statfs.files_free.to_le_bytes());
    bytes[56..64].copy_from_slice(&1u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&statfs.name_max.to_le_bytes());
    bytes[72..80].copy_from_slice(&LINUX_STATFS_BLOCK_SIZE.to_le_bytes());
    bytes
}

pub(crate) fn encode_linux_statx(attr: LinuxFileAttr) -> [u8; 256] {
    let statx = LinuxStatx {
        stx_mask: 0x17ff,
        stx_blksize: attr.blksize as u32,
        stx_nlink: attr.nlink as u32,
        stx_uid: attr.uid,
        stx_gid: attr.gid,
        stx_mode: (attr.mode & 0xffff) as u16,
        stx_ino: attr.inode,
        stx_size: attr.size,
        stx_blocks: attr.blocks,
        stx_atime: statx_timestamp(attr.atime_sec, attr.atime_nsec),
        stx_ctime: statx_timestamp(attr.ctime_sec, attr.ctime_nsec),
        stx_mtime: statx_timestamp(attr.mtime_sec, attr.mtime_nsec),
        ..LinuxStatx::default()
    };
    let mut bytes = [0; 256];
    bytes[0..4].copy_from_slice(&statx.stx_mask.to_le_bytes());
    bytes[4..8].copy_from_slice(&statx.stx_blksize.to_le_bytes());
    bytes[8..16].copy_from_slice(&statx.stx_attributes.to_le_bytes());
    bytes[16..20].copy_from_slice(&statx.stx_nlink.to_le_bytes());
    bytes[20..24].copy_from_slice(&statx.stx_uid.to_le_bytes());
    bytes[24..28].copy_from_slice(&statx.stx_gid.to_le_bytes());
    bytes[28..30].copy_from_slice(&statx.stx_mode.to_le_bytes());
    bytes[32..40].copy_from_slice(&statx.stx_ino.to_le_bytes());
    bytes[40..48].copy_from_slice(&statx.stx_size.to_le_bytes());
    bytes[48..56].copy_from_slice(&statx.stx_blocks.to_le_bytes());
    bytes[56..64].copy_from_slice(&statx.stx_attributes_mask.to_le_bytes());
    write_statx_timestamp(&mut bytes[64..80], statx.stx_atime);
    write_statx_timestamp(&mut bytes[96..112], statx.stx_ctime);
    write_statx_timestamp(&mut bytes[112..128], statx.stx_mtime);
    bytes
}

pub(crate) fn statx_timestamp(sec: i64, nsec: i64) -> LinuxStatxTimestamp {
    LinuxStatxTimestamp {
        tv_sec: sec,
        tv_nsec: nsec as u32,
        __reserved: 0,
    }
}

pub(crate) fn write_statx_timestamp(bytes: &mut [u8], timestamp: LinuxStatxTimestamp) {
    bytes[0..8].copy_from_slice(&timestamp.tv_sec.to_le_bytes());
    bytes[8..12].copy_from_slice(&timestamp.tv_nsec.to_le_bytes());
    bytes[12..16].copy_from_slice(&timestamp.__reserved.to_le_bytes());
}
