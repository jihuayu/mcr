use mcr_sys::{
    FileSyscalls, LinuxErrno, LinuxIovec, LinuxStat, LinuxStatx, LinuxStatxTimestamp,
    SyscallOutcome, SyscallRequest,
};
use mcr_vfs::{
    DirectoryEntry, Fd, LinuxFileAttr, OpenFlags, SeekWhence, VfsError, VirtualFileSystem,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub trait GuestMemory {
    fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), GuestMemoryError>;
    fn write_bytes(&mut self, addr: u64, buffer: &[u8]) -> Result<(), GuestMemoryError>;

    fn read_c_string(&self, addr: u64, max_len: usize) -> Result<String, GuestMemoryError> {
        let mut bytes = Vec::new();
        for offset in 0..max_len {
            let mut byte = [0];
            self.read_bytes(
                addr.checked_add(offset as u64)
                    .ok_or(GuestMemoryError::Fault)?,
                &mut byte,
            )?;
            if byte[0] == 0 {
                return String::from_utf8(bytes).map_err(|_| GuestMemoryError::Fault);
            }
            bytes.push(byte[0]);
        }
        Err(GuestMemoryError::Fault)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestMemoryError {
    Fault,
}

pub struct RuntimeFileSystem<M> {
    vfs: VirtualFileSystem,
    memory: M,
}

impl<M> RuntimeFileSystem<M> {
    pub fn new(vfs: VirtualFileSystem, memory: M) -> Self {
        Self { vfs, memory }
    }

    pub fn vfs(&self) -> &VirtualFileSystem {
        &self.vfs
    }

    pub fn vfs_mut(&mut self) -> &mut VirtualFileSystem {
        &mut self.vfs
    }

    pub fn memory(&self) -> &M {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    pub fn into_parts(self) -> (VirtualFileSystem, M) {
        (self.vfs, self.memory)
    }
}

impl<M> FileSyscalls for RuntimeFileSystem<M>
where
    M: GuestMemory,
{
    fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let result = match request.syscall {
            mcr_sys::Syscall::Openat => self.sys_openat(request),
            mcr_sys::Syscall::Read => self.sys_read(request),
            mcr_sys::Syscall::Write => self.sys_write(request),
            mcr_sys::Syscall::Readv => self.sys_readv(request),
            mcr_sys::Syscall::Writev => self.sys_writev(request),
            mcr_sys::Syscall::Close => self.sys_close(request),
            mcr_sys::Syscall::Lseek => self.sys_lseek(request),
            mcr_sys::Syscall::Fstat => self.sys_fstat(request),
            mcr_sys::Syscall::Newfstatat => self.sys_newfstatat(request),
            mcr_sys::Syscall::Statx => self.sys_statx(request),
            mcr_sys::Syscall::Access => self.sys_access(request),
            mcr_sys::Syscall::Readlink => self.sys_readlink(request),
            mcr_sys::Syscall::Getdents64 => self.sys_getdents64(request),
            _ => return SyscallOutcome::unsupported(),
        };
        outcome(result)
    }
}

impl<M> FileSyscalls for &mut RuntimeFileSystem<M>
where
    M: GuestMemory,
{
    fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        RuntimeFileSystem::dispatch_file(self, request)
    }
}

impl<M> RuntimeFileSystem<M>
where
    M: GuestMemory,
{
    fn sys_openat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let dirfd = arg_i32(request, 0);
        let path = self.read_path(arg(request, 1))?;
        let flags = arg_u32(request, 2);
        let mode = arg_u32(request, 3);
        let fd = self
            .vfs
            .openat(dirfd, &path, OpenFlags::new(flags), mode)
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    fn sys_read(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let addr = arg(request, 1);
        let len = usize_arg(request, 2)?;
        let mut buffer = vec![0; len];
        let count = self.vfs.read(fd, &mut buffer).map_err(vfs_errno)?;
        self.memory
            .write_bytes(addr, &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_write(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let addr = arg(request, 1);
        let len = usize_arg(request, 2)?;
        let mut buffer = vec![0; len];
        self.memory
            .read_bytes(addr, &mut buffer)
            .map_err(memory_errno)?;
        let count = self.vfs.write(fd, &buffer).map_err(vfs_errno)?;
        Ok(count as u64)
    }

    fn sys_readv(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let iov = self.read_iovecs(arg(request, 1), usize_arg(request, 2)?)?;
        let mut total = 0u64;
        for item in iov {
            let len = usize::try_from(item.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
            let mut buffer = vec![0; len];
            let count = self.vfs.read(fd, &mut buffer).map_err(vfs_errno)?;
            self.memory
                .write_bytes(item.iov_base, &buffer[..count])
                .map_err(memory_errno)?;
            total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
            if count < len {
                break;
            }
        }
        Ok(total)
    }

    fn sys_writev(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let iov = self.read_iovecs(arg(request, 1), usize_arg(request, 2)?)?;
        let mut total = 0u64;
        for item in iov {
            let len = usize::try_from(item.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
            let mut buffer = vec![0; len];
            self.memory
                .read_bytes(item.iov_base, &mut buffer)
                .map_err(memory_errno)?;
            let count = self.vfs.write(fd, &buffer).map_err(vfs_errno)?;
            total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
            if count < len {
                break;
            }
        }
        Ok(total)
    }

    fn sys_close(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        self.vfs.close(arg_i32(request, 0)).map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_lseek(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let offset = arg(request, 1) as i64;
        let whence = SeekWhence::from_linux(arg_u32(request, 2)).map_err(vfs_errno)?;
        self.vfs
            .lseek(arg_i32(request, 0), offset, whence)
            .map_err(vfs_errno)
    }

    fn sys_fstat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let attr = self.vfs.fstat(arg_i32(request, 0)).map_err(vfs_errno)?;
        self.write_stat(arg(request, 1), attr)?;
        Ok(0)
    }

    fn sys_newfstatat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let attr = self
            .vfs
            .newfstatat(arg_i32(request, 0), &path, arg_u32(request, 3))
            .map_err(vfs_errno)?;
        self.write_stat(arg(request, 2), attr)?;
        Ok(0)
    }

    fn sys_statx(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let attr = self
            .vfs
            .statx(arg_i32(request, 0), &path, arg_u32(request, 2))
            .map_err(vfs_errno)?;
        self.write_statx(arg(request, 4), attr)?;
        Ok(0)
    }

    fn sys_access(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs
            .access(&path, arg_u32(request, 1))
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_readlink(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        let len = usize_arg(request, 2)?;
        let mut buffer = vec![0; len];
        let count = self.vfs.readlink(&path, &mut buffer).map_err(vfs_errno)?;
        self.memory
            .write_bytes(arg(request, 1), &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_getdents64(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let max_bytes = usize_arg(request, 2)?;
        let entries = self
            .vfs
            .getdents64(arg_i32(request, 0), max_bytes)
            .map_err(vfs_errno)?;
        let encoded = encode_dirents(&entries)?;
        if encoded.len() > max_bytes {
            return Err(LinuxErrno::EINVAL);
        }
        self.memory
            .write_bytes(arg(request, 1), &encoded)
            .map_err(memory_errno)?;
        Ok(encoded.len() as u64)
    }

    fn read_path(&self, addr: u64) -> Result<String, LinuxErrno> {
        self.memory.read_c_string(addr, 4096).map_err(memory_errno)
    }

    fn read_iovecs(&self, addr: u64, count: usize) -> Result<Vec<LinuxIovec>, LinuxErrno> {
        const IOV_MAX: usize = 1024;
        if count > IOV_MAX {
            return Err(LinuxErrno::EINVAL);
        }

        let mut iovecs = Vec::with_capacity(count);
        for index in 0..count {
            let item_addr = addr
                .checked_add((index * 16) as u64)
                .ok_or(LinuxErrno::EFAULT)?;
            let mut bytes = [0; 16];
            self.memory
                .read_bytes(item_addr, &mut bytes)
                .map_err(memory_errno)?;
            iovecs.push(LinuxIovec {
                iov_base: u64::from_le_bytes(bytes[0..8].try_into().expect("slice len")),
                iov_len: u64::from_le_bytes(bytes[8..16].try_into().expect("slice len")),
            });
        }
        Ok(iovecs)
    }

    fn write_stat(&mut self, addr: u64, attr: LinuxFileAttr) -> Result<(), LinuxErrno> {
        self.memory
            .write_bytes(addr, &encode_linux_stat(attr))
            .map_err(memory_errno)
    }

    fn write_statx(&mut self, addr: u64, attr: LinuxFileAttr) -> Result<(), LinuxErrno> {
        self.memory
            .write_bytes(addr, &encode_linux_statx(attr))
            .map_err(memory_errno)
    }
}

fn outcome(result: Result<u64, LinuxErrno>) -> SyscallOutcome {
    match result {
        Ok(value) => SyscallOutcome::success(value),
        Err(errno) => SyscallOutcome::errno(errno),
    }
}

fn arg(request: &SyscallRequest, index: usize) -> u64 {
    request.arg(index).unwrap_or_default()
}

fn arg_i32(request: &SyscallRequest, index: usize) -> Fd {
    arg(request, index) as i32
}

fn arg_u32(request: &SyscallRequest, index: usize) -> u32 {
    arg(request, index) as u32
}

fn usize_arg(request: &SyscallRequest, index: usize) -> Result<usize, LinuxErrno> {
    usize::try_from(arg(request, index)).map_err(|_| LinuxErrno::EINVAL)
}

fn vfs_errno(error: VfsError) -> LinuxErrno {
    LinuxErrno::new(error.linux_errno()).unwrap_or(LinuxErrno::EINVAL)
}

fn memory_errno(_error: GuestMemoryError) -> LinuxErrno {
    LinuxErrno::EFAULT
}

fn encode_dirents(entries: &[DirectoryEntry]) -> Result<Vec<u8>, LinuxErrno> {
    let mut bytes = Vec::new();
    for entry in entries {
        entry.encode_linux_dirent64(&mut bytes).map_err(vfs_errno)?;
    }
    Ok(bytes)
}

fn encode_linux_stat(attr: LinuxFileAttr) -> [u8; 144] {
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

fn encode_linux_statx(attr: LinuxFileAttr) -> [u8; 256] {
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

fn statx_timestamp(sec: i64, nsec: i64) -> LinuxStatxTimestamp {
    LinuxStatxTimestamp {
        tv_sec: sec,
        tv_nsec: nsec as u32,
        __reserved: 0,
    }
}

fn write_statx_timestamp(bytes: &mut [u8], timestamp: LinuxStatxTimestamp) {
    bytes[0..8].copy_from_slice(&timestamp.tv_sec.to_le_bytes());
    bytes[8..12].copy_from_slice(&timestamp.tv_nsec.to_le_bytes());
    bytes[12..16].copy_from_slice(&timestamp.__reserved.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mcr_sys::{GuestContext, Syscall, SyscallRegisters, SyscallReturn};
    use mcr_vfs::{
        AT_FDCWD, FdTable, O_DIRECTORY, O_RDONLY, O_RDWR, PathTree, Rootfs, VirtualFileSystem,
    };

    use super::*;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-runtime");
    }

    #[test]
    fn dispatcher_connects_openat_read_write_lseek_and_close_to_vfs() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
        runtime.memory_mut().write(0x2000, b"!!");
        let fd = dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDWR), 0, 0, 0],
        );
        assert_eq!(fd, SyscallReturn::Success(3));

        assert_eq!(
            dispatch(&mut runtime, Syscall::Lseek, [3, 5, 0, 0, 0, 0]),
            SyscallReturn::Success(5)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Write, [3, 0x2000, 2, 0, 0, 0]),
            SyscallReturn::Success(2)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Lseek, [3, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Read, [3, 0x3000, 7, 0, 0, 0]),
            SyscallReturn::Success(7)
        );
        assert_eq!(runtime.memory().read(0x3000, 7), b"hello!!");
        assert_eq!(
            dispatch(&mut runtime, Syscall::Close, [3, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Read, [3, 0x3000, 1, 0, 0, 0]),
            SyscallReturn::Errno(LinuxErrno::EBADF)
        );
    }

    #[test]
    fn readv_writev_move_multiple_guest_buffers() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/tmp/iov");
        runtime.memory_mut().write(0x2100, b"ab");
        runtime.memory_mut().write(0x2200, b"cd");
        runtime.memory_mut().write_iovec(0x2000, 0x2100, 2);
        runtime.memory_mut().write_iovec(0x2010, 0x2200, 2);
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [
                    AT_FDCWD as u64,
                    0x1000,
                    u64::from(mcr_vfs::O_CREAT | O_RDWR),
                    0o644,
                    0,
                    0,
                ],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Writev, [3, 0x2000, 2, 0, 0, 0]),
            SyscallReturn::Success(4)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Lseek, [3, 0, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        runtime.memory_mut().write_iovec(0x3000, 0x3100, 2);
        runtime.memory_mut().write_iovec(0x3010, 0x3200, 2);
        assert_eq!(
            dispatch(&mut runtime, Syscall::Readv, [3, 0x3000, 2, 0, 0, 0]),
            SyscallReturn::Success(4)
        );
        assert_eq!(runtime.memory().read(0x3100, 2), b"ab");
        assert_eq!(runtime.memory().read(0x3200, 2), b"cd");
    }

    #[test]
    fn stat_access_readlink_and_getdents64_write_linux_layouts() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/tmp/file");
        runtime.memory_mut().write_cstr(0x1100, "/tmp");
        runtime.memory_mut().write_cstr(0x1200, "/link");

        let fd = dispatch(
            &mut runtime,
            Syscall::Openat,
            [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
        );
        assert_eq!(fd, SyscallReturn::Success(3));
        assert_eq!(
            dispatch(&mut runtime, Syscall::Fstat, [3, 0x4000, 0, 0, 0, 0]),
            SyscallReturn::Success(0)
        );
        assert_eq!(u64_at(runtime.memory(), 0x4000 + 48), 5);
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Newfstatat,
                [AT_FDCWD as u64, 0x1000, 0x4100, 0, 0, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(u64_at(runtime.memory(), 0x4100 + 48), 5);
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Statx,
                [AT_FDCWD as u64, 0x1000, 0, 0, 0x4200, 0],
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(u64_at(runtime.memory(), 0x4200 + 40), 5);
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Access,
                [0x1000, u64::from(mcr_vfs::R_OK), 0, 0, 0, 0]
            ),
            SyscallReturn::Success(0)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Readlink,
                [0x1200, 0x4300, 32, 0, 0, 0]
            ),
            SyscallReturn::Success(9)
        );
        assert_eq!(runtime.memory().read(0x4300, 9), b"/tmp/file");

        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [
                    AT_FDCWD as u64,
                    0x1100,
                    u64::from(O_RDONLY | O_DIRECTORY),
                    0,
                    0,
                    0
                ],
            ),
            SyscallReturn::Success(4)
        );
        let dents = dispatch(&mut runtime, Syscall::Getdents64, [4, 0x5000, 256, 0, 0, 0]);
        assert!(matches!(dents, SyscallReturn::Success(value) if value > 0));
        let first_reclen = u16_at(runtime.memory(), 0x5000 + 16);
        assert_eq!(first_reclen % 8, 0);
        assert_eq!(runtime.memory().read(0x5000 + 19, 2), b".\0");
    }

    #[test]
    fn errno_cases_match_linux_shapes() {
        let mut runtime = runtime_with_sample_vfs();
        runtime.memory_mut().write_cstr(0x1000, "/missing");
        runtime.memory_mut().write_cstr(0x1100, "/tmp/file");
        runtime.memory_mut().write_cstr(0x1200, "child");
        runtime.memory_mut().write_cstr(0x1300, "/private/secret");
        runtime
            .vfs_mut()
            .tree_mut()
            .lookup_path_mut(&guest_path("/private"))
            .unwrap()
            .set_mode(0o600);

        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [AT_FDCWD as u64, 0x1000, u64::from(O_RDONLY), 0, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::ENOENT)
        );
        assert_eq!(
            dispatch(&mut runtime, Syscall::Read, [99, 0x2000, 1, 0, 0, 0]),
            SyscallReturn::Errno(LinuxErrno::EBADF)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [AT_FDCWD as u64, 0x1100, u64::from(O_RDONLY), 0, 0, 0],
            ),
            SyscallReturn::Success(3)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Openat,
                [3, 0x1200, u64::from(O_RDONLY), 0, 0, 0],
            ),
            SyscallReturn::Errno(LinuxErrno::ENOTDIR)
        );
        assert_eq!(
            dispatch(
                &mut runtime,
                Syscall::Access,
                [0x1300, u64::from(mcr_vfs::R_OK), 0, 0, 0, 0]
            ),
            SyscallReturn::Errno(LinuxErrno::EACCES)
        );
    }

    #[derive(Clone, Default)]
    struct TestMemory {
        bytes: BTreeMap<u64, u8>,
    }

    impl TestMemory {
        fn write(&mut self, addr: u64, bytes: &[u8]) {
            for (index, byte) in bytes.iter().copied().enumerate() {
                self.bytes.insert(addr + index as u64, byte);
            }
        }

        fn write_cstr(&mut self, addr: u64, value: &str) {
            self.write(addr, value.as_bytes());
            self.write(addr + value.len() as u64, &[0]);
        }

        fn write_iovec(&mut self, addr: u64, base: u64, len: u64) {
            self.write(addr, &base.to_le_bytes());
            self.write(addr + 8, &len.to_le_bytes());
        }

        fn read(&self, addr: u64, len: usize) -> Vec<u8> {
            let mut bytes = vec![0; len];
            self.read_bytes(addr, &mut bytes).unwrap();
            bytes
        }
    }

    impl GuestMemory for TestMemory {
        fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), GuestMemoryError> {
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = *self
                    .bytes
                    .get(&(addr + index as u64))
                    .ok_or(GuestMemoryError::Fault)?;
            }
            Ok(())
        }

        fn write_bytes(&mut self, addr: u64, buffer: &[u8]) -> Result<(), GuestMemoryError> {
            self.write(addr, buffer);
            Ok(())
        }
    }

    fn runtime_with_sample_vfs() -> RuntimeFileSystem<TestMemory> {
        let rootfs = Rootfs::new("/host/root");
        let mut tree = PathTree::new();
        tree.create_dir("/tmp").unwrap();
        tree.create_file_with_content("/tmp/file", b"hello", 0o644)
            .unwrap();
        tree.create_dir("/private").unwrap();
        tree.create_file_with_content("/private/secret", b"secret", 0o600)
            .unwrap();
        tree.create_symlink("/link", "/tmp/file").unwrap();
        RuntimeFileSystem::new(
            VirtualFileSystem::from_parts(rootfs, tree, FdTable::with_stdio()),
            TestMemory::default(),
        )
    }

    fn dispatch(
        runtime: &mut RuntimeFileSystem<TestMemory>,
        syscall: Syscall,
        args: [u64; 6],
    ) -> SyscallReturn {
        let registers = SyscallRegisters {
            rax: syscall.number().raw(),
            rdi: args[0],
            rsi: args[1],
            rdx: args[2],
            r10: args[3],
            r8: args[4],
            r9: args[5],
            rip: 0,
        };
        let request =
            mcr_sys::SyscallRequest::from_guest_context(GuestContext::new(1, 1, registers));
        runtime.dispatch_file(&request).result
    }

    fn guest_path(path: &str) -> mcr_vfs::GuestPath {
        Rootfs::new("/host")
            .resolve_path(path, &PathTree::new())
            .unwrap()
            .guest_path()
            .clone()
    }

    fn u64_at(memory: &TestMemory, addr: u64) -> u64 {
        u64::from_le_bytes(memory.read(addr, 8).try_into().expect("slice len"))
    }

    fn u16_at(memory: &TestMemory, addr: u64) -> u16 {
        u16::from_le_bytes(memory.read(addr, 2).try_into().expect("slice len"))
    }
}
