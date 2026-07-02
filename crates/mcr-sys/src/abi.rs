use crate::syscall::{Syscall, SyscallNumber};

pub type GuestAddress = u64;
pub type GuestPid = u32;
pub type GuestTid = u32;

pub const LINUX_UTSNAME_FIELD_LEN: usize = 65;
pub const LINUX_DIRENT64_NAME_OFFSET: usize = 19;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyscallArgs([u64; 6]);

impl SyscallArgs {
    #[must_use]
    pub const fn new(args: [u64; 6]) -> Self {
        Self(args)
    }

    #[must_use]
    pub const fn from_registers(rdi: u64, rsi: u64, rdx: u64, r10: u64, r8: u64, r9: u64) -> Self {
        Self([rdi, rsi, rdx, r10, r8, r9])
    }

    #[must_use]
    pub const fn raw(self) -> [u64; 6] {
        self.0
    }

    #[must_use]
    pub const fn get(self, index: usize) -> Option<u64> {
        if index < self.0.len() {
            Some(self.0[index])
        } else {
            None
        }
    }
}

impl From<[u64; 6]> for SyscallArgs {
    fn from(value: [u64; 6]) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyscallRegisters {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    pub rip: GuestAddress,
}

impl SyscallRegisters {
    #[must_use]
    pub const fn number(self) -> SyscallNumber {
        SyscallNumber::new(self.rax)
    }

    #[must_use]
    pub const fn syscall(self) -> Syscall {
        Syscall::from_number(self.number())
    }

    #[must_use]
    pub const fn args(self) -> SyscallArgs {
        SyscallArgs::from_registers(self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxIovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxStatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxStatx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: [u16; 1],
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: LinuxStatxTimestamp,
    pub stx_btime: LinuxStatxTimestamp,
    pub stx_ctime: LinuxStatxTimestamp,
    pub stx_mtime: LinuxStatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    pub stx_subvol: u64,
    pub stx_atomic_write_unit_min: u32,
    pub stx_atomic_write_unit_max: u32,
    pub stx_atomic_write_segments_max: u32,
    pub stx_dio_read_offset_align: u32,
    pub stx_atomic_write_unit_max_opt: u32,
    pub __spare2: [u32; 1],
    pub __spare3: [u64; 8],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxDirent64Header {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxUtsname {
    pub sysname: [u8; LINUX_UTSNAME_FIELD_LEN],
    pub nodename: [u8; LINUX_UTSNAME_FIELD_LEN],
    pub release: [u8; LINUX_UTSNAME_FIELD_LEN],
    pub version: [u8; LINUX_UTSNAME_FIELD_LEN],
    pub machine: [u8; LINUX_UTSNAME_FIELD_LEN],
    pub domainname: [u8; LINUX_UTSNAME_FIELD_LEN],
}

impl Default for LinuxUtsname {
    fn default() -> Self {
        Self {
            sysname: [0; LINUX_UTSNAME_FIELD_LEN],
            nodename: [0; LINUX_UTSNAME_FIELD_LEN],
            release: [0; LINUX_UTSNAME_FIELD_LEN],
            version: [0; LINUX_UTSNAME_FIELD_LEN],
            machine: [0; LINUX_UTSNAME_FIELD_LEN],
            domainname: [0; LINUX_UTSNAME_FIELD_LEN],
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::{
        LINUX_DIRENT64_NAME_OFFSET, LINUX_UTSNAME_FIELD_LEN, LinuxDirent64Header, LinuxIovec,
        LinuxStat, LinuxStatx, LinuxStatxTimestamp, LinuxTimespec, LinuxUtsname, SyscallArgs,
        SyscallRegisters,
    };
    use crate::syscall::Syscall;

    #[test]
    fn syscall_args_follow_linux_x86_64_register_order() {
        let regs = SyscallRegisters {
            rax: Syscall::Openat.number().raw(),
            rdi: 1,
            rsi: 2,
            rdx: 3,
            r10: 4,
            r8: 5,
            r9: 6,
            rip: 0x400123,
        };

        assert_eq!(regs.syscall(), Syscall::Openat);
        assert_eq!(regs.args(), SyscallArgs::new([1, 2, 3, 4, 5, 6]));
        assert_eq!(regs.args().get(6), None);
    }

    #[test]
    fn abi_struct_sizes_match_linux_x86_64_layouts() {
        assert_eq!(size_of::<LinuxTimespec>(), 16);
        assert_eq!(size_of::<LinuxIovec>(), 16);
        assert_eq!(size_of::<LinuxStat>(), 144);
        assert_eq!(size_of::<LinuxStatxTimestamp>(), 16);
        assert_eq!(size_of::<LinuxStatx>(), 256);
        assert_eq!(size_of::<LinuxUtsname>(), LINUX_UTSNAME_FIELD_LEN * 6);
        assert_eq!(align_of::<LinuxStat>(), 8);
        assert_eq!(align_of::<LinuxStatx>(), 8);
    }

    #[test]
    fn linux_dirent64_header_tracks_flexible_name_offset() {
        assert_eq!(LINUX_DIRENT64_NAME_OFFSET, 19);
        assert_eq!(size_of::<LinuxDirent64Header>(), LINUX_DIRENT64_NAME_OFFSET);
    }
}
