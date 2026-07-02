use crate::abi::{GuestAddress, SyscallArgs};

pub const LINUX_PROT_NONE: u32 = 0x0;
pub const LINUX_PROT_READ: u32 = 0x1;
pub const LINUX_PROT_WRITE: u32 = 0x2;
pub const LINUX_PROT_EXEC: u32 = 0x4;
pub const LINUX_PROT_VALID_MASK: u32 = LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC;

pub const LINUX_MAP_SHARED: u32 = 0x01;
pub const LINUX_MAP_PRIVATE: u32 = 0x02;
pub const LINUX_MAP_FIXED: u32 = 0x10;
pub const LINUX_MAP_ANONYMOUS: u32 = 0x20;
pub const LINUX_MAP_32BIT: u32 = 0x40;
pub const LINUX_MAP_GROWSDOWN: u32 = 0x0100;
pub const LINUX_MAP_DENYWRITE: u32 = 0x0800;
pub const LINUX_MAP_EXECUTABLE: u32 = 0x1000;
pub const LINUX_MAP_LOCKED: u32 = 0x2000;
pub const LINUX_MAP_NORESERVE: u32 = 0x4000;
pub const LINUX_MAP_POPULATE: u32 = 0x8000;
pub const LINUX_MAP_NONBLOCK: u32 = 0x10000;
pub const LINUX_MAP_STACK: u32 = 0x20000;
pub const LINUX_MAP_HUGETLB: u32 = 0x40000;
pub const LINUX_MAP_SYNC: u32 = 0x80000;
pub const LINUX_MAP_FIXED_NOREPLACE: u32 = 0x100000;

pub const LINUX_MAP_TYPE_MASK: u32 = LINUX_MAP_SHARED | LINUX_MAP_PRIVATE;
pub const LINUX_MAP_VALID_MASK: u32 = LINUX_MAP_SHARED
    | LINUX_MAP_PRIVATE
    | LINUX_MAP_FIXED
    | LINUX_MAP_ANONYMOUS
    | LINUX_MAP_32BIT
    | LINUX_MAP_GROWSDOWN
    | LINUX_MAP_DENYWRITE
    | LINUX_MAP_EXECUTABLE
    | LINUX_MAP_LOCKED
    | LINUX_MAP_NORESERVE
    | LINUX_MAP_POPULATE
    | LINUX_MAP_NONBLOCK
    | LINUX_MAP_STACK
    | LINUX_MAP_HUGETLB
    | LINUX_MAP_SYNC
    | LINUX_MAP_FIXED_NOREPLACE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmapSyscallArgs {
    pub addr: GuestAddress,
    pub length: u64,
    pub prot: u32,
    pub flags: u32,
    pub fd: i32,
    pub offset: i64,
}

impl MmapSyscallArgs {
    #[must_use]
    pub fn from_args(args: SyscallArgs) -> Self {
        Self {
            addr: args.get(0).unwrap_or_default(),
            length: args.get(1).unwrap_or_default(),
            prot: args.get(2).unwrap_or_default() as u32,
            flags: args.get(3).unwrap_or_default() as u32,
            fd: args.get(4).unwrap_or_default() as i64 as i32,
            offset: args.get(5).unwrap_or_default() as i64,
        }
    }

    #[must_use]
    pub const fn is_anonymous(self) -> bool {
        self.flags & LINUX_MAP_ANONYMOUS != 0
    }

    #[must_use]
    pub const fn is_private(self) -> bool {
        self.flags & LINUX_MAP_PRIVATE != 0
    }

    #[must_use]
    pub const fn is_shared(self) -> bool {
        self.flags & LINUX_MAP_SHARED != 0
    }

    #[must_use]
    pub const fn is_fixed(self) -> bool {
        self.flags & LINUX_MAP_FIXED != 0
    }

    #[must_use]
    pub const fn is_fixed_noreplace(self) -> bool {
        self.flags & LINUX_MAP_FIXED_NOREPLACE != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MprotectSyscallArgs {
    pub addr: GuestAddress,
    pub length: u64,
    pub prot: u32,
}

impl MprotectSyscallArgs {
    #[must_use]
    pub fn from_args(args: SyscallArgs) -> Self {
        Self {
            addr: args.get(0).unwrap_or_default(),
            length: args.get(1).unwrap_or_default(),
            prot: args.get(2).unwrap_or_default() as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MunmapSyscallArgs {
    pub addr: GuestAddress,
    pub length: u64,
}

impl MunmapSyscallArgs {
    #[must_use]
    pub fn from_args(args: SyscallArgs) -> Self {
        Self {
            addr: args.get(0).unwrap_or_default(),
            length: args.get(1).unwrap_or_default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrkSyscallArgs {
    pub addr: GuestAddress,
}

impl BrkSyscallArgs {
    #[must_use]
    pub fn from_args(args: SyscallArgs) -> Self {
        Self {
            addr: args.get(0).unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BrkSyscallArgs, LINUX_MAP_ANONYMOUS, LINUX_MAP_PRIVATE, LINUX_PROT_READ, LINUX_PROT_WRITE,
        MmapSyscallArgs, MprotectSyscallArgs, MunmapSyscallArgs,
    };
    use crate::SyscallArgs;

    #[test]
    fn mmap_args_decode_linux_signed_fields() {
        let args = SyscallArgs::new([
            0x7000_0000,
            4096,
            u64::from(LINUX_PROT_READ | LINUX_PROT_WRITE),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS),
            u64::MAX,
            (-4096_i64) as u64,
        ]);

        let decoded = MmapSyscallArgs::from_args(args);

        assert_eq!(decoded.addr, 0x7000_0000);
        assert_eq!(decoded.length, 4096);
        assert_eq!(decoded.prot, LINUX_PROT_READ | LINUX_PROT_WRITE);
        assert_eq!(decoded.flags, LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS);
        assert_eq!(decoded.fd, -1);
        assert_eq!(decoded.offset, -4096);
        assert!(decoded.is_anonymous());
        assert!(decoded.is_private());
    }

    #[test]
    fn memory_syscall_arg_helpers_decode_common_shapes() {
        let args = SyscallArgs::new([0x1000, 8192, u64::from(LINUX_PROT_READ), 0, 0, 0]);

        assert_eq!(
            MprotectSyscallArgs::from_args(args),
            MprotectSyscallArgs {
                addr: 0x1000,
                length: 8192,
                prot: LINUX_PROT_READ
            }
        );
        assert_eq!(
            MunmapSyscallArgs::from_args(args),
            MunmapSyscallArgs {
                addr: 0x1000,
                length: 8192
            }
        );
        assert_eq!(
            BrkSyscallArgs::from_args(args),
            BrkSyscallArgs { addr: 0x1000 }
        );
    }
}
