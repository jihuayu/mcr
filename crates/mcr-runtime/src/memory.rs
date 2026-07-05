use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use mcr_elf::GuestMemoryImage;
use mcr_sys::{
    BrkSyscallArgs, LINUX_MAP_HUGETLB, LINUX_MAP_PRIVATE, LINUX_MAP_SHARED, LINUX_MAP_SYNC,
    LINUX_MAP_TYPE_MASK, LINUX_MAP_VALID_MASK, LINUX_PROT_EXEC, LINUX_PROT_READ,
    LINUX_PROT_VALID_MASK, LINUX_PROT_WRITE, LinuxErrno, MemorySyscalls, MmapSyscallArgs,
    MprotectSyscallArgs, MunmapSyscallArgs, Syscall, SyscallOutcome, SyscallRequest,
};
use mcr_win::{HostError, HostErrorCode, HostErrorKind, HostMemory, MemoryProtection};

pub const GUEST_PAGE_SIZE: u64 = 4096;
pub const MIN_GUEST_ADDRESS: u64 = GUEST_PAGE_SIZE;
pub const DEFAULT_MMAP_BASE: u64 = 0x0000_7000_0000_0000;
pub const GUEST_ADDRESS_SPACE_END: u64 = 0x0000_8000_0000_0000;
const MMAP_HOST_CONFLICT_RETRIES: usize = 64;
#[cfg(windows)]
const HOST_ALLOCATION_GRANULARITY: u64 = 0x1_0000;
#[cfg(not(windows))]
const HOST_ALLOCATION_GRANULARITY: u64 = GUEST_PAGE_SIZE;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestMemoryProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl GuestMemoryProtection {
    #[must_use]
    pub const fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    pub const fn from_linux(prot: u32) -> Result<Self, GuestMemoryError> {
        if prot & !LINUX_PROT_VALID_MASK != 0 {
            return Err(GuestMemoryError::InvalidProtection);
        }

        Ok(Self {
            read: prot & LINUX_PROT_READ != 0,
            write: prot & LINUX_PROT_WRITE != 0,
            execute: prot & LINUX_PROT_EXEC != 0,
        })
    }

    #[must_use]
    pub const fn to_host(self) -> MemoryProtection {
        match (self.read, self.write, self.execute) {
            (_, true, true) => MemoryProtection::ExecuteReadWrite,
            (_, true, false) => MemoryProtection::ReadWrite,
            (_, false, true) => MemoryProtection::ExecuteRead,
            (true, false, false) => MemoryProtection::ReadOnly,
            (false, false, false) => MemoryProtection::NoAccess,
        }
    }

    #[must_use]
    pub fn from_segment(permissions: mcr_elf::SegmentPermissions) -> Self {
        Self::new(
            permissions.read(),
            permissions.write(),
            permissions.execute(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestVmaKind {
    Anonymous,
    Heap,
    /// File-backed mappings are represented as zero-filled private host memory
    /// for MVP. Reads/writes are coherent only within this guest mapping; there
    /// is no host file page-cache sharing or writeback yet.
    FileBacked {
        fd: i32,
        offset: i64,
        shared: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestVma {
    start: u64,
    end: u64,
    protection: GuestMemoryProtection,
    kind: GuestVmaKind,
    allocation_id: u64,
    allocation_offset: u64,
}

impl GuestVma {
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }

    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end - self.start
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    #[must_use]
    pub const fn protection(&self) -> GuestMemoryProtection {
        self.protection
    }

    #[must_use]
    pub const fn kind(&self) -> &GuestVmaKind {
        &self.kind
    }

    const fn contains(&self, address: u64) -> bool {
        self.start <= address && address < self.end
    }
}

#[derive(Debug)]
struct GuestAllocation {
    guest_start: u64,
    memory: Arc<HostMemory>,
}

impl GuestAllocation {
    fn guest_end(&self) -> u64 {
        self.guest_start.saturating_add(self.memory.len() as u64)
    }

    fn contains_guest_range(&self, start: u64, end: u64) -> bool {
        self.guest_start <= start && end <= self.guest_end()
    }

    fn overlaps_guest_range(&self, start: u64, end: u64) -> bool {
        self.guest_start < end && start < self.guest_end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestMemoryError {
    InvalidAddress,
    InvalidLength,
    InvalidProtection,
    InvalidFlags,
    InvalidOffset,
    BadFileDescriptor,
    AddressInUse,
    NotMapped,
    OutOfMemory,
    AccessDenied,
    RegionTooLarge,
    Host(HostError),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GuestLibcIntrinsic {
    Memcpy,
    Memmove,
    Memset,
    Memchr,
    Memcmp,
    Strlen { max_len: usize },
}

pub const DEFAULT_LIBC_STRLEN_MAX: usize = 1024 * 1024;

impl GuestLibcIntrinsic {
    #[must_use]
    pub fn from_symbol_name(symbol: &str) -> Option<Self> {
        let name = symbol.split_once('@').map_or(symbol, |(name, _)| name);
        match name {
            "memcpy" => Some(Self::Memcpy),
            "memmove" => Some(Self::Memmove),
            "memset" => Some(Self::Memset),
            "memchr" => Some(Self::Memchr),
            "memcmp" => Some(Self::Memcmp),
            "strlen" => Some(Self::Strlen {
                max_len: DEFAULT_LIBC_STRLEN_MAX,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GuestLibcIntrinsicError {
    Memory(GuestMemoryError),
    UnsupportedOverlap,
    UnterminatedString,
}

impl From<GuestMemoryError> for GuestLibcIntrinsicError {
    fn from(value: GuestMemoryError) -> Self {
        Self::Memory(value)
    }
}

impl GuestMemoryError {
    #[must_use]
    pub const fn errno(&self) -> LinuxErrno {
        match self {
            Self::AccessDenied => LinuxErrno::EACCES,
            Self::AddressInUse => LinuxErrno::EEXIST,
            Self::BadFileDescriptor => LinuxErrno::EBADF,
            Self::Host(error) => host_error_errno(error.kind()),
            Self::NotMapped | Self::OutOfMemory | Self::RegionTooLarge => LinuxErrno::ENOMEM,
            Self::InvalidAddress
            | Self::InvalidLength
            | Self::InvalidProtection
            | Self::InvalidFlags
            | Self::InvalidOffset => LinuxErrno::EINVAL,
        }
    }

    fn host_error(&self) -> Option<&HostError> {
        match self {
            Self::Host(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestBrkOutcome {
    pub current: u64,
    pub error: Option<GuestMemoryError>,
}

#[derive(Debug)]
pub struct GuestMemory {
    vmas: BTreeMap<u64, GuestVma>,
    allocations: BTreeMap<u64, GuestAllocation>,
    next_allocation_id: u64,
    brk_base: u64,
    current_brk: u64,
    mmap_base: u64,
    address_space_end: u64,
    host_address_mode: HostAddressMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostAddressMode {
    Flexible,
    FixedGuest,
}

impl GuestMemory {
    pub fn new(initial_brk: u64) -> Result<Self, GuestMemoryError> {
        Self::with_layout(initial_brk, DEFAULT_MMAP_BASE, GUEST_ADDRESS_SPACE_END)
    }

    pub fn with_layout(
        initial_brk: u64,
        mmap_base: u64,
        address_space_end: u64,
    ) -> Result<Self, GuestMemoryError> {
        if !is_page_aligned(initial_brk)
            || !is_page_aligned(mmap_base)
            || !is_page_aligned(address_space_end)
            || initial_brk < MIN_GUEST_ADDRESS
            || mmap_base < MIN_GUEST_ADDRESS
            || address_space_end <= MIN_GUEST_ADDRESS
        {
            return Err(GuestMemoryError::InvalidAddress);
        }

        Ok(Self {
            vmas: BTreeMap::new(),
            allocations: BTreeMap::new(),
            next_allocation_id: 1,
            brk_base: initial_brk,
            current_brk: initial_brk,
            mmap_base,
            address_space_end,
            host_address_mode: HostAddressMode::Flexible,
        })
    }

    pub fn from_image(image: &GuestMemoryImage) -> Result<Self, GuestMemoryError> {
        let initial_brk = align_up(image.brk().max(MIN_GUEST_ADDRESS))?;
        let mut memory = Self::new(initial_brk)?;
        for vma in image.vmas() {
            let region = image
                .regions()
                .iter()
                .find(|region| region.start() == vma.start() && region.end() == vma.end())
                .ok_or(GuestMemoryError::InvalidAddress)?;
            memory.insert_loaded_mapping(
                vma.start(),
                vma.end()
                    .checked_sub(vma.start())
                    .ok_or(GuestMemoryError::InvalidAddress)?,
                GuestMemoryProtection::from_segment(vma.permissions()),
                region.bytes(),
            )?;
        }
        Ok(memory)
    }

    pub fn try_clone_runtime(&self) -> Result<Self, GuestMemoryError> {
        self.try_clone_runtime_with_allocator(true, |allocation, protection| {
            HostMemory::allocate(allocation.memory.len(), protection)
                .map_err(GuestMemoryError::Host)
        })
    }

    pub fn try_clone_runtime_at_guest_addresses(&self) -> Result<Self, GuestMemoryError> {
        self.try_clone_runtime_with_allocator(false, |allocation, protection| {
            allocate_guest_host_memory_at(
                allocation.guest_start,
                allocation.memory.len(),
                protection,
                HostAddressMode::FixedGuest,
            )
        })
        .map(|mut memory| {
            memory.host_address_mode = HostAddressMode::FixedGuest;
            memory
        })
    }

    #[must_use]
    pub const fn uses_fixed_guest_host_addresses(&self) -> bool {
        matches!(self.host_address_mode, HostAddressMode::FixedGuest)
    }

    pub fn empty_clone_layout(&self) -> Self {
        Self {
            vmas: BTreeMap::new(),
            allocations: BTreeMap::new(),
            next_allocation_id: 1,
            brk_base: self.brk_base,
            current_brk: self.current_brk,
            mmap_base: self.mmap_base,
            address_space_end: self.address_space_end,
            host_address_mode: self.host_address_mode,
        }
    }

    fn try_clone_runtime_with_allocator(
        &self,
        allow_readonly_sharing: bool,
        mut allocate: impl FnMut(
            &GuestAllocation,
            MemoryProtection,
        ) -> Result<HostMemory, GuestMemoryError>,
    ) -> Result<Self, GuestMemoryError> {
        let mut allocations = BTreeMap::new();
        for (allocation_id, allocation) in &self.allocations {
            if allow_readonly_sharing && self.allocation_is_readonly_shareable(*allocation_id) {
                allocations.insert(
                    *allocation_id,
                    GuestAllocation {
                        guest_start: allocation.guest_start,
                        memory: Arc::clone(&allocation.memory),
                    },
                );
                continue;
            }
            let ranges = self.allocation_protection_ranges(*allocation_id)?;
            let memory = clone_allocation_memory(allocation, &ranges, &mut allocate)?;
            allocations.insert(
                *allocation_id,
                GuestAllocation {
                    guest_start: allocation.guest_start,
                    memory: Arc::new(memory),
                },
            );
        }

        Ok(Self {
            vmas: self.vmas.clone(),
            allocations,
            next_allocation_id: self.next_allocation_id,
            brk_base: self.brk_base,
            current_brk: self.current_brk,
            mmap_base: self.mmap_base,
            address_space_end: self.address_space_end,
            host_address_mode: HostAddressMode::Flexible,
        })
    }

    fn allocation_is_readonly_shareable(&self, allocation_id: u64) -> bool {
        matches!(self.host_address_mode, HostAddressMode::Flexible)
            && self
                .vmas
                .values()
                .filter(|vma| vma.allocation_id == allocation_id)
                .all(|vma| !vma.protection.write)
    }

    fn ensure_allocation_unique(&mut self, allocation_id: u64) -> Result<(), GuestMemoryError> {
        let Some(allocation) = self.allocations.get(&allocation_id) else {
            return Err(GuestMemoryError::NotMapped);
        };
        if Arc::strong_count(&allocation.memory) == 1 {
            return Ok(());
        }

        let ranges = self.allocation_protection_ranges(allocation_id)?;
        let memory =
            clone_allocation_memory(allocation, &ranges, &mut |allocation, protection| {
                allocate_guest_host_memory_at(
                    allocation.guest_start,
                    allocation.memory.len(),
                    protection,
                    self.host_address_mode,
                )
            })?;
        self.allocations
            .get_mut(&allocation_id)
            .expect("allocation existence was checked")
            .memory = Arc::new(memory);
        Ok(())
    }

    fn allocation_memory_mut(
        &mut self,
        allocation_id: u64,
    ) -> Result<&mut HostMemory, GuestMemoryError> {
        self.ensure_allocation_unique(allocation_id)?;
        let allocation = self
            .allocations
            .get_mut(&allocation_id)
            .expect("allocation uniqueness was checked");
        Arc::get_mut(&mut allocation.memory).ok_or(GuestMemoryError::AccessDenied)
    }

    #[must_use]
    pub const fn brk_base(&self) -> u64 {
        self.brk_base
    }

    #[must_use]
    pub const fn current_brk(&self) -> u64 {
        self.current_brk
    }

    pub fn vmas(&self) -> impl Iterator<Item = &GuestVma> {
        self.vmas.values()
    }

    #[must_use]
    pub fn vma_containing(&self, address: u64) -> Option<&GuestVma> {
        let (_, vma) = self.vmas.range(..=address).next_back()?;
        vma.contains(address).then_some(vma)
    }

    pub fn mmap(&mut self, args: MmapSyscallArgs) -> Result<u64, GuestMemoryError> {
        let protection = GuestMemoryProtection::from_linux(args.prot)?;
        let length = page_round_length(args.length)?;
        let kind = mmap_kind(args)?;
        let mut start = self.mmap_start(args, length)?;
        let mut attempts = 0usize;

        loop {
            if args.is_fixed() {
                self.unmap_range(start, start + length);
            }

            match self.insert_mapping(start, length, protection, kind.clone()) {
                Ok(()) => return Ok(start),
                Err(error) if self.should_retry_mmap_host_conflict(args, attempts, &error) => {
                    attempts += 1;
                    start = self.next_retry_mmap_start(start, length)?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn munmap(&mut self, args: MunmapSyscallArgs) -> Result<(), GuestMemoryError> {
        let end = checked_page_range(args.addr, args.length)?;
        self.unmap_range(args.addr, end);
        Ok(())
    }

    pub fn mprotect(&mut self, args: MprotectSyscallArgs) -> Result<(), GuestMemoryError> {
        let protection = GuestMemoryProtection::from_linux(args.prot)?;
        if args.length == 0 {
            return Ok(());
        }
        let end = checked_page_range(args.addr, args.length)?;
        if !self.is_range_mapped(args.addr, end) {
            return Err(GuestMemoryError::NotMapped);
        }

        self.split_vma_at(args.addr);
        self.split_vma_at(end);
        self.ensure_guest_page_range_unique(args.addr, end)?;

        let keys = self
            .vmas
            .range(args.addr..end)
            .map(|(start, _)| *start)
            .collect::<Vec<_>>();
        let operations = keys
            .iter()
            .map(|key| {
                let vma = self.vmas.get(key).expect("VMA key collected from map");
                (vma.allocation_id, vma.allocation_offset, vma.len())
            })
            .collect::<Vec<_>>();

        for (allocation_id, offset, len) in operations {
            let offset = usize::try_from(offset).map_err(|_| GuestMemoryError::RegionTooLarge)?;
            let len = usize::try_from(len).map_err(|_| GuestMemoryError::RegionTooLarge)?;
            let allocation = self
                .allocations
                .get(&allocation_id)
                .expect("VMA references live allocation");
            allocation
                .memory
                .protect_range(offset, len, protection.to_host())
                .map_err(GuestMemoryError::Host)?;
        }

        for key in keys {
            let vma = self.vmas.get_mut(&key).expect("VMA key collected from map");
            vma.protection = protection;
        }
        self.coalesce_adjacent();
        Ok(())
    }

    pub fn set_brk(&mut self, requested: u64) -> GuestBrkOutcome {
        if requested == 0 {
            return GuestBrkOutcome {
                current: self.current_brk,
                error: None,
            };
        }

        if requested < self.brk_base {
            return GuestBrkOutcome {
                current: self.current_brk,
                error: Some(GuestMemoryError::InvalidAddress),
            };
        }

        match self.try_set_brk(requested) {
            Ok(()) => GuestBrkOutcome {
                current: self.current_brk,
                error: None,
            },
            Err(error) => GuestBrkOutcome {
                current: self.current_brk,
                error: Some(error),
            },
        }
    }

    pub fn set_mmap_base(&mut self, mmap_base: u64) -> Result<(), GuestMemoryError> {
        if mmap_base < MIN_GUEST_ADDRESS
            || mmap_base >= self.address_space_end
            || !is_page_aligned(mmap_base)
        {
            return Err(GuestMemoryError::InvalidAddress);
        }
        self.mmap_base = mmap_base;
        Ok(())
    }

    pub fn read(&self, address: u64, buf: &mut [u8]) -> Result<(), GuestMemoryError> {
        self.copy_guest(address, buf, AccessKind::Read)
    }

    pub fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), GuestMemoryError> {
        self.write_guest(address, bytes)
    }

    pub fn intrinsic_memset(
        &mut self,
        address: u64,
        value: u8,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        checked_raw_range(address, len as u64)?;
        self.write_guest(address, &vec![value; len])
    }

    pub fn intrinsic_memmove(
        &mut self,
        destination: u64,
        source: u64,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        let mut bytes = vec![0; len];
        self.copy_guest(source, &mut bytes, AccessKind::Read)?;
        self.write_guest(destination, &bytes)
    }

    pub fn intrinsic_memcmp(
        &self,
        lhs: u64,
        rhs: u64,
        len: usize,
    ) -> Result<i32, GuestMemoryError> {
        let mut lhs_bytes = vec![0; len];
        let mut rhs_bytes = vec![0; len];
        self.copy_guest(lhs, &mut lhs_bytes, AccessKind::Read)?;
        self.copy_guest(rhs, &mut rhs_bytes, AccessKind::Read)?;
        Ok(lhs_bytes
            .iter()
            .zip(rhs_bytes.iter())
            .find_map(|(left, right)| {
                (left != right).then_some(i32::from(*left) - i32::from(*right))
            })
            .unwrap_or(0))
    }

    pub fn intrinsic_memchr(
        &self,
        address: u64,
        needle: u8,
        len: usize,
    ) -> Result<Option<u64>, GuestMemoryError> {
        let mut bytes = vec![0; len];
        self.copy_guest(address, &mut bytes, AccessKind::Read)?;
        Ok(bytes
            .iter()
            .position(|byte| *byte == needle)
            .map(|index| address + index as u64))
    }

    pub fn intrinsic_strlen(
        &self,
        address: u64,
        max_len: usize,
    ) -> Result<Option<usize>, GuestMemoryError> {
        let mut bytes = vec![0; max_len];
        self.copy_guest(address, &mut bytes, AccessKind::Read)?;
        Ok(bytes.iter().position(|byte| *byte == 0))
    }

    pub fn dispatch_libc_intrinsic(
        &mut self,
        intrinsic: GuestLibcIntrinsic,
        rdi: u64,
        rsi: u64,
        rdx: u64,
    ) -> Result<u64, GuestLibcIntrinsicError> {
        match intrinsic {
            GuestLibcIntrinsic::Memcpy => {
                let len = usize::try_from(rdx).map_err(|_| GuestMemoryError::RegionTooLarge)?;
                if raw_ranges_overlap(rdi, rsi, len)? {
                    return Err(GuestLibcIntrinsicError::UnsupportedOverlap);
                }
                self.intrinsic_memmove(rdi, rsi, len)?;
                Ok(rdi)
            }
            GuestLibcIntrinsic::Memmove => {
                let len = usize::try_from(rdx).map_err(|_| GuestMemoryError::RegionTooLarge)?;
                self.intrinsic_memmove(rdi, rsi, len)?;
                Ok(rdi)
            }
            GuestLibcIntrinsic::Memset => {
                let len = usize::try_from(rdx).map_err(|_| GuestMemoryError::RegionTooLarge)?;
                self.intrinsic_memset(rdi, rsi as u8, len)?;
                Ok(rdi)
            }
            GuestLibcIntrinsic::Memchr => {
                let len = usize::try_from(rdx).map_err(|_| GuestMemoryError::RegionTooLarge)?;
                Ok(self.intrinsic_memchr(rdi, rsi as u8, len)?.unwrap_or(0))
            }
            GuestLibcIntrinsic::Memcmp => {
                let len = usize::try_from(rdx).map_err(|_| GuestMemoryError::RegionTooLarge)?;
                let result = self.intrinsic_memcmp(rdi, rsi, len)?;
                Ok((result as i64) as u64)
            }
            GuestLibcIntrinsic::Strlen { max_len } => self
                .intrinsic_strlen(rdi, max_len)?
                .map(|len| len as u64)
                .ok_or(GuestLibcIntrinsicError::UnterminatedString),
        }
    }

    pub fn patch_code(&mut self, address: u64, bytes: &[u8]) -> Result<Vec<u8>, GuestMemoryError> {
        let end = checked_raw_range(address, bytes.len() as u64)?;
        let vma = self
            .vma_containing(address)
            .cloned()
            .ok_or(GuestMemoryError::NotMapped)?;
        if end > vma.end {
            return Err(GuestMemoryError::InvalidLength);
        }

        self.ensure_guest_page_range_unique(address, end)?;
        let vma = self
            .vma_containing(address)
            .cloned()
            .ok_or(GuestMemoryError::NotMapped)?;
        let ranges = self.allocation_protection_ranges(vma.allocation_id)?;
        let allocation_offset = usize::try_from(vma.allocation_offset + (address - vma.start))
            .map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let allocation = self
            .allocations
            .get(&vma.allocation_id)
            .expect("VMA references live allocation");
        allocation
            .memory
            .protect_range(allocation_offset, bytes.len(), MemoryProtection::ReadWrite)
            .map_err(GuestMemoryError::Host)?;
        allocation_offset
            .checked_add(bytes.len())
            .ok_or(GuestMemoryError::RegionTooLarge)?;
        let mut old = vec![0; bytes.len()];
        allocation
            .memory
            .copy_to_slice(allocation_offset, &mut old)
            .map_err(GuestMemoryError::Host)?;
        self.allocation_memory_mut(vma.allocation_id)?
            .copy_from_slice(allocation_offset, bytes)
            .map_err(GuestMemoryError::Host)?;
        let allocation = self
            .allocations
            .get(&vma.allocation_id)
            .expect("VMA references live allocation");
        apply_allocation_protections(&allocation.memory, &ranges)?;
        Ok(old)
    }

    pub fn patch_code_fixed<const N: usize>(
        &mut self,
        patches: impl IntoIterator<Item = (u64, [u8; N])>,
    ) -> Result<(), GuestMemoryError> {
        let patches = patches.into_iter().collect::<Vec<_>>();
        for (address, _) in &patches {
            let end = checked_raw_range(*address, N as u64)?;
            let vma = self
                .vma_containing(*address)
                .cloned()
                .ok_or(GuestMemoryError::NotMapped)?;
            if end > vma.end {
                return Err(GuestMemoryError::InvalidLength);
            }
            self.ensure_guest_page_range_unique(*address, end)?;
        }

        #[derive(Debug)]
        struct PlannedPatch<const N: usize> {
            allocation_offset: usize,
            bytes: [u8; N],
        }

        let mut planned: BTreeMap<u64, Vec<PlannedPatch<N>>> = BTreeMap::new();
        for (address, bytes) in patches {
            let end = checked_raw_range(address, N as u64)?;
            let vma = self
                .vma_containing(address)
                .cloned()
                .ok_or(GuestMemoryError::NotMapped)?;
            if end > vma.end {
                return Err(GuestMemoryError::InvalidLength);
            }

            let allocation_offset = usize::try_from(vma.allocation_offset + (address - vma.start))
                .map_err(|_| GuestMemoryError::RegionTooLarge)?;
            planned
                .entry(vma.allocation_id)
                .or_default()
                .push(PlannedPatch {
                    allocation_offset,
                    bytes,
                });
        }

        for (allocation_id, patches) in planned {
            let ranges = self.allocation_protection_ranges(allocation_id)?;
            for patch in patches {
                patch
                    .allocation_offset
                    .checked_add(N)
                    .ok_or(GuestMemoryError::RegionTooLarge)?;
                {
                    let allocation = self
                        .allocations
                        .get(&allocation_id)
                        .expect("VMA references live allocation");
                    allocation
                        .memory
                        .protect_range(patch.allocation_offset, N, MemoryProtection::ReadWrite)
                        .map_err(GuestMemoryError::Host)?;
                }
                self.allocation_memory_mut(allocation_id)?
                    .copy_from_slice(patch.allocation_offset, &patch.bytes)
                    .map_err(GuestMemoryError::Host)?;
            }
            let allocation = self
                .allocations
                .get(&allocation_id)
                .expect("VMA references live allocation");
            apply_allocation_protections(&allocation.memory, &ranges)?;
        }

        Ok(())
    }

    fn ensure_guest_page_range_unique(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<(), GuestMemoryError> {
        if start >= end {
            return Ok(());
        }
        let page_start = align_down_to(start, GUEST_PAGE_SIZE);
        let page_end = align_up_to(end, GUEST_PAGE_SIZE)?;
        self.ensure_guest_range_unique(page_start, page_end)
    }

    fn ensure_guest_range_unique(&mut self, start: u64, end: u64) -> Result<(), GuestMemoryError> {
        if start >= end {
            return Ok(());
        }
        if matches!(self.host_address_mode, HostAddressMode::FixedGuest) {
            let allocation_ids = self
                .vmas
                .values()
                .filter(|vma| vma.start < end && start < vma.end)
                .map(|vma| vma.allocation_id)
                .collect::<BTreeSet<_>>();
            for allocation_id in allocation_ids {
                self.ensure_allocation_unique(allocation_id)?;
            }
            return Ok(());
        }

        self.split_vma_at(start);
        self.split_vma_at(end);
        let keys = self
            .vmas
            .range(start..end)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in keys {
            let vma = self
                .vmas
                .get(&key)
                .cloned()
                .ok_or(GuestMemoryError::NotMapped)?;
            self.detach_shared_vma(vma)?;
        }
        self.drop_unreferenced_allocations();
        Ok(())
    }

    fn detach_shared_vma(&mut self, vma: GuestVma) -> Result<(), GuestMemoryError> {
        let Some(allocation) = self.allocations.get(&vma.allocation_id) else {
            return Err(GuestMemoryError::NotMapped);
        };
        if Arc::strong_count(&allocation.memory) == 1 {
            return Ok(());
        }

        let len = usize::try_from(vma.len()).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let offset =
            usize::try_from(vma.allocation_offset).map_err(|_| GuestMemoryError::RegionTooLarge)?;

        let mut memory = allocate_guest_host_memory_at(
            vma.start,
            len,
            MemoryProtection::NoAccess,
            self.host_address_mode,
        )?;
        if vma.protection.read || vma.protection.write || vma.protection.execute {
            memory
                .protect_range(0, len, MemoryProtection::ReadWrite)
                .map_err(GuestMemoryError::Host)?;
            memory
                .copy_from_memory(0, &allocation.memory, offset, len)
                .map_err(GuestMemoryError::Host)?;
        }
        memory
            .protect(vma.protection.to_host())
            .map_err(GuestMemoryError::Host)?;

        let allocation_id = self.next_allocation_id;
        self.next_allocation_id = self
            .next_allocation_id
            .checked_add(1)
            .ok_or(GuestMemoryError::OutOfMemory)?;
        self.allocations.insert(
            allocation_id,
            GuestAllocation {
                guest_start: vma.start,
                memory: Arc::new(memory),
            },
        );
        let detached = self
            .vmas
            .get_mut(&vma.start)
            .ok_or(GuestMemoryError::NotMapped)?;
        detached.allocation_id = allocation_id;
        detached.allocation_offset = 0;
        Ok(())
    }

    fn try_set_brk(&mut self, requested: u64) -> Result<(), GuestMemoryError> {
        let new_mapped_end = align_up(requested)?;
        if new_mapped_end > self.address_space_end {
            return Err(GuestMemoryError::OutOfMemory);
        }

        let old_mapped_end = self.heap_mapped_end();
        if new_mapped_end > old_mapped_end {
            self.ensure_brk_can_grow(old_mapped_end, new_mapped_end)?;
            self.resize_heap(new_mapped_end)?;
        } else if new_mapped_end < old_mapped_end {
            self.shrink_heap(new_mapped_end);
        }

        self.current_brk = requested;
        Ok(())
    }

    fn mmap_start(&self, args: MmapSyscallArgs, length: u64) -> Result<u64, GuestMemoryError> {
        if args.is_fixed() || args.is_fixed_noreplace() {
            if args.addr < MIN_GUEST_ADDRESS || !is_page_aligned(args.addr) {
                return Err(GuestMemoryError::InvalidAddress);
            }
            checked_mapping_end(args.addr, length, self.address_space_end)?;
            if self.overlaps(args.addr, args.addr + length) {
                if args.is_fixed_noreplace() {
                    return Err(GuestMemoryError::AddressInUse);
                }
                if args.is_fixed() {
                    return Ok(args.addr);
                }
            }
            return Ok(args.addr);
        }

        let hint = if args.addr == 0 {
            self.mmap_base
        } else {
            align_up(args.addr.max(MIN_GUEST_ADDRESS))?
        };
        self.find_free_range(hint, length)
    }

    fn should_retry_mmap_host_conflict(
        &self,
        args: MmapSyscallArgs,
        attempts: usize,
        error: &GuestMemoryError,
    ) -> bool {
        matches!(self.host_address_mode, HostAddressMode::FixedGuest)
            && !args.is_fixed()
            && !args.is_fixed_noreplace()
            && attempts < MMAP_HOST_CONFLICT_RETRIES
            && matches!(error, GuestMemoryError::Host(_))
    }

    fn next_retry_mmap_start(
        &self,
        previous_start: u64,
        length: u64,
    ) -> Result<u64, GuestMemoryError> {
        let next_hint = previous_start
            .checked_add(length)
            .ok_or(GuestMemoryError::OutOfMemory)
            .and_then(align_up)?;
        if next_hint >= self.address_space_end {
            return Err(GuestMemoryError::OutOfMemory);
        }
        self.find_free_range(next_hint, length)
    }

    fn ensure_host_allocation(
        &mut self,
        start: u64,
        length: u64,
        initial_protection: MemoryProtection,
    ) -> Result<(u64, u64), GuestMemoryError> {
        let end = checked_raw_range(start, length)?;
        if let Some((allocation_id, allocation)) = self
            .allocations
            .iter()
            .find(|(_, allocation)| allocation.contains_guest_range(start, end))
        {
            return Ok((*allocation_id, start - allocation.guest_start));
        }

        let (mut guest_start, allocation_length) = host_allocation_range(start, length)?;
        let mut guest_end = checked_raw_range(guest_start, allocation_length)?;
        let overlapping_ids = self
            .allocations
            .iter()
            .filter_map(|(allocation_id, allocation)| {
                allocation
                    .overlaps_guest_range(guest_start, guest_end)
                    .then_some(*allocation_id)
            })
            .collect::<Vec<_>>();
        for allocation_id in &overlapping_ids {
            let allocation = self
                .allocations
                .get(allocation_id)
                .expect("allocation id collected from map");
            guest_start = guest_start.min(allocation.guest_start);
            guest_end = guest_end.max(allocation.guest_end());
        }

        if !overlapping_ids.is_empty() {
            return self.replace_overlapping_allocations(
                start,
                guest_start,
                guest_end,
                overlapping_ids,
            );
        }

        let allocation_offset = start
            .checked_sub(guest_start)
            .ok_or(GuestMemoryError::InvalidAddress)?;
        let allocation_length = guest_end
            .checked_sub(guest_start)
            .ok_or(GuestMemoryError::InvalidAddress)?;
        let len =
            usize::try_from(allocation_length).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let memory = allocate_guest_host_memory_at(
            guest_start,
            len,
            initial_protection,
            self.host_address_mode,
        )?;
        let allocation_id = self.next_allocation_id;
        self.next_allocation_id = self
            .next_allocation_id
            .checked_add(1)
            .ok_or(GuestMemoryError::OutOfMemory)?;
        self.allocations.insert(
            allocation_id,
            GuestAllocation {
                guest_start,
                memory: Arc::new(memory),
            },
        );
        Ok((allocation_id, allocation_offset))
    }

    fn replace_overlapping_allocations(
        &mut self,
        requested_start: u64,
        guest_start: u64,
        guest_end: u64,
        allocation_ids: Vec<u64>,
    ) -> Result<(u64, u64), GuestMemoryError> {
        struct SavedAllocation {
            guest_start: u64,
            bytes: Vec<u8>,
        }

        let mut saved = Vec::new();
        for allocation_id in &allocation_ids {
            let ranges = self.allocation_protection_ranges(*allocation_id)?;
            let allocation = self
                .allocations
                .get(allocation_id)
                .expect("allocation id collected from map");
            let mut guard = AllocationProtectionGuard::new(&allocation.memory, &ranges)?;
            saved.push(SavedAllocation {
                guest_start: allocation.guest_start,
                bytes: allocation.memory.as_slice().to_vec(),
            });
            guard.restore()?;
        }
        for allocation_id in &allocation_ids {
            self.allocations.remove(allocation_id);
        }

        let allocation_length = guest_end
            .checked_sub(guest_start)
            .ok_or(GuestMemoryError::InvalidAddress)?;
        let len =
            usize::try_from(allocation_length).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let mut memory = allocate_guest_host_memory_at(
            guest_start,
            len,
            MemoryProtection::ReadWrite,
            self.host_address_mode,
        )?;
        for allocation in saved {
            let offset = usize::try_from(allocation.guest_start - guest_start)
                .map_err(|_| GuestMemoryError::RegionTooLarge)?;
            memory.as_mut_slice()[offset..offset + allocation.bytes.len()]
                .copy_from_slice(&allocation.bytes);
        }

        let allocation_id = self.next_allocation_id;
        self.next_allocation_id = self
            .next_allocation_id
            .checked_add(1)
            .ok_or(GuestMemoryError::OutOfMemory)?;
        self.allocations.insert(
            allocation_id,
            GuestAllocation {
                guest_start,
                memory: Arc::new(memory),
            },
        );
        for vma in self.vmas.values_mut() {
            if allocation_ids.contains(&vma.allocation_id) {
                vma.allocation_id = allocation_id;
                vma.allocation_offset = vma.start - guest_start;
            }
        }
        let ranges = self.allocation_protection_ranges(allocation_id)?;
        let allocation = self
            .allocations
            .get(&allocation_id)
            .expect("replacement allocation was inserted");
        apply_allocation_protections(&allocation.memory, &ranges)?;
        Ok((allocation_id, requested_start - guest_start))
    }

    fn insert_mapping(
        &mut self,
        start: u64,
        length: u64,
        protection: GuestMemoryProtection,
        kind: GuestVmaKind,
    ) -> Result<(), GuestMemoryError> {
        let end = checked_mapping_end(start, length, self.address_space_end)?;
        if self.overlaps(start, end) {
            return Err(GuestMemoryError::AddressInUse);
        }

        let (allocation_id, allocation_offset) =
            self.ensure_host_allocation(start, length, protection.to_host())?;
        let offset =
            usize::try_from(allocation_offset).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let len = usize::try_from(length).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        if protection.read || protection.write || protection.execute {
            self.zero_allocation_range(allocation_id, allocation_offset, len)?;
        }
        let allocation = self
            .allocations
            .get(&allocation_id)
            .expect("new allocation was inserted");
        allocation
            .memory
            .protect_range(offset, len, protection.to_host())
            .map_err(GuestMemoryError::Host)?;
        self.vmas.insert(
            start,
            GuestVma {
                start,
                end,
                protection,
                kind,
                allocation_id,
                allocation_offset,
            },
        );
        Ok(())
    }

    fn zero_allocation_range(
        &mut self,
        allocation_id: u64,
        allocation_offset: u64,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        let offset =
            usize::try_from(allocation_offset).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        offset
            .checked_add(len)
            .ok_or(GuestMemoryError::RegionTooLarge)?;
        let ranges = self.allocation_protection_ranges(allocation_id)?;
        self.ensure_allocation_unique(allocation_id)?;
        {
            let allocation = self
                .allocations
                .get(&allocation_id)
                .expect("new mapping references live allocation");
            allocation
                .memory
                .protect_range(offset, len, MemoryProtection::ReadWrite)
                .map_err(GuestMemoryError::Host)?;
        }
        {
            self.allocation_memory_mut(allocation_id)?
                .fill_range(offset, len, 0)
                .map_err(GuestMemoryError::Host)?;
        }
        let allocation = self
            .allocations
            .get(&allocation_id)
            .expect("new mapping references live allocation");
        apply_allocation_protections(&allocation.memory, &ranges)?;
        Ok(())
    }

    fn insert_loaded_mapping(
        &mut self,
        start: u64,
        length: u64,
        protection: GuestMemoryProtection,
        bytes: &[u8],
    ) -> Result<(), GuestMemoryError> {
        let end = checked_mapping_end(start, length, self.address_space_end)?;
        if self.overlaps(start, end) {
            return Err(GuestMemoryError::AddressInUse);
        }
        let len = usize::try_from(length).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        if bytes.len() != len {
            return Err(GuestMemoryError::InvalidLength);
        }
        let (allocation_id, allocation_offset) =
            self.ensure_host_allocation(start, length, MemoryProtection::ReadWrite)?;
        self.ensure_allocation_unique(allocation_id)?;
        let offset =
            usize::try_from(allocation_offset).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        self.allocation_memory_mut(allocation_id)?
            .copy_from_slice(offset, bytes)
            .map_err(GuestMemoryError::Host)?;
        let allocation = self
            .allocations
            .get(&allocation_id)
            .expect("new allocation was inserted");
        allocation
            .memory
            .protect_range(offset, len, protection.to_host())
            .map_err(GuestMemoryError::Host)?;
        self.vmas.insert(
            start,
            GuestVma {
                start,
                end,
                protection,
                kind: GuestVmaKind::Anonymous,
                allocation_id,
                allocation_offset,
            },
        );
        Ok(())
    }

    fn resize_heap(&mut self, mapped_end: u64) -> Result<(), GuestMemoryError> {
        if mapped_end == self.brk_base {
            self.remove_heap_vmas();
            return Ok(());
        }

        let old_mapped_end = self.heap_mapped_end();
        let new_size = mapped_end
            .checked_sub(self.brk_base)
            .ok_or(GuestMemoryError::InvalidAddress)?;
        let protection = GuestMemoryProtection::new(true, true, false);
        let (allocation_id, allocation_offset) = self.ensure_host_allocation(
            self.brk_base,
            mapped_end
                .checked_sub(self.brk_base)
                .ok_or(GuestMemoryError::InvalidAddress)?,
            MemoryProtection::ReadWrite,
        )?;
        let zero_start = old_mapped_end.max(self.brk_base);
        if zero_start < mapped_end {
            let zero_offset = allocation_offset
                .checked_add(
                    zero_start
                        .checked_sub(self.brk_base)
                        .ok_or(GuestMemoryError::InvalidAddress)?,
                )
                .ok_or(GuestMemoryError::RegionTooLarge)?;
            let zero_len = usize::try_from(mapped_end - zero_start)
                .map_err(|_| GuestMemoryError::RegionTooLarge)?;
            self.zero_allocation_range(allocation_id, zero_offset, zero_len)?;
        }
        self.vmas.insert(
            self.brk_base,
            GuestVma {
                start: self.brk_base,
                end: mapped_end,
                protection,
                kind: GuestVmaKind::Heap,
                allocation_id,
                allocation_offset,
            },
        );
        let offset =
            usize::try_from(allocation_offset).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let len = usize::try_from(new_size).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        self.ensure_allocation_unique(allocation_id)?;
        let allocation = self
            .allocations
            .get(&allocation_id)
            .expect("heap VMA references live allocation");
        allocation
            .memory
            .protect_range(offset, len, protection.to_host())
            .map_err(GuestMemoryError::Host)?;
        Ok(())
    }

    fn shrink_heap(&mut self, mapped_end: u64) {
        if mapped_end <= self.brk_base {
            self.remove_heap_vmas();
            return;
        }

        self.split_vma_at(mapped_end);
        let heap_keys = self
            .vmas
            .range(mapped_end..)
            .filter_map(|(start, vma)| matches!(vma.kind, GuestVmaKind::Heap).then_some(*start))
            .collect::<Vec<_>>();
        for key in heap_keys {
            self.vmas.remove(&key);
        }
        self.drop_unreferenced_allocations();
    }

    fn ensure_brk_can_grow(
        &self,
        old_mapped_end: u64,
        new_mapped_end: u64,
    ) -> Result<(), GuestMemoryError> {
        if self.vmas.values().any(|vma| {
            !matches!(vma.kind, GuestVmaKind::Heap)
                && vma.start < new_mapped_end
                && old_mapped_end < vma.end
        }) {
            return Err(GuestMemoryError::OutOfMemory);
        }
        Ok(())
    }

    fn heap_vma(&self) -> Option<&GuestVma> {
        self.vmas
            .values()
            .find(|vma| matches!(vma.kind, GuestVmaKind::Heap))
    }

    fn heap_mapped_end(&self) -> u64 {
        self.heap_vma()
            .map_or(self.brk_base, |vma| vma.end.max(self.brk_base))
    }

    fn remove_heap_vmas(&mut self) {
        let heap_keys = self
            .vmas
            .iter()
            .filter_map(|(start, vma)| matches!(vma.kind, GuestVmaKind::Heap).then_some(*start))
            .collect::<Vec<_>>();
        for key in heap_keys {
            self.vmas.remove(&key);
        }
        self.drop_unreferenced_allocations();
    }

    fn find_free_range(&self, hint: u64, length: u64) -> Result<u64, GuestMemoryError> {
        let mut candidate = align_up_to(hint, HOST_ALLOCATION_GRANULARITY)?;
        if candidate < MIN_GUEST_ADDRESS {
            candidate = MIN_GUEST_ADDRESS;
        }

        for vma in self.vmas.values() {
            let end = checked_mapping_end(candidate, length, self.address_space_end)?;
            if end <= vma.start {
                return Ok(candidate);
            }
            if candidate < vma.end {
                candidate = align_up_to(vma.end, HOST_ALLOCATION_GRANULARITY)?;
            }
        }

        checked_mapping_end(candidate, length, self.address_space_end)?;
        Ok(candidate)
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.vmas
            .values()
            .any(|vma| vma.start < end && start < vma.end)
    }

    fn is_range_mapped(&self, start: u64, end: u64) -> bool {
        let mut cursor = start;
        for vma in self.vmas.values().filter(|vma| vma.end > start) {
            if vma.start > cursor {
                return false;
            }
            if vma.end > cursor {
                cursor = vma.end;
            }
            if cursor >= end {
                return true;
            }
        }
        false
    }

    fn split_vma_at(&mut self, address: u64) {
        let Some(vma) = self.vma_containing(address).cloned() else {
            return;
        };
        if address == vma.start || address == vma.end {
            return;
        }

        self.vmas.remove(&vma.start);
        let mut left = vma.clone();
        left.end = address;
        let mut right = vma;
        right.start = address;
        right.allocation_offset += address - left.start;
        self.vmas.insert(left.start, left);
        self.vmas.insert(right.start, right);
    }

    fn unmap_range(&mut self, start: u64, end: u64) {
        self.split_vma_at(start);
        self.split_vma_at(end);
        let keys = self
            .vmas
            .range(start..end)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in keys {
            self.vmas.remove(&key);
        }
        self.drop_unreferenced_allocations();
    }

    fn drop_unreferenced_allocations(&mut self) {
        let referenced = self
            .vmas
            .values()
            .map(|vma| vma.allocation_id)
            .collect::<BTreeSet<_>>();
        self.allocations
            .retain(|allocation_id, _| referenced.contains(allocation_id));
    }

    fn coalesce_adjacent(&mut self) {
        let mut merged: BTreeMap<u64, GuestVma> = BTreeMap::new();
        for vma in self.vmas.values().cloned() {
            if let Some(previous) = merged.values_mut().next_back()
                && can_merge(previous, &vma)
            {
                previous.end = vma.end;
                continue;
            }
            merged.insert(vma.start, vma);
        }
        self.vmas = merged;
    }

    fn copy_guest(
        &self,
        address: u64,
        destination: &mut [u8],
        access: AccessKind,
    ) -> Result<(), GuestMemoryError> {
        let end = checked_raw_range(address, destination.len() as u64)?;
        let mut cursor = address;
        let mut copied = 0usize;
        while cursor < end {
            let vma = self
                .vma_containing(cursor)
                .ok_or(GuestMemoryError::NotMapped)?;
            access.check(vma.protection)?;
            let chunk_len = (vma.end.min(end) - cursor) as usize;
            let allocation = self
                .allocations
                .get(&vma.allocation_id)
                .ok_or(GuestMemoryError::NotMapped)?;
            let allocation_offset = usize::try_from(vma.allocation_offset + (cursor - vma.start))
                .map_err(|_| GuestMemoryError::RegionTooLarge)?;
            allocation
                .memory
                .copy_to_slice(
                    allocation_offset,
                    &mut destination[copied..copied + chunk_len],
                )
                .map_err(GuestMemoryError::Host)?;
            cursor += chunk_len as u64;
            copied += chunk_len;
        }
        Ok(())
    }

    fn write_guest(&mut self, address: u64, bytes: &[u8]) -> Result<(), GuestMemoryError> {
        let end = checked_raw_range(address, bytes.len() as u64)?;
        let mut cursor = address;
        let mut copied = 0usize;
        while cursor < end {
            let vma = self
                .vma_containing(cursor)
                .cloned()
                .ok_or(GuestMemoryError::NotMapped)?;
            AccessKind::Write.check(vma.protection)?;
            self.ensure_guest_page_range_unique(cursor, vma.end.min(end))?;
            let vma = self
                .vma_containing(cursor)
                .cloned()
                .ok_or(GuestMemoryError::NotMapped)?;
            let chunk_len = (vma.end.min(end) - cursor) as usize;
            let allocation_offset = usize::try_from(vma.allocation_offset + (cursor - vma.start))
                .map_err(|_| GuestMemoryError::RegionTooLarge)?;
            self.allocation_memory_mut(vma.allocation_id)?
                .copy_from_slice(allocation_offset, &bytes[copied..copied + chunk_len])
                .map_err(GuestMemoryError::Host)?;
            cursor += chunk_len as u64;
            copied += chunk_len;
        }
        Ok(())
    }

    fn allocation_protection_ranges(
        &self,
        allocation_id: u64,
    ) -> Result<Vec<AllocationProtectionRange>, GuestMemoryError> {
        self.vmas
            .values()
            .filter(|vma| vma.allocation_id == allocation_id)
            .map(|vma| {
                Ok(AllocationProtectionRange {
                    offset: usize::try_from(vma.allocation_offset)
                        .map_err(|_| GuestMemoryError::RegionTooLarge)?,
                    len: usize::try_from(vma.len())
                        .map_err(|_| GuestMemoryError::RegionTooLarge)?,
                    protection: vma.protection,
                })
            })
            .collect()
    }
}

fn clone_allocation_memory(
    allocation: &GuestAllocation,
    ranges: &[AllocationProtectionRange],
    allocate: &mut impl FnMut(
        &GuestAllocation,
        MemoryProtection,
    ) -> Result<HostMemory, GuestMemoryError>,
) -> Result<HostMemory, GuestMemoryError> {
    let mut memory = allocate(allocation, MemoryProtection::NoAccess)?;
    for range in ranges {
        if !range.protection.read && !range.protection.write && !range.protection.execute {
            continue;
        }
        memory
            .protect_range(range.offset, range.len, MemoryProtection::ReadWrite)
            .map_err(GuestMemoryError::Host)?;
        memory
            .copy_from_memory(range.offset, &allocation.memory, range.offset, range.len)
            .map_err(GuestMemoryError::Host)?;
    }
    apply_allocation_protections(&memory, ranges)?;
    Ok(memory)
}

fn allocate_guest_host_memory_at(
    start: u64,
    len: usize,
    protection: MemoryProtection,
    mode: HostAddressMode,
) -> Result<HostMemory, GuestMemoryError> {
    match mode {
        HostAddressMode::Flexible => {
            let _ = start;
            HostMemory::allocate(len, protection).map_err(GuestMemoryError::Host)
        }
        HostAddressMode::FixedGuest => allocate_fixed_guest_host_memory(start, len, protection),
    }
}

fn allocate_fixed_guest_host_memory(
    start: u64,
    len: usize,
    protection: MemoryProtection,
) -> Result<HostMemory, GuestMemoryError> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(windows, target_arch = "x86_64")
    ))]
    {
        let address = usize::try_from(start).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        HostMemory::allocate_at(address, len, protection).map_err(GuestMemoryError::Host)
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(windows, target_arch = "x86_64")
    )))]
    {
        let _ = start;
        HostMemory::allocate(len, protection).map_err(GuestMemoryError::Host)
    }
}

fn host_allocation_range(start: u64, length: u64) -> Result<(u64, u64), GuestMemoryError> {
    let end = checked_raw_range(start, length)?;
    let guest_start = align_down_to(start, HOST_ALLOCATION_GRANULARITY);
    let guest_end = align_up_to(end, HOST_ALLOCATION_GRANULARITY)?;
    Ok((guest_start, guest_end - guest_start))
}

#[derive(Clone, Copy, Debug)]
struct AllocationProtectionRange {
    offset: usize,
    len: usize,
    protection: GuestMemoryProtection,
}

struct AllocationProtectionGuard<'a> {
    memory: &'a HostMemory,
    ranges: &'a [AllocationProtectionRange],
    restored: bool,
}

impl<'a> AllocationProtectionGuard<'a> {
    fn new(
        memory: &'a HostMemory,
        ranges: &'a [AllocationProtectionRange],
    ) -> Result<Self, GuestMemoryError> {
        memory
            .protect(MemoryProtection::ReadWrite)
            .map_err(GuestMemoryError::Host)?;
        Ok(Self {
            memory,
            ranges,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<(), GuestMemoryError> {
        if !self.restored {
            apply_allocation_protections(self.memory, self.ranges)?;
            self.restored = true;
        }
        Ok(())
    }
}

impl Drop for AllocationProtectionGuard<'_> {
    fn drop(&mut self) {
        if !self.restored {
            let _ = apply_allocation_protections(self.memory, self.ranges);
        }
    }
}

fn apply_allocation_protections(
    memory: &HostMemory,
    ranges: &[AllocationProtectionRange],
) -> Result<(), GuestMemoryError> {
    for range in ranges {
        memory
            .protect_range(range.offset, range.len, range.protection.to_host())
            .map_err(GuestMemoryError::Host)?;
    }
    Ok(())
}

impl MemorySyscalls for GuestMemory {
    fn dispatch_memory(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        match request.syscall {
            Syscall::Mmap => syscall_result(self.mmap(MmapSyscallArgs::from_args(request.args))),
            Syscall::Munmap => syscall_result(
                self.munmap(MunmapSyscallArgs::from_args(request.args))
                    .map(|()| 0),
            ),
            Syscall::Mprotect => syscall_result(
                self.mprotect(MprotectSyscallArgs::from_args(request.args))
                    .map(|()| 0),
            ),
            Syscall::Madvise => syscall_result(self.madvise(
                request.args.get(0).unwrap_or_default(),
                request.args.get(1).unwrap_or_default(),
                request.args.get(2).unwrap_or_default() as u32,
            )),
            Syscall::Brk => {
                let outcome = self.set_brk(BrkSyscallArgs::from_args(request.args).addr);
                let mut syscall_outcome = SyscallOutcome::success(outcome.current);
                if let Some(error) = outcome.error.and_then(|error| error.host_error().cloned()) {
                    syscall_outcome = syscall_outcome.with_host_error(host_error_trace(&error));
                }
                syscall_outcome
            }
            _ => SyscallOutcome::unsupported(),
        }
    }
}

impl GuestMemory {
    pub fn madvise(&self, addr: u64, length: u64, advice: u32) -> Result<u64, GuestMemoryError> {
        if !is_page_aligned(addr) {
            return Err(GuestMemoryError::InvalidAddress);
        }
        if !is_supported_madvise(advice) {
            return Err(GuestMemoryError::InvalidFlags);
        }
        if length == 0 {
            return Ok(0);
        }
        checked_raw_range(addr, length)?;
        Ok(0)
    }
}

impl crate::GuestMemoryAccess for GuestMemory {
    fn read_bytes(
        &self,
        addr: u64,
        buffer: &mut [u8],
    ) -> Result<(), crate::GuestMemoryAccessError> {
        self.read(addr, buffer)
            .map_err(|_| crate::GuestMemoryAccessError::Fault)
    }

    fn write_bytes(
        &mut self,
        addr: u64,
        buffer: &[u8],
    ) -> Result<(), crate::GuestMemoryAccessError> {
        self.write(addr, buffer)
            .map_err(|_| crate::GuestMemoryAccessError::Fault)
    }
}

impl mcr_jit::GuestMemoryOperandAccess for GuestMemory {
    fn read_memory_operand(
        &self,
        address: u64,
        buffer: &mut [u8],
    ) -> Result<(), mcr_jit::GuestMemoryOperandError> {
        self.read(address, buffer).map_err(memory_operand_error)
    }

    fn write_memory_operand(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), mcr_jit::GuestMemoryOperandError> {
        self.write(address, bytes).map_err(memory_operand_error)
    }
}

const fn memory_operand_error(error: GuestMemoryError) -> mcr_jit::GuestMemoryOperandError {
    match error {
        GuestMemoryError::NotMapped => mcr_jit::GuestMemoryOperandError::NotMapped,
        GuestMemoryError::AccessDenied => mcr_jit::GuestMemoryOperandError::AccessDenied,
        GuestMemoryError::InvalidAddress
        | GuestMemoryError::InvalidLength
        | GuestMemoryError::InvalidProtection
        | GuestMemoryError::InvalidFlags
        | GuestMemoryError::InvalidOffset
        | GuestMemoryError::BadFileDescriptor
        | GuestMemoryError::AddressInUse
        | GuestMemoryError::OutOfMemory
        | GuestMemoryError::RegionTooLarge
        | GuestMemoryError::Host(_) => mcr_jit::GuestMemoryOperandError::Fault,
    }
}

#[derive(Clone, Copy)]
enum AccessKind {
    Read,
    Write,
}

impl AccessKind {
    const fn check(self, protection: GuestMemoryProtection) -> Result<(), GuestMemoryError> {
        match self {
            Self::Read if protection.read => Ok(()),
            Self::Write if protection.write => Ok(()),
            _ => Err(GuestMemoryError::AccessDenied),
        }
    }
}

fn mmap_kind(args: MmapSyscallArgs) -> Result<GuestVmaKind, GuestMemoryError> {
    if args.flags & !LINUX_MAP_VALID_MASK != 0
        || args.flags & (LINUX_MAP_HUGETLB | LINUX_MAP_SYNC) != 0
    {
        return Err(GuestMemoryError::InvalidFlags);
    }

    let map_type = args.flags & LINUX_MAP_TYPE_MASK;
    if map_type != LINUX_MAP_PRIVATE && map_type != LINUX_MAP_SHARED {
        return Err(GuestMemoryError::InvalidFlags);
    }

    if args.is_anonymous() {
        if args.offset != 0 {
            return Err(GuestMemoryError::InvalidOffset);
        }
        return Ok(GuestVmaKind::Anonymous);
    }

    if args.fd < 0 {
        return Err(GuestMemoryError::BadFileDescriptor);
    }
    if args.offset < 0 || !is_page_aligned(args.offset as u64) {
        return Err(GuestMemoryError::InvalidOffset);
    }
    Ok(GuestVmaKind::FileBacked {
        fd: args.fd,
        offset: args.offset,
        shared: args.flags & LINUX_MAP_SHARED != 0,
    })
}

fn syscall_result(result: Result<u64, GuestMemoryError>) -> SyscallOutcome {
    match result {
        Ok(value) => SyscallOutcome::success(value),
        Err(error) => {
            let mut outcome = SyscallOutcome::errno(error.errno());
            if let Some(host_error) = error.host_error() {
                outcome = outcome.with_host_error(host_error_trace(host_error));
            }
            outcome
        }
    }
}

fn host_error_trace(error: &HostError) -> mcr_sys::HostErrorTrace {
    let code = match error.code() {
        Some(HostErrorCode::Windows(code)) => i64::from(code),
        Some(HostErrorCode::Winsock(code) | HostErrorCode::Os(code)) => i64::from(code),
        None => 0,
    };
    mcr_sys::HostErrorTrace::new("memory", code, Some(error.to_string()))
}

const fn host_error_errno(kind: HostErrorKind) -> LinuxErrno {
    match kind {
        HostErrorKind::AccessDenied => LinuxErrno::EACCES,
        HostErrorKind::InvalidInput => LinuxErrno::EINVAL,
        HostErrorKind::OutOfMemory => LinuxErrno::ENOMEM,
        HostErrorKind::Unsupported => LinuxErrno::ENOSYS,
        HostErrorKind::Interrupted => LinuxErrno::EINTR,
        HostErrorKind::TimedOut => LinuxErrno::ETIMEDOUT,
        HostErrorKind::WouldBlock => LinuxErrno::EAGAIN,
        HostErrorKind::BrokenPipe => LinuxErrno::EPIPE,
        HostErrorKind::NotFound => LinuxErrno::ENOENT,
        HostErrorKind::AlreadyExists => LinuxErrno::EEXIST,
        HostErrorKind::Poisoned | HostErrorKind::Unavailable | HostErrorKind::Other => {
            LinuxErrno::EIO
        }
    }
}

fn checked_page_range(start: u64, length: u64) -> Result<u64, GuestMemoryError> {
    if !is_page_aligned(start) || length == 0 {
        return Err(GuestMemoryError::InvalidAddress);
    }
    let length = page_round_length(length)?;
    checked_raw_range(start, length)
}

fn checked_raw_range(start: u64, length: u64) -> Result<u64, GuestMemoryError> {
    start
        .checked_add(length)
        .filter(|end| *end >= start)
        .ok_or(GuestMemoryError::InvalidLength)
}

fn raw_ranges_overlap(lhs: u64, rhs: u64, len: usize) -> Result<bool, GuestMemoryError> {
    if len == 0 {
        return Ok(false);
    }
    let length = u64::try_from(len).map_err(|_| GuestMemoryError::RegionTooLarge)?;
    let lhs_end = checked_raw_range(lhs, length)?;
    let rhs_end = checked_raw_range(rhs, length)?;
    Ok(lhs < rhs_end && rhs < lhs_end)
}

fn checked_mapping_end(
    start: u64,
    length: u64,
    address_space_end: u64,
) -> Result<u64, GuestMemoryError> {
    if start < MIN_GUEST_ADDRESS || !is_page_aligned(start) {
        return Err(GuestMemoryError::InvalidAddress);
    }
    let end = checked_raw_range(start, length)?;
    if end > address_space_end {
        return Err(GuestMemoryError::OutOfMemory);
    }
    Ok(end)
}

fn page_round_length(length: u64) -> Result<u64, GuestMemoryError> {
    if length == 0 {
        return Err(GuestMemoryError::InvalidLength);
    }
    align_up(length)
}

const fn is_page_aligned(value: u64) -> bool {
    value % GUEST_PAGE_SIZE == 0
}

const fn is_supported_madvise(advice: u32) -> bool {
    matches!(
        advice,
        0..=4 | 8..=25 | 100 | 101
    )
}

const fn align_up(value: u64) -> Result<u64, GuestMemoryError> {
    let mask = GUEST_PAGE_SIZE - 1;
    match value.checked_add(mask) {
        Some(value) => Ok(value & !mask),
        None => Err(GuestMemoryError::InvalidLength),
    }
}

const fn align_down_to(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

const fn align_up_to(value: u64, alignment: u64) -> Result<u64, GuestMemoryError> {
    let mask = alignment - 1;
    match value.checked_add(mask) {
        Some(value) => Ok(value & !mask),
        None => Err(GuestMemoryError::InvalidLength),
    }
}

fn can_merge(left: &GuestVma, right: &GuestVma) -> bool {
    left.end == right.start
        && left.protection == right.protection
        && left.kind == right.kind
        && left.allocation_id == right.allocation_id
        && left.allocation_offset + left.len() == right.allocation_offset
}

#[cfg(test)]
mod tests {
    use mcr_sys::{
        LINUX_MAP_ANONYMOUS, LINUX_MAP_FIXED, LINUX_MAP_FIXED_NOREPLACE, LINUX_MAP_PRIVATE,
        LINUX_MAP_SHARED, LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE, MemorySyscalls,
        MmapSyscallArgs, MprotectSyscallArgs, MunmapSyscallArgs, Syscall, SyscallArgs,
        SyscallRequest,
    };

    use super::{
        GUEST_PAGE_SIZE, GuestLibcIntrinsic, GuestLibcIntrinsicError, GuestMemory,
        GuestMemoryError, GuestMemoryProtection, GuestVmaKind, HOST_ALLOCATION_GRANULARITY,
        HostAddressMode,
    };

    const BRK_BASE: u64 = 0x0100_0000;
    const MMAP_BASE: u64 = 0x0200_0000;
    const ADDRESS_END: u64 = 0x0400_0000;

    fn memory() -> GuestMemory {
        GuestMemory::with_layout(BRK_BASE, MMAP_BASE, ADDRESS_END).unwrap()
    }

    fn anonymous(addr: u64, length: u64, prot: u32, flags: u32) -> MmapSyscallArgs {
        MmapSyscallArgs {
            addr,
            length,
            prot,
            flags: flags | LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            fd: -1,
            offset: 0,
        }
    }

    #[test]
    fn mmap_places_anonymous_mapping_and_detects_overlap() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(0, GUEST_PAGE_SIZE, LINUX_PROT_READ, 0))
            .unwrap();

        assert_eq!(addr, MMAP_BASE);
        assert_eq!(memory.vmas().count(), 1);
        assert_eq!(
            memory.vma_containing(addr).unwrap().protection(),
            GuestMemoryProtection::new(true, false, false)
        );

        let overlap = memory.mmap(anonymous(
            addr,
            GUEST_PAGE_SIZE,
            LINUX_PROT_READ,
            LINUX_MAP_FIXED_NOREPLACE,
        ));

        assert_eq!(overlap, Err(GuestMemoryError::AddressInUse));
    }

    #[cfg(windows)]
    #[test]
    fn fixed_guest_mmap_retries_after_host_address_conflict() {
        use mcr_win::{HostMemory, MemoryProtection};

        let Ok(_reserved) = HostMemory::allocate_at(
            MMAP_BASE as usize,
            GUEST_PAGE_SIZE as usize,
            MemoryProtection::NoAccess,
        ) else {
            return;
        };
        let mut memory = memory();
        memory.host_address_mode = HostAddressMode::FixedGuest;

        let mapped = memory
            .mmap(anonymous(0, GUEST_PAGE_SIZE, LINUX_PROT_READ, 0))
            .unwrap();

        assert!(mapped >= MMAP_BASE + HOST_ALLOCATION_GRANULARITY);
        assert_eq!(memory.vma_containing(mapped).unwrap().start(), mapped);
    }

    #[test]
    fn noaccess_reservation_can_be_remapped_and_written() {
        let mut memory = memory();
        let reserved = memory
            .mmap(anonymous(0, 4 * GUEST_PAGE_SIZE, 0, 0))
            .unwrap();
        let mut buf = [0];

        assert_eq!(
            memory.read(reserved, &mut buf),
            Err(GuestMemoryError::AccessDenied)
        );

        let mapped = memory
            .mmap(anonymous(
                reserved + GUEST_PAGE_SIZE,
                GUEST_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_FIXED,
            ))
            .unwrap();

        memory.write(mapped, b"ok").unwrap();
        let mut out = [0; 2];
        memory.read(mapped, &mut out).unwrap();

        assert_eq!(out, *b"ok");
    }

    #[test]
    fn mmap_fixed_replaces_overlapping_mapping() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(0, GUEST_PAGE_SIZE * 2, LINUX_PROT_READ, 0))
            .unwrap();
        memory.write(addr, b"a").unwrap_err();

        let fixed = memory
            .mmap(anonymous(
                addr,
                GUEST_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_FIXED,
            ))
            .unwrap();

        assert_eq!(fixed, addr);
        memory.write(addr, b"b").unwrap();
        assert_eq!(memory.vmas().count(), 2);
    }

    #[test]
    fn intrinsic_memory_primitives_preserve_guest_access_rules_and_overlap() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(
                0,
                GUEST_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                0,
            ))
            .unwrap();

        memory.intrinsic_memset(addr, b'a', 8).unwrap();
        assert_eq!(memory.intrinsic_memchr(addr, b'a', 8).unwrap(), Some(addr));
        assert_eq!(memory.intrinsic_memchr(addr, b'z', 8).unwrap(), None);

        memory.write(addr, b"abcdef\0tail").unwrap();
        memory.intrinsic_memmove(addr + 2, addr, 6).unwrap();
        let mut moved = [0; 8];
        memory.read(addr, &mut moved).unwrap();
        assert_eq!(&moved, b"ababcdef");
        assert_eq!(memory.intrinsic_memcmp(addr + 2, addr + 2, 3).unwrap(), 0);
        assert!(memory.intrinsic_memcmp(addr, addr + 5, 3).unwrap() < 0);
        assert_eq!(memory.intrinsic_strlen(addr, 12).unwrap(), Some(11));

        memory
            .mprotect(MprotectSyscallArgs {
                addr,
                length: GUEST_PAGE_SIZE,
                prot: LINUX_PROT_READ,
            })
            .unwrap();
        assert_eq!(
            memory.intrinsic_memset(addr, 0, 1),
            Err(GuestMemoryError::AccessDenied)
        );
    }

    #[test]
    fn libc_intrinsic_dispatch_uses_sysv_register_arguments_and_abi_returns() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(
                0,
                GUEST_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                0,
            ))
            .unwrap();
        let src = addr;
        let dst = addr + 32;
        let other = addr + 64;
        memory.write(src, b"abc\0tail").unwrap();
        memory.write(other, b"abd\0tail").unwrap();

        assert_eq!(
            memory
                .dispatch_libc_intrinsic(GuestLibcIntrinsic::Memcpy, dst, src, 3)
                .unwrap(),
            dst
        );
        let mut copied = [0; 3];
        memory.read(dst, &mut copied).unwrap();
        assert_eq!(&copied, b"abc");

        assert_eq!(
            memory
                .dispatch_libc_intrinsic(GuestLibcIntrinsic::Memset, dst + 3, b'x'.into(), 2)
                .unwrap(),
            dst + 3
        );
        assert_eq!(
            memory
                .dispatch_libc_intrinsic(GuestLibcIntrinsic::Memchr, src, b'b'.into(), 4)
                .unwrap(),
            src + 1
        );
        assert_eq!(
            memory
                .dispatch_libc_intrinsic(GuestLibcIntrinsic::Strlen { max_len: 16 }, src, 0, 0)
                .unwrap(),
            3
        );
        assert_eq!(
            memory
                .dispatch_libc_intrinsic(GuestLibcIntrinsic::Memcmp, src, other, 3)
                .unwrap() as i64,
            -1
        );

        assert_eq!(
            memory.dispatch_libc_intrinsic(GuestLibcIntrinsic::Memcpy, src + 1, src, 3),
            Err(GuestLibcIntrinsicError::UnsupportedOverlap)
        );
        assert_eq!(
            memory.dispatch_libc_intrinsic(GuestLibcIntrinsic::Strlen { max_len: 2 }, src, 0, 0),
            Err(GuestLibcIntrinsicError::UnterminatedString)
        );
    }

    #[test]
    fn libc_intrinsic_symbol_classifier_accepts_versioned_libc_names() {
        assert_eq!(
            GuestLibcIntrinsic::from_symbol_name("memcpy"),
            Some(GuestLibcIntrinsic::Memcpy)
        );
        assert_eq!(
            GuestLibcIntrinsic::from_symbol_name("memset@@GLIBC_2.2.5"),
            Some(GuestLibcIntrinsic::Memset)
        );
        assert_eq!(
            GuestLibcIntrinsic::from_symbol_name("strlen@GLIBC_2.2.5"),
            Some(GuestLibcIntrinsic::Strlen {
                max_len: super::DEFAULT_LIBC_STRLEN_MAX
            })
        );
        assert_eq!(GuestLibcIntrinsic::from_symbol_name("strcpy"), None);
    }

    #[test]
    fn mprotect_updates_permissions_and_splits_vmas() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(
                0,
                GUEST_PAGE_SIZE * 3,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                0,
            ))
            .unwrap();
        memory.write(addr + GUEST_PAGE_SIZE, b"x").unwrap();

        memory
            .mprotect(MprotectSyscallArgs {
                addr: addr + GUEST_PAGE_SIZE,
                length: GUEST_PAGE_SIZE,
                prot: LINUX_PROT_READ,
            })
            .unwrap();

        assert_eq!(memory.vmas().count(), 3);
        assert_eq!(
            memory.write(addr + GUEST_PAGE_SIZE, b"y"),
            Err(GuestMemoryError::AccessDenied)
        );
        let mut byte = [0];
        memory.read(addr + GUEST_PAGE_SIZE, &mut byte).unwrap();
        assert_eq!(byte, [b'x']);
    }

    #[test]
    fn patch_code_fixed_updates_executable_bytes_and_restores_protection() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(
                0,
                GUEST_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_EXEC,
                0,
            ))
            .unwrap();

        memory
            .patch_code_fixed([(addr, [0xcc, 0x90]), (addr + 8, [0x90, 0xcc])])
            .unwrap();

        let mut bytes = [0; 10];
        memory.read(addr, &mut bytes).unwrap();
        assert_eq!(bytes[..2], [0xcc, 0x90]);
        assert_eq!(bytes[8..10], [0x90, 0xcc]);
        assert_eq!(
            memory.write(addr, b"x"),
            Err(GuestMemoryError::AccessDenied)
        );
    }

    #[test]
    fn munmap_removes_middle_range_and_keeps_remaining_bytes() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(
                0,
                GUEST_PAGE_SIZE * 3,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                0,
            ))
            .unwrap();
        memory.write(addr, b"l").unwrap();
        memory.write(addr + GUEST_PAGE_SIZE * 2, b"r").unwrap();

        memory
            .munmap(MunmapSyscallArgs {
                addr: addr + GUEST_PAGE_SIZE,
                length: GUEST_PAGE_SIZE,
            })
            .unwrap();

        assert_eq!(memory.vmas().count(), 2);
        assert_eq!(
            memory.read(addr + GUEST_PAGE_SIZE, &mut [0]),
            Err(GuestMemoryError::NotMapped)
        );
        let mut bytes = [0, 0];
        memory.read(addr, &mut bytes[..1]).unwrap();
        memory
            .read(addr + GUEST_PAGE_SIZE * 2, &mut bytes[1..])
            .unwrap();
        assert_eq!(bytes, [b'l', b'r']);
    }

    #[test]
    fn anonymous_mmap_zero_fills_reused_unmapped_range() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(
                0,
                GUEST_PAGE_SIZE * 3,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                0,
            ))
            .unwrap();
        let middle = addr + GUEST_PAGE_SIZE;
        memory.write(addr, b"l").unwrap();
        memory.write(middle, b"stale").unwrap();
        memory.write(addr + GUEST_PAGE_SIZE * 2, b"r").unwrap();
        memory
            .mprotect(MprotectSyscallArgs {
                addr,
                length: GUEST_PAGE_SIZE,
                prot: LINUX_PROT_READ,
            })
            .unwrap();
        memory
            .munmap(MunmapSyscallArgs {
                addr: middle,
                length: GUEST_PAGE_SIZE,
            })
            .unwrap();

        let remapped = memory
            .mmap(anonymous(
                middle,
                GUEST_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_FIXED,
            ))
            .unwrap();

        assert_eq!(remapped, middle);
        let mut zeroes = [0xff; 5];
        memory.read(middle, &mut zeroes).unwrap();
        assert_eq!(zeroes, [0; 5]);
        assert_eq!(
            memory.write(addr, b"x"),
            Err(GuestMemoryError::AccessDenied)
        );
        let mut preserved = [0, 0];
        memory.read(addr, &mut preserved[..1]).unwrap();
        memory
            .read(addr + GUEST_PAGE_SIZE * 2, &mut preserved[1..])
            .unwrap();
        assert_eq!(preserved, [b'l', b'r']);
    }

    #[test]
    fn try_clone_runtime_preserves_mappings_and_isolates_writes() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(
                0,
                GUEST_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                0,
            ))
            .unwrap();
        memory.write(addr, b"parent").unwrap();

        let mut clone = memory.try_clone_runtime().unwrap();
        clone.write(addr, b"child!").unwrap();

        let mut parent_bytes = [0; 6];
        memory.read(addr, &mut parent_bytes).unwrap();
        let mut child_bytes = [0; 6];
        clone.read(addr, &mut child_bytes).unwrap();

        assert_eq!(&parent_bytes, b"parent");
        assert_eq!(&child_bytes, b"child!");
    }

    #[test]
    fn try_clone_runtime_reuses_read_only_allocations_until_writeable() {
        let mut memory = memory();
        let addr = MMAP_BASE;
        memory
            .insert_loaded_mapping(
                addr,
                GUEST_PAGE_SIZE,
                GuestMemoryProtection::new(true, false, true),
                &vec![b'p'; GUEST_PAGE_SIZE as usize],
            )
            .unwrap();
        let allocation_id = memory.vma_containing(addr).unwrap().allocation_id;

        let mut clone = memory.try_clone_runtime().unwrap();

        assert!(std::sync::Arc::ptr_eq(
            &memory.allocations.get(&allocation_id).unwrap().memory,
            &clone.allocations.get(&allocation_id).unwrap().memory
        ));

        clone
            .mprotect(MprotectSyscallArgs {
                addr,
                length: GUEST_PAGE_SIZE,
                prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
            })
            .unwrap();
        clone.write(addr, b"child").unwrap();

        let clone_allocation_id = clone.vma_containing(addr).unwrap().allocation_id;
        assert!(!std::sync::Arc::ptr_eq(
            &memory.allocations.get(&allocation_id).unwrap().memory,
            &clone.allocations.get(&clone_allocation_id).unwrap().memory
        ));
        let mut parent = [0; 5];
        let mut child = [0; 5];
        memory.read(addr, &mut parent).unwrap();
        clone.read(addr, &mut child).unwrap();
        assert_eq!(&parent, b"ppppp");
        assert_eq!(&child, b"child");
    }

    #[test]
    fn try_clone_runtime_detaches_only_mutated_read_only_pages() {
        let mut memory = memory();
        let addr = MMAP_BASE;
        memory
            .insert_loaded_mapping(
                addr,
                GUEST_PAGE_SIZE * 3,
                GuestMemoryProtection::new(true, false, false),
                &vec![b'p'; (GUEST_PAGE_SIZE * 3) as usize],
            )
            .unwrap();
        let parent_allocation_id = memory.vma_containing(addr).unwrap().allocation_id;

        let mut clone = memory.try_clone_runtime().unwrap();
        let middle = addr + GUEST_PAGE_SIZE;
        clone
            .mprotect(MprotectSyscallArgs {
                addr: middle,
                length: GUEST_PAGE_SIZE,
                prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
            })
            .unwrap();
        clone.write(middle, b"child").unwrap();

        let clone_left_id = clone.vma_containing(addr).unwrap().allocation_id;
        let clone_middle_id = clone.vma_containing(middle).unwrap().allocation_id;
        let clone_right_id = clone
            .vma_containing(addr + GUEST_PAGE_SIZE * 2)
            .unwrap()
            .allocation_id;
        let parent_memory = &memory
            .allocations
            .get(&parent_allocation_id)
            .unwrap()
            .memory;
        assert!(std::sync::Arc::ptr_eq(
            parent_memory,
            &clone.allocations.get(&clone_left_id).unwrap().memory
        ));
        assert!(!std::sync::Arc::ptr_eq(
            parent_memory,
            &clone.allocations.get(&clone_middle_id).unwrap().memory
        ));
        assert!(std::sync::Arc::ptr_eq(
            parent_memory,
            &clone.allocations.get(&clone_right_id).unwrap().memory
        ));

        let mut parent = [0; 5];
        let mut child = [0; 5];
        memory.read(middle, &mut parent).unwrap();
        clone.read(middle, &mut child).unwrap();
        assert_eq!(&parent, b"ppppp");
        assert_eq!(&child, b"child");
    }

    #[test]
    fn try_clone_runtime_preserves_split_vma_protections() {
        let mut memory = memory();
        let addr = memory
            .mmap(anonymous(
                0,
                GUEST_PAGE_SIZE * 3,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                0,
            ))
            .unwrap();
        memory.write(addr, b"left").unwrap();
        memory.write(addr + GUEST_PAGE_SIZE * 2, b"right").unwrap();
        memory
            .mprotect(MprotectSyscallArgs {
                addr: addr + GUEST_PAGE_SIZE,
                length: GUEST_PAGE_SIZE,
                prot: LINUX_PROT_READ,
            })
            .unwrap();

        let mut clone = memory.try_clone_runtime().unwrap();

        assert_eq!(clone.vmas().count(), 3);
        assert_eq!(
            clone.write(addr + GUEST_PAGE_SIZE, b"x"),
            Err(GuestMemoryError::AccessDenied)
        );
        let mut bytes = [0; 9];
        clone.read(addr, &mut bytes[..4]).unwrap();
        clone
            .read(addr + GUEST_PAGE_SIZE * 2, &mut bytes[4..])
            .unwrap();
        assert_eq!(&bytes, b"leftright");
    }

    #[test]
    fn invalid_memory_addresses_and_flags_are_rejected() {
        let mut memory = memory();

        assert_eq!(
            memory.mmap(anonymous(
                123,
                GUEST_PAGE_SIZE,
                LINUX_PROT_READ,
                LINUX_MAP_FIXED
            )),
            Err(GuestMemoryError::InvalidAddress)
        );
        assert_eq!(
            memory.munmap(MunmapSyscallArgs {
                addr: 123,
                length: GUEST_PAGE_SIZE
            }),
            Err(GuestMemoryError::InvalidAddress)
        );
        assert_eq!(
            memory.mprotect(MprotectSyscallArgs {
                addr: MMAP_BASE,
                length: GUEST_PAGE_SIZE,
                prot: LINUX_PROT_READ
            }),
            Err(GuestMemoryError::NotMapped)
        );
        assert_eq!(
            memory.mmap(anonymous(0, GUEST_PAGE_SIZE, 0x8000, 0)),
            Err(GuestMemoryError::InvalidProtection)
        );
    }

    #[test]
    fn brk_grows_shrinks_and_preserves_heap_data() {
        let mut memory = memory();

        assert_eq!(memory.set_brk(0).current, BRK_BASE);
        assert_eq!(memory.set_brk(BRK_BASE + 16).current, BRK_BASE + 16);
        memory.write(BRK_BASE, b"heap").unwrap();
        assert_eq!(
            memory.vma_containing(BRK_BASE).unwrap().kind(),
            &GuestVmaKind::Heap
        );

        assert_eq!(
            memory.set_brk(BRK_BASE + GUEST_PAGE_SIZE + 8).current,
            BRK_BASE + GUEST_PAGE_SIZE + 8
        );
        let mut bytes = [0; 4];
        memory.read(BRK_BASE, &mut bytes).unwrap();
        assert_eq!(&bytes, b"heap");

        assert_eq!(memory.set_brk(BRK_BASE + 1).current, BRK_BASE + 1);
        assert!(memory.vma_containing(BRK_BASE).is_some());
        assert_eq!(memory.set_brk(BRK_BASE).current, BRK_BASE);
        assert!(memory.vma_containing(BRK_BASE).is_none());
    }

    #[test]
    fn brk_growth_fails_when_it_would_overlap_another_vma() {
        let mut memory = memory();
        memory
            .mmap(anonymous(
                BRK_BASE + GUEST_PAGE_SIZE,
                GUEST_PAGE_SIZE,
                LINUX_PROT_READ,
                LINUX_MAP_FIXED,
            ))
            .unwrap();

        let outcome = memory.set_brk(BRK_BASE + GUEST_PAGE_SIZE * 2);

        assert_eq!(outcome.current, BRK_BASE);
        assert_eq!(outcome.error, Some(GuestMemoryError::OutOfMemory));
    }

    #[cfg(windows)]
    #[test]
    fn brk_growth_reuses_fixed_allocation_tail_after_native_clone() {
        let brk_base = 0x0100_1000;
        let mut memory = GuestMemory::with_layout(brk_base, MMAP_BASE, ADDRESS_END).unwrap();
        memory
            .insert_loaded_mapping(
                0x0100_0000,
                GUEST_PAGE_SIZE,
                GuestMemoryProtection::new(true, false, true),
                &[0x7f; GUEST_PAGE_SIZE as usize],
            )
            .unwrap();
        let mut memory = memory.try_clone_runtime_at_guest_addresses().unwrap();

        let outcome = memory.set_brk(brk_base + GUEST_PAGE_SIZE);

        assert_eq!(outcome.current, brk_base + GUEST_PAGE_SIZE);
        assert_eq!(outcome.error, None);
        memory.write(brk_base, b"heap").unwrap();
        let mut loaded = [0];
        memory.read(0x0100_0000, &mut loaded).unwrap();
        assert_eq!(loaded, [0x7f]);
    }

    #[test]
    fn file_backed_mmap_is_zero_filled_and_guest_local() {
        let mut memory = memory();
        let addr = memory
            .mmap(MmapSyscallArgs {
                addr: 0,
                length: GUEST_PAGE_SIZE,
                prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
                flags: LINUX_MAP_SHARED,
                fd: 3,
                offset: 0,
            })
            .unwrap();

        assert!(matches!(
            memory.vma_containing(addr).unwrap().kind(),
            GuestVmaKind::FileBacked {
                fd: 3,
                offset: 0,
                shared: true
            }
        ));
        let mut byte = [1];
        memory.read(addr, &mut byte).unwrap();
        assert_eq!(byte, [0]);
        memory.write(addr, b"x").unwrap();
        memory.read(addr, &mut byte).unwrap();
        assert_eq!(byte, [b'x']);
    }

    #[test]
    fn memory_syscall_dispatch_returns_linux_results() {
        let mut memory = memory();
        let request = SyscallRequest {
            context: mcr_sys::TraceContext {
                pid: 1,
                tid: 1,
                rip: 0,
            },
            syscall: Syscall::Mmap,
            number: Syscall::MMAP,
            args: SyscallArgs::new([
                0,
                GUEST_PAGE_SIZE,
                u64::from(LINUX_PROT_READ | LINUX_PROT_EXEC),
                u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS),
                u64::MAX,
                0,
            ]),
        };

        let outcome = memory.dispatch_memory(&request);

        assert_eq!(outcome.result, mcr_sys::SyscallReturn::success(MMAP_BASE));
    }

    #[test]
    fn madvise_accepts_common_hints_and_rejects_invalid_arguments() {
        let memory = memory();

        assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 0), Ok(0));
        assert_eq!(memory.madvise(MMAP_BASE, 0, 4), Ok(0));
        assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 8), Ok(0));
        assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 25), Ok(0));
        assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 100), Ok(0));
        assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 101), Ok(0));
        assert_eq!(
            memory.madvise(MMAP_BASE + 1, GUEST_PAGE_SIZE, 0),
            Err(GuestMemoryError::InvalidAddress)
        );
        assert_eq!(
            memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 0xffff),
            Err(GuestMemoryError::InvalidFlags)
        );
        assert_eq!(
            memory.madvise(!(GUEST_PAGE_SIZE - 1), GUEST_PAGE_SIZE * 2, 0),
            Err(GuestMemoryError::InvalidLength)
        );
    }
}
