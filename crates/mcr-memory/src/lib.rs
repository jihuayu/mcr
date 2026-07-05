#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use mcr_elf::GuestMemoryImage;
use mcr_sys::{
    LINUX_MAP_HUGETLB, LINUX_MAP_PRIVATE, LINUX_MAP_SHARED, LINUX_MAP_SYNC, LINUX_MAP_TYPE_MASK,
    LINUX_MAP_VALID_MASK, LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_VALID_MASK,
    LINUX_PROT_WRITE, LinuxErrno, MmapSyscallArgs, MprotectSyscallArgs, MunmapSyscallArgs,
    SyscallOutcome,
};
use mcr_win::{HostError, HostErrorCode, HostErrorKind, HostMemory, MemoryProtection};

mod access;
mod intrinsics;
mod memory_access;
mod ranges;
mod syscalls;

pub use access::{GuestMemoryAccess, GuestMemoryAccessError};

use ranges::*;

pub const GUEST_PAGE_SIZE: u64 = 4096;
pub const MIN_GUEST_ADDRESS: u64 = GUEST_PAGE_SIZE;
pub const DEFAULT_MMAP_BASE: u64 = 0x0000_7000_0000_0000;
pub const GUEST_ADDRESS_SPACE_END: u64 = 0x0000_8000_0000_0000;
const MMAP_HOST_CONFLICT_RETRIES: usize = 64;

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

struct SavedAllocation {
    allocation_id: u64,
    guest_start: u64,
    bytes: Vec<u8>,
    ranges: Vec<AllocationProtectionRange>,
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
        self.try_clone_runtime_with_allocator(true, |allocation| {
            HostMemory::allocate(allocation.memory.len(), MemoryProtection::ReadWrite)
                .map_err(GuestMemoryError::Host)
        })
    }

    pub fn try_clone_runtime_at_guest_addresses(&self) -> Result<Self, GuestMemoryError> {
        self.try_clone_runtime_with_allocator(false, |allocation| {
            allocate_guest_host_memory_at(
                allocation.guest_start,
                allocation.memory.len(),
                MemoryProtection::ReadWrite,
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
        mut allocate: impl FnMut(&GuestAllocation) -> Result<HostMemory, GuestMemoryError>,
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
            let mut source_guard = AllocationProtectionGuard::new(&allocation.memory, &ranges)?;
            let mut memory = allocate(allocation)?;
            memory
                .as_mut_slice()
                .copy_from_slice(allocation.memory.as_slice());
            source_guard.restore()?;
            apply_allocation_protections(&memory, &ranges)?;
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
        let (guest_start, len, bytes) = {
            let mut guard = AllocationProtectionGuard::new(&allocation.memory, &ranges)?;
            let bytes = allocation.memory.as_slice().to_vec();
            guard.restore()?;
            (allocation.guest_start, allocation.memory.len(), bytes)
        };

        let mut memory = allocate_guest_host_memory_at(
            guest_start,
            len,
            MemoryProtection::ReadWrite,
            self.host_address_mode,
        )?;
        memory.as_mut_slice().copy_from_slice(&bytes);
        apply_allocation_protections(&memory, &ranges)?;
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

    pub fn slice(&self, address: u64, len: usize) -> Result<Option<&[u8]>, GuestMemoryError> {
        self.guest_slice(address, len, AccessKind::Read)
    }

    pub fn slice_mut(
        &mut self,
        address: u64,
        len: usize,
    ) -> Result<Option<&mut [u8]>, GuestMemoryError> {
        let length = u64::try_from(len).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let end = checked_raw_range(address, length)?;
        if len == 0 {
            return Ok(Some(&mut []));
        }
        let vma = self
            .vma_containing(address)
            .cloned()
            .ok_or(GuestMemoryError::NotMapped)?;
        AccessKind::Write.check(vma.protection)?;
        if end > vma.end {
            return Ok(None);
        }

        self.ensure_guest_page_range_unique(address, end)?;
        let vma = self
            .vma_containing(address)
            .cloned()
            .ok_or(GuestMemoryError::NotMapped)?;
        let offset = guest_slice_offset(&vma, address)?;
        let slice_end = offset
            .checked_add(len)
            .ok_or(GuestMemoryError::RegionTooLarge)?;
        Ok(Some(
            &mut self
                .allocation_memory_mut(vma.allocation_id)?
                .as_mut_slice()[offset..slice_end],
        ))
    }

    fn guest_slice(
        &self,
        address: u64,
        len: usize,
        access: AccessKind,
    ) -> Result<Option<&[u8]>, GuestMemoryError> {
        let length = u64::try_from(len).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let end = checked_raw_range(address, length)?;
        if len == 0 {
            return Ok(Some(&[]));
        }
        let vma = self
            .vma_containing(address)
            .ok_or(GuestMemoryError::NotMapped)?;
        access.check(vma.protection)?;
        if end > vma.end {
            return Ok(None);
        }
        let allocation = self
            .allocations
            .get(&vma.allocation_id)
            .expect("VMA references live allocation");
        let offset = guest_slice_offset(vma, address)?;
        let slice_end = offset
            .checked_add(len)
            .ok_or(GuestMemoryError::RegionTooLarge)?;
        Ok(Some(&allocation.memory.as_slice()[offset..slice_end]))
    }

    pub fn read_c_string_bytes(
        &self,
        address: u64,
        max_len: usize,
    ) -> Result<Vec<u8>, GuestMemoryError> {
        let mut bytes = Vec::new();
        let mut cursor = address;
        while bytes.len() < max_len {
            let vma = self
                .vma_containing(cursor)
                .ok_or(GuestMemoryError::NotMapped)?;
            AccessKind::Read.check(vma.protection)?;
            let remaining = max_len - bytes.len();
            let chunk_len = usize::try_from((vma.end - cursor).min(remaining as u64))
                .map_err(|_| GuestMemoryError::RegionTooLarge)?;
            if chunk_len == 0 {
                break;
            }
            let chunk = self
                .guest_slice(cursor, chunk_len, AccessKind::Read)?
                .expect("chunk is bounded by one readable VMA");
            if let Some(nul) = chunk.iter().position(|byte| *byte == 0) {
                bytes.extend_from_slice(&chunk[..nul]);
                return Ok(bytes);
            }
            bytes.extend_from_slice(chunk);
            cursor = cursor
                .checked_add(chunk_len as u64)
                .ok_or(GuestMemoryError::InvalidLength)?;
        }
        Err(GuestMemoryError::InvalidLength)
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
        let allocation = self
            .allocations
            .get(&vma.allocation_id)
            .expect("VMA references live allocation");
        allocation
            .memory
            .protect(MemoryProtection::ReadWrite)
            .map_err(GuestMemoryError::Host)?;
        let allocation_offset = usize::try_from(vma.allocation_offset + (address - vma.start))
            .map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let patch_end = allocation_offset
            .checked_add(bytes.len())
            .ok_or(GuestMemoryError::RegionTooLarge)?;
        let old = allocation.memory.as_slice()[allocation_offset..patch_end].to_vec();
        self.allocation_memory_mut(vma.allocation_id)?
            .as_mut_slice()[allocation_offset..patch_end]
            .copy_from_slice(bytes);
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
        if matches!(self.host_address_mode, HostAddressMode::FixedGuest) {
            let mut allocation_ids = BTreeSet::new();
            for (address, _) in &patches {
                let end = checked_raw_range(*address, N as u64)?;
                let vma = self
                    .vma_containing(*address)
                    .cloned()
                    .ok_or(GuestMemoryError::NotMapped)?;
                if end > vma.end {
                    return Err(GuestMemoryError::InvalidLength);
                }
                allocation_ids.insert(vma.allocation_id);
            }
            for allocation_id in allocation_ids {
                self.ensure_allocation_unique(allocation_id)?;
            }
        } else {
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
            let allocation = self
                .allocations
                .get(&allocation_id)
                .expect("VMA references live allocation");
            allocation
                .memory
                .protect(MemoryProtection::ReadWrite)
                .map_err(GuestMemoryError::Host)?;
            for patch in patches {
                let patch_end = patch
                    .allocation_offset
                    .checked_add(N)
                    .ok_or(GuestMemoryError::RegionTooLarge)?;
                self.allocation_memory_mut(allocation_id)?.as_mut_slice()
                    [patch.allocation_offset..patch_end]
                    .copy_from_slice(&patch.bytes);
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
        let bytes = {
            let ranges = self.allocation_protection_ranges(vma.allocation_id)?;
            let mut guard = AllocationProtectionGuard::new(&allocation.memory, &ranges)?;
            let bytes = allocation.memory.as_slice()[offset..offset + len].to_vec();
            guard.restore()?;
            bytes
        };

        let mut memory = allocate_guest_host_memory_at(
            vma.start,
            len,
            MemoryProtection::ReadWrite,
            self.host_address_mode,
        )?;
        memory.as_mut_slice().copy_from_slice(&bytes);
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
            MemoryProtection::ReadWrite,
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
        let mut saved = Vec::new();
        for allocation_id in &allocation_ids {
            let ranges = self.allocation_protection_ranges(*allocation_id)?;
            let allocation = self
                .allocations
                .get(allocation_id)
                .expect("allocation id collected from map");
            let bytes = {
                let mut guard = AllocationProtectionGuard::new(&allocation.memory, &ranges)?;
                let bytes = allocation.memory.as_slice().to_vec();
                guard.restore()?;
                bytes
            };
            saved.push(SavedAllocation {
                allocation_id: *allocation_id,
                guest_start: allocation.guest_start,
                bytes,
                ranges,
            });
        }
        let replacement_ranges = self
            .vmas
            .values()
            .filter(|vma| allocation_ids.contains(&vma.allocation_id))
            .map(|vma| {
                Ok(AllocationProtectionRange {
                    offset: usize::try_from(vma.start - guest_start)
                        .map_err(|_| GuestMemoryError::RegionTooLarge)?,
                    len: usize::try_from(vma.len())
                        .map_err(|_| GuestMemoryError::RegionTooLarge)?,
                    protection: vma.protection,
                })
            })
            .collect::<Result<Vec<_>, GuestMemoryError>>()?;

        for allocation_id in &allocation_ids {
            self.allocations.remove(allocation_id);
        }

        let allocation_length = guest_end
            .checked_sub(guest_start)
            .ok_or(GuestMemoryError::InvalidAddress)?;
        let len =
            usize::try_from(allocation_length).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let mut memory = match allocate_guest_host_memory_at(
            guest_start,
            len,
            MemoryProtection::ReadWrite,
            self.host_address_mode,
        ) {
            Ok(memory) => memory,
            Err(error) => {
                self.restore_saved_allocations(&saved)?;
                return Err(error);
            }
        };
        for allocation in &saved {
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
        let allocation = self
            .allocations
            .get(&allocation_id)
            .expect("replacement allocation was inserted");
        if let Err(error) = apply_allocation_protections(&allocation.memory, &replacement_ranges) {
            self.allocations.remove(&allocation_id);
            self.restore_saved_allocations(&saved)?;
            return Err(error);
        }
        for vma in self.vmas.values_mut() {
            if allocation_ids.contains(&vma.allocation_id) {
                vma.allocation_id = allocation_id;
                vma.allocation_offset = vma.start - guest_start;
            }
        }
        Ok((allocation_id, requested_start - guest_start))
    }

    fn restore_saved_allocations(
        &mut self,
        saved: &[SavedAllocation],
    ) -> Result<(), GuestMemoryError> {
        for allocation in saved {
            let mut memory = allocate_guest_host_memory_at(
                allocation.guest_start,
                allocation.bytes.len(),
                MemoryProtection::ReadWrite,
                self.host_address_mode,
            )?;
            memory.as_mut_slice().copy_from_slice(&allocation.bytes);
            apply_allocation_protections(&memory, &allocation.ranges)?;
            self.allocations.insert(
                allocation.allocation_id,
                GuestAllocation {
                    guest_start: allocation.guest_start,
                    memory: Arc::new(memory),
                },
            );
        }
        Ok(())
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

        let (allocation_id, allocation_offset) = self.ensure_host_allocation(start, length)?;
        let offset =
            usize::try_from(allocation_offset).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        let len = usize::try_from(length).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        self.zero_allocation_range(allocation_id, allocation_offset, len)?;
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
        let end = offset
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
                .protect(MemoryProtection::ReadWrite)
                .map_err(GuestMemoryError::Host)?;
        }
        {
            self.allocation_memory_mut(allocation_id)?.as_mut_slice()[offset..end].fill(0);
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
        let (allocation_id, allocation_offset) = self.ensure_host_allocation(start, length)?;
        self.ensure_allocation_unique(allocation_id)?;
        let offset =
            usize::try_from(allocation_offset).map_err(|_| GuestMemoryError::RegionTooLarge)?;
        self.allocation_memory_mut(allocation_id)?.as_mut_slice()[offset..offset + len]
            .copy_from_slice(bytes);
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
        let mut candidate = align_up(hint)?;
        if candidate < MIN_GUEST_ADDRESS {
            candidate = MIN_GUEST_ADDRESS;
        }

        for vma in self.vmas.values() {
            let end = checked_mapping_end(candidate, length, self.address_space_end)?;
            if end <= vma.start {
                return Ok(candidate);
            }
            if candidate < vma.end {
                candidate = align_up(vma.end)?;
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
                .expect("VMA references live allocation");
            let allocation_offset = usize::try_from(vma.allocation_offset + (cursor - vma.start))
                .map_err(|_| GuestMemoryError::RegionTooLarge)?;
            destination[copied..copied + chunk_len].copy_from_slice(
                &allocation.memory.as_slice()[allocation_offset..allocation_offset + chunk_len],
            );
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
                .as_mut_slice()[allocation_offset..allocation_offset + chunk_len]
                .copy_from_slice(&bytes[copied..copied + chunk_len]);
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

fn guest_slice_offset(vma: &GuestVma, address: u64) -> Result<usize, GuestMemoryError> {
    usize::try_from(vma.allocation_offset + (address - vma.start))
        .map_err(|_| GuestMemoryError::RegionTooLarge)
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
    #[cfg(windows)]
    const HOST_ALLOCATION_GRANULARITY: u64 = 0x1_0000;
    #[cfg(not(windows))]
    const HOST_ALLOCATION_GRANULARITY: u64 = GUEST_PAGE_SIZE;

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

#[cfg(test)]
mod tests;
