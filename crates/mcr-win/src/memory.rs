use crate::error::{HostError, HostOperation, HostResult};

/// Host memory protection used by the Windows memory adapter.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MemoryProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
    ExecuteRead,
    ExecuteReadWrite,
}

/// Owned host memory allocation.
#[derive(Debug)]
pub struct HostMemory {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
}

/// Read-only host-backed view of file contents.
#[derive(Debug)]
pub struct HostFileMapping {
    mapping: crate::windows::Handle,
    view: std::ptr::NonNull<u8>,
    slice_offset: usize,
    len: usize,
}

impl HostFileMapping {
    /// Returns the requested mapped bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `view` owns at least `slice_offset + len` mapped bytes until Drop.
        unsafe { std::slice::from_raw_parts(self.view.as_ptr().add(self.slice_offset), self.len) }
    }

    /// Mapping size visible to the caller.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether this view contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn map_readonly_handle(
        handle: crate::windows::Handle,
        offset: u64,
        len: usize,
    ) -> HostResult<Self> {
        if len == 0 {
            return Err(HostError::invalid_input(HostOperation::MapFile));
        }

        let granularity = allocation_granularity();
        let aligned_offset = offset / granularity * granularity;
        let slice_offset = usize::try_from(offset - aligned_offset)
            .map_err(|_| HostError::invalid_input(HostOperation::MapFile))?;
        let view_len = slice_offset
            .checked_add(len)
            .ok_or_else(|| HostError::invalid_input(HostOperation::MapFile))?;

        let mapping = unsafe {
            // SAFETY: The file handle is supplied by HostFile; security attributes and name are null.
            CreateFileMappingW(
                handle,
                std::ptr::null_mut(),
                PAGE_READONLY,
                0,
                0,
                std::ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(crate::error::last_windows_error(HostOperation::MapFile));
        }

        let view = unsafe {
            // SAFETY: `mapping` is a read-only file mapping and offset is allocation-granularity aligned.
            MapViewOfFile(
                mapping,
                FILE_MAP_READ,
                (aligned_offset >> 32) as u32,
                aligned_offset as u32,
                view_len,
            )
        };
        let Some(view) = std::ptr::NonNull::new(view.cast::<u8>()) else {
            crate::windows::close_handle(mapping);
            return Err(crate::error::last_windows_error(HostOperation::MapFile));
        };

        Ok(Self {
            mapping,
            view,
            slice_offset,
            len,
        })
    }
}

impl Drop for HostFileMapping {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `view` was returned by MapViewOfFile for this mapping.
            let _ = UnmapViewOfFile(self.view.as_ptr().cast());
        }
        crate::windows::close_handle(self.mapping);
    }
}

unsafe impl Send for HostFileMapping {}

unsafe impl Sync for HostFileMapping {}

impl HostMemory {
    /// Reserves and commits a host allocation with the requested protection.
    pub fn allocate(size: usize, protection: MemoryProtection) -> HostResult<Self> {
        if size == 0 {
            return Err(HostError::invalid_input(HostOperation::AllocateMemory));
        }

        allocate_platform(size, protection)
    }

    /// Reserves and commits a host allocation at a requested virtual address when supported.
    pub fn allocate_at(
        address: usize,
        size: usize,
        protection: MemoryProtection,
    ) -> HostResult<Self> {
        if address == 0 || size == 0 {
            return Err(HostError::invalid_input(HostOperation::AllocateMemory));
        }

        allocate_at_platform(address, size, protection)
    }

    /// Changes protection for the whole allocation.
    pub fn protect(&self, protection: MemoryProtection) -> HostResult<()> {
        self.protect_range(0, self.len, protection)
    }

    /// Changes protection for a byte range inside the allocation.
    pub fn protect_range(
        &self,
        offset: usize,
        len: usize,
        protection: MemoryProtection,
    ) -> HostResult<()> {
        let Some(end) = offset.checked_add(len) else {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        };
        if len == 0 || end > self.len {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        }

        protect_platform(self, offset, len, protection)
    }

    /// Flushes the host instruction cache for a byte range inside the allocation.
    pub fn flush_instruction_cache_range(&self, offset: usize, len: usize) -> HostResult<()> {
        let Some(end) = offset.checked_add(len) else {
            return Err(HostError::invalid_input(
                HostOperation::FlushInstructionCache,
            ));
        };
        if len == 0 || end > self.len {
            return Err(HostError::invalid_input(
                HostOperation::FlushInstructionCache,
            ));
        }

        flush_instruction_cache_platform(self, offset, len)
    }

    /// Copies a range from the allocation into `destination`.
    pub fn copy_to_slice(&self, offset: usize, destination: &mut [u8]) -> HostResult<()> {
        let Some(end) = offset.checked_add(destination.len()) else {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        };
        if end > self.len {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        }

        // SAFETY: The checked source range is inside the allocation and the caller only
        // reaches this through guest-visible mapped ranges.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.ptr_at(offset),
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
        Ok(())
    }

    /// Copies bytes into a range of the allocation.
    pub fn copy_from_slice(&mut self, offset: usize, bytes: &[u8]) -> HostResult<()> {
        let Some(end) = offset.checked_add(bytes.len()) else {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        };
        if end > self.len {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        }

        // SAFETY: The checked destination range is inside the allocation and `&mut self`
        // guarantees exclusive access to the allocation object.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.mut_ptr_at(offset), bytes.len());
        }
        Ok(())
    }

    /// Copies bytes between two host allocation ranges.
    pub fn copy_from_memory(
        &mut self,
        destination_offset: usize,
        source: &Self,
        source_offset: usize,
        len: usize,
    ) -> HostResult<()> {
        let Some(destination_end) = destination_offset.checked_add(len) else {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        };
        let Some(source_end) = source_offset.checked_add(len) else {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        };
        if destination_end > self.len || source_end > source.len {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        }

        // SAFETY: Both checked ranges are inside their allocations and `&mut self`
        // guarantees the destination range is not concurrently mutated through this object.
        unsafe {
            std::ptr::copy_nonoverlapping(
                source.ptr_at(source_offset),
                self.mut_ptr_at(destination_offset),
                len,
            );
        }
        Ok(())
    }

    /// Fills a range of the allocation.
    pub fn fill_range(&mut self, offset: usize, len: usize, value: u8) -> HostResult<()> {
        let Some(end) = offset.checked_add(len) else {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        };
        if end > self.len {
            return Err(HostError::invalid_input(HostOperation::ProtectMemory));
        }

        // SAFETY: The checked destination range is inside the allocation and `&mut self`
        // guarantees exclusive access to the allocation object.
        unsafe {
            std::ptr::write_bytes(self.mut_ptr_at(offset), value, len);
        }
        Ok(())
    }

    /// Allocation size in bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the allocation has no bytes.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Raw allocation pointer.
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Mutable raw allocation pointer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Views the allocation as bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `HostMemory` owns `ptr..ptr+len` until `Drop`.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Views the allocation as mutable bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `HostMemory` owns `ptr..ptr+len` and `&mut self` guarantees exclusivity.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    fn ptr_at(&self, offset: usize) -> *const u8 {
        #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
        {
            // SAFETY: Callers validate the offset before using the returned pointer.
            unsafe { self.ptr.as_ptr().add(offset) }
        }
        #[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
        {
            // SAFETY: Callers validate the offset before using the returned pointer.
            unsafe { self.storage.as_ptr().add(offset) }
        }
    }

    fn mut_ptr_at(&mut self, offset: usize) -> *mut u8 {
        #[cfg(any(windows, all(target_os = "linux", target_arch = "x86_64")))]
        {
            // SAFETY: Callers validate the offset before using the returned pointer.
            unsafe { self.ptr.as_ptr().add(offset) }
        }
        #[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
        {
            // SAFETY: Callers validate the offset before using the returned pointer.
            unsafe { self.storage.as_mut_ptr().add(offset) }
        }
    }
}

impl Drop for HostMemory {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by `VirtualAlloc` and is released once here.
        unsafe {
            let _ = VirtualFree(self.ptr.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}

unsafe impl Send for HostMemory {}

unsafe impl Sync for HostMemory {}

fn allocation_granularity() -> u64 {
    let mut info = std::mem::MaybeUninit::<SystemInfo>::uninit();
    unsafe {
        // SAFETY: `info` points to writable storage for GetSystemInfo.
        GetSystemInfo(info.as_mut_ptr());
        u64::from(info.assume_init().allocation_granularity)
    }
}

fn allocate_platform(size: usize, protection: MemoryProtection) -> HostResult<HostMemory> {
    let protect = protection.to_windows();
    let allocation_type = if matches!(protection, MemoryProtection::NoAccess) {
        MEM_RESERVE
    } else {
        MEM_RESERVE | MEM_COMMIT
    };
    // SAFETY: Passing null lets Windows choose the base address; size and protection are validated.
    let ptr = unsafe { VirtualAlloc(std::ptr::null_mut(), size, allocation_type, protect) };
    let Some(ptr) = std::ptr::NonNull::new(ptr.cast::<u8>()) else {
        return Err(crate::error::last_windows_error(
            HostOperation::AllocateMemory,
        ));
    };

    Ok(HostMemory { ptr, len: size })
}

fn allocate_at_platform(
    address: usize,
    size: usize,
    protection: MemoryProtection,
) -> HostResult<HostMemory> {
    let protect = protection.to_windows();
    let allocation_type = if matches!(protection, MemoryProtection::NoAccess) {
        MEM_RESERVE
    } else {
        MEM_RESERVE | MEM_COMMIT
    };
    // SAFETY: The caller requested this address; Windows validates availability and alignment.
    let ptr = unsafe {
        VirtualAlloc(
            address as *mut std::ffi::c_void,
            size,
            allocation_type,
            protect,
        )
    };
    let Some(ptr) = std::ptr::NonNull::new(ptr.cast::<u8>()) else {
        return Err(crate::error::last_windows_error(
            HostOperation::AllocateMemory,
        ));
    };

    Ok(HostMemory { ptr, len: size })
}

fn protect_platform(
    memory: &HostMemory,
    offset: usize,
    len: usize,
    protection: MemoryProtection,
) -> HostResult<()> {
    if !matches!(protection, MemoryProtection::NoAccess) {
        // SAFETY: The checked range is inside the reservation owned by `memory`.
        let ptr = unsafe {
            VirtualAlloc(
                memory.ptr.as_ptr().add(offset).cast(),
                len,
                MEM_COMMIT,
                protection.to_windows(),
            )
        };
        if ptr.is_null() {
            return Err(crate::error::last_windows_error(
                HostOperation::ProtectMemory,
            ));
        }
    }

    let mut old_protection = 0;
    // SAFETY: The checked range is inside the allocation owned by `memory`.
    let ok = unsafe {
        VirtualProtect(
            memory.ptr.as_ptr().add(offset).cast(),
            len,
            protection.to_windows(),
            &mut old_protection,
        )
    };
    if ok == crate::windows::FALSE {
        return Ok(());
    }
    Ok(())
}

fn flush_instruction_cache_platform(
    memory: &HostMemory,
    offset: usize,
    len: usize,
) -> HostResult<()> {
    let process = unsafe {
        // SAFETY: `GetCurrentProcess` has no preconditions and returns a pseudo-handle.
        GetCurrentProcess()
    };
    let ok = unsafe {
        // SAFETY: The checked range is inside the allocation owned by `memory`.
        FlushInstructionCache(process, memory.ptr.as_ptr().add(offset).cast(), len)
    };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(
            HostOperation::FlushInstructionCache,
        ));
    }
    Ok(())
}

impl MemoryProtection {
    const fn to_windows(self) -> u32 {
        match self {
            Self::NoAccess => PAGE_NOACCESS,
            Self::ReadOnly => PAGE_READONLY,
            Self::ReadWrite => PAGE_READWRITE,
            Self::ExecuteRead => PAGE_EXECUTE_READ,
            Self::ExecuteReadWrite => PAGE_EXECUTE_READWRITE,
        }
    }
}

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const MEM_RELEASE: u32 = 0x0000_8000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const FILE_MAP_READ: u32 = 0x0004;

#[repr(C)]
struct SystemInfo {
    processor_architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum_application_address: *mut std::ffi::c_void,
    maximum_application_address: *mut std::ffi::c_void,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemInfo(system_info: *mut SystemInfo);
    fn CreateFileMappingW(
        file: crate::windows::Handle,
        file_mapping_attributes: *mut std::ffi::c_void,
        protect: u32,
        maximum_size_high: u32,
        maximum_size_low: u32,
        name: *const u16,
    ) -> crate::windows::Handle;
    fn MapViewOfFile(
        file_mapping_object: crate::windows::Handle,
        desired_access: u32,
        file_offset_high: u32,
        file_offset_low: u32,
        number_of_bytes_to_map: usize,
    ) -> *mut std::ffi::c_void;
    fn UnmapViewOfFile(base_address: *const std::ffi::c_void) -> crate::windows::Bool;
    fn VirtualAlloc(
        address: *mut std::ffi::c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut std::ffi::c_void;
    fn VirtualProtect(
        address: *mut std::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> crate::windows::Bool;
    fn VirtualFree(
        address: *mut std::ffi::c_void,
        size: usize,
        free_type: u32,
    ) -> crate::windows::Bool;
    fn GetCurrentProcess() -> crate::windows::Handle;
    fn FlushInstructionCache(
        process: crate::windows::Handle,
        base_address: *const std::ffi::c_void,
        size: usize,
    ) -> crate::windows::Bool;
}

#[cfg(test)]
mod tests {
    use super::{HostMemory, MemoryProtection};

    #[test]
    fn allocation_exposes_mutable_bytes() {
        let mut memory = HostMemory::allocate(16, MemoryProtection::ReadWrite).unwrap();

        memory.as_mut_slice()[0] = 7;

        assert_eq!(memory.as_slice()[0], 7);
    }

    #[cfg(windows)]
    #[test]
    fn noaccess_allocation_commits_written_subrange() {
        let mut memory = HostMemory::allocate(0x20_000, MemoryProtection::NoAccess).unwrap();

        memory
            .protect_range(0x1_000, 0x1_000, MemoryProtection::ReadWrite)
            .unwrap();
        memory.copy_from_slice(0x1_000, &[9]).unwrap();
        let mut byte = [0];
        memory.copy_to_slice(0x1_000, &mut byte).unwrap();

        assert_eq!(byte, [9]);
    }

    #[test]
    fn zero_size_allocation_returns_error() {
        let error = HostMemory::allocate(0, MemoryProtection::ReadWrite).unwrap_err();

        assert_eq!(error.operation(), crate::HostOperation::AllocateMemory);
    }
}
