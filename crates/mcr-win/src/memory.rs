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
    #[cfg(windows)]
    ptr: std::ptr::NonNull<u8>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    ptr: std::ptr::NonNull<u8>,
    #[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
    storage: Box<[u8]>,
    len: usize,
}

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
        #[cfg(windows)]
        {
            self.ptr.as_ptr()
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            self.ptr.as_ptr()
        }
        #[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
        {
            self.storage.as_ptr()
        }
    }

    /// Mutable raw allocation pointer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        #[cfg(windows)]
        {
            self.ptr.as_ptr()
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            self.ptr.as_ptr()
        }
        #[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
        {
            self.storage.as_mut_ptr()
        }
    }

    /// Views the allocation as bytes.
    pub fn as_slice(&self) -> &[u8] {
        #[cfg(windows)]
        {
            // SAFETY: `HostMemory` owns `ptr..ptr+len` until `Drop`.
            unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            // SAFETY: `HostMemory` owns `ptr..ptr+len` until `Drop`.
            unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }
        #[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
        {
            &self.storage
        }
    }

    /// Views the allocation as mutable bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        #[cfg(windows)]
        {
            // SAFETY: `HostMemory` owns `ptr..ptr+len` and `&mut self` guarantees exclusivity.
            unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            // SAFETY: `HostMemory` owns `ptr..ptr+len` and `&mut self` guarantees exclusivity.
            unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
        }
        #[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
        {
            &mut self.storage
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for HostMemory {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by `mmap` and is released once here.
        unsafe {
            let _ = libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

#[cfg(windows)]
impl Drop for HostMemory {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by `VirtualAlloc` and is released once here.
        unsafe {
            let _ = VirtualFree(self.ptr.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}

#[cfg(windows)]
unsafe impl Send for HostMemory {}

#[cfg(windows)]
unsafe impl Sync for HostMemory {}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe impl Send for HostMemory {}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe impl Sync for HostMemory {}

#[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
fn allocate_platform(size: usize, _protection: MemoryProtection) -> HostResult<HostMemory> {
    Ok(HostMemory {
        storage: vec![0; size].into_boxed_slice(),
        len: size,
    })
}

#[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
fn allocate_at_platform(
    _address: usize,
    size: usize,
    protection: MemoryProtection,
) -> HostResult<HostMemory> {
    allocate_platform(size, protection)
}

#[cfg(not(any(windows, all(target_os = "linux", target_arch = "x86_64"))))]
fn protect_platform(
    _memory: &HostMemory,
    _offset: usize,
    _len: usize,
    _protection: MemoryProtection,
) -> HostResult<()> {
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn allocate_platform(size: usize, protection: MemoryProtection) -> HostResult<HostMemory> {
    mmap_allocate(
        std::ptr::null_mut(),
        size,
        protection,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn allocate_at_platform(
    address: usize,
    size: usize,
    protection: MemoryProtection,
) -> HostResult<HostMemory> {
    mmap_allocate(
        address as *mut std::ffi::c_void,
        size,
        protection,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn mmap_allocate(
    address: *mut std::ffi::c_void,
    size: usize,
    protection: MemoryProtection,
    flags: i32,
) -> HostResult<HostMemory> {
    // SAFETY: The arguments are validated by callers; `mmap` returns an owned mapping on success.
    let ptr = unsafe { libc::mmap(address, size, protection.to_unix(), flags, -1, 0) };
    if ptr == libc::MAP_FAILED {
        return Err(crate::error::last_os_error(HostOperation::AllocateMemory));
    }
    let Some(ptr) = std::ptr::NonNull::new(ptr.cast::<u8>()) else {
        return Err(HostError::invalid_input(HostOperation::AllocateMemory));
    };
    Ok(HostMemory { ptr, len: size })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn protect_platform(
    memory: &HostMemory,
    offset: usize,
    len: usize,
    protection: MemoryProtection,
) -> HostResult<()> {
    // SAFETY: The checked range is inside the allocation owned by `memory`.
    let ok = unsafe {
        libc::mprotect(
            memory.ptr.as_ptr().wrapping_add(offset).cast(),
            len,
            protection.to_unix(),
        )
    };
    if ok != 0 {
        return Err(crate::error::last_os_error(HostOperation::ProtectMemory));
    }
    Ok(())
}

#[cfg(windows)]
fn allocate_platform(size: usize, protection: MemoryProtection) -> HostResult<HostMemory> {
    let protect = protection.to_windows();
    // SAFETY: Passing null lets Windows choose the base address; size and protection are validated.
    let ptr = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            size,
            MEM_RESERVE | MEM_COMMIT,
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

#[cfg(windows)]
fn allocate_at_platform(
    address: usize,
    size: usize,
    protection: MemoryProtection,
) -> HostResult<HostMemory> {
    let protect = protection.to_windows();
    // SAFETY: The caller requested this address; Windows validates availability and alignment.
    let ptr = unsafe {
        VirtualAlloc(
            address as *mut std::ffi::c_void,
            size,
            MEM_RESERVE | MEM_COMMIT,
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

#[cfg(windows)]
fn protect_platform(
    memory: &HostMemory,
    offset: usize,
    len: usize,
    protection: MemoryProtection,
) -> HostResult<()> {
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
        return Err(crate::error::last_windows_error(
            HostOperation::ProtectMemory,
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl MemoryProtection {
    const fn to_unix(self) -> i32 {
        match self {
            Self::NoAccess => libc::PROT_NONE,
            Self::ReadOnly => libc::PROT_READ,
            Self::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
            Self::ExecuteRead => libc::PROT_READ | libc::PROT_EXEC,
            Self::ExecuteReadWrite => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        }
    }
}

#[cfg(windows)]
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

#[cfg(windows)]
const MEM_COMMIT: u32 = 0x0000_1000;
#[cfg(windows)]
const MEM_RESERVE: u32 = 0x0000_2000;
#[cfg(windows)]
const MEM_RELEASE: u32 = 0x0000_8000;
#[cfg(windows)]
const PAGE_NOACCESS: u32 = 0x01;
#[cfg(windows)]
const PAGE_READONLY: u32 = 0x02;
#[cfg(windows)]
const PAGE_READWRITE: u32 = 0x04;
#[cfg(windows)]
const PAGE_EXECUTE_READ: u32 = 0x20;
#[cfg(windows)]
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
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

    #[test]
    fn zero_size_allocation_returns_error() {
        let error = HostMemory::allocate(0, MemoryProtection::ReadWrite).unwrap_err();

        assert_eq!(error.operation(), crate::HostOperation::AllocateMemory);
    }
}
