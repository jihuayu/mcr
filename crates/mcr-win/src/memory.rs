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
    #[cfg(not(windows))]
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
        #[cfg(not(windows))]
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
        #[cfg(not(windows))]
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
        #[cfg(not(windows))]
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
        #[cfg(not(windows))]
        {
            &mut self.storage
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

#[cfg(not(windows))]
fn allocate_platform(size: usize, _protection: MemoryProtection) -> HostResult<HostMemory> {
    Ok(HostMemory {
        storage: vec![0; size].into_boxed_slice(),
        len: size,
    })
}

#[cfg(not(windows))]
fn protect_platform(
    _memory: &HostMemory,
    _offset: usize,
    _len: usize,
    _protection: MemoryProtection,
) -> HostResult<()> {
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
