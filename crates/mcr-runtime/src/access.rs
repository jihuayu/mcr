use super::{GuestMemory, GuestMemoryAccess, GuestMemoryAccessError};

pub trait RuntimeMemoryAccess: GuestMemoryAccess {
    fn borrowed_bytes(
        &self,
        _addr: u64,
        _len: usize,
    ) -> Result<Option<&[u8]>, GuestMemoryAccessError> {
        Ok(None)
    }

    fn borrowed_bytes_mut(
        &mut self,
        _addr: u64,
        _len: usize,
    ) -> Result<Option<&mut [u8]>, GuestMemoryAccessError> {
        Ok(None)
    }
}

impl RuntimeMemoryAccess for GuestMemory {
    fn borrowed_bytes(
        &self,
        addr: u64,
        len: usize,
    ) -> Result<Option<&[u8]>, GuestMemoryAccessError> {
        self.slice(addr, len)
            .map_err(|_| GuestMemoryAccessError::Fault)
    }

    fn borrowed_bytes_mut(
        &mut self,
        addr: u64,
        len: usize,
    ) -> Result<Option<&mut [u8]>, GuestMemoryAccessError> {
        self.slice_mut(addr, len)
            .map_err(|_| GuestMemoryAccessError::Fault)
    }
}
