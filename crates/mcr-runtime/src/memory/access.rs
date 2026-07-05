use super::{GuestMemory, GuestMemoryError};

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
