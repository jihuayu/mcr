pub trait GuestMemoryAccess {
    fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), GuestMemoryAccessError>;
    fn write_bytes(&mut self, addr: u64, buffer: &[u8]) -> Result<(), GuestMemoryAccessError>;

    fn read_c_string(&self, addr: u64, max_len: usize) -> Result<String, GuestMemoryAccessError> {
        let mut bytes = Vec::new();
        for offset in 0..max_len {
            let mut byte = [0];
            self.read_bytes(
                addr.checked_add(offset as u64)
                    .ok_or(GuestMemoryAccessError::Fault)?,
                &mut byte,
            )?;
            if byte[0] == 0 {
                return String::from_utf8(bytes).map_err(|_| GuestMemoryAccessError::Fault);
            }
            bytes.push(byte[0]);
        }
        Err(GuestMemoryAccessError::Fault)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestMemoryAccessError {
    Fault,
}
