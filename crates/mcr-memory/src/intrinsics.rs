use super::ranges::{checked_raw_range, raw_ranges_overlap};
use super::{
    AccessKind, GuestLibcIntrinsic, GuestLibcIntrinsicError, GuestMemory, GuestMemoryError,
};

impl GuestMemory {
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
}
