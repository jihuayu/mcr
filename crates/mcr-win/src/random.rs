use crate::error::{HostError, HostOperation, HostResult};

/// Fills `buf` with cryptographically secure host random bytes.
pub fn fill_random(buf: &mut [u8]) -> HostResult<()> {
    if buf.is_empty() {
        return Ok(());
    }

    fill_random_platform(buf)
}

#[cfg(not(windows))]
fn fill_random_platform(buf: &mut [u8]) -> HostResult<()> {
    use std::io::Read;

    let mut file = std::fs::File::open("/dev/urandom")
        .map_err(|error| HostError::from_io(HostOperation::FillRandom, error))?;
    file.read_exact(buf)
        .map_err(|error| HostError::from_io(HostOperation::FillRandom, error))
}

#[cfg(windows)]
fn fill_random_platform(buf: &mut [u8]) -> HostResult<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let remaining = buf.len() - offset;
        let chunk_len = remaining.min(u32::MAX as usize) as u32;
        // SAFETY: The slice chunk is valid for `chunk_len` bytes and BCrypt owns no borrowed state.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf[offset..].as_mut_ptr(),
                chunk_len,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(HostError::with_code(
                HostOperation::FillRandom,
                crate::HostErrorKind::Other,
                crate::HostErrorCode::Windows(status as u32),
            ));
        }
        offset += chunk_len as usize;
    }
    Ok(())
}

#[cfg(windows)]
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

#[cfg(windows)]
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut std::ffi::c_void,
        buffer: *mut u8,
        count: u32,
        flags: u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    #[test]
    fn fill_random_accepts_non_empty_buffer() {
        let mut bytes = [0; 32];

        super::fill_random(&mut bytes).unwrap();

        assert_eq!(bytes.len(), 32);
    }
}
