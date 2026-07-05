use super::{GUEST_PAGE_SIZE, GuestMemoryError, GuestVma, MIN_GUEST_ADDRESS};

pub(super) fn checked_page_range(start: u64, length: u64) -> Result<u64, GuestMemoryError> {
    if !is_page_aligned(start) || length == 0 {
        return Err(GuestMemoryError::InvalidAddress);
    }
    let length = page_round_length(length)?;
    checked_raw_range(start, length)
}

pub(super) fn checked_raw_range(start: u64, length: u64) -> Result<u64, GuestMemoryError> {
    start
        .checked_add(length)
        .filter(|end| *end >= start)
        .ok_or(GuestMemoryError::InvalidLength)
}

pub(super) fn raw_ranges_overlap(lhs: u64, rhs: u64, len: usize) -> Result<bool, GuestMemoryError> {
    if len == 0 {
        return Ok(false);
    }
    let length = u64::try_from(len).map_err(|_| GuestMemoryError::RegionTooLarge)?;
    let lhs_end = checked_raw_range(lhs, length)?;
    let rhs_end = checked_raw_range(rhs, length)?;
    Ok(lhs < rhs_end && rhs < lhs_end)
}

pub(super) fn checked_mapping_end(
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

pub(super) fn page_round_length(length: u64) -> Result<u64, GuestMemoryError> {
    if length == 0 {
        return Err(GuestMemoryError::InvalidLength);
    }
    align_up(length)
}

pub(super) const fn is_page_aligned(value: u64) -> bool {
    value % GUEST_PAGE_SIZE == 0
}

pub(super) const fn is_supported_madvise(advice: u32) -> bool {
    matches!(
        advice,
        0..=4 | 8..=25 | 100 | 101
    )
}

pub(super) const fn align_up(value: u64) -> Result<u64, GuestMemoryError> {
    let mask = GUEST_PAGE_SIZE - 1;
    match value.checked_add(mask) {
        Some(value) => Ok(value & !mask),
        None => Err(GuestMemoryError::InvalidLength),
    }
}

pub(super) const fn align_down_to(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

pub(super) const fn align_up_to(value: u64, alignment: u64) -> Result<u64, GuestMemoryError> {
    let mask = alignment - 1;
    match value.checked_add(mask) {
        Some(value) => Ok(value & !mask),
        None => Err(GuestMemoryError::InvalidLength),
    }
}

pub(super) fn can_merge(left: &GuestVma, right: &GuestVma) -> bool {
    left.end == right.start
        && left.protection == right.protection
        && left.kind == right.kind
        && left.allocation_id == right.allocation_id
        && left.allocation_offset + left.len() == right.allocation_offset
}
