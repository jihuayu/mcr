use crate::{EI_CLASS, EI_DATA, ELF64_HEADER_SIZE, ELFCLASS64, ELFDATA2LSB, PT_LOAD};

pub const ELF64_PT_LOAD: u32 = PT_LOAD;
pub const ELF64_PROGRAM_HEADER_MIN_VIEW_SIZE: usize = 56;
pub const ELF64_PROGRAM_HEADER_MAX_VIEW_SIZE: usize = 4096;
pub const ELF64_PROGRAM_HEADER_MAX_VIEW_COUNT: usize = 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Elf64ProgramHeaderTableView {
    file_offset: u64,
    entry_size: usize,
    entry_count: usize,
}

impl Elf64ProgramHeaderTableView {
    #[must_use]
    pub const fn file_offset(self) -> u64 {
        self.file_offset
    }

    #[must_use]
    pub const fn entry_size(self) -> usize {
        self.entry_size
    }

    #[must_use]
    pub const fn entry_count(self) -> usize {
        self.entry_count
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Elf64ProgramHeaderView {
    kind: u32,
    offset: u64,
    file_size: u64,
    memory_size: u64,
}

impl Elf64ProgramHeaderView {
    #[must_use]
    pub const fn kind(self) -> u32 {
        self.kind
    }

    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn file_size(self) -> u64 {
        self.file_size
    }

    #[must_use]
    pub const fn memory_size(self) -> u64 {
        self.memory_size
    }

    #[must_use]
    pub const fn is_load(self) -> bool {
        self.kind == ELF64_PT_LOAD
    }
}

#[must_use]
pub fn elf64_program_header_table_view(header: &[u8]) -> Option<Elf64ProgramHeaderTableView> {
    if header.len() < ELF64_HEADER_SIZE as usize {
        return None;
    }
    if header.get(0..4) != Some(b"\x7fELF")
        || header[EI_CLASS] != ELFCLASS64
        || header[EI_DATA] != ELFDATA2LSB
    {
        return None;
    }

    let entry_size = usize::from(read_u16(&header[54..56]));
    let entry_count = usize::from(read_u16(&header[56..58]));
    if !(ELF64_PROGRAM_HEADER_MIN_VIEW_SIZE..=ELF64_PROGRAM_HEADER_MAX_VIEW_SIZE)
        .contains(&entry_size)
        || entry_count > ELF64_PROGRAM_HEADER_MAX_VIEW_COUNT
    {
        return None;
    }

    Some(Elf64ProgramHeaderTableView {
        file_offset: read_u64(&header[32..40]),
        entry_size,
        entry_count,
    })
}

#[must_use]
pub fn elf64_program_header_entry_view(entry: &[u8]) -> Option<Elf64ProgramHeaderView> {
    if entry.len() < ELF64_PROGRAM_HEADER_MIN_VIEW_SIZE {
        return None;
    }

    Some(Elf64ProgramHeaderView {
        kind: read_u32(&entry[0..4]),
        offset: read_u64(&entry[8..16]),
        file_size: read_u64(&entry[32..40]),
        memory_size: read_u64(&entry[40..48]),
    })
}

#[must_use]
pub fn elf64_program_header_views(bytes: &[u8]) -> Option<Vec<Elf64ProgramHeaderView>> {
    let table = elf64_program_header_table_view(bytes)?;
    let table_size = table.entry_size.checked_mul(table.entry_count)?;
    let start = usize::try_from(table.file_offset).ok()?;
    let end = start.checked_add(table_size)?;
    if end > bytes.len() {
        return None;
    }

    let mut headers = Vec::with_capacity(table.entry_count);
    for index in 0..table.entry_count {
        let entry_start = start + index * table.entry_size;
        let entry_end = entry_start + table.entry_size;
        headers.push(elf64_program_header_entry_view(
            &bytes[entry_start..entry_end],
        )?);
    }
    Some(headers)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("slice length checked by caller"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("slice length checked by caller"))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("slice length checked by caller"))
}
