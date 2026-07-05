use std::{fmt, ops::Range};

use crate::{
    EI_CLASS, EI_DATA, EI_VERSION, ELF64_HEADER_SIZE, ELF64_PROGRAM_HEADER_SIZE, ELFCLASS64,
    ELFDATA2LSB, EM_X86_64, EV_CURRENT_U8, EV_CURRENT_U32, ElfObjectType, Interpreter, LoadPlan,
    LoadSegment, MemoryMapping, PAGE_SIZE, PT_INTERP, PT_LOAD, PT_PHDR, ProgramHeaderTable,
    SegmentPermissions,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfValidationError {
    FileTooSmall {
        expected_at_least: usize,
        actual: usize,
    },
    InvalidMagic,
    UnsupportedClass {
        value: u8,
    },
    UnsupportedEndian {
        value: u8,
    },
    UnsupportedIdentVersion {
        value: u8,
    },
    UnsupportedFileVersion {
        value: u32,
    },
    UnsupportedObjectType {
        value: u16,
    },
    UnsupportedMachine {
        value: u16,
    },
    InvalidHeaderSize {
        expected: u16,
        actual: u16,
    },
    MissingProgramHeaders,
    InvalidProgramHeaderEntrySize {
        expected: u16,
        actual: u16,
    },
    ProgramHeaderTableOverflow,
    ProgramHeaderTableOutOfBounds {
        offset: u64,
        size: u64,
        file_size: usize,
    },
    SegmentFileSizeExceedsMemorySize {
        index: u16,
        file_size: u64,
        memory_size: u64,
    },
    SegmentFileRangeOverflow {
        index: u16,
        offset: u64,
        file_size: u64,
    },
    SegmentFileRangeOutOfBounds {
        index: u16,
        offset: u64,
        file_size: u64,
        file_len: usize,
    },
    SegmentAddressOverflow {
        index: u16,
        virtual_address: u64,
        memory_size: u64,
    },
    SegmentMappingOverflow {
        index: u16,
    },
    InvalidSegmentAlignment {
        index: u16,
        alignment: u64,
    },
    MisalignedSegment {
        index: u16,
        file_offset: u64,
        virtual_address: u64,
        alignment: u64,
    },
    UnsupportedSegmentFlags {
        index: u16,
        flags: u32,
    },
    MissingLoadSegments,
    OverlappingLoadSegments {
        first_index: u16,
        second_index: u16,
    },
    EntrypointNotExecutable {
        entrypoint: u64,
    },
    DuplicateInterpreter {
        first_index: u16,
        second_index: u16,
    },
    InterpreterRangeOverflow {
        index: u16,
        offset: u64,
        file_size: u64,
    },
    InterpreterOutOfBounds {
        index: u16,
        offset: u64,
        file_size: u64,
        file_len: usize,
    },
    UnterminatedInterpreter {
        index: u16,
    },
    EmptyInterpreter {
        index: u16,
    },
}

impl fmt::Display for ElfValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileTooSmall {
                expected_at_least,
                actual,
            } => write!(
                formatter,
                "ELF file is too small: expected at least {expected_at_least} bytes, got {actual}"
            ),
            Self::InvalidMagic => write!(formatter, "ELF magic bytes are invalid"),
            Self::UnsupportedClass { value } => {
                write!(formatter, "unsupported ELF class {value}; expected ELF64")
            }
            Self::UnsupportedEndian { value } => {
                write!(
                    formatter,
                    "unsupported ELF endian marker {value}; expected little-endian"
                )
            }
            Self::UnsupportedIdentVersion { value } => {
                write!(formatter, "unsupported ELF ident version {value}")
            }
            Self::UnsupportedFileVersion { value } => {
                write!(formatter, "unsupported ELF file version {value}")
            }
            Self::UnsupportedObjectType { value } => {
                write!(formatter, "unsupported ELF object type {value}")
            }
            Self::UnsupportedMachine { value } => {
                write!(
                    formatter,
                    "unsupported ELF machine {value}; expected x86-64"
                )
            }
            Self::InvalidHeaderSize { expected, actual } => write!(
                formatter,
                "invalid ELF header size {actual}; expected {expected}"
            ),
            Self::MissingProgramHeaders => write!(formatter, "ELF has no program headers"),
            Self::InvalidProgramHeaderEntrySize { expected, actual } => write!(
                formatter,
                "invalid ELF program-header entry size {actual}; expected {expected}"
            ),
            Self::ProgramHeaderTableOverflow => {
                write!(formatter, "ELF program-header table size overflows")
            }
            Self::ProgramHeaderTableOutOfBounds {
                offset,
                size,
                file_size,
            } => write!(
                formatter,
                "ELF program-header table [{offset:#x}, +{size:#x}) exceeds file size {file_size:#x}"
            ),
            Self::SegmentFileSizeExceedsMemorySize {
                index,
                file_size,
                memory_size,
            } => write!(
                formatter,
                "PT_LOAD #{index} file size {file_size:#x} exceeds memory size {memory_size:#x}"
            ),
            Self::SegmentFileRangeOverflow {
                index,
                offset,
                file_size,
            } => write!(
                formatter,
                "PT_LOAD #{index} file range overflows: offset {offset:#x}, size {file_size:#x}"
            ),
            Self::SegmentFileRangeOutOfBounds {
                index,
                offset,
                file_size,
                file_len,
            } => write!(
                formatter,
                "PT_LOAD #{index} file range [{offset:#x}, +{file_size:#x}) exceeds file size {file_len:#x}"
            ),
            Self::SegmentAddressOverflow {
                index,
                virtual_address,
                memory_size,
            } => write!(
                formatter,
                "PT_LOAD #{index} address range overflows: address {virtual_address:#x}, size {memory_size:#x}"
            ),
            Self::SegmentMappingOverflow { index } => {
                write!(formatter, "PT_LOAD #{index} page-aligned mapping overflows")
            }
            Self::InvalidSegmentAlignment { index, alignment } => write!(
                formatter,
                "PT_LOAD #{index} has invalid alignment {alignment:#x}"
            ),
            Self::MisalignedSegment {
                index,
                file_offset,
                virtual_address,
                alignment,
            } => write!(
                formatter,
                "PT_LOAD #{index} offset {file_offset:#x} and address {virtual_address:#x} are not congruent for alignment {alignment:#x}"
            ),
            Self::UnsupportedSegmentFlags { index, flags } => {
                write!(
                    formatter,
                    "PT_LOAD #{index} has unsupported flags {flags:#x}"
                )
            }
            Self::MissingLoadSegments => write!(formatter, "ELF has no PT_LOAD segments"),
            Self::OverlappingLoadSegments {
                first_index,
                second_index,
            } => write!(
                formatter,
                "PT_LOAD #{first_index} overlaps PT_LOAD #{second_index}"
            ),
            Self::EntrypointNotExecutable { entrypoint } => write!(
                formatter,
                "entrypoint {entrypoint:#x} is not inside an executable PT_LOAD segment"
            ),
            Self::DuplicateInterpreter {
                first_index,
                second_index,
            } => write!(
                formatter,
                "duplicate PT_INTERP headers at #{first_index} and #{second_index}"
            ),
            Self::InterpreterRangeOverflow {
                index,
                offset,
                file_size,
            } => write!(
                formatter,
                "PT_INTERP #{index} file range overflows: offset {offset:#x}, size {file_size:#x}"
            ),
            Self::InterpreterOutOfBounds {
                index,
                offset,
                file_size,
                file_len,
            } => write!(
                formatter,
                "PT_INTERP #{index} file range [{offset:#x}, +{file_size:#x}) exceeds file size {file_len:#x}"
            ),
            Self::UnterminatedInterpreter { index } => {
                write!(formatter, "PT_INTERP #{index} is not NUL-terminated")
            }
            Self::EmptyInterpreter { index } => {
                write!(
                    formatter,
                    "PT_INTERP #{index} has an empty interpreter path"
                )
            }
        }
    }
}

impl std::error::Error for ElfValidationError {}

#[must_use]
pub fn is_elf64(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes[0..4] == [0x7f, b'E', b'L', b'F'] && bytes[EI_CLASS] == ELFCLASS64
}

pub fn parse_load_plan(bytes: &[u8]) -> Result<LoadPlan, ElfValidationError> {
    validate_ident(bytes)?;

    let header = ElfHeader::parse(bytes)?;
    let object_type = ElfObjectType::from_raw(header.object_type)?;
    validate_program_header_table(&header, bytes.len())?;

    let raw_headers = parse_program_headers(bytes, &header)?;
    let mut segments = Vec::new();
    let mut interpreter = None;
    let mut program_header_virtual_address = None;

    for header in &raw_headers {
        match header.header_type {
            PT_LOAD => segments.push(load_segment_from_header(header, bytes.len())?),
            PT_INTERP => {
                if let Some(existing_index) = interpreter
                    .as_ref()
                    .map(|item: &ParsedInterpreter| item.index)
                {
                    return Err(ElfValidationError::DuplicateInterpreter {
                        first_index: existing_index,
                        second_index: header.index,
                    });
                }
                interpreter = Some(parse_interpreter(header, bytes)?);
            }
            PT_PHDR => {
                program_header_virtual_address = Some(header.virtual_address);
            }
            _ => {}
        }
    }

    if segments.is_empty() {
        return Err(ElfValidationError::MissingLoadSegments);
    }

    segments.sort_by_key(|segment| segment.virtual_address);
    validate_non_overlapping_segments(&segments)?;
    validate_entrypoint(header.entrypoint, &segments)?;

    Ok(LoadPlan {
        object_type,
        entrypoint: header.entrypoint,
        program_headers: ProgramHeaderTable {
            file_offset: header.program_header_offset,
            entry_size: header.program_header_entry_size,
            entry_count: header.program_header_count,
            virtual_address: program_header_virtual_address
                .or_else(|| infer_program_header_virtual_address(&segments, &header)),
        },
        interpreter: interpreter.map(|item| item.interpreter),
        segments,
    })
}

fn validate_ident(bytes: &[u8]) -> Result<(), ElfValidationError> {
    if bytes.len() < ELF64_HEADER_SIZE as usize {
        return Err(ElfValidationError::FileTooSmall {
            expected_at_least: ELF64_HEADER_SIZE as usize,
            actual: bytes.len(),
        });
    }

    if bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfValidationError::InvalidMagic);
    }

    if bytes[EI_CLASS] != ELFCLASS64 {
        return Err(ElfValidationError::UnsupportedClass {
            value: bytes[EI_CLASS],
        });
    }

    if bytes[EI_DATA] != ELFDATA2LSB {
        return Err(ElfValidationError::UnsupportedEndian {
            value: bytes[EI_DATA],
        });
    }

    if bytes[EI_VERSION] != EV_CURRENT_U8 {
        return Err(ElfValidationError::UnsupportedIdentVersion {
            value: bytes[EI_VERSION],
        });
    }

    Ok(())
}

fn validate_program_header_table(
    header: &ElfHeader,
    file_size: usize,
) -> Result<(), ElfValidationError> {
    if header.header_size != ELF64_HEADER_SIZE {
        return Err(ElfValidationError::InvalidHeaderSize {
            expected: ELF64_HEADER_SIZE,
            actual: header.header_size,
        });
    }

    if header.program_header_count == 0 {
        return Err(ElfValidationError::MissingProgramHeaders);
    }

    if header.program_header_entry_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(ElfValidationError::InvalidProgramHeaderEntrySize {
            expected: ELF64_PROGRAM_HEADER_SIZE,
            actual: header.program_header_entry_size,
        });
    }

    let table_size = u64::from(header.program_header_entry_size)
        .checked_mul(u64::from(header.program_header_count))
        .ok_or(ElfValidationError::ProgramHeaderTableOverflow)?;
    let table_end = header
        .program_header_offset
        .checked_add(table_size)
        .ok_or(ElfValidationError::ProgramHeaderTableOverflow)?;

    if table_end > file_size as u64 {
        return Err(ElfValidationError::ProgramHeaderTableOutOfBounds {
            offset: header.program_header_offset,
            size: table_size,
            file_size,
        });
    }

    Ok(())
}

fn parse_program_headers(
    bytes: &[u8],
    header: &ElfHeader,
) -> Result<Vec<RawProgramHeader>, ElfValidationError> {
    (0..header.program_header_count)
        .map(|index| {
            let offset = header.program_header_offset
                + u64::from(index) * u64::from(header.program_header_entry_size);
            RawProgramHeader::parse(index, bytes, offset as usize)
        })
        .collect()
}

fn load_segment_from_header(
    header: &RawProgramHeader,
    file_len: usize,
) -> Result<LoadSegment, ElfValidationError> {
    if header.file_size > header.memory_size {
        return Err(ElfValidationError::SegmentFileSizeExceedsMemorySize {
            index: header.index,
            file_size: header.file_size,
            memory_size: header.memory_size,
        });
    }

    let file_end = header.file_offset.checked_add(header.file_size).ok_or(
        ElfValidationError::SegmentFileRangeOverflow {
            index: header.index,
            offset: header.file_offset,
            file_size: header.file_size,
        },
    )?;

    if file_end > file_len as u64 {
        return Err(ElfValidationError::SegmentFileRangeOutOfBounds {
            index: header.index,
            offset: header.file_offset,
            file_size: header.file_size,
            file_len,
        });
    }

    header
        .virtual_address
        .checked_add(header.memory_size)
        .ok_or(ElfValidationError::SegmentAddressOverflow {
            index: header.index,
            virtual_address: header.virtual_address,
            memory_size: header.memory_size,
        })?;

    validate_segment_alignment(header)?;

    let permissions = SegmentPermissions::try_from(header.flags).map_err(|flags| {
        ElfValidationError::UnsupportedSegmentFlags {
            index: header.index,
            flags,
        }
    })?;
    let mapping = build_memory_mapping(header, permissions)?;

    Ok(LoadSegment {
        program_header_index: header.index,
        file_offset: header.file_offset,
        virtual_address: header.virtual_address,
        file_size: header.file_size,
        memory_size: header.memory_size,
        alignment: header.alignment,
        permissions,
        mapping,
    })
}

fn validate_segment_alignment(header: &RawProgramHeader) -> Result<(), ElfValidationError> {
    if header.alignment > 1 && !header.alignment.is_power_of_two() {
        return Err(ElfValidationError::InvalidSegmentAlignment {
            index: header.index,
            alignment: header.alignment,
        });
    }

    if header.alignment > 1
        && header.file_offset % header.alignment != header.virtual_address % header.alignment
    {
        return Err(ElfValidationError::MisalignedSegment {
            index: header.index,
            file_offset: header.file_offset,
            virtual_address: header.virtual_address,
            alignment: header.alignment,
        });
    }

    Ok(())
}

fn build_memory_mapping(
    header: &RawProgramHeader,
    permissions: SegmentPermissions,
) -> Result<MemoryMapping, ElfValidationError> {
    let start = align_down(header.virtual_address, PAGE_SIZE);
    let page_offset = header.virtual_address - start;
    let end = align_up(
        header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or(ElfValidationError::SegmentMappingOverflow {
                index: header.index,
            })?,
        PAGE_SIZE,
    )
    .ok_or(ElfValidationError::SegmentMappingOverflow {
        index: header.index,
    })?;
    let file_offset = header.file_offset.checked_sub(page_offset).ok_or(
        ElfValidationError::SegmentMappingOverflow {
            index: header.index,
        },
    )?;
    let file_size = header.file_size.checked_add(page_offset).ok_or(
        ElfValidationError::SegmentMappingOverflow {
            index: header.index,
        },
    )?;

    Ok(MemoryMapping {
        start,
        end,
        file_offset,
        file_size,
        permissions,
    })
}

fn validate_non_overlapping_segments(segments: &[LoadSegment]) -> Result<(), ElfValidationError> {
    for pair in segments.windows(2) {
        let first = &pair[0];
        let second = &pair[1];

        if first.memory_size == 0 || second.memory_size == 0 {
            continue;
        }

        if first.virtual_address + first.memory_size > second.virtual_address {
            return Err(ElfValidationError::OverlappingLoadSegments {
                first_index: first.program_header_index,
                second_index: second.program_header_index,
            });
        }
    }

    Ok(())
}

fn validate_entrypoint(
    entrypoint: u64,
    segments: &[LoadSegment],
) -> Result<(), ElfValidationError> {
    if segments.iter().any(|segment| {
        segment.permissions.execute() && segment.contains_virtual_address(entrypoint)
    }) {
        return Ok(());
    }

    Err(ElfValidationError::EntrypointNotExecutable { entrypoint })
}

fn parse_interpreter(
    header: &RawProgramHeader,
    bytes: &[u8],
) -> Result<ParsedInterpreter, ElfValidationError> {
    let range =
        checked_file_range(header.file_offset, header.file_size, bytes.len()).map_err(|error| {
            match error {
                FileRangeError::Overflow => ElfValidationError::InterpreterRangeOverflow {
                    index: header.index,
                    offset: header.file_offset,
                    file_size: header.file_size,
                },
                FileRangeError::OutOfBounds => ElfValidationError::InterpreterOutOfBounds {
                    index: header.index,
                    offset: header.file_offset,
                    file_size: header.file_size,
                    file_len: bytes.len(),
                },
            }
        })?;
    let bytes = &bytes[range];

    if bytes.last() != Some(&0) {
        return Err(ElfValidationError::UnterminatedInterpreter {
            index: header.index,
        });
    }

    let path = &bytes[..bytes.len() - 1];
    if path.is_empty() {
        return Err(ElfValidationError::EmptyInterpreter {
            index: header.index,
        });
    }

    Ok(ParsedInterpreter {
        index: header.index,
        interpreter: Interpreter {
            path: path.to_vec(),
        },
    })
}

fn infer_program_header_virtual_address(
    segments: &[LoadSegment],
    header: &ElfHeader,
) -> Option<u64> {
    segments.iter().find_map(|segment| {
        let phoff_in_segment = header
            .program_header_offset
            .checked_sub(segment.file_offset())?;
        let phend_in_segment = phoff_in_segment.checked_add(
            u64::from(header.program_header_entry_size) * u64::from(header.program_header_count),
        )?;

        if phend_in_segment <= segment.file_size() {
            Some(segment.virtual_address() + phoff_in_segment)
        } else {
            None
        }
    })
}

#[derive(Debug)]
struct ParsedInterpreter {
    index: u16,
    interpreter: Interpreter,
}

#[derive(Debug)]
struct ElfHeader {
    object_type: u16,
    machine: u16,
    version: u32,
    entrypoint: u64,
    program_header_offset: u64,
    header_size: u16,
    program_header_entry_size: u16,
    program_header_count: u16,
}

impl ElfHeader {
    fn parse(bytes: &[u8]) -> Result<Self, ElfValidationError> {
        let header = Self {
            object_type: read_u16(bytes, 16),
            machine: read_u16(bytes, 18),
            version: read_u32(bytes, 20),
            entrypoint: read_u64(bytes, 24),
            program_header_offset: read_u64(bytes, 32),
            header_size: read_u16(bytes, 52),
            program_header_entry_size: read_u16(bytes, 54),
            program_header_count: read_u16(bytes, 56),
        };

        if header.version != EV_CURRENT_U32 {
            return Err(ElfValidationError::UnsupportedFileVersion {
                value: header.version,
            });
        }

        if header.machine != EM_X86_64 {
            return Err(ElfValidationError::UnsupportedMachine {
                value: header.machine,
            });
        }

        Ok(header)
    }
}

#[derive(Debug)]
struct RawProgramHeader {
    index: u16,
    header_type: u32,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

impl RawProgramHeader {
    fn parse(index: u16, bytes: &[u8], offset: usize) -> Result<Self, ElfValidationError> {
        let range = checked_file_range(
            offset as u64,
            u64::from(ELF64_PROGRAM_HEADER_SIZE),
            bytes.len(),
        )
        .map_err(|error| match error {
            FileRangeError::Overflow => ElfValidationError::ProgramHeaderTableOverflow,
            FileRangeError::OutOfBounds => ElfValidationError::ProgramHeaderTableOutOfBounds {
                offset: offset as u64,
                size: u64::from(ELF64_PROGRAM_HEADER_SIZE),
                file_size: bytes.len(),
            },
        })?;
        let bytes = &bytes[range];

        Ok(Self {
            index,
            header_type: read_u32(bytes, 0),
            flags: read_u32(bytes, 4),
            file_offset: read_u64(bytes, 8),
            virtual_address: read_u64(bytes, 16),
            file_size: read_u64(bytes, 32),
            memory_size: read_u64(bytes, 40),
            alignment: read_u64(bytes, 48),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileRangeError {
    Overflow,
    OutOfBounds,
}

fn checked_file_range(
    offset: u64,
    size: u64,
    file_len: usize,
) -> Result<Range<usize>, FileRangeError> {
    let end = offset.checked_add(size).ok_or(FileRangeError::Overflow)?;

    if end > file_len as u64 {
        return Err(FileRangeError::OutOfBounds);
    }

    Ok(offset as usize..end as usize)
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
