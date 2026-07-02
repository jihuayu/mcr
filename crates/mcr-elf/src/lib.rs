use std::fmt;
use std::ops::Range;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const ELF64_HEADER_SIZE: u16 = 64;
pub const ELF64_PROGRAM_HEADER_SIZE: u16 = 56;
pub const PAGE_SIZE: u64 = 4096;

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT_U8: u8 = 1;
const EV_CURRENT_U32: u32 = 1;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const PF_SUPPORTED: u32 = PF_X | PF_W | PF_R;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfObjectType {
    Executable,
    SharedObject,
}

impl ElfObjectType {
    fn from_raw(raw: u16) -> Result<Self, ElfValidationError> {
        match raw {
            ET_EXEC => Ok(Self::Executable),
            ET_DYN => Ok(Self::SharedObject),
            value => Err(ElfValidationError::UnsupportedObjectType { value }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadPlan {
    object_type: ElfObjectType,
    entrypoint: u64,
    program_headers: ProgramHeaderTable,
    interpreter: Option<Interpreter>,
    segments: Vec<LoadSegment>,
}

impl LoadPlan {
    #[must_use]
    pub fn object_type(&self) -> ElfObjectType {
        self.object_type
    }

    #[must_use]
    pub fn entrypoint(&self) -> u64 {
        self.entrypoint
    }

    #[must_use]
    pub fn program_headers(&self) -> &ProgramHeaderTable {
        &self.program_headers
    }

    #[must_use]
    pub fn interpreter(&self) -> Option<&Interpreter> {
        self.interpreter.as_ref()
    }

    #[must_use]
    pub fn segments(&self) -> &[LoadSegment] {
        &self.segments
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramHeaderTable {
    file_offset: u64,
    entry_size: u16,
    entry_count: u16,
    virtual_address: Option<u64>,
}

impl ProgramHeaderTable {
    #[must_use]
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }

    #[must_use]
    pub fn entry_size(&self) -> u16 {
        self.entry_size
    }

    #[must_use]
    pub fn entry_count(&self) -> u16 {
        self.entry_count
    }

    #[must_use]
    pub fn virtual_address(&self) -> Option<u64> {
        self.virtual_address
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interpreter {
    path: Vec<u8>,
}

impl Interpreter {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.path
    }

    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.path).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadSegment {
    program_header_index: u16,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
    permissions: SegmentPermissions,
    mapping: MemoryMapping,
}

impl LoadSegment {
    #[must_use]
    pub fn program_header_index(&self) -> u16 {
        self.program_header_index
    }

    #[must_use]
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }

    #[must_use]
    pub fn virtual_address(&self) -> u64 {
        self.virtual_address
    }

    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    #[must_use]
    pub fn memory_size(&self) -> u64 {
        self.memory_size
    }

    #[must_use]
    pub fn alignment(&self) -> u64 {
        self.alignment
    }

    #[must_use]
    pub fn permissions(&self) -> SegmentPermissions {
        self.permissions
    }

    #[must_use]
    pub fn mapping(&self) -> &MemoryMapping {
        &self.mapping
    }

    #[must_use]
    pub fn memory_range(&self) -> Range<u64> {
        self.virtual_address..self.virtual_address + self.memory_size
    }

    #[must_use]
    pub fn contains_virtual_address(&self, address: u64) -> bool {
        self.virtual_address <= address && address < self.virtual_address + self.memory_size
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryMapping {
    start: u64,
    end: u64,
    file_offset: u64,
    file_size: u64,
    permissions: SegmentPermissions,
}

impl MemoryMapping {
    #[must_use]
    pub fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub fn end(&self) -> u64 {
        self.end
    }

    #[must_use]
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }

    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    #[must_use]
    pub fn memory_size(&self) -> u64 {
        self.end - self.start
    }

    #[must_use]
    pub fn permissions(&self) -> SegmentPermissions {
        self.permissions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentPermissions {
    read: bool,
    write: bool,
    execute: bool,
}

impl SegmentPermissions {
    #[must_use]
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    #[must_use]
    pub fn read(&self) -> bool {
        self.read
    }

    #[must_use]
    pub fn write(&self) -> bool {
        self.write
    }

    #[must_use]
    pub fn execute(&self) -> bool {
        self.execute
    }
}

impl TryFrom<u32> for SegmentPermissions {
    type Error = u32;

    fn try_from(flags: u32) -> Result<Self, Self::Error> {
        if flags & !PF_SUPPORTED != 0 {
            return Err(flags);
        }

        Ok(Self {
            read: flags & PF_R != 0,
            write: flags & PF_W != 0,
            execute: flags & PF_X != 0,
        })
    }
}

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

#[cfg(test)]
mod tests {
    use mcr_testkit::elf::{
        ELF64_HEADER_SIZE as TEST_ELF64_HEADER_SIZE, ET_DYN as TEST_ET_DYN,
        ET_EXEC as TEST_ET_EXEC, Elf64Builder, Elf64ProgramHeader, PF_R as TEST_PF_R,
        PF_W as TEST_PF_W, PF_X as TEST_PF_X, PT_INTERP as TEST_PT_INTERP,
    };

    use super::{
        CRATE_NAME, ElfObjectType, ElfValidationError, SegmentPermissions, is_elf64,
        parse_load_plan,
    };

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-elf");
    }

    #[test]
    fn parses_static_executable_load_plan() {
        let elf = Elf64Builder::new()
            .object_type(TEST_ET_EXEC)
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0x1000,
                0x401000,
                0x20,
                0x20,
            ))
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_W,
                0x2000,
                0x402000,
                0x08,
                0x100,
            ))
            .data_at(0x1000, vec![0xcc; 0x20])
            .data_at(0x2000, vec![0x2a; 0x08])
            .build();

        let plan = parse_load_plan(&elf).expect("valid static ELF should parse");

        assert!(is_elf64(&elf));
        assert_eq!(plan.object_type(), ElfObjectType::Executable);
        assert_eq!(plan.entrypoint(), 0x401000);
        assert!(plan.interpreter().is_none());
        assert_eq!(plan.segments().len(), 2);

        let text = &plan.segments()[0];
        assert_eq!(text.program_header_index(), 0);
        assert_eq!(
            text.permissions(),
            SegmentPermissions::new(true, false, true)
        );
        assert_eq!(text.mapping().start(), 0x401000);
        assert_eq!(text.mapping().end(), 0x402000);
        assert_eq!(text.mapping().file_offset(), 0x1000);
        assert_eq!(text.mapping().file_size(), 0x20);

        let data = &plan.segments()[1];
        assert_eq!(data.program_header_index(), 1);
        assert_eq!(
            data.permissions(),
            SegmentPermissions::new(true, true, false)
        );
        assert_eq!(data.mapping().start(), 0x402000);
        assert_eq!(data.mapping().end(), 0x403000);
        assert_eq!(data.mapping().file_offset(), 0x2000);
        assert_eq!(data.mapping().file_size(), 0x08);

        let program_headers = plan.program_headers();
        assert_eq!(
            program_headers.file_offset(),
            u64::from(TEST_ELF64_HEADER_SIZE)
        );
        assert_eq!(program_headers.entry_count(), 2);
        assert_eq!(program_headers.virtual_address(), None);
    }

    #[test]
    fn plans_unaligned_segment_with_page_aligned_mapping() {
        let elf = Elf64Builder::new()
            .entrypoint(0x401234)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0x1234,
                0x401234,
                0x20,
                0x40,
            ))
            .data_at(0x1234, vec![0xcc; 0x20])
            .build();

        let plan = parse_load_plan(&elf).expect("valid unaligned segment should parse");
        let segment = &plan.segments()[0];

        assert_eq!(segment.mapping().start(), 0x401000);
        assert_eq!(segment.mapping().end(), 0x402000);
        assert_eq!(segment.mapping().file_offset(), 0x1000);
        assert_eq!(segment.mapping().file_size(), 0x254);
    }

    #[test]
    fn detects_dynamic_interpreter() {
        let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
        let elf = Elf64Builder::new()
            .object_type(TEST_ET_DYN)
            .entrypoint(0x1010)
            .program_header(Elf64ProgramHeader::new(
                TEST_PT_INTERP,
                TEST_PF_R,
                0x300,
                0,
                interpreter.len() as u64,
                interpreter.len() as u64,
                1,
            ))
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0x1000,
                0x1000,
                0x80,
                0x80,
            ))
            .data_at(0x300, interpreter.to_vec())
            .data_at(0x1000, vec![0x90; 0x80])
            .build();

        let plan = parse_load_plan(&elf).expect("dynamic ELF should parse");

        assert_eq!(plan.object_type(), ElfObjectType::SharedObject);
        assert_eq!(
            plan.interpreter().expect("interpreter").as_bytes(),
            b"/lib64/ld-linux-x86-64.so.2"
        );
    }

    #[test]
    fn rejects_malformed_magic() {
        let mut elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0x1000,
                0x401000,
                0x20,
                0x20,
            ))
            .data_at(0x1000, vec![0xcc; 0x20])
            .build();
        elf[0] = 0;

        assert_eq!(parse_load_plan(&elf), Err(ElfValidationError::InvalidMagic));
        assert!(!is_elf64(&elf));
    }

    #[test]
    fn rejects_unsupported_architecture() {
        let mut elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0x1000,
                0x401000,
                0x20,
                0x20,
            ))
            .data_at(0x1000, vec![0xcc; 0x20])
            .build();
        elf[18..20].copy_from_slice(&183_u16.to_le_bytes());

        assert_eq!(
            parse_load_plan(&elf),
            Err(ElfValidationError::UnsupportedMachine { value: 183 })
        );
    }

    #[test]
    fn rejects_segment_file_size_larger_than_memory_size() {
        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0x1000,
                0x401000,
                0x21,
                0x20,
            ))
            .data_at(0x1000, vec![0xcc; 0x21])
            .build();

        assert_eq!(
            parse_load_plan(&elf),
            Err(ElfValidationError::SegmentFileSizeExceedsMemorySize {
                index: 0,
                file_size: 0x21,
                memory_size: 0x20,
            })
        );
    }

    #[test]
    fn rejects_entrypoint_outside_executable_segment() {
        let elf = Elf64Builder::new()
            .entrypoint(0x402000)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0x1000,
                0x401000,
                0x20,
                0x20,
            ))
            .data_at(0x1000, vec![0xcc; 0x20])
            .build();

        assert_eq!(
            parse_load_plan(&elf),
            Err(ElfValidationError::EntrypointNotExecutable {
                entrypoint: 0x402000,
            })
        );
    }

    #[test]
    fn rejects_unterminated_interpreter() {
        let interpreter = b"/lib64/ld-linux-x86-64.so.2";
        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::new(
                TEST_PT_INTERP,
                TEST_PF_R,
                0x300,
                0,
                interpreter.len() as u64,
                interpreter.len() as u64,
                1,
            ))
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0x1000,
                0x401000,
                0x20,
                0x20,
            ))
            .data_at(0x300, interpreter.to_vec())
            .data_at(0x1000, vec![0xcc; 0x20])
            .build();

        assert_eq!(
            parse_load_plan(&elf),
            Err(ElfValidationError::UnterminatedInterpreter { index: 0 })
        );
    }
}
