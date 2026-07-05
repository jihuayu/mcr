use std::fmt;

use crate::{
    DEFAULT_INTERPRETER_LOAD_BASE, DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE, ElfObjectType,
    ElfValidationError, InitialStack, InitialStackConfig, InitialStackError, Interpreter, LoadPlan,
    ProgramHeaderTable, SegmentPermissions, build_initial_stack, parse_load_plan,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMemoryImage {
    entrypoint: u64,
    initial_stack_pointer: u64,
    initial_stack: InitialStack,
    executable_load_bias: u64,
    interpreter: Option<LoadedInterpreter>,
    brk: u64,
    vmas: Vec<GuestVma>,
    regions: Vec<GuestMemoryRegion>,
}

impl GuestMemoryImage {
    #[must_use]
    pub const fn entrypoint(&self) -> u64 {
        self.entrypoint
    }

    #[must_use]
    pub const fn initial_stack_pointer(&self) -> u64 {
        self.initial_stack_pointer
    }

    #[must_use]
    pub const fn initial_stack(&self) -> &InitialStack {
        &self.initial_stack
    }

    #[must_use]
    pub const fn executable_load_bias(&self) -> u64 {
        self.executable_load_bias
    }

    #[must_use]
    pub const fn interpreter(&self) -> Option<&LoadedInterpreter> {
        self.interpreter.as_ref()
    }

    #[must_use]
    pub const fn brk(&self) -> u64 {
        self.brk
    }

    #[must_use]
    pub fn vmas(&self) -> &[GuestVma] {
        &self.vmas
    }

    #[must_use]
    pub fn regions(&self) -> &[GuestMemoryRegion] {
        &self.regions
    }

    #[must_use]
    pub fn read(&self, address: u64, len: usize) -> Option<&[u8]> {
        let len = u64::try_from(len).ok()?;
        let end = address.checked_add(len)?;
        let region = self
            .regions
            .iter()
            .find(|region| region.start <= address && end <= region.end)?;
        let offset = usize::try_from(address - region.start).ok()?;
        let end = offset.checked_add(usize::try_from(len).ok()?)?;
        Some(&region.bytes[offset..end])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedInterpreter {
    path: Vec<u8>,
    load_bias: u64,
    entrypoint: u64,
    program_headers: ProgramHeaderTable,
}

impl LoadedInterpreter {
    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    #[must_use]
    pub const fn load_bias(&self) -> u64 {
        self.load_bias
    }

    #[must_use]
    pub const fn entrypoint(&self) -> u64 {
        self.entrypoint
    }

    #[must_use]
    pub const fn program_headers(&self) -> &ProgramHeaderTable {
        &self.program_headers
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestVma {
    start: u64,
    end: u64,
    permissions: SegmentPermissions,
    kind: GuestVmaKind,
}

impl GuestVma {
    #[must_use]
    pub const fn new(
        start: u64,
        end: u64,
        permissions: SegmentPermissions,
        kind: GuestVmaKind,
    ) -> Self {
        Self {
            start,
            end,
            permissions,
            kind,
        }
    }

    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }

    #[must_use]
    pub const fn permissions(&self) -> SegmentPermissions {
        self.permissions
    }

    #[must_use]
    pub const fn kind(&self) -> &GuestVmaKind {
        &self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestVmaKind {
    ElfLoad {
        program_header_index: u16,
        file_offset: u64,
        file_size: u64,
    },
    InterpreterLoad {
        path: Vec<u8>,
        program_header_index: u16,
        file_offset: u64,
        file_size: u64,
    },
    Stack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMemoryRegion {
    start: u64,
    end: u64,
    bytes: Vec<u8>,
}

impl GuestMemoryRegion {
    pub fn new(start: u64, bytes: Vec<u8>) -> Result<Self, GuestImageError> {
        let len = u64::try_from(bytes.len()).map_err(|_| GuestImageError::RegionTooLarge {
            start,
            size: u64::MAX,
        })?;
        let end = start
            .checked_add(len)
            .ok_or(GuestImageError::AddressRangeOverflow { start, size: len })?;
        Ok(Self { start, end, bytes })
    }

    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestImageError {
    Stack(InitialStackError),
    Interpreter(ElfValidationError),
    MissingInterpreterBytes,
    UnsupportedInterpreter {
        path: Vec<u8>,
    },
    SegmentFileRangeOverflow {
        index: u16,
        file_offset: u64,
        file_size: u64,
    },
    SegmentFileRangeOutOfBounds {
        index: u16,
        file_offset: u64,
        file_size: u64,
        file_len: usize,
    },
    AddressRangeOverflow {
        start: u64,
        size: u64,
    },
    RegionTooLarge {
        start: u64,
        size: u64,
    },
    InvalidVmaRange {
        start: u64,
        end: u64,
    },
    VmaOverlap {
        existing: Box<GuestVma>,
        requested: Box<GuestVma>,
    },
}

impl fmt::Display for GuestImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stack(error) => write!(formatter, "{error}"),
            Self::Interpreter(error) => write!(formatter, "{error}"),
            Self::MissingInterpreterBytes => {
                write!(
                    formatter,
                    "ELF interpreter bytes are required for dynamic executable"
                )
            }
            Self::UnsupportedInterpreter { path } => write!(
                formatter,
                "unsupported ELF interpreter `{}`",
                String::from_utf8_lossy(path)
            ),
            Self::SegmentFileRangeOverflow {
                index,
                file_offset,
                file_size,
            } => write!(
                formatter,
                "ELF segment #{index} file range overflows: offset {file_offset:#x}, size {file_size:#x}"
            ),
            Self::SegmentFileRangeOutOfBounds {
                index,
                file_offset,
                file_size,
                file_len,
            } => write!(
                formatter,
                "ELF segment #{index} file range [{file_offset:#x}, +{file_size:#x}) exceeds file size {file_len:#x}"
            ),
            Self::AddressRangeOverflow { start, size } => write!(
                formatter,
                "guest address range overflows: start {start:#x}, size {size:#x}"
            ),
            Self::RegionTooLarge { start, size } => write!(
                formatter,
                "guest memory region at {start:#x} is too large for this host: {size:#x} bytes"
            ),
            Self::InvalidVmaRange { start, end } => {
                write!(formatter, "invalid guest VMA range [{start:#x}, {end:#x})")
            }
            Self::VmaOverlap {
                existing,
                requested,
            } => write!(
                formatter,
                "guest VMA [{:#x}, {:#x}) overlaps existing [{:#x}, {:#x})",
                requested.start, requested.end, existing.start, existing.end
            ),
        }
    }
}

impl std::error::Error for GuestImageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stack(error) => Some(error),
            Self::Interpreter(error) => Some(error),
            Self::MissingInterpreterBytes
            | Self::UnsupportedInterpreter { .. }
            | Self::SegmentFileRangeOverflow { .. }
            | Self::SegmentFileRangeOutOfBounds { .. }
            | Self::AddressRangeOverflow { .. }
            | Self::RegionTooLarge { .. }
            | Self::InvalidVmaRange { .. }
            | Self::VmaOverlap { .. } => None,
        }
    }
}

impl From<InitialStackError> for GuestImageError {
    fn from(value: InitialStackError) -> Self {
        Self::Stack(value)
    }
}

pub fn build_guest_memory_image(
    load_plan: &LoadPlan,
    elf_bytes: &[u8],
    stack_config: InitialStackConfig,
) -> Result<GuestMemoryImage, GuestImageError> {
    build_guest_memory_image_with_interpreter(load_plan, elf_bytes, None, stack_config)
}

pub fn build_guest_memory_image_with_interpreter(
    load_plan: &LoadPlan,
    elf_bytes: &[u8],
    interpreter_bytes: Option<&[u8]>,
    stack_config: InitialStackConfig,
) -> Result<GuestMemoryImage, GuestImageError> {
    let mut vmas = Vec::new();
    let mut regions = Vec::new();
    let executable_load_bias = executable_load_bias(load_plan);
    let interpreter = if let Some(interpreter) = load_plan.interpreter() {
        let interpreter_bytes =
            interpreter_bytes.ok_or(GuestImageError::MissingInterpreterBytes)?;
        let interpreter_plan =
            parse_load_plan(interpreter_bytes).map_err(GuestImageError::Interpreter)?;
        let interpreter_load_bias = DEFAULT_INTERPRETER_LOAD_BASE;
        let loaded_interpreter = load_interpreter_image(
            interpreter,
            &interpreter_plan,
            interpreter_bytes,
            interpreter_load_bias,
            &mut vmas,
            &mut regions,
        )?;
        Some(loaded_interpreter)
    } else {
        None
    };

    for segment in load_plan.segments() {
        let mapping = segment.mapping();
        let mapping_start = relocated_image_address(mapping.start(), executable_load_bias)?;
        let mapping_end = relocated_image_address(mapping.end(), executable_load_bias)?;
        let mapped_bytes = read_segment_mapping_bytes(
            elf_bytes,
            segment.program_header_index(),
            mapping.file_offset(),
            mapping.file_size(),
        )?;
        let region_size = usize::try_from(mapping.memory_size()).map_err(|_| {
            GuestImageError::RegionTooLarge {
                start: mapping.start(),
                size: mapping.memory_size(),
            }
        })?;
        let mut region_bytes = vec![0; region_size];
        region_bytes[..mapped_bytes.len()].copy_from_slice(mapped_bytes);

        register_vma(
            &mut vmas,
            GuestVma::new(
                mapping_start,
                mapping_end,
                mapping.permissions(),
                GuestVmaKind::ElfLoad {
                    program_header_index: segment.program_header_index(),
                    file_offset: mapping.file_offset(),
                    file_size: mapping.file_size(),
                },
            ),
        )?;
        regions.push(GuestMemoryRegion::new(mapping_start, region_bytes)?);
    }

    let stack_config = stack_config
        .with_executable_load_bias(executable_load_bias)
        .with_interpreter_base(interpreter.as_ref().map_or(0, LoadedInterpreter::load_bias));
    let initial_stack = build_initial_stack(load_plan, stack_config)?;
    let stack_size = usize::try_from(initial_stack.stack_size()).map_err(|_| {
        GuestImageError::RegionTooLarge {
            start: initial_stack.stack_base(),
            size: initial_stack.stack_size(),
        }
    })?;
    let stack_offset = usize::try_from(initial_stack.stack_pointer() - initial_stack.stack_base())
        .map_err(|_| GuestImageError::AddressRangeOverflow {
            start: initial_stack.stack_base(),
            size: initial_stack.stack_size(),
        })?;
    let stack_end = stack_offset
        .checked_add(initial_stack.bytes().len())
        .ok_or(GuestImageError::AddressRangeOverflow {
            start: initial_stack.stack_pointer(),
            size: initial_stack.bytes().len() as u64,
        })?;
    let mut stack_region = vec![0; stack_size];
    stack_region[stack_offset..stack_end].copy_from_slice(initial_stack.bytes());

    register_vma(
        &mut vmas,
        GuestVma::new(
            initial_stack.stack_base(),
            initial_stack.stack_top(),
            SegmentPermissions::new(true, true, false),
            GuestVmaKind::Stack,
        ),
    )?;
    regions.push(GuestMemoryRegion::new(
        initial_stack.stack_base(),
        stack_region,
    )?);

    regions.sort_by_key(|region| region.start);

    Ok(GuestMemoryImage {
        entrypoint: interpreter.as_ref().map_or(
            relocated_image_address(load_plan.entrypoint(), executable_load_bias)?,
            |item| item.entrypoint(),
        ),
        initial_stack_pointer: initial_stack.stack_pointer(),
        initial_stack,
        executable_load_bias,
        interpreter,
        brk: load_plan
            .segments()
            .iter()
            .map(|segment| relocated_image_address(segment.mapping().end(), executable_load_bias))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(0),
        vmas,
        regions,
    })
}

fn load_interpreter_image(
    interpreter: &Interpreter,
    interpreter_plan: &LoadPlan,
    interpreter_bytes: &[u8],
    load_bias: u64,
    vmas: &mut Vec<GuestVma>,
    regions: &mut Vec<GuestMemoryRegion>,
) -> Result<LoadedInterpreter, GuestImageError> {
    if interpreter_plan.interpreter().is_some() {
        return Err(GuestImageError::UnsupportedInterpreter {
            path: interpreter.as_bytes().to_vec(),
        });
    }

    for segment in interpreter_plan.segments() {
        let mapping = segment.mapping();
        let mapping_start = relocated_image_address(mapping.start(), load_bias)?;
        let mapping_end = relocated_image_address(mapping.end(), load_bias)?;
        let mapped_bytes = read_segment_mapping_bytes(
            interpreter_bytes,
            segment.program_header_index(),
            mapping.file_offset(),
            mapping.file_size(),
        )?;
        let region_size = usize::try_from(mapping.memory_size()).map_err(|_| {
            GuestImageError::RegionTooLarge {
                start: mapping_start,
                size: mapping.memory_size(),
            }
        })?;
        let mut region_bytes = vec![0; region_size];
        region_bytes[..mapped_bytes.len()].copy_from_slice(mapped_bytes);

        register_vma(
            vmas,
            GuestVma::new(
                mapping_start,
                mapping_end,
                mapping.permissions(),
                GuestVmaKind::InterpreterLoad {
                    path: interpreter.as_bytes().to_vec(),
                    program_header_index: segment.program_header_index(),
                    file_offset: mapping.file_offset(),
                    file_size: mapping.file_size(),
                },
            ),
        )?;
        regions.push(GuestMemoryRegion::new(mapping_start, region_bytes)?);
    }

    Ok(LoadedInterpreter {
        path: interpreter.as_bytes().to_vec(),
        load_bias,
        entrypoint: relocated_image_address(interpreter_plan.entrypoint(), load_bias)?,
        program_headers: ProgramHeaderTable {
            file_offset: interpreter_plan.program_headers().file_offset(),
            entry_size: interpreter_plan.program_headers().entry_size(),
            entry_count: interpreter_plan.program_headers().entry_count(),
            virtual_address: interpreter_plan
                .program_headers()
                .virtual_address()
                .map(|address| relocated_image_address(address, load_bias))
                .transpose()?,
        },
    })
}

fn executable_load_bias(load_plan: &LoadPlan) -> u64 {
    match load_plan.object_type() {
        ElfObjectType::Executable => 0,
        ElfObjectType::SharedObject => {
            if load_plan.interpreter().is_some() {
                DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE
            } else {
                0
            }
        }
    }
}

fn relocated_image_address(address: u64, load_bias: u64) -> Result<u64, GuestImageError> {
    address
        .checked_add(load_bias)
        .ok_or(GuestImageError::AddressRangeOverflow {
            start: address,
            size: load_bias,
        })
}

fn read_segment_mapping_bytes(
    elf_bytes: &[u8],
    index: u16,
    file_offset: u64,
    file_size: u64,
) -> Result<&[u8], GuestImageError> {
    let file_end =
        file_offset
            .checked_add(file_size)
            .ok_or(GuestImageError::SegmentFileRangeOverflow {
                index,
                file_offset,
                file_size,
            })?;

    if file_end > elf_bytes.len() as u64 {
        return Err(GuestImageError::SegmentFileRangeOutOfBounds {
            index,
            file_offset,
            file_size,
            file_len: elf_bytes.len(),
        });
    }

    Ok(&elf_bytes[file_offset as usize..file_end as usize])
}

fn register_vma(vmas: &mut Vec<GuestVma>, vma: GuestVma) -> Result<(), GuestImageError> {
    if vma.start >= vma.end {
        return Err(GuestImageError::InvalidVmaRange {
            start: vma.start,
            end: vma.end,
        });
    }

    if let Some(existing) = vmas
        .iter()
        .find(|existing| existing.start < vma.end && vma.start < existing.end)
    {
        return Err(GuestImageError::VmaOverlap {
            existing: Box::new(existing.clone()),
            requested: Box::new(vma),
        });
    }

    vmas.push(vma);
    vmas.sort_by_key(|vma| vma.start);
    Ok(())
}
