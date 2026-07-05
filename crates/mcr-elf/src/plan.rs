use std::ops::Range;

use crate::{ET_DYN, ET_EXEC, ElfValidationError, PF_R, PF_SUPPORTED, PF_W, PF_X};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfObjectType {
    Executable,
    SharedObject,
}

impl ElfObjectType {
    pub(crate) fn from_raw(raw: u16) -> Result<Self, ElfValidationError> {
        match raw {
            ET_EXEC => Ok(Self::Executable),
            ET_DYN => Ok(Self::SharedObject),
            value => Err(ElfValidationError::UnsupportedObjectType { value }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadPlan {
    pub(crate) object_type: ElfObjectType,
    pub(crate) entrypoint: u64,
    pub(crate) program_headers: ProgramHeaderTable,
    pub(crate) interpreter: Option<Interpreter>,
    pub(crate) segments: Vec<LoadSegment>,
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
    pub(crate) file_offset: u64,
    pub(crate) entry_size: u16,
    pub(crate) entry_count: u16,
    pub(crate) virtual_address: Option<u64>,
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
    pub(crate) path: Vec<u8>,
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
    pub(crate) program_header_index: u16,
    pub(crate) file_offset: u64,
    pub(crate) virtual_address: u64,
    pub(crate) file_size: u64,
    pub(crate) memory_size: u64,
    pub(crate) alignment: u64,
    pub(crate) permissions: SegmentPermissions,
    pub(crate) mapping: MemoryMapping,
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
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) file_offset: u64,
    pub(crate) file_size: u64,
    pub(crate) permissions: SegmentPermissions,
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
