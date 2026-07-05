pub mod auxv;
mod image;
mod parser;
mod plan;
mod stack;

#[cfg(test)]
mod tests;

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

pub const AT_RANDOM_BYTES: usize = 16;
pub const INITIAL_STACK_ALIGNMENT: u64 = 16;
pub const DEFAULT_PLATFORM: &[u8] = b"x86_64";
pub const DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE: u64 = 0x0040_0000;
pub const DEFAULT_INTERPRETER_LOAD_BASE: u64 = 0x7000_0000;
pub const DEFAULT_CLOCK_TICKS_PER_SECOND: u64 = 100;

pub use image::{
    GuestImageError, GuestMemoryImage, GuestMemoryRegion, GuestVma, GuestVmaKind,
    LoadedInterpreter, build_guest_memory_image, build_guest_memory_image_with_interpreter,
};
pub use parser::{ElfValidationError, is_elf64, parse_load_plan};
pub use plan::{
    ElfObjectType, Interpreter, LoadPlan, LoadSegment, MemoryMapping, ProgramHeaderTable,
    SegmentPermissions,
};
pub use stack::{
    AuxiliaryVectorEntry, InitialStack, InitialStackConfig, InitialStackError, build_initial_stack,
};
