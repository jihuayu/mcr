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

pub mod auxv {
    pub const AT_NULL: u64 = 0;
    pub const AT_PHDR: u64 = 3;
    pub const AT_PHENT: u64 = 4;
    pub const AT_PHNUM: u64 = 5;
    pub const AT_PAGESZ: u64 = 6;
    pub const AT_BASE: u64 = 7;
    pub const AT_FLAGS: u64 = 8;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_UID: u64 = 11;
    pub const AT_EUID: u64 = 12;
    pub const AT_GID: u64 = 13;
    pub const AT_EGID: u64 = 14;
    pub const AT_PLATFORM: u64 = 15;
    pub const AT_HWCAP: u64 = 16;
    pub const AT_CLKTCK: u64 = 17;
    pub const AT_SECURE: u64 = 23;
    pub const AT_RANDOM: u64 = 25;
    pub const AT_HWCAP2: u64 = 26;
    pub const AT_EXECFN: u64 = 31;
}

pub const AT_RANDOM_BYTES: usize = 16;
pub const INITIAL_STACK_ALIGNMENT: u64 = 16;
pub const DEFAULT_PLATFORM: &[u8] = b"x86_64";
pub const DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE: u64 = 0x0040_0000;
pub const DEFAULT_INTERPRETER_LOAD_BASE: u64 = 0x7000_0000;
pub const DEFAULT_CLOCK_TICKS_PER_SECOND: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxiliaryVectorEntry {
    key: u64,
    value: u64,
}

impl AuxiliaryVectorEntry {
    #[must_use]
    pub const fn new(key: u64, value: u64) -> Self {
        Self { key, value }
    }

    #[must_use]
    pub const fn key(&self) -> u64 {
        self.key
    }

    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialStackConfig {
    stack_top: u64,
    stack_size: u64,
    executable_path: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    random_bytes: [u8; AT_RANDOM_BYTES],
    executable_load_bias: u64,
    interpreter_base: u64,
    platform: Vec<u8>,
}

impl InitialStackConfig {
    #[must_use]
    pub fn new(stack_top: u64, stack_size: u64, executable_path: impl Into<Vec<u8>>) -> Self {
        let executable_path = executable_path.into();
        Self {
            stack_top,
            stack_size,
            argv: vec![executable_path.clone()],
            executable_path,
            envp: Vec::new(),
            random_bytes: [0; AT_RANDOM_BYTES],
            executable_load_bias: 0,
            interpreter_base: 0,
            platform: DEFAULT_PLATFORM.to_vec(),
        }
    }

    #[must_use]
    pub fn with_argv<I, A>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<Vec<u8>>,
    {
        self.argv = argv.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_envp<I, E>(mut self, envp: I) -> Self
    where
        I: IntoIterator<Item = E>,
        E: Into<Vec<u8>>,
    {
        self.envp = envp.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub const fn with_random_bytes(mut self, random_bytes: [u8; AT_RANDOM_BYTES]) -> Self {
        self.random_bytes = random_bytes;
        self
    }

    #[must_use]
    pub const fn with_executable_load_bias(mut self, executable_load_bias: u64) -> Self {
        self.executable_load_bias = executable_load_bias;
        self
    }

    #[must_use]
    pub const fn with_interpreter_base(mut self, interpreter_base: u64) -> Self {
        self.interpreter_base = interpreter_base;
        self
    }

    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<Vec<u8>>) -> Self {
        self.platform = platform.into();
        self
    }

    #[must_use]
    pub const fn stack_top(&self) -> u64 {
        self.stack_top
    }

    #[must_use]
    pub const fn stack_size(&self) -> u64 {
        self.stack_size
    }

    #[must_use]
    pub fn executable_path(&self) -> &[u8] {
        &self.executable_path
    }

    #[must_use]
    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    #[must_use]
    pub fn envp(&self) -> &[Vec<u8>] {
        &self.envp
    }

    #[must_use]
    pub const fn random_bytes(&self) -> &[u8; AT_RANDOM_BYTES] {
        &self.random_bytes
    }

    #[must_use]
    pub const fn executable_load_bias(&self) -> u64 {
        self.executable_load_bias
    }

    #[must_use]
    pub const fn interpreter_base(&self) -> u64 {
        self.interpreter_base
    }

    #[must_use]
    pub fn platform(&self) -> &[u8] {
        &self.platform
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialStack {
    stack_top: u64,
    stack_size: u64,
    stack_pointer: u64,
    bytes: Vec<u8>,
    argv_addresses: Vec<u64>,
    envp_addresses: Vec<u64>,
    executable_path_address: u64,
    platform_address: u64,
    random_address: u64,
    auxv_entries: Vec<AuxiliaryVectorEntry>,
}

impl InitialStack {
    #[must_use]
    pub const fn stack_top(&self) -> u64 {
        self.stack_top
    }

    #[must_use]
    pub const fn stack_size(&self) -> u64 {
        self.stack_size
    }

    #[must_use]
    pub fn stack_base(&self) -> u64 {
        self.stack_top - self.stack_size
    }

    #[must_use]
    pub const fn stack_pointer(&self) -> u64 {
        self.stack_pointer
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn argv_addresses(&self) -> &[u64] {
        &self.argv_addresses
    }

    #[must_use]
    pub fn envp_addresses(&self) -> &[u64] {
        &self.envp_addresses
    }

    #[must_use]
    pub const fn executable_path_address(&self) -> u64 {
        self.executable_path_address
    }

    #[must_use]
    pub const fn platform_address(&self) -> u64 {
        self.platform_address
    }

    #[must_use]
    pub const fn random_address(&self) -> u64 {
        self.random_address
    }

    #[must_use]
    pub fn auxv_entries(&self) -> &[AuxiliaryVectorEntry] {
        &self.auxv_entries
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitialStackError {
    MissingProgramHeaderAddress,
    InvalidStackSize { stack_size: u64 },
    StackRangeUnderflow { stack_top: u64, stack_size: u64 },
    StackLayoutOverflow,
    StackDataExceedsStack { needed: u64, stack_size: u64 },
    RelocatedAddressOverflow { address: u64, load_bias: u64 },
    InteriorNul { field: &'static str, index: usize },
    EmptyPlatform,
}

impl fmt::Display for InitialStackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProgramHeaderAddress => {
                write!(formatter, "ELF load plan has no guest AT_PHDR address")
            }
            Self::InvalidStackSize { stack_size } => {
                write!(formatter, "invalid initial stack size {stack_size:#x}")
            }
            Self::StackRangeUnderflow {
                stack_top,
                stack_size,
            } => write!(
                formatter,
                "initial stack range underflows: top {stack_top:#x}, size {stack_size:#x}"
            ),
            Self::StackLayoutOverflow => write!(formatter, "initial stack layout overflows"),
            Self::StackDataExceedsStack { needed, stack_size } => write!(
                formatter,
                "initial stack needs {needed:#x} bytes but stack size is {stack_size:#x}"
            ),
            Self::RelocatedAddressOverflow { address, load_bias } => write!(
                formatter,
                "initial stack relocated address overflows: address {address:#x}, load bias {load_bias:#x}"
            ),
            Self::InteriorNul { field, index } => {
                write!(
                    formatter,
                    "initial stack {field}[{index}] contains an interior NUL"
                )
            }
            Self::EmptyPlatform => write!(formatter, "initial stack platform string is empty"),
        }
    }
}

impl std::error::Error for InitialStackError {}

pub fn build_initial_stack(
    load_plan: &LoadPlan,
    config: InitialStackConfig,
) -> Result<InitialStack, InitialStackError> {
    validate_stack_config(&config)?;

    let phdr_address = relocated_address(
        load_plan
            .program_headers()
            .virtual_address()
            .ok_or(InitialStackError::MissingProgramHeaderAddress)?,
        config.executable_load_bias,
    )?;
    let entrypoint = relocated_address(load_plan.entrypoint(), config.executable_load_bias)?;
    let interpreter_base = config.interpreter_base;

    let stack_base = config.stack_top.checked_sub(config.stack_size).ok_or(
        InitialStackError::StackRangeUnderflow {
            stack_top: config.stack_top,
            stack_size: config.stack_size,
        },
    )?;

    let mut cursor = config.stack_top;
    let mut placed = Vec::new();

    let executable_path_address =
        place_c_string(&mut cursor, &mut placed, &config.executable_path)?;
    let platform_address = place_c_string(&mut cursor, &mut placed, &config.platform)?;
    let envp_addresses = place_c_strings(&mut cursor, &mut placed, &config.envp)?;
    let argv_addresses = place_c_strings(&mut cursor, &mut placed, &config.argv)?;

    cursor = cursor
        .checked_sub(AT_RANDOM_BYTES as u64)
        .ok_or(InitialStackError::StackLayoutOverflow)?;
    let random_address = cursor;
    placed.push(PlacedStackBytes {
        address: random_address,
        bytes: config.random_bytes.to_vec(),
    });

    cursor = align_down(cursor, INITIAL_STACK_ALIGNMENT);

    let auxv_entries = vec![
        AuxiliaryVectorEntry::new(auxv::AT_PHDR, phdr_address),
        AuxiliaryVectorEntry::new(
            auxv::AT_PHENT,
            u64::from(load_plan.program_headers().entry_size()),
        ),
        AuxiliaryVectorEntry::new(
            auxv::AT_PHNUM,
            u64::from(load_plan.program_headers().entry_count()),
        ),
        AuxiliaryVectorEntry::new(auxv::AT_PAGESZ, PAGE_SIZE),
        AuxiliaryVectorEntry::new(auxv::AT_BASE, interpreter_base),
        AuxiliaryVectorEntry::new(auxv::AT_FLAGS, 0),
        AuxiliaryVectorEntry::new(auxv::AT_ENTRY, entrypoint),
        AuxiliaryVectorEntry::new(auxv::AT_UID, 0),
        AuxiliaryVectorEntry::new(auxv::AT_EUID, 0),
        AuxiliaryVectorEntry::new(auxv::AT_GID, 0),
        AuxiliaryVectorEntry::new(auxv::AT_EGID, 0),
        AuxiliaryVectorEntry::new(auxv::AT_HWCAP, 0),
        AuxiliaryVectorEntry::new(auxv::AT_CLKTCK, DEFAULT_CLOCK_TICKS_PER_SECOND),
        AuxiliaryVectorEntry::new(auxv::AT_SECURE, 0),
        AuxiliaryVectorEntry::new(auxv::AT_RANDOM, random_address),
        AuxiliaryVectorEntry::new(auxv::AT_HWCAP2, 0),
        AuxiliaryVectorEntry::new(auxv::AT_EXECFN, executable_path_address),
        AuxiliaryVectorEntry::new(auxv::AT_PLATFORM, platform_address),
        AuxiliaryVectorEntry::new(auxv::AT_NULL, 0),
    ];

    let pointer_area = build_pointer_area(&argv_addresses, &envp_addresses, &auxv_entries)?;
    let pointer_area_len =
        u64::try_from(pointer_area.len()).map_err(|_| InitialStackError::StackLayoutOverflow)?;
    let stack_pointer = align_down(
        cursor
            .checked_sub(pointer_area_len)
            .ok_or(InitialStackError::StackLayoutOverflow)?,
        INITIAL_STACK_ALIGNMENT,
    );

    if stack_pointer < stack_base {
        return Err(InitialStackError::StackDataExceedsStack {
            needed: config.stack_top - stack_pointer,
            stack_size: config.stack_size,
        });
    }

    let used_len = usize::try_from(config.stack_top - stack_pointer)
        .map_err(|_| InitialStackError::StackLayoutOverflow)?;
    let mut bytes = vec![0; used_len];
    bytes[..pointer_area.len()].copy_from_slice(&pointer_area);

    for item in placed {
        let offset = usize::try_from(item.address - stack_pointer)
            .map_err(|_| InitialStackError::StackLayoutOverflow)?;
        let end = offset
            .checked_add(item.bytes.len())
            .ok_or(InitialStackError::StackLayoutOverflow)?;
        bytes[offset..end].copy_from_slice(&item.bytes);
    }

    Ok(InitialStack {
        stack_top: config.stack_top,
        stack_size: config.stack_size,
        stack_pointer,
        bytes,
        argv_addresses,
        envp_addresses,
        executable_path_address,
        platform_address,
        random_address,
        auxv_entries,
    })
}

fn validate_stack_config(config: &InitialStackConfig) -> Result<(), InitialStackError> {
    if config.stack_size == 0 {
        return Err(InitialStackError::InvalidStackSize {
            stack_size: config.stack_size,
        });
    }

    validate_no_interior_nul("executable_path", 0, &config.executable_path)?;
    validate_no_interior_nul_entries("argv", &config.argv)?;
    validate_no_interior_nul_entries("envp", &config.envp)?;

    if config.platform.is_empty() {
        return Err(InitialStackError::EmptyPlatform);
    }
    validate_no_interior_nul("platform", 0, &config.platform)?;

    Ok(())
}

fn validate_no_interior_nul_entries(
    field: &'static str,
    entries: &[Vec<u8>],
) -> Result<(), InitialStackError> {
    for (index, entry) in entries.iter().enumerate() {
        validate_no_interior_nul(field, index, entry)?;
    }
    Ok(())
}

fn validate_no_interior_nul(
    field: &'static str,
    index: usize,
    bytes: &[u8],
) -> Result<(), InitialStackError> {
    if bytes.contains(&0) {
        return Err(InitialStackError::InteriorNul { field, index });
    }
    Ok(())
}

fn relocated_address(address: u64, load_bias: u64) -> Result<u64, InitialStackError> {
    address
        .checked_add(load_bias)
        .ok_or(InitialStackError::RelocatedAddressOverflow { address, load_bias })
}

#[derive(Debug)]
struct PlacedStackBytes {
    address: u64,
    bytes: Vec<u8>,
}

fn place_c_strings(
    cursor: &mut u64,
    placed: &mut Vec<PlacedStackBytes>,
    strings: &[Vec<u8>],
) -> Result<Vec<u64>, InitialStackError> {
    let mut addresses = Vec::with_capacity(strings.len());
    for string in strings.iter().rev() {
        addresses.push(place_c_string(cursor, placed, string)?);
    }
    addresses.reverse();
    Ok(addresses)
}

fn place_c_string(
    cursor: &mut u64,
    placed: &mut Vec<PlacedStackBytes>,
    bytes: &[u8],
) -> Result<u64, InitialStackError> {
    let len_with_nul = u64::try_from(bytes.len())
        .map_err(|_| InitialStackError::StackLayoutOverflow)?
        .checked_add(1)
        .ok_or(InitialStackError::StackLayoutOverflow)?;
    *cursor = cursor
        .checked_sub(len_with_nul)
        .ok_or(InitialStackError::StackLayoutOverflow)?;

    let mut stored = Vec::with_capacity(bytes.len() + 1);
    stored.extend_from_slice(bytes);
    stored.push(0);

    placed.push(PlacedStackBytes {
        address: *cursor,
        bytes: stored,
    });

    Ok(*cursor)
}

fn build_pointer_area(
    argv_addresses: &[u64],
    envp_addresses: &[u64],
    auxv_entries: &[AuxiliaryVectorEntry],
) -> Result<Vec<u8>, InitialStackError> {
    let mut bytes = Vec::new();
    push_u64(
        &mut bytes,
        u64::try_from(argv_addresses.len()).map_err(|_| InitialStackError::StackLayoutOverflow)?,
    );
    for address in argv_addresses {
        push_u64(&mut bytes, *address);
    }
    push_u64(&mut bytes, 0);
    for address in envp_addresses {
        push_u64(&mut bytes, *address);
    }
    push_u64(&mut bytes, 0);
    for entry in auxv_entries {
        push_u64(&mut bytes, entry.key());
        push_u64(&mut bytes, entry.value());
    }
    Ok(bytes)
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

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
        AuxiliaryVectorEntry, CRATE_NAME, DEFAULT_CLOCK_TICKS_PER_SECOND,
        DEFAULT_INTERPRETER_LOAD_BASE, DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE, ElfObjectType,
        ElfValidationError, GuestImageError, GuestVma, GuestVmaKind, InitialStackConfig,
        InitialStackError, SegmentPermissions, auxv, build_guest_memory_image,
        build_guest_memory_image_with_interpreter, build_initial_stack, is_elf64, parse_load_plan,
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
    fn builds_deterministic_initial_stack_layout() {
        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0,
                0x400000,
                0x80,
                0x2000,
            ))
            .build();
        let plan = parse_load_plan(&elf).expect("valid static ELF should parse");
        let random_bytes = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];

        let stack = build_initial_stack(
            &plan,
            InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/app".to_vec())
                .with_argv([b"/bin/app".to_vec(), b"--flag".to_vec()])
                .with_envp([b"HOME=/root".to_vec(), b"PATH=/bin".to_vec()])
                .with_random_bytes(random_bytes),
        )
        .expect("initial stack should build");

        assert_eq!(stack.stack_top(), 0x8000_0000);
        assert_eq!(stack.stack_base(), 0x7fff_c000);
        assert_eq!(stack.stack_pointer(), 0x7fff_fe40);
        assert_eq!(stack.bytes().len(), 0x1c0);
        assert_eq!(stack.argv_addresses(), &[0x7fff_ffcb, 0x7fff_ffd4]);
        assert_eq!(stack.envp_addresses(), &[0x7fff_ffdb, 0x7fff_ffe6]);
        assert_eq!(stack.executable_path_address(), 0x7fff_fff7);
        assert_eq!(stack.platform_address(), 0x7fff_fff0);
        assert_eq!(stack.random_address(), 0x7fff_ffbb);

        assert_eq!(read_stack_u64(&stack, 0x7fff_fe40), 2);
        assert_eq!(read_stack_u64(&stack, 0x7fff_fe48), 0x7fff_ffcb);
        assert_eq!(read_stack_u64(&stack, 0x7fff_fe50), 0x7fff_ffd4);
        assert_eq!(read_stack_u64(&stack, 0x7fff_fe58), 0);
        assert_eq!(read_stack_u64(&stack, 0x7fff_fe60), 0x7fff_ffdb);
        assert_eq!(read_stack_u64(&stack, 0x7fff_fe68), 0x7fff_ffe6);
        assert_eq!(read_stack_u64(&stack, 0x7fff_fe70), 0);

        assert_eq!(
            read_stack_bytes(&stack, 0x7fff_ffbb, 16),
            random_bytes.as_slice()
        );
        assert_eq!(read_stack_c_string(&stack, 0x7fff_ffcb), b"/bin/app");
        assert_eq!(read_stack_c_string(&stack, 0x7fff_ffd4), b"--flag");
        assert_eq!(read_stack_c_string(&stack, 0x7fff_ffdb), b"HOME=/root");
        assert_eq!(read_stack_c_string(&stack, 0x7fff_ffe6), b"PATH=/bin");
        assert_eq!(read_stack_c_string(&stack, 0x7fff_fff0), b"x86_64");
        assert_eq!(read_stack_c_string(&stack, 0x7fff_fff7), b"/bin/app");
    }

    #[test]
    fn builds_mvp_auxiliary_vector_values() {
        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0,
                0x400000,
                0x80,
                0x2000,
            ))
            .build();
        let plan = parse_load_plan(&elf).expect("valid static ELF should parse");

        let stack = build_initial_stack(
            &plan,
            InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/app".to_vec())
                .with_argv([b"/bin/app".to_vec()])
                .with_envp([b"LANG=C".to_vec()])
                .with_interpreter_base(0x7000_0000),
        )
        .expect("initial stack should build");

        assert_eq!(
            stack.auxv_entries(),
            &[
                AuxiliaryVectorEntry::new(auxv::AT_PHDR, 0x400040),
                AuxiliaryVectorEntry::new(auxv::AT_PHENT, 56),
                AuxiliaryVectorEntry::new(auxv::AT_PHNUM, 1),
                AuxiliaryVectorEntry::new(auxv::AT_PAGESZ, 4096),
                AuxiliaryVectorEntry::new(auxv::AT_BASE, 0x7000_0000),
                AuxiliaryVectorEntry::new(auxv::AT_FLAGS, 0),
                AuxiliaryVectorEntry::new(auxv::AT_ENTRY, 0x401000),
                AuxiliaryVectorEntry::new(auxv::AT_UID, 0),
                AuxiliaryVectorEntry::new(auxv::AT_EUID, 0),
                AuxiliaryVectorEntry::new(auxv::AT_GID, 0),
                AuxiliaryVectorEntry::new(auxv::AT_EGID, 0),
                AuxiliaryVectorEntry::new(auxv::AT_HWCAP, 0),
                AuxiliaryVectorEntry::new(auxv::AT_CLKTCK, DEFAULT_CLOCK_TICKS_PER_SECOND),
                AuxiliaryVectorEntry::new(auxv::AT_SECURE, 0),
                AuxiliaryVectorEntry::new(auxv::AT_RANDOM, stack.random_address()),
                AuxiliaryVectorEntry::new(auxv::AT_HWCAP2, 0),
                AuxiliaryVectorEntry::new(auxv::AT_EXECFN, stack.executable_path_address()),
                AuxiliaryVectorEntry::new(auxv::AT_PLATFORM, stack.platform_address()),
                AuxiliaryVectorEntry::new(auxv::AT_NULL, 0),
            ]
        );

        let auxv_start = stack.stack_pointer() + 8 + 8 * 2 + 8 * 2;
        for (index, entry) in stack.auxv_entries().iter().enumerate() {
            let address = auxv_start + u64::try_from(index).unwrap() * 16;
            assert_eq!(read_stack_u64(&stack, address), entry.key());
            assert_eq!(read_stack_u64(&stack, address + 8), entry.value());
        }
    }

    #[test]
    fn builds_guest_memory_image_from_load_plan() {
        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0,
                0x400000,
                0x1000,
                0x2000,
            ))
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_W,
                0x3000,
                0x402000,
                0x03,
                0x08,
            ))
            .data_at(0x100, vec![0xaa, 0xbb, 0xcc, 0xdd])
            .data_at(0x3000, vec![0x11, 0x22, 0x33])
            .build();
        let plan = parse_load_plan(&elf).expect("valid ELF should parse");

        let image = build_guest_memory_image(
            &plan,
            &elf,
            InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/app".to_vec()),
        )
        .expect("guest memory image should build");

        assert_eq!(image.entrypoint(), 0x401000);
        assert_eq!(
            image.initial_stack_pointer(),
            image.initial_stack().stack_pointer()
        );
        assert_eq!(image.brk(), 0x403000);
        assert_eq!(image.read(0x400100, 4).unwrap(), &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(
            image.read(0x402000, 8).unwrap(),
            &[0x11, 0x22, 0x33, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            image
                .read(
                    image.initial_stack().stack_pointer(),
                    image.initial_stack().bytes().len()
                )
                .unwrap(),
            image.initial_stack().bytes()
        );

        assert_eq!(
            image.vmas(),
            &[
                GuestVma::new(
                    0x400000,
                    0x402000,
                    SegmentPermissions::new(true, false, true),
                    GuestVmaKind::ElfLoad {
                        program_header_index: 0,
                        file_offset: 0,
                        file_size: 0x1000,
                    },
                ),
                GuestVma::new(
                    0x402000,
                    0x403000,
                    SegmentPermissions::new(true, true, false),
                    GuestVmaKind::ElfLoad {
                        program_header_index: 1,
                        file_offset: 0x3000,
                        file_size: 0x03,
                    },
                ),
                GuestVma::new(
                    0x7fff_c000,
                    0x8000_0000,
                    SegmentPermissions::new(true, true, false),
                    GuestVmaKind::Stack,
                ),
            ]
        );
    }

    #[test]
    fn builds_dynamic_guest_memory_image_with_musl_interpreter() {
        let interpreter_path = b"/lib/ld-musl-x86_64.so.1\0";
        let executable = Elf64Builder::new()
            .object_type(TEST_ET_DYN)
            .entrypoint(0x1010)
            .program_header(Elf64ProgramHeader::new(
                TEST_PT_INTERP,
                TEST_PF_R,
                0x300,
                0,
                interpreter_path.len() as u64,
                interpreter_path.len() as u64,
                1,
            ))
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0,
                0,
                0x1000,
                0x2000,
            ))
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_W,
                0x3000,
                0x3000,
                0x20,
                0x100,
            ))
            .data_at(0x300, interpreter_path.to_vec())
            .data_at(0x400, vec![0xaa, 0xbb, 0xcc, 0xdd])
            .data_at(0x3000, vec![0x11, 0x22])
            .build();
        let interpreter = Elf64Builder::new()
            .object_type(TEST_ET_DYN)
            .entrypoint(0x400)
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0,
                0,
                0x1000,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_W,
                0x2000,
                0x2000,
                0x10,
                0x100,
            ))
            .data_at(0x400, vec![0x90; 4])
            .data_at(0x2000, vec![0x33, 0x44])
            .build();
        let plan = parse_load_plan(&executable).expect("dynamic ELF should parse");

        let image = build_guest_memory_image_with_interpreter(
            &plan,
            &executable,
            Some(&interpreter),
            InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/sh".to_vec()).with_argv([
                b"/bin/sh".to_vec(),
                b"-c".to_vec(),
                b"echo hi".to_vec(),
            ]),
        )
        .expect("dynamic guest image should build");

        let loaded_interpreter = image.interpreter().expect("interpreter should load");
        assert_eq!(image.entrypoint(), DEFAULT_INTERPRETER_LOAD_BASE + 0x400);
        assert_eq!(
            image.executable_load_bias(),
            DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE
        );
        assert_eq!(loaded_interpreter.path(), b"/lib/ld-musl-x86_64.so.1");
        assert_eq!(
            loaded_interpreter.load_bias(),
            DEFAULT_INTERPRETER_LOAD_BASE
        );
        assert_eq!(
            image.read(DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE + 0x400, 4),
            Some([0xaa, 0xbb, 0xcc, 0xdd].as_slice())
        );
        assert_eq!(
            image.read(DEFAULT_INTERPRETER_LOAD_BASE + 0x400, 4),
            Some([0x90, 0x90, 0x90, 0x90].as_slice())
        );
        assert!(image.vmas().iter().any(|vma| matches!(
            vma.kind(),
            GuestVmaKind::InterpreterLoad {
                path,
                program_header_index: 0,
                ..
            } if path == b"/lib/ld-musl-x86_64.so.1"
        )));
        assert!(image.vmas().iter().any(|vma| matches!(
            vma.kind(),
            GuestVmaKind::ElfLoad {
                program_header_index: 1,
                ..
            }
        ) && vma.start()
            == DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE));

        let auxv = image.initial_stack().auxv_entries();
        assert_eq!(
            auxv_value(auxv, auxv::AT_PHDR),
            DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE + 0x40
        );
        assert_eq!(
            auxv_value(auxv, auxv::AT_BASE),
            DEFAULT_INTERPRETER_LOAD_BASE
        );
        assert_eq!(
            auxv_value(auxv, auxv::AT_ENTRY),
            DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE + 0x1010
        );
        assert_eq!(auxv_value(auxv, auxv::AT_SECURE), 0);
        assert_eq!(
            auxv_value(auxv, auxv::AT_CLKTCK),
            DEFAULT_CLOCK_TICKS_PER_SECOND
        );
        assert_eq!(auxv_value(auxv, auxv::AT_UID), 0);
        assert_eq!(auxv_value(auxv, auxv::AT_EUID), 0);
        assert_eq!(auxv_value(auxv, auxv::AT_GID), 0);
        assert_eq!(auxv_value(auxv, auxv::AT_EGID), 0);
    }

    #[test]
    fn dynamic_image_requires_interpreter_bytes() {
        let interpreter_path = b"/lib/ld-musl-x86_64.so.1\0";
        let executable = Elf64Builder::new()
            .object_type(TEST_ET_DYN)
            .entrypoint(0x1010)
            .program_header(Elf64ProgramHeader::new(
                TEST_PT_INTERP,
                TEST_PF_R,
                0x300,
                0,
                interpreter_path.len() as u64,
                interpreter_path.len() as u64,
                1,
            ))
            .program_header(Elf64ProgramHeader::load(
                TEST_PF_R | TEST_PF_X,
                0,
                0,
                0x1000,
                0x2000,
            ))
            .data_at(0x300, interpreter_path.to_vec())
            .build();
        let plan = parse_load_plan(&executable).expect("dynamic ELF should parse");

        assert_eq!(
            build_guest_memory_image(
                &plan,
                &executable,
                InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/sh".to_vec()),
            ),
            Err(GuestImageError::MissingInterpreterBytes)
        );
    }

    #[test]
    fn rejects_initial_stack_when_phdr_address_is_unavailable() {
        let elf = Elf64Builder::new()
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
        let plan = parse_load_plan(&elf).expect("valid static ELF should parse");

        assert_eq!(
            build_initial_stack(
                &plan,
                InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/app".to_vec())
            ),
            Err(InitialStackError::MissingProgramHeaderAddress)
        );
    }

    fn read_stack_u64(stack: &super::InitialStack, guest_address: u64) -> u64 {
        let bytes = read_stack_bytes(stack, guest_address, 8);
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    fn read_stack_bytes(stack: &super::InitialStack, guest_address: u64, len: usize) -> &[u8] {
        let offset = usize::try_from(guest_address - stack.stack_pointer()).unwrap();
        &stack.bytes()[offset..offset + len]
    }

    fn read_stack_c_string(stack: &super::InitialStack, guest_address: u64) -> &[u8] {
        let start = usize::try_from(guest_address - stack.stack_pointer()).unwrap();
        let end = stack.bytes()[start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| start + offset)
            .expect("NUL terminator");
        &stack.bytes()[start..end]
    }

    fn auxv_value(entries: &[AuxiliaryVectorEntry], key: u64) -> u64 {
        entries
            .iter()
            .find(|entry| entry.key() == key)
            .unwrap_or_else(|| panic!("missing auxv key {key}"))
            .value()
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
