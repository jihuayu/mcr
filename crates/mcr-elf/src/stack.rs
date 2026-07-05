use std::fmt;

use crate::{
    AT_RANDOM_BYTES, DEFAULT_CLOCK_TICKS_PER_SECOND, DEFAULT_PLATFORM, INITIAL_STACK_ALIGNMENT,
    LoadPlan, PAGE_SIZE, auxv,
};

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

fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}
