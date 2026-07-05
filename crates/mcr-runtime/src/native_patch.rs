#[allow(unused_imports)]
use super::*;

pub(crate) use mcr_jit::native_patch::*;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn native_executable_range_patch_key(
    memory: &GuestMemory,
    start: u64,
    end: u64,
    protection: GuestMemoryProtection,
) -> Result<NativeImagePatchKey, GuestExecutionError> {
    let len = end
        .checked_sub(start)
        .ok_or(GuestExecutionError::Memory(GuestMemoryError::InvalidLength))?;
    let bytes = read_executable_patch_range(memory, start, end)?;
    Ok(native_executable_range_patch_key_from_bytes(
        len,
        NativePatchProtection {
            read: protection.read,
            write: protection.write,
            execute: protection.execute,
        },
        &bytes,
    ))
}

pub(crate) fn find_executable_native_patches(
    memory: &mut GuestMemory,
    skipped_ranges: &[(u64, u64)],
    previous_fs_base: u64,
    guest_task_worker_pool: Option<&HostWorkerPoolExecutor>,
) -> Result<ExecutableNativePatches, GuestExecutionError> {
    let executable_ranges = memory
        .vmas()
        .filter(|vma| vma.protection().execute)
        .filter(|vma| !range_is_covered(vma.start(), vma.end(), skipped_ranges))
        .map(|vma| (vma.start(), vma.end()))
        .collect::<Vec<_>>();

    if let Some(pool) = guest_task_worker_pool
        && let Some(patches) = try_find_executable_native_patches_on_worker_pool(
            memory,
            &executable_ranges,
            previous_fs_base,
            pool,
        )?
    {
        return Ok(patches);
    }

    find_executable_native_patches_synchronously(memory, &executable_ranges, previous_fs_base)
}

pub(crate) fn find_executable_native_patches_synchronously(
    memory: &GuestMemory,
    executable_ranges: &[(u64, u64)],
    previous_fs_base: u64,
) -> Result<ExecutableNativePatches, GuestExecutionError> {
    let mut patches = ExecutableNativePatches::default();
    for (start, end) in executable_ranges.iter().copied() {
        let bytes = read_executable_patch_range(memory, start, end)?;
        merge_executable_native_patches(
            &mut patches,
            scan_executable_native_patch_range(start, end, bytes, previous_fs_base),
        );
    }
    Ok(patches)
}

pub(crate) fn try_find_executable_native_patches_on_worker_pool(
    memory: &GuestMemory,
    executable_ranges: &[(u64, u64)],
    previous_fs_base: u64,
    pool: &HostWorkerPoolExecutor,
) -> Result<Option<ExecutableNativePatches>, GuestExecutionError> {
    let mut jobs = Vec::with_capacity(executable_ranges.len());
    for (start, end) in executable_ranges.iter().copied() {
        let bytes = read_executable_patch_range(memory, start, end)?;
        match pool.submit_result(move || {
            scan_executable_native_patch_range(start, end, bytes, previous_fs_base)
        }) {
            Ok(job) => jobs.push(job),
            Err(error) => {
                host_step_trace(format_args!(
                    "runtime native-patch-scan worker submit fallback range=[0x{start:016x}..0x{end:016x}) error={error}"
                ));
                drain_native_patch_scan_jobs(jobs);
                return Ok(None);
            }
        }
    }

    let mut patches = ExecutableNativePatches::default();
    for job in jobs {
        match job.recv() {
            Ok(range_patches) => merge_executable_native_patches(&mut patches, range_patches),
            Err(error) => {
                host_step_trace(format_args!(
                    "runtime native-patch-scan worker receive fallback error={error}"
                ));
                return Ok(None);
            }
        }
    }
    Ok(Some(patches))
}

pub(crate) fn drain_native_patch_scan_jobs(jobs: Vec<HostWorkerPoolJob<ExecutableNativePatches>>) {
    for job in jobs {
        let _ = job.recv();
    }
}

pub(crate) fn read_executable_patch_range(
    memory: &GuestMemory,
    start: u64,
    end: u64,
) -> Result<Vec<u8>, GuestExecutionError> {
    let len = usize::try_from(end - start)
        .map_err(|_| GuestExecutionError::Memory(GuestMemoryError::RegionTooLarge))?;
    let mut bytes = vec![0; len];
    memory.read(start, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn scan_executable_native_patch_range(
    start: u64,
    end: u64,
    bytes: Vec<u8>,
    previous_fs_base: u64,
) -> ExecutableNativePatches {
    let range_start = Instant::now();
    host_step_trace(format_args!(
        "runtime native-patch-scan start range=[0x{start:016x}..0x{end:016x}) bytes={}",
        bytes.len()
    ));
    let patches = mcr_jit::native_patch::scan_executable_native_patch_range(
        start,
        end,
        bytes,
        previous_fs_base,
    );
    host_step_trace(format_args!(
        "runtime native-patch-scan done range=[0x{start:016x}..0x{end:016x}) syscall_patches={} fs_relative_patches={} elapsed_ms={}",
        patches.syscall_patches.len(),
        {
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                patches.fs_relative_patches.len()
            }
            #[cfg(not(all(windows, target_arch = "x86_64")))]
            {
                0
            }
        },
        host_step_elapsed_ms(range_start)
    ));
    patches
}

pub(crate) fn apply_executable_syscall_patches(
    memory: &mut GuestMemory,
    patches: &[ExecutableSyscallPatch],
) -> Result<(), GuestExecutionError> {
    let patch_start = Instant::now();
    host_step_trace(format_args!(
        "runtime syscall-patch apply start patches={}",
        patches.len()
    ));
    memory.patch_code_fixed(executable_syscall_patch_writes(patches))?;
    host_step_trace(format_args!(
        "runtime syscall-patch apply done patches={} elapsed_ms={}",
        patches.len(),
        host_step_elapsed_ms(patch_start)
    ));
    Ok(())
}

pub(crate) fn apply_native_patch_metadata(
    memory: &mut GuestMemory,
    fs_base: u64,
    metadata: &NativePatchMetadata,
) -> Result<(), GuestExecutionError> {
    apply_executable_syscall_patches(memory, &metadata.syscall_patches)?;
    #[cfg(all(windows, target_arch = "x86_64"))]
    apply_fs_relative_patch_entries(
        memory,
        fs_base,
        metadata.fs_relative_patches.len(),
        metadata
            .fs_relative_patches
            .iter()
            .map(|(&address, &patch)| (address, patch)),
    )?;
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = fs_base;
    }
    Ok(())
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn apply_fs_relative_patch_entries(
    memory: &mut GuestMemory,
    fs_base: u64,
    patch_count: usize,
    patches: impl IntoIterator<Item = (u64, FsRelativePatch)>,
) -> Result<(), GuestExecutionError> {
    let patch_start = Instant::now();
    host_step_trace(format_args!(
        "runtime fs-relative-patch apply start patches={} fs_base=0x{fs_base:016x}",
        patch_count
    ));
    memory.patch_code_fixed(fs_relative_patch_writes(fs_base, patches))?;
    host_step_trace(format_args!(
        "runtime fs-relative-patch apply done patches={} elapsed_ms={}",
        patch_count,
        host_step_elapsed_ms(patch_start)
    ));
    Ok(())
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn is_fork_like_syscall_number(number: u64) -> bool {
    number == mcr_sys::Syscall::Fork.number().raw()
        || number == mcr_sys::Syscall::Vfork.number().raw()
        || number == mcr_sys::Syscall::Clone.number().raw()
        || number == mcr_sys::Syscall::Clone3.number().raw()
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn blocking_fd_wait(fds: &FdTable, syscall_number: u64, fd: u64) -> Option<(Fd, bool)> {
    let fd = fd as Fd;
    if fds.get(fd).is_ok_and(|entry| entry.flags().nonblock()) {
        return None;
    }

    if syscall_number == mcr_sys::Syscall::Read.number().raw()
        || syscall_number == mcr_sys::Syscall::Readv.number().raw()
    {
        Some((fd, false))
    } else if syscall_number == mcr_sys::Syscall::Write.number().raw()
        || syscall_number == mcr_sys::Syscall::Writev.number().raw()
    {
        Some((fd, true))
    } else {
        None
    }
}

pub(crate) fn native_execution_error(
    error: mcr_win::NativeExecutionError,
    registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: Option<NativeFaultInstruction>,
    stack_words: Vec<NativeFaultStackWord>,
) -> GuestExecutionError {
    match error {
        mcr_win::NativeExecutionError::GuestFault {
            signal,
            rip,
            address,
        } => GuestExecutionError::Execution(ExecutionError::NativeFault {
            signal,
            rip,
            address,
            fs_base,
            registers: guest_registers_from_host(registers),
            instruction: instruction.map(Box::new),
            stack_words,
        }),
        mcr_win::NativeExecutionError::UnsupportedHost
        | mcr_win::NativeExecutionError::SignalHandler(_)
        | mcr_win::NativeExecutionError::HostFs => {
            GuestExecutionError::Execution(ExecutionError::NativeFault {
                signal: 0,
                rip: 0,
                address: 0,
                fs_base,
                registers: GuestRegisters::default(),
                instruction: None,
                stack_words: Vec::new(),
            })
        }
    }
}

pub(crate) fn native_fault_instruction(
    memory: &GuestMemory,
    rip: u64,
) -> Option<NativeFaultInstruction> {
    const MAX_INSTRUCTION_BYTES: usize = 15;

    let bytes = read_guest_block(memory, rip, MAX_INSTRUCTION_BYTES).ok()?;
    mcr_jit::decode_native_fault_instruction(&bytes, rip)
}

pub(crate) fn native_fault_stack_words(
    memory: &GuestMemory,
    rsp: u64,
) -> Vec<NativeFaultStackWord> {
    const STACK_WORDS: usize = 8;

    (0..STACK_WORDS)
        .filter_map(|index| {
            let address = rsp.checked_add((index * 8) as u64)?;
            let mut bytes = [0; 8];
            memory.read(address, &mut bytes).ok()?;
            Some(NativeFaultStackWord {
                address,
                value: u64::from_le_bytes(bytes),
            })
        })
        .collect()
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn native_fault_is_unrewritten_fs_relative(
    instruction: &NativeFaultInstruction,
) -> bool {
    fs_relative_original(&instruction.bytes).is_some()
}

pub(crate) fn read_guest_block(
    memory: &GuestMemory,
    rip: u64,
    max_len: usize,
) -> Result<Vec<u8>, GuestMemoryError> {
    let Some(vma) = memory.vma_containing(rip) else {
        return Err(GuestMemoryError::NotMapped);
    };
    if !vma.protection().execute {
        return Err(GuestMemoryError::AccessDenied);
    }

    let len = usize::try_from((vma.end() - rip).min(max_len as u64))
        .map_err(|_| GuestMemoryError::RegionTooLarge)?;
    let mut bytes = vec![0; len];
    memory.read(rip, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn registers_from_gpr(value: GprState) -> GuestRegisters {
    GuestRegisters {
        rax: value.rax(),
        rbx: value.rbx(),
        rcx: value.rcx(),
        rdx: value.rdx(),
        rsi: value.rsi(),
        rdi: value.rdi(),
        rbp: value.rbp(),
        rsp: value.rsp(),
        r8: value.r8(),
        r9: value.r9(),
        r10: value.r10(),
        r11: value.r11(),
        r12: value.r12(),
        r13: value.r13(),
        r14: value.r14(),
        r15: value.r15(),
        rip: value.rip(),
        rflags: value.rflags(),
        fs_base: 0,
    }
}

pub(crate) fn registers_from_gpr_with_fs_base(value: GprState, fs_base: u64) -> GuestRegisters {
    GuestRegisters {
        fs_base,
        ..registers_from_gpr(value)
    }
}

pub(crate) fn gpr_from_registers(value: GuestRegisters) -> GprState {
    GprState::with_full_registers(
        value.rip,
        value.rsp,
        [
            value.rax, value.rbx, value.rcx, value.rdx, value.rsi, value.rdi, value.rbp, value.r8,
            value.r9, value.r10, value.r11, value.r12, value.r13, value.r14, value.r15,
        ],
        value.rflags,
    )
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn host_registers_from_gpr(value: GprState) -> mcr_win::HostCpuRegisters {
    mcr_win::HostCpuRegisters {
        rax: value.rax(),
        rbx: value.rbx(),
        rcx: value.rcx(),
        rdx: value.rdx(),
        rsi: value.rsi(),
        rdi: value.rdi(),
        rbp: value.rbp(),
        rsp: value.rsp(),
        r8: value.r8(),
        r9: value.r9(),
        r10: value.r10(),
        r11: value.r11(),
        r12: value.r12(),
        r13: value.r13(),
        r14: value.r14(),
        r15: value.r15(),
        rip: value.rip(),
        rflags: value.rflags(),
        xmm: mcr_win::HostXmmRegisters::default(),
        mxcsr: mcr_win::DEFAULT_MXCSR,
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn guest_registers_from_host(value: mcr_win::HostCpuRegisters) -> GuestRegisters {
    GuestRegisters {
        rax: value.rax,
        rbx: value.rbx,
        rcx: value.rcx,
        rdx: value.rdx,
        rsi: value.rsi,
        rdi: value.rdi,
        rbp: value.rbp,
        rsp: value.rsp,
        r8: value.r8,
        r9: value.r9,
        r10: value.r10,
        r11: value.r11,
        r12: value.r12,
        r13: value.r13,
        r14: value.r14,
        r15: value.r15,
        rip: value.rip,
        rflags: value.rflags,
        fs_base: 0,
    }
}

#[derive(Debug, Default)]
pub(crate) struct FileBackedMappingCache {
    pub(crate) entries: BTreeMap<FileBackedMappingCacheKey, Arc<[u8]>>,
    pub(crate) hits: usize,
    pub(crate) misses: usize,
}

impl FileBackedMappingCache {
    pub(crate) fn lookup(&mut self, key: FileBackedMappingCacheKey) -> Option<Arc<[u8]>> {
        let bytes = self.entries.get(&key)?;
        self.hits += 1;
        Some(bytes.clone())
    }

    pub(crate) fn record_miss(&mut self) {
        self.misses += 1;
    }

    pub(crate) fn insert(&mut self, key: FileBackedMappingCacheKey, bytes: Vec<u8>) -> Arc<[u8]> {
        self.entries
            .retain(|cached, _| cached.file.generation() == key.file.generation());
        let bytes: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
        self.entries.insert(key, bytes.clone());
        bytes
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> FileBackedMappingCacheSnapshot {
        FileBackedMappingCacheSnapshot {
            entries: self.entries.len(),
            hits: self.hits,
            misses: self.misses,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FileBackedMappingCacheKey {
    pub(crate) file: RegularFileCacheKey,
    pub(crate) offset: u64,
    pub(crate) length: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileBackedMappingCacheSnapshot {
    pub(crate) entries: usize,
    pub(crate) hits: usize,
    pub(crate) misses: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileBackedLibcIntrinsicSymbol {
    pub(crate) value: u64,
    pub(crate) intrinsic: GuestLibcIntrinsic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ElfSectionHeader {
    pub(crate) section_type: u32,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) link: u32,
    pub(crate) entry_size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ElfLoadHeader {
    pub(crate) file_offset: u64,
    pub(crate) virtual_address: u64,
    pub(crate) file_size: u64,
    pub(crate) memory_size: u64,
}

const ELF64_MAGIC: &[u8; 4] = b"\x7fELF";
const ELF64_CLASS_64: u8 = 2;
const ELF64_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF64_MACHINE_X86_64: u16 = 62;
const ELF64_PT_LOAD: u32 = 1;
const ELF64_SHT_DYNSYM: u32 = 11;
const ELF64_STT_FUNC: u8 = 2;
const ELF64_STT_GNU_IFUNC: u8 = 10;
const ELF64_SYMBOL_SIZE: usize = 24;

pub(crate) fn parse_file_backed_libc_intrinsic_symbols(
    bytes: &[u8],
) -> Vec<FileBackedLibcIntrinsicSymbol> {
    let Some(sections) = elf_section_headers(bytes) else {
        return Vec::new();
    };
    let mut symbols = Vec::new();
    for section in sections
        .iter()
        .filter(|section| section.section_type == ELF64_SHT_DYNSYM)
    {
        let Some(strtab) = usize::try_from(section.link)
            .ok()
            .and_then(|index| sections.get(index))
            .and_then(|section| elf_range(bytes, section.offset, section.size))
        else {
            continue;
        };
        let entry_size = usize::try_from(section.entry_size)
            .ok()
            .filter(|size| *size >= ELF64_SYMBOL_SIZE)
            .unwrap_or(ELF64_SYMBOL_SIZE);
        let Some(dynsym) = elf_range(bytes, section.offset, section.size) else {
            continue;
        };
        for entry in dynsym.chunks_exact(entry_size) {
            let Some(symbol) = parse_file_backed_libc_intrinsic_symbol(entry, strtab) else {
                continue;
            };
            symbols.push(symbol);
        }
    }
    symbols
}

pub(crate) fn parse_file_backed_libc_intrinsic_symbol(
    entry: &[u8],
    strtab: &[u8],
) -> Option<FileBackedLibcIntrinsicSymbol> {
    let name_offset = elf_u32(entry, 0)? as usize;
    let symbol_type = *entry.get(4)? & 0x0f;
    if !matches!(symbol_type, ELF64_STT_FUNC | ELF64_STT_GNU_IFUNC) {
        return None;
    }
    let value = elf_u64(entry, 8)?;
    if value == 0 {
        return None;
    }
    let name = elf_cstr(strtab, name_offset)?;
    let intrinsic = GuestLibcIntrinsic::from_symbol_name(name)?;
    Some(FileBackedLibcIntrinsicSymbol { value, intrinsic })
}

pub(crate) fn elf_load_bias_for_mapping(
    bytes: &[u8],
    file_offset: u64,
    mapped: u64,
) -> Option<u64> {
    let page_size = GUEST_PAGE_SIZE;
    for load in elf_load_headers(bytes)? {
        let segment_file_start = elf_align_down(load.file_offset, page_size);
        let segment_file_end = align_up_checked(
            load.file_offset
                .checked_add(load.file_size.max(load.memory_size))?,
            page_size,
        )?;
        if file_offset < segment_file_start || file_offset >= segment_file_end {
            continue;
        }
        let segment_vaddr_start = elf_align_down(load.virtual_address, page_size);
        let mapped_image_address =
            segment_vaddr_start.checked_add(file_offset.checked_sub(segment_file_start)?)?;
        return mapped.checked_sub(mapped_image_address);
    }
    None
}

pub(crate) fn elf_section_headers(bytes: &[u8]) -> Option<Vec<ElfSectionHeader>> {
    validate_elf64_header(bytes)?;
    let section_offset = elf_u64(bytes, 40)?;
    let section_entry_size = usize::from(elf_u16(bytes, 58)?);
    let section_count = usize::from(elf_u16(bytes, 60)?);
    if section_entry_size < 64 {
        return None;
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = usize::try_from(section_offset)
            .ok()?
            .checked_add(index.checked_mul(section_entry_size)?)?;
        let section = bytes.get(offset..offset.checked_add(section_entry_size)?)?;
        sections.push(ElfSectionHeader {
            section_type: elf_u32(section, 4)?,
            offset: elf_u64(section, 24)?,
            size: elf_u64(section, 32)?,
            link: elf_u32(section, 40)?,
            entry_size: elf_u64(section, 56)?,
        });
    }
    Some(sections)
}

pub(crate) fn elf_load_headers(bytes: &[u8]) -> Option<Vec<ElfLoadHeader>> {
    validate_elf64_header(bytes)?;
    let program_offset = elf_u64(bytes, 32)?;
    let program_entry_size = usize::from(elf_u16(bytes, 54)?);
    let program_count = usize::from(elf_u16(bytes, 56)?);
    if program_entry_size < 56 {
        return None;
    }
    let mut loads = Vec::new();
    for index in 0..program_count {
        let offset = usize::try_from(program_offset)
            .ok()?
            .checked_add(index.checked_mul(program_entry_size)?)?;
        let header = bytes.get(offset..offset.checked_add(program_entry_size)?)?;
        if elf_u32(header, 0)? != ELF64_PT_LOAD {
            continue;
        }
        loads.push(ElfLoadHeader {
            file_offset: elf_u64(header, 8)?,
            virtual_address: elf_u64(header, 16)?,
            file_size: elf_u64(header, 32)?,
            memory_size: elf_u64(header, 40)?,
        });
    }
    Some(loads)
}

pub(crate) fn validate_elf64_header(bytes: &[u8]) -> Option<()> {
    if bytes.get(0..4)? != ELF64_MAGIC
        || *bytes.get(4)? != ELF64_CLASS_64
        || *bytes.get(5)? != ELF64_DATA_LITTLE_ENDIAN
        || elf_u16(bytes, 18)? != ELF64_MACHINE_X86_64
    {
        return None;
    }
    Some(())
}

pub(crate) fn elf_range(bytes: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
    let offset = usize::try_from(offset).ok()?;
    let len = usize::try_from(len).ok()?;
    bytes.get(offset..offset.checked_add(len)?)
}

pub(crate) fn elf_cstr(bytes: &[u8], offset: usize) -> Option<&str> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&tail[..end]).ok()
}

pub(crate) fn elf_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(crate) fn elf_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn elf_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

const fn elf_align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

pub(crate) fn align_up_checked(value: u64, alignment: u64) -> Option<u64> {
    let remainder = value % alignment;
    if remainder == 0 {
        return Some(value);
    }
    value.checked_add(alignment - remainder)
}
