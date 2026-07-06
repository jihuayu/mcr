#[allow(unused_imports)]
use super::*;

pub(crate) use mcr_jit::native_patch::*;

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) const FS_RELATIVE_PATCH_MATERIALIZE_LIMIT: usize = 65_536;

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
) -> Result<bool, GuestExecutionError> {
    apply_executable_syscall_patches(memory, &metadata.syscall_patches)?;
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        apply_fs_relative_trap_entries(
            memory,
            metadata.fs_relative_traps.len(),
            metadata
                .fs_relative_traps
                .iter()
                .map(|(&address, &trap)| (address, trap)),
        )?;
        if should_materialize_fs_relative_patches(metadata.fs_relative_patches.len()) {
            apply_fs_relative_patch_entries(
                memory,
                fs_base,
                metadata.fs_relative_patches.len(),
                metadata
                    .fs_relative_patches
                    .iter()
                    .map(|(&address, &patch)| (address, patch)),
            )?;
            return Ok(!metadata.fs_relative_patches.is_empty());
        }
        host_step_trace(format_args!(
            "runtime fs-relative-patch materialize skipped patches={} reason=large-patch-set",
            metadata.fs_relative_patches.len()
        ));
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = fs_base;
    }
    Ok(false)
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) const fn should_materialize_fs_relative_patches(patch_count: usize) -> bool {
    patch_count <= FS_RELATIVE_PATCH_MATERIALIZE_LIMIT
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

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn apply_fs_relative_trap_entries(
    memory: &mut GuestMemory,
    trap_count: usize,
    traps: impl IntoIterator<Item = (u64, FsRelativeTrap)>,
) -> Result<(), GuestExecutionError> {
    let trap_start = Instant::now();
    host_step_trace(format_args!(
        "runtime fs-relative-trap apply start traps={trap_count}"
    ));
    memory.patch_code_fixed(traps.into_iter().map(|(address, _)| (address, [0xcc])))?;
    host_step_trace(format_args!(
        "runtime fs-relative-trap apply done traps={trap_count} elapsed_ms={}",
        host_step_elapsed_ms(trap_start)
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
        || syscall_number == mcr_sys::Syscall::EpollWait.number().raw()
        || syscall_number == mcr_sys::Syscall::EpollPwait.number().raw()
        || syscall_number == mcr_sys::Syscall::EpollPwait2.number().raw()
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
        || fs_relative_instruction_bytes(&instruction.bytes)
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn emulate_fs_relative_native_fault(
    memory: &mut GuestMemory,
    registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    if let Some(registers) = emulate_fs_modrm_mov_load(memory, registers, fs_base, instruction)? {
        return Ok(Some(registers));
    }
    if let Some(registers) = emulate_fs_absolute_mov_load(memory, registers, fs_base, instruction)?
    {
        return Ok(Some(registers));
    }
    if let Some(registers) =
        emulate_fs_absolute_movzx_load(memory, registers, fs_base, instruction)?
    {
        return Ok(Some(registers));
    }
    if let Some(registers) = emulate_fs_absolute_mov_store(memory, registers, fs_base, instruction)?
    {
        return Ok(Some(registers));
    }
    if let Some(registers) =
        emulate_fs_modrm_mov_immediate_store(memory, registers, fs_base, instruction)?
    {
        return Ok(Some(registers));
    }
    if let Some(registers) =
        emulate_fs_absolute_mov_immediate_store(memory, registers, fs_base, instruction)?
    {
        return Ok(Some(registers));
    }
    if let Some(registers) =
        emulate_fs_absolute_movhps_load(memory, registers, fs_base, instruction)?
    {
        return Ok(Some(registers));
    }
    if let Some(registers) = emulate_fs_absolute_cmp_imm8(memory, registers, fs_base, instruction)?
    {
        return Ok(Some(registers));
    }
    if let Some(registers) = emulate_fs_absolute_add(memory, registers, fs_base, instruction)? {
        return Ok(Some(registers));
    }
    emulate_fs_absolute_sub(memory, registers, fs_base, instruction)
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn emulate_fs_relative_trap(
    memory: &mut GuestMemory,
    registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    rip: u64,
    trap: FsRelativeTrap,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let Some(instruction) = mcr_jit::decode_native_fault_instruction(trap.original_bytes(), rip)
    else {
        return Ok(None);
    };
    emulate_fs_relative_native_fault(memory, registers, fs_base, &instruction)
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_modrm_mov_load(
    memory: &GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let mut index = fs_index + 1;
    let rex = if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        let rex = bytes[index];
        index += 1;
        rex
    } else {
        0
    };
    if bytes.get(index).copied() != Some(0x8b) {
        return Ok(None);
    }
    let Some(&modrm) = bytes.get(index + 1) else {
        return Ok(None);
    };
    let Some((offset, _next_index)) = modrm_memory_offset(&registers, rex, bytes, index + 1)?
    else {
        return Ok(None);
    };
    let addr = fs_base.wrapping_add(offset);
    let reg = ((modrm >> 3) & 0x07) | if rex & 0x04 != 0 { 8 } else { 0 };
    if rex & 0x08 != 0 {
        let mut value = [0; 8];
        memory.read(addr, &mut value)?;
        set_host_register64(&mut registers, reg, u64::from_le_bytes(value))?;
    } else {
        let mut value = [0; 4];
        memory.read(addr, &mut value)?;
        set_host_register64(&mut registers, reg, u64::from(u32::from_le_bytes(value)))?;
    }
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_absolute_mov_load(
    memory: &GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let mut index = fs_index + 1;
    let rex = if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        let rex = bytes[index];
        index += 1;
        rex
    } else {
        0
    };
    if bytes.get(index).copied() != Some(0x8b) {
        return Ok(None);
    }
    let Some(&modrm) = bytes.get(index + 1) else {
        return Ok(None);
    };
    let Some(&sib) = bytes.get(index + 2) else {
        return Ok(None);
    };
    if modrm & 0xc7 != 0x04 || sib != 0x25 {
        return Ok(None);
    }
    let displacement_start = index + 3;
    let displacement_end = displacement_start + 4;
    let Some(displacement_bytes) = bytes.get(displacement_start..displacement_end) else {
        return Ok(None);
    };
    let displacement = i32::from_le_bytes(
        displacement_bytes
            .try_into()
            .expect("displacement length checked"),
    );
    let addr = fs_base.wrapping_add(displacement as i64 as u64);
    let reg = ((modrm >> 3) & 0x07) | if rex & 0x04 != 0 { 8 } else { 0 };
    if rex & 0x08 != 0 {
        let mut value = [0; 8];
        memory.read(addr, &mut value)?;
        set_host_register64(&mut registers, reg, u64::from_le_bytes(value))?;
    } else {
        let mut value = [0; 4];
        memory.read(addr, &mut value)?;
        set_host_register64(&mut registers, reg, u64::from(u32::from_le_bytes(value)))?;
    }
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_absolute_movzx_load(
    memory: &GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let mut index = fs_index + 1;
    let rex = if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        let rex = bytes[index];
        index += 1;
        rex
    } else {
        0
    };
    if bytes.get(index).copied() != Some(0x0f) {
        return Ok(None);
    }
    let Some(opcode) = bytes.get(index + 1).copied() else {
        return Ok(None);
    };
    let value_len = match opcode {
        0xb6 => 1,
        0xb7 => 2,
        _ => return Ok(None),
    };
    let Some(&modrm) = bytes.get(index + 2) else {
        return Ok(None);
    };
    let Some(&sib) = bytes.get(index + 3) else {
        return Ok(None);
    };
    if modrm & 0xc7 != 0x04 || sib != 0x25 {
        return Ok(None);
    }
    let displacement_start = index + 4;
    let displacement_end = displacement_start + 4;
    let Some(displacement_bytes) = bytes.get(displacement_start..displacement_end) else {
        return Ok(None);
    };
    let displacement = i32::from_le_bytes(
        displacement_bytes
            .try_into()
            .expect("displacement length checked"),
    );
    let addr = fs_base.wrapping_add(displacement as i64 as u64);
    let mut value = [0; 2];
    memory.read(addr, &mut value[..value_len])?;
    let value = match value_len {
        1 => u64::from(value[0]),
        2 => u64::from(u16::from_le_bytes(value)),
        _ => unreachable!("movzx size is matched above"),
    };
    let reg = ((modrm >> 3) & 0x07) | if rex & 0x04 != 0 { 8 } else { 0 };
    set_host_register64(&mut registers, reg, value)?;
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_absolute_mov_store(
    memory: &mut GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let mut index = fs_index + 1;
    let rex = if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        let rex = bytes[index];
        index += 1;
        rex
    } else {
        0
    };
    let Some(opcode) = bytes.get(index).copied() else {
        return Ok(None);
    };
    let value_len = match opcode {
        0x88 => 1,
        0x89 if rex & 0x08 != 0 => 8,
        0x89 => 4,
        _ => return Ok(None),
    };
    let Some(&modrm) = bytes.get(index + 1) else {
        return Ok(None);
    };
    let Some(&sib) = bytes.get(index + 2) else {
        return Ok(None);
    };
    if modrm & 0xc7 != 0x04 || sib != 0x25 {
        return Ok(None);
    }
    let displacement_start = index + 3;
    let displacement_end = displacement_start + 4;
    let Some(displacement_bytes) = bytes.get(displacement_start..displacement_end) else {
        return Ok(None);
    };
    let displacement = i32::from_le_bytes(
        displacement_bytes
            .try_into()
            .expect("displacement length checked"),
    );
    let addr = fs_base.wrapping_add(displacement as i64 as u64);
    let reg = ((modrm >> 3) & 0x07) | if rex & 0x04 != 0 { 8 } else { 0 };
    let value = host_register64(&registers, reg)?.to_le_bytes();
    memory.write(addr, &value[..value_len])?;
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_modrm_mov_immediate_store(
    memory: &mut GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let mut index = fs_index + 1;
    let rex = if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        let rex = bytes[index];
        index += 1;
        rex
    } else {
        0
    };
    let Some(opcode) = bytes.get(index).copied() else {
        return Ok(None);
    };
    let immediate_len = match opcode {
        0xc6 => 1,
        0xc7 => 4,
        _ => return Ok(None),
    };
    let Some(&modrm) = bytes.get(index + 1) else {
        return Ok(None);
    };
    if modrm & 0x38 != 0 {
        return Ok(None);
    }
    let Some((offset, immediate_start)) = modrm_memory_offset(&registers, rex, bytes, index + 1)?
    else {
        return Ok(None);
    };
    let immediate_end = immediate_start + immediate_len;
    let Some(immediate_bytes) = bytes.get(immediate_start..immediate_end) else {
        return Ok(None);
    };
    let addr = fs_base.wrapping_add(offset);
    match opcode {
        0xc6 => memory.write(addr, immediate_bytes)?,
        0xc7 if rex & 0x08 != 0 => {
            let immediate = i32::from_le_bytes(
                immediate_bytes
                    .try_into()
                    .expect("immediate length checked"),
            );
            memory.write(addr, &(immediate as i64 as u64).to_le_bytes())?;
        }
        0xc7 => {
            let immediate = i32::from_le_bytes(
                immediate_bytes
                    .try_into()
                    .expect("immediate length checked"),
            );
            memory.write(addr, &immediate.to_le_bytes())?;
        }
        _ => unreachable!("opcode was checked"),
    };
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_absolute_mov_immediate_store(
    memory: &mut GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let mut index = fs_index + 1;
    let rex = if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        let rex = bytes[index];
        index += 1;
        rex
    } else {
        0
    };
    let Some(opcode) = bytes.get(index).copied() else {
        return Ok(None);
    };
    let immediate_len = match opcode {
        0xc6 => 1,
        0xc7 => 4,
        _ => return Ok(None),
    };
    let Some(&modrm) = bytes.get(index + 1) else {
        return Ok(None);
    };
    let Some(&sib) = bytes.get(index + 2) else {
        return Ok(None);
    };
    if modrm & 0xf8 != 0x00 || modrm & 0x07 != 0x04 || sib != 0x25 {
        return Ok(None);
    }
    let displacement_start = index + 3;
    let displacement_end = displacement_start + 4;
    let Some(displacement_bytes) = bytes.get(displacement_start..displacement_end) else {
        return Ok(None);
    };
    let immediate_end = displacement_end + immediate_len;
    let Some(immediate_bytes) = bytes.get(displacement_end..immediate_end) else {
        return Ok(None);
    };
    let displacement = i32::from_le_bytes(
        displacement_bytes
            .try_into()
            .expect("displacement length checked"),
    );
    let addr = fs_base.wrapping_add(displacement as i64 as u64);
    match opcode {
        0xc6 => memory.write(addr, immediate_bytes)?,
        0xc7 if rex & 0x08 != 0 => {
            let immediate = i32::from_le_bytes(
                immediate_bytes
                    .try_into()
                    .expect("immediate length checked"),
            );
            memory.write(addr, &(immediate as i64 as u64).to_le_bytes())?;
        }
        0xc7 => {
            let immediate = i32::from_le_bytes(
                immediate_bytes
                    .try_into()
                    .expect("immediate length checked"),
            );
            memory.write(addr, &immediate.to_le_bytes())?;
        }
        _ => unreachable!("opcode was checked"),
    };
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_absolute_cmp_imm8(
    memory: &GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let mut index = fs_index + 1;
    let rex = if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        let rex = bytes[index];
        index += 1;
        rex
    } else {
        0
    };
    let Some(opcode) = bytes.get(index).copied() else {
        return Ok(None);
    };
    if !matches!(opcode, 0x80 | 0x83) {
        return Ok(None);
    }
    let Some(&modrm) = bytes.get(index + 1) else {
        return Ok(None);
    };
    let Some(&sib) = bytes.get(index + 2) else {
        return Ok(None);
    };
    if modrm & 0xf8 != 0x38 || modrm & 0x07 != 0x04 || sib != 0x25 {
        return Ok(None);
    }
    let displacement_start = index + 3;
    let displacement_end = displacement_start + 4;
    let Some(displacement_bytes) = bytes.get(displacement_start..displacement_end) else {
        return Ok(None);
    };
    let Some(&imm8) = bytes.get(displacement_end) else {
        return Ok(None);
    };
    let displacement = i32::from_le_bytes(
        displacement_bytes
            .try_into()
            .expect("displacement length checked"),
    );
    let addr = fs_base.wrapping_add(displacement as i64 as u64);
    match opcode {
        0x80 => {
            let mut lhs_bytes = [0; 1];
            memory.read(addr, &mut lhs_bytes)?;
            let lhs = lhs_bytes[0];
            let rhs = imm8;
            let result = lhs.wrapping_sub(rhs);
            apply_sub_flags8(&mut registers, lhs, rhs, result);
        }
        0x83 if rex & 0x08 != 0 => {
            let mut lhs_bytes = [0; 8];
            memory.read(addr, &mut lhs_bytes)?;
            let lhs = u64::from_le_bytes(lhs_bytes);
            let rhs = (imm8 as i8 as i64) as u64;
            let result = lhs.wrapping_sub(rhs);
            apply_sub_flags64(&mut registers, lhs, rhs, result);
        }
        0x83 => {
            let mut lhs_bytes = [0; 4];
            memory.read(addr, &mut lhs_bytes)?;
            let lhs = u32::from_le_bytes(lhs_bytes);
            let rhs = imm8 as i8 as i32 as u32;
            let result = lhs.wrapping_sub(rhs);
            apply_sub_flags32(&mut registers, lhs, rhs, result);
        }
        _ => unreachable!("opcode was checked"),
    }
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_absolute_movhps_load(
    memory: &GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let mut index = fs_index + 1;
    let rex = if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        let rex = bytes[index];
        index += 1;
        rex
    } else {
        0
    };
    if bytes.get(index).copied() != Some(0x0f) || bytes.get(index + 1).copied() != Some(0x16) {
        return Ok(None);
    }
    let Some(&modrm) = bytes.get(index + 2) else {
        return Ok(None);
    };
    let Some(&sib) = bytes.get(index + 3) else {
        return Ok(None);
    };
    if modrm & 0xc7 != 0x04 || sib != 0x25 {
        return Ok(None);
    }
    let displacement_start = index + 4;
    let displacement_end = displacement_start + 4;
    let Some(displacement_bytes) = bytes.get(displacement_start..displacement_end) else {
        return Ok(None);
    };
    let displacement = i32::from_le_bytes(
        displacement_bytes
            .try_into()
            .expect("displacement length checked"),
    );
    let addr = fs_base.wrapping_add(displacement as i64 as u64);
    let reg = (((modrm >> 3) & 0x07) | if rex & 0x04 != 0 { 8 } else { 0 }) as usize;
    let mut value = [0; 8];
    memory.read(addr, &mut value)?;
    registers.xmm[reg][8..].copy_from_slice(&value);
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_absolute_sub(
    memory: &GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let index = fs_index + 1;
    if bytes.len() != fs_index + 9
        || bytes.get(index).copied() != Some(0x48)
        || bytes.get(index + 1).copied() != Some(0x2b)
        || bytes.get(index + 3).copied() != Some(0x25)
        || bytes
            .get(index + 2)
            .copied()
            .is_none_or(|modrm| modrm & 0xc7 != 0x04)
    {
        return Ok(None);
    }
    let displacement_start = index + 4;
    let displacement_end = displacement_start + 4;
    let displacement = i32::from_le_bytes(
        bytes[displacement_start..displacement_end]
            .try_into()
            .expect("displacement length checked"),
    );
    let addr = fs_base.wrapping_add(displacement as i64 as u64);
    let mut rhs_bytes = [0; 8];
    memory.read(addr, &mut rhs_bytes)?;
    let rhs = u64::from_le_bytes(rhs_bytes);
    let reg = (bytes[index + 2] >> 3) & 0x07;
    let lhs = host_register64(&registers, reg)?;
    let result = lhs.wrapping_sub(rhs);
    set_host_register64(&mut registers, reg, result)?;
    apply_sub_flags64(&mut registers, lhs, rhs, result);
    host_step_trace(format_args!(
        "runtime native-fs-sub-emulate rip=0x{:016x} lhs=0x{lhs:016x} rhs=0x{rhs:016x} result=0x{result:016x} rflags=0x{:016x}",
        instruction.rip, registers.rflags
    ));
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn emulate_fs_absolute_add(
    memory: &GuestMemory,
    mut registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: &NativeFaultInstruction,
) -> Result<Option<mcr_win::HostCpuRegisters>, GuestExecutionError> {
    let bytes = instruction.bytes.as_slice();
    let Some(fs_index) = fs_segment_prefix_index(bytes) else {
        return Ok(None);
    };
    let mut index = fs_index + 1;
    let rex = if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        let rex = bytes[index];
        index += 1;
        rex
    } else {
        0
    };
    if bytes.get(index).copied() != Some(0x03) {
        return Ok(None);
    }
    let Some(&modrm) = bytes.get(index + 1) else {
        return Ok(None);
    };
    let Some(&sib) = bytes.get(index + 2) else {
        return Ok(None);
    };
    if modrm & 0xc7 != 0x04 || sib != 0x25 {
        return Ok(None);
    }
    let displacement_start = index + 3;
    let displacement_end = displacement_start + 4;
    let Some(displacement_bytes) = bytes.get(displacement_start..displacement_end) else {
        return Ok(None);
    };
    let displacement = i32::from_le_bytes(
        displacement_bytes
            .try_into()
            .expect("displacement length checked"),
    );
    let addr = fs_base.wrapping_add(displacement as i64 as u64);
    let reg = ((modrm >> 3) & 0x07) | if rex & 0x04 != 0 { 8 } else { 0 };
    if rex & 0x08 != 0 {
        let mut rhs_bytes = [0; 8];
        memory.read(addr, &mut rhs_bytes)?;
        let rhs = u64::from_le_bytes(rhs_bytes);
        let lhs = host_register64(&registers, reg)?;
        let result = lhs.wrapping_add(rhs);
        set_host_register64(&mut registers, reg, result)?;
        apply_add_flags64(&mut registers, lhs, rhs, result);
    } else {
        let mut rhs_bytes = [0; 4];
        memory.read(addr, &mut rhs_bytes)?;
        let rhs = u32::from_le_bytes(rhs_bytes);
        let lhs = host_register64(&registers, reg)? as u32;
        let result = lhs.wrapping_add(rhs);
        set_host_register64(&mut registers, reg, u64::from(result))?;
        apply_add_flags32(&mut registers, lhs, rhs, result);
    }
    registers.rip = registers
        .rip
        .checked_add(instruction.bytes.len() as u64)
        .ok_or(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        ))?;
    Ok(Some(registers))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn modrm_memory_offset(
    registers: &mcr_win::HostCpuRegisters,
    rex: u8,
    bytes: &[u8],
    modrm_index: usize,
) -> Result<Option<(u64, usize)>, GuestExecutionError> {
    let Some(&modrm) = bytes.get(modrm_index) else {
        return Ok(None);
    };
    let mode = modrm >> 6;
    if mode == 0b11 {
        return Ok(None);
    }
    let rm = modrm & 0x07;
    let mut index = modrm_index + 1;
    let mut offset = 0u64;
    let mut needs_disp32_without_base = false;
    if rm == 0x04 {
        let Some(&sib) = bytes.get(index) else {
            return Ok(None);
        };
        index += 1;
        let scale = 1u64 << (sib >> 6);
        let sib_index = (sib >> 3) & 0x07;
        if sib_index != 0x04 {
            let index_reg = sib_index | if rex & 0x02 != 0 { 8 } else { 0 };
            offset =
                offset.wrapping_add(host_register64(registers, index_reg)?.wrapping_mul(scale));
        }
        let base = sib & 0x07;
        if mode == 0 && base == 0x05 {
            needs_disp32_without_base = true;
        } else {
            let base_reg = base | if rex & 0x01 != 0 { 8 } else { 0 };
            offset = offset.wrapping_add(host_register64(registers, base_reg)?);
        }
    } else if mode == 0 && rm == 0x05 {
        return Ok(None);
    } else {
        let base_reg = rm | if rex & 0x01 != 0 { 8 } else { 0 };
        offset = offset.wrapping_add(host_register64(registers, base_reg)?);
    }

    let displacement = match mode {
        0 if needs_disp32_without_base => {
            let Some(bytes) = bytes.get(index..index + 4) else {
                return Ok(None);
            };
            index += 4;
            i64::from(i32::from_le_bytes(
                bytes.try_into().expect("disp32 length checked"),
            ))
        }
        0 => 0,
        1 => {
            let Some(&byte) = bytes.get(index) else {
                return Ok(None);
            };
            index += 1;
            i64::from(byte as i8)
        }
        2 => {
            let Some(bytes) = bytes.get(index..index + 4) else {
                return Ok(None);
            };
            index += 4;
            i64::from(i32::from_le_bytes(
                bytes.try_into().expect("disp32 length checked"),
            ))
        }
        _ => return Ok(None),
    };
    Ok(Some((offset.wrapping_add(displacement as u64), index)))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn fs_segment_prefix_index(bytes: &[u8]) -> Option<usize> {
    let mut index = 0usize;
    while bytes.get(index).copied() == Some(0x66) {
        index += 1;
    }
    (bytes.get(index).copied() == Some(0x64)).then_some(index)
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn host_register64(
    registers: &mcr_win::HostCpuRegisters,
    index: u8,
) -> Result<u64, GuestExecutionError> {
    match index {
        0 => Ok(registers.rax),
        1 => Ok(registers.rcx),
        2 => Ok(registers.rdx),
        3 => Ok(registers.rbx),
        4 => Ok(registers.rsp),
        5 => Ok(registers.rbp),
        6 => Ok(registers.rsi),
        7 => Ok(registers.rdi),
        8 => Ok(registers.r8),
        9 => Ok(registers.r9),
        10 => Ok(registers.r10),
        11 => Ok(registers.r11),
        12 => Ok(registers.r12),
        13 => Ok(registers.r13),
        14 => Ok(registers.r14),
        15 => Ok(registers.r15),
        _ => Err(GuestExecutionError::Memory(
            GuestMemoryError::InvalidAddress,
        )),
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn set_host_register64(
    registers: &mut mcr_win::HostCpuRegisters,
    index: u8,
    value: u64,
) -> Result<(), GuestExecutionError> {
    match index {
        0 => registers.rax = value,
        1 => registers.rcx = value,
        2 => registers.rdx = value,
        3 => registers.rbx = value,
        4 => registers.rsp = value,
        5 => registers.rbp = value,
        6 => registers.rsi = value,
        7 => registers.rdi = value,
        8 => registers.r8 = value,
        9 => registers.r9 = value,
        10 => registers.r10 = value,
        11 => registers.r11 = value,
        12 => registers.r12 = value,
        13 => registers.r13 = value,
        14 => registers.r14 = value,
        15 => registers.r15 = value,
        _ => {
            return Err(GuestExecutionError::Memory(
                GuestMemoryError::InvalidAddress,
            ));
        }
    }
    Ok(())
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn apply_add_flags64(registers: &mut mcr_win::HostCpuRegisters, lhs: u64, rhs: u64, result: u64) {
    const CF: u64 = 0x001;
    const PF: u64 = 0x004;
    const AF: u64 = 0x010;
    const ZF: u64 = 0x040;
    const SF: u64 = 0x080;
    const OF: u64 = 0x800;
    const STATUS_MASK: u64 = CF | PF | AF | ZF | SF | OF;

    let mut flags = registers.rflags & !STATUS_MASK;
    if result < lhs {
        flags |= CF;
    }
    if (result as u8).count_ones() % 2 == 0 {
        flags |= PF;
    }
    if (lhs ^ rhs ^ result) & 0x10 != 0 {
        flags |= AF;
    }
    if result == 0 {
        flags |= ZF;
    }
    if result & (1 << 63) != 0 {
        flags |= SF;
    }
    if (!(lhs ^ rhs) & (lhs ^ result) & (1 << 63)) != 0 {
        flags |= OF;
    }
    registers.rflags = flags;
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn apply_add_flags32(registers: &mut mcr_win::HostCpuRegisters, lhs: u32, rhs: u32, result: u32) {
    const CF: u64 = 0x001;
    const PF: u64 = 0x004;
    const AF: u64 = 0x010;
    const ZF: u64 = 0x040;
    const SF: u64 = 0x080;
    const OF: u64 = 0x800;
    const STATUS_MASK: u64 = CF | PF | AF | ZF | SF | OF;

    let mut flags = registers.rflags & !STATUS_MASK;
    if result < lhs {
        flags |= CF;
    }
    if (result as u8).count_ones() % 2 == 0 {
        flags |= PF;
    }
    if (lhs ^ rhs ^ result) & 0x10 != 0 {
        flags |= AF;
    }
    if result == 0 {
        flags |= ZF;
    }
    if result & (1 << 31) != 0 {
        flags |= SF;
    }
    if (!(lhs ^ rhs) & (lhs ^ result) & (1 << 31)) != 0 {
        flags |= OF;
    }
    registers.rflags = flags;
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn apply_sub_flags64(registers: &mut mcr_win::HostCpuRegisters, lhs: u64, rhs: u64, result: u64) {
    const CF: u64 = 0x001;
    const PF: u64 = 0x004;
    const AF: u64 = 0x010;
    const ZF: u64 = 0x040;
    const SF: u64 = 0x080;
    const OF: u64 = 0x800;
    const STATUS_MASK: u64 = CF | PF | AF | ZF | SF | OF;

    let mut flags = registers.rflags & !STATUS_MASK;
    if lhs < rhs {
        flags |= CF;
    }
    if (result as u8).count_ones() % 2 == 0 {
        flags |= PF;
    }
    if (lhs ^ rhs ^ result) & 0x10 != 0 {
        flags |= AF;
    }
    if result == 0 {
        flags |= ZF;
    }
    if result & (1 << 63) != 0 {
        flags |= SF;
    }
    if ((lhs ^ rhs) & (lhs ^ result) & (1 << 63)) != 0 {
        flags |= OF;
    }
    registers.rflags = flags;
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn apply_sub_flags8(registers: &mut mcr_win::HostCpuRegisters, lhs: u8, rhs: u8, result: u8) {
    const CF: u64 = 0x001;
    const PF: u64 = 0x004;
    const AF: u64 = 0x010;
    const ZF: u64 = 0x040;
    const SF: u64 = 0x080;
    const OF: u64 = 0x800;
    const STATUS_MASK: u64 = CF | PF | AF | ZF | SF | OF;

    let mut flags = registers.rflags & !STATUS_MASK;
    if lhs < rhs {
        flags |= CF;
    }
    if result.count_ones() % 2 == 0 {
        flags |= PF;
    }
    if (lhs ^ rhs ^ result) & 0x10 != 0 {
        flags |= AF;
    }
    if result == 0 {
        flags |= ZF;
    }
    if result & (1 << 7) != 0 {
        flags |= SF;
    }
    if ((lhs ^ rhs) & (lhs ^ result) & (1 << 7)) != 0 {
        flags |= OF;
    }
    registers.rflags = flags;
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn apply_sub_flags32(registers: &mut mcr_win::HostCpuRegisters, lhs: u32, rhs: u32, result: u32) {
    const CF: u64 = 0x001;
    const PF: u64 = 0x004;
    const AF: u64 = 0x010;
    const ZF: u64 = 0x040;
    const SF: u64 = 0x080;
    const OF: u64 = 0x800;
    const STATUS_MASK: u64 = CF | PF | AF | ZF | SF | OF;

    let mut flags = registers.rflags & !STATUS_MASK;
    if lhs < rhs {
        flags |= CF;
    }
    if (result as u8).count_ones() % 2 == 0 {
        flags |= PF;
    }
    if (lhs ^ rhs ^ result) & 0x10 != 0 {
        flags |= AF;
    }
    if result == 0 {
        flags |= ZF;
    }
    if result & (1 << 31) != 0 {
        flags |= SF;
    }
    if ((lhs ^ rhs) & (lhs ^ result) & (1 << 31)) != 0 {
        flags |= OF;
    }
    registers.rflags = flags;
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
