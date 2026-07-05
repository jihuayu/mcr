use crate::{
    BlockDecoder, BlockTerminator, DecodedFlowControl, DecodedMnemonic, ExecutionError, GuestBlock,
    GuestMemoryOperandAccess, GuestMemoryOperandError, GuestRegisters, LinearInstructionScanner,
    SameIsaExecutionCore, SyscallSite, TrampolineCore, decode_native_fault_instruction,
    native_patch::{
        ExecutableSyscallPatch, NativeImagePatchKey, NativePatchMetadata,
        executable_syscall_patch_writes, load_persistent_native_patch_metadata_from_dir,
        scan_executable_native_patch_range, store_persistent_native_patch_metadata_in_dir,
    },
    syscall_instruction_sites,
};
use std::collections::BTreeMap;

use mcr_sys::{LinuxErrno, Syscall, SyscallReturn};

#[derive(Default)]
struct TestGuestMemory {
    bytes: BTreeMap<u64, u8>,
    writable: bool,
}

impl TestGuestMemory {
    fn with_bytes(address: u64, bytes: &[u8]) -> Self {
        let mut memory = Self {
            bytes: BTreeMap::new(),
            writable: true,
        };
        memory.write(address, bytes);
        memory
    }

    fn read<const N: usize>(&self, address: u64) -> [u8; N] {
        let mut bytes = [0; N];
        for (offset, byte) in bytes.iter_mut().enumerate() {
            *byte = *self
                .bytes
                .get(&(address + offset as u64))
                .expect("test byte should be mapped");
        }
        bytes
    }

    fn write(&mut self, address: u64, bytes: &[u8]) {
        for (offset, byte) in bytes.iter().copied().enumerate() {
            self.bytes.insert(address + offset as u64, byte);
        }
    }

    fn read_u64(&self, address: u64) -> u64 {
        u64::from_le_bytes(self.read(address))
    }
}

impl GuestMemoryOperandAccess for TestGuestMemory {
    fn read_memory_operand(
        &self,
        address: u64,
        buffer: &mut [u8],
    ) -> Result<(), GuestMemoryOperandError> {
        for (offset, byte) in buffer.iter_mut().enumerate() {
            *byte = *self
                .bytes
                .get(&(address + offset as u64))
                .ok_or(GuestMemoryOperandError::NotMapped)?;
        }
        Ok(())
    }

    fn write_memory_operand(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), GuestMemoryOperandError> {
        if !self.writable {
            return Err(GuestMemoryOperandError::AccessDenied);
        }
        self.write(address, bytes);
        Ok(())
    }
}

fn unique_native_patch_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("mcr-jit-{name}-{}-{nanos}", std::process::id()))
}

#[test]
fn package_name_is_stable() {
    assert_eq!(crate::CRATE_NAME, "mcr-jit");
}

#[test]
fn decoder_identifies_syscall_instruction_site() {
    let block = GuestBlock::new(
        &[
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax,1
            0x0f, 0x05, // syscall
            0xcc, // int3, outside the decoded block
        ],
        0x400000,
    );

    let decoded = BlockDecoder::new().decode(block).expect("decode block");

    assert_eq!(decoded.instructions().len(), 2);
    assert_eq!(decoded.instructions()[1].mnemonic, DecodedMnemonic::Syscall);
    assert_eq!(
        decoded.terminator(),
        &BlockTerminator::Syscall(crate::SyscallSite {
            rip: 0x400007,
            next_rip: 0x400009,
        })
    );
}

#[test]
fn syscall_site_scan_ignores_immediate_bytes() {
    let sites = syscall_instruction_sites(
        &[
            0xc7, 0x04, 0x24, 0x00, 0x0f, 0x05, 0x00, // mov dword ptr [rsp],0x50f00
            0x0f, 0x05, // syscall
        ],
        0x401000,
    );

    assert_eq!(
        sites,
        [SyscallSite {
            rip: 0x401007,
            next_rip: 0x401009
        }]
    );
}

#[test]
fn syscall_site_scan_skips_candidate_free_ranges() {
    let sites = syscall_instruction_sites(&[0x90; 1024], 0x401000);

    assert!(sites.is_empty());
}

#[test]
fn native_patch_scan_and_syscall_write_plan_live_in_jit() {
    let patches = scan_executable_native_patch_range(
        0x401000,
        0x401007,
        vec![
            0xe8, 0x0f, 0x05, 0xfe, 0xff, // call with 0f 05 in displacement
            0x0f, 0x05, // real syscall instruction
        ],
        0,
    );

    assert_eq!(patches.scanned_ranges, [(0x401000, 0x401007)]);
    assert_eq!(
        patches.syscall_patches,
        [ExecutableSyscallPatch { address: 0x401005 }]
    );
    assert_eq!(
        executable_syscall_patch_writes(&patches.syscall_patches).collect::<Vec<_>>(),
        [(0x401005, [0xcc, 0x90])]
    );
}

#[test]
fn native_patch_metadata_cache_round_trips_inside_jit() {
    let dir = unique_native_patch_dir("cache-roundtrip");
    let _ = std::fs::remove_dir_all(&dir);
    let key = NativeImagePatchKey {
        hash: 0x1234,
        executable_len: 0x2000,
    };
    let metadata = NativePatchMetadata {
        scanned_ranges: vec![(0x401000, 0x402000)],
        syscall_patches: vec![ExecutableSyscallPatch { address: 0x401123 }],
        #[cfg(all(windows, target_arch = "x86_64"))]
        fs_relative_patches: BTreeMap::new(),
    };

    store_persistent_native_patch_metadata_in_dir(&key, &metadata, 0x400000, &dir).unwrap();
    let loaded = load_persistent_native_patch_metadata_from_dir(&key, 0x600000, &dir)
        .unwrap()
        .expect("metadata should load");

    assert_eq!(loaded.scanned_ranges, [(0x601000, 0x602000)]);
    assert_eq!(
        loaded.syscall_patches,
        [ExecutableSyscallPatch { address: 0x601123 }]
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn native_fault_instruction_decodes_memory_operand() {
    let instruction =
        decode_native_fault_instruction(&[0x48, 0x8b, 0x40, 0x28, 0x90], 0x7000_0075_1bd6)
            .expect("fault instruction should decode");

    assert_eq!(instruction.rip, 0x7000_0075_1bd6);
    assert_eq!(instruction.bytes, [0x48, 0x8b, 0x40, 0x28]);
    assert!(
        instruction.decoded.contains("code=Mov_r64_rm64"),
        "{}",
        instruction.decoded
    );
    assert!(
        instruction
            .decoded
            .contains("mem(seg=DS,base=RAX,index=None,scale=1,disp=0x28)"),
        "{}",
        instruction.decoded
    );
}

#[test]
fn decoder_stops_at_control_flow_before_later_syscall() {
    let block = GuestBlock::new(
        &[
            0xeb, 0x02, // jmp +2
            0x0f, 0x05, // syscall outside this basic block
        ],
        0x401000,
    );

    let decoded = BlockDecoder::new().decode(block).expect("decode block");

    assert_eq!(decoded.instructions().len(), 1);
    assert_eq!(
        decoded.terminator(),
        &BlockTerminator::ControlFlow {
            rip: 0x401000,
            flow: DecodedFlowControl::UnconditionalBranch,
        }
    );
    assert_eq!(decoded.syscall_site(), None);
}

#[test]
fn decoder_reports_invalid_instruction_with_guest_rip() {
    let error = BlockDecoder::new()
        .decode(GuestBlock::new(&[0xc4], 0x402000))
        .expect_err("truncated vex prefix is invalid");

    assert_eq!(
        error,
        crate::DecodeError::InvalidInstruction { rip: 0x402000 }
    );
}

#[test]
fn decoder_treats_ud2_as_exception_terminator() {
    let decoded = BlockDecoder::new()
        .decode(GuestBlock::new(&[0x0f, 0x0b], 0x402100))
        .expect("ud2 decodes as an exception instruction");

    assert_eq!(
        decoded.terminator(),
        &BlockTerminator::ControlFlow {
            rip: 0x402100,
            flow: DecodedFlowControl::Exception,
        }
    );
}

#[test]
fn linear_scanner_ignores_syscall_bytes_inside_instruction_operands() {
    let instructions = LinearInstructionScanner::new().scan(GuestBlock::new(
        &[
            0xe8, 0x0f, 0x05, 0xfe, 0xff, // call with 0f 05 in displacement
            0x0f, 0x05, // real syscall instruction
        ],
        0x8149cc,
    ));
    let syscall_rips = instructions
        .iter()
        .filter_map(|instruction| {
            (instruction.mnemonic == DecodedMnemonic::Syscall).then_some(instruction.rip)
        })
        .collect::<Vec<_>>();

    assert_eq!(syscall_rips, [0x8149d1]);
}

#[test]
fn trampoline_preserves_guest_state_and_applies_linux_return_registers() {
    let site = crate::SyscallSite {
        rip: 0x500010,
        next_rip: 0x500012,
    };
    let mut registers = GuestRegisters {
        rax: Syscall::Write.number().raw(),
        rbx: 0xb0b,
        rcx: 0xc0c,
        rdx: 3,
        rsi: 0x600000,
        rdi: 1,
        rbp: 0xb0b0,
        rsp: 0x700000,
        r8: 5,
        r9: 6,
        r10: 4,
        r11: 0x1111,
        r12: 0x1212,
        r13: 0x1313,
        r14: 0x1414,
        r15: 0x1515,
        rip: site.rip,
        fs_base: 0,
        rflags: 0x202,
    };
    let original = registers;
    let mut captured = None;
    let mut trampoline = TrampolineCore::new(10, 11, |context: mcr_sys::GuestContext| {
        captured = Some(context);
        SyscallReturn::success(3).encode_u64()
    });

    trampoline.enter_syscall(&mut registers, site);

    let context = captured.expect("dispatcher called");
    assert_eq!(context.pid, 10);
    assert_eq!(context.tid, 11);
    assert_eq!(context.registers.rax, Syscall::Write.number().raw());
    assert_eq!(context.registers.args().raw(), [1, 0x600000, 3, 4, 5, 6]);
    assert_eq!(context.registers.rip, site.rip);

    assert_eq!(registers.rax, 3);
    assert_eq!(registers.rip, site.next_rip);
    assert_eq!(registers.rcx, site.next_rip);
    assert_eq!(registers.r11, original.rflags);
    assert_eq!(registers.rbx, original.rbx);
    assert_eq!(registers.rbp, original.rbp);
    assert_eq!(registers.rsp, original.rsp);
    assert_eq!(registers.r12, original.r12);
    assert_eq!(registers.r13, original.r13);
    assert_eq!(registers.r14, original.r14);
    assert_eq!(registers.r15, original.r15);
}

#[test]
fn execution_core_decodes_syscall_and_invokes_dispatcher_callback() {
    let block = GuestBlock::new(
        &[
            0x48, 0xc7, 0xc0, 0x27, 0x00, 0x00, 0x00, // mov rax,39
            0x0f, 0x05, // syscall
        ],
        0x410000,
    );
    let mut registers = GuestRegisters {
        rax: Syscall::Getpid.number().raw(),
        rdi: 0x10,
        rsi: 0x20,
        rdx: 0x30,
        r10: 0x40,
        r8: 0x50,
        r9: 0x60,
        rip: block.rip(),
        rflags: 0x246,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    let decoded = SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall block");

    assert_eq!(
        decoded.syscall_site(),
        Some(crate::SyscallSite {
            rip: 0x410007,
            next_rip: 0x410009,
        })
    );
    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x410009);
}

#[test]
fn execution_core_returns_syscall_trap_without_dispatching() {
    let block = GuestBlock::new(
        &[
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax,1
            0x48, 0xc7, 0xc7, 0x02, 0x00, 0x00, 0x00, // mov rdi,2
            0x48, 0xc7, 0xc6, 0x34, 0x12, 0x00, 0x00, // mov rsi,0x1234
            0x48, 0xc7, 0xc2, 0x05, 0x00, 0x00, 0x00, // mov rdx,5
            0x0f, 0x05, // syscall
        ],
        0x411000,
    );
    let registers = GuestRegisters {
        rax: Syscall::Getpid.number().raw(),
        rdi: 0x10,
        rsi: 0x20,
        rdx: 0x30,
        r10: 0x40,
        r8: 0x50,
        r9: 0x60,
        rip: block.rip(),
        rflags: 0x246,
        ..GuestRegisters::default()
    };
    let mut dispatcher_called = false;

    let trap = {
        let _trampoline = TrampolineCore::new(42, 43, |_: mcr_sys::GuestContext| {
            dispatcher_called = true;
            SyscallReturn::success(4242).encode_u64()
        });
        SameIsaExecutionCore::new()
            .execute_to_syscall_trap(block, registers)
            .expect("execute to syscall trap")
    };

    assert!(!dispatcher_called);
    assert_eq!(
        trap.site(),
        crate::SyscallSite {
            rip: 0x41101c,
            next_rip: 0x41101e,
        }
    );
    assert_eq!(trap.decoded().syscall_site(), Some(trap.site()));
    assert_eq!(
        trap.registers().syscall_registers().args().raw(),
        [2, 0x1234, 5, 0x40, 0x50, 0x60]
    );
    assert_eq!(
        trap.registers().syscall_registers().rax,
        Syscall::Write.number().raw()
    );
    assert_eq!(trap.registers().rip, trap.site().rip);
    assert_eq!(registers.rax, Syscall::Getpid.number().raw());
    assert_eq!(registers.rip, block.rip());
}

#[test]
fn execution_core_follows_direct_jump_to_syscall() {
    let block = GuestBlock::new(
        &[
            0xeb, 0x07, // jmp +7
            0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, // skipped mov rax,0
            0x48, 0xc7, 0xc0, 0x27, 0x00, 0x00, 0x00, // mov rax,39
            0x0f, 0x05, // syscall
        ],
        0x430000,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x246,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall behind jump");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x430012);
}

#[test]
fn execution_core_starts_at_register_rip_inside_guest_block() {
    let block = GuestBlock::new(
        &[
            0x0f, 0x0b, // ud2 padding before current rip
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
        ],
        0x430100,
    );
    let mut registers = GuestRegisters {
        rip: 0x430102,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall from register rip inside loaded guest block");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x430109);
}

#[test]
fn execution_core_follows_indirect_register_jump_to_syscall() {
    let block = GuestBlock::new(
        &[
            0x48, 0xb8, 0x13, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x430013
            0xff, 0xe0, // jmp rax
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x0f, 0x05, // skipped syscall
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
        ],
        0x430000,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x246,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall behind indirect jump");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x43001a);
}

#[test]
fn execution_core_follows_indirect_register_call_and_return_to_syscall() {
    let block = GuestBlock::new(
        &[
            0x48, 0xb8, 0x13, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax,0x430013
            0xff, 0xd0, // call rax
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
            0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax,60
            0xc3, // ret
        ],
        0x430000,
    );
    let registers = GuestRegisters {
        rip: block.rip(),
        rsp: 0x700000,
        rflags: 0x246,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });
    let mut memory = TestGuestMemory::with_bytes(0x6ffff8, &[0; 8]);

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute syscall behind indirect call");
    let mut trapped_registers = trap.registers();
    trampoline.enter_syscall(&mut trapped_registers, trap.site());

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(trapped_registers.rax, 4242);
    assert_eq!(trapped_registers.rip, 0x430013);
    assert_eq!(memory.read_u64(0x6ffff8), 0x43000c);
}

#[test]
fn execution_core_follows_zero_flag_conditional_branch_to_syscall() {
    let block = GuestBlock::new(
        &[
            0x31, 0xc0, // xor eax,eax
            0x85, 0xc0, // test eax,eax
            0x74, 0x07, // je +7
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x90, 0x90, // skipped nops
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
        ],
        0x440000,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x246,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall behind conditional jump");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x440014);
}

#[test]
fn execution_core_falls_through_untaken_conditional_branch_to_syscall() {
    let block = GuestBlock::new(
        &[
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
            0x85, 0xc0, // test eax,eax
            0x74, 0x07, // je +7, not taken
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x0f, 0x05, // syscall
        ],
        0x450000,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x246,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall after untaken conditional jump");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x450010);
}

#[test]
fn execution_core_sets_syscall_registers_with_basic_register_arithmetic() {
    let block = GuestBlock::new(
        &[
            0x48, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // mov rbx,-1
            0x89, 0xdf, // mov edi,ebx
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax,2
            0x83, 0xe8, 0x01, // sub eax,1
            0xba, 0x02, 0x00, 0x00, 0x00, // mov edx,2
            0xb9, 0x08, 0x00, 0x00, 0x00, // mov ecx,8
            0x01, 0xca, // add edx,ecx
            0x83, 0xea, 0x03, // sub edx,3
            0x48, 0x8d, 0x1d, 0x23, 0x01, 0x00, 0x00, // lea rbx,[rip+0x123]
            0x48, 0x89, 0xde, // mov rsi,rbx
            0x48, 0x83, 0xc6, 0x08, // add rsi,8
            0x48, 0x83, 0xee, 0x08, // sub rsi,8
            0x0f, 0x05, // syscall
        ],
        0x460000,
    );
    let mut registers = GuestRegisters {
        rdi: 0xf000_0000_0000_0000,
        rip: block.rip(),
        rflags: 0x246,
        ..GuestRegisters::default()
    };
    let mut captured = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured = Some(context.registers);
        SyscallReturn::success(7).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall registers built by register arithmetic");

    let syscall_registers = captured.expect("dispatcher called");
    assert_eq!(syscall_registers.rax, Syscall::Write.number().raw());
    assert_eq!(
        syscall_registers.args().raw(),
        [0xffff_ffff, 0x46014d, 7, 0, 0, 0]
    );
    assert_eq!(registers.rax, 7);
    assert_eq!(registers.rip, 0x460037);
}

#[test]
fn execution_core_executes_register_bitwise_logic_and_immediate_test() {
    let block = GuestBlock::new(
        &[
            0xb8, 0xf0, 0xf0, 0xf0, 0xf0, // mov eax,0xf0f0f0f0
            0x25, 0xf0, 0x0f, 0xf0, 0x0f, // and eax,0x0ff00ff0
            0x0d, 0x0f, 0x00, 0x0f, 0x00, // or eax,0x000f000f
            0x35, 0xff, 0x00, 0xff, 0x00, // xor eax,0x00ff00ff
            0x48, 0xc7, 0xc7, 0xf0, 0xff, 0xff, 0xff, // mov rdi,-16
            0x48, 0x83, 0xe7, 0xf8, // and rdi,-8
            0x48, 0x83, 0xcf, 0x0f, // or rdi,0xf
            0x48, 0x81, 0xf7, 0xff, 0x00, 0x00, 0x00, // xor rdi,0xff
            0x48, 0xf7, 0xc7, 0xff, 0x00, 0x00, 0x00, // test rdi,0xff
            0x74, 0x07, // je success
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x0f, 0x05, // skipped syscall
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
        ],
        0x460080,
    );
    let registers = GuestRegisters {
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::default();

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute register bitwise logic before syscall");

    assert_eq!(trap.registers().rax, Syscall::Getpid.number().raw());
    assert_eq!(trap.registers().rdi, 0xffff_ffff_ffff_ff00);
    assert_eq!(trap.site().rip, 0x4600bf);
}

#[test]
fn execution_core_executes_memory_bitwise_logic_and_immediate_test() {
    let block = GuestBlock::new(
        &[
            0x81, 0x23, 0x0f, 0x0f, 0x0f, 0x0f, // and dword ptr [rbx],0x0f0f0f0f
            0x81, 0x0b, 0x00, 0x00, 0x00, 0xf0, // or dword ptr [rbx],0xf0000000
            0x31, 0x03, // xor dword ptr [rbx],eax
            0xf7, 0x03, 0xff, 0x00, 0x00, 0x00, // test dword ptr [rbx],0xff
            0x74, 0x07, // je success
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x0f, 0x05, // skipped syscall
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
        ],
        0x460100,
    );
    let registers = GuestRegisters {
        rax: 0xf000_000f,
        rbx: 0x701000,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::with_bytes(0x701000, &0xff00_00ff_u32.to_le_bytes());

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute memory bitwise logic before syscall");

    assert_eq!(u32::from_le_bytes(memory.read(0x701000)), 0x0f00_0000);
    assert_eq!(trap.registers().rax, Syscall::Getpid.number().raw());
    assert_eq!(trap.site().rip, 0x460122);
}

#[test]
fn execution_core_loads_and_stores_64_bit_memory_mov_operands() {
    let block = GuestBlock::new(
        &[
            0x48, 0x8b, 0x43, 0x08, // mov rax,[rbx+8]
            0x48, 0x89, 0x43, 0x10, // mov [rbx+0x10],rax
            0x0f, 0x05, // syscall
        ],
        0x461000,
    );
    let registers = GuestRegisters {
        rbx: 0x700000,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory =
        TestGuestMemory::with_bytes(0x700008, &0x0708_091a_2b3c_4d5e_u64.to_le_bytes());

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute memory movs before syscall");

    assert_eq!(trap.registers().rax, 0x0708_091a_2b3c_4d5e);
    assert_eq!(memory.read_u64(0x700010), 0x0708_091a_2b3c_4d5e);
    assert_eq!(trap.site().rip, 0x461008);
}

#[test]
fn execution_core_applies_fs_base_to_memory_operands() {
    let block = GuestBlock::new(
        &[
            0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // mov rax,fs:[0x28]
            0x0f, 0x05, // syscall
        ],
        0x461080,
    );
    let registers = GuestRegisters {
        fs_base: 0x7000_0020_0000,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::with_bytes(
        0x7000_0020_0028,
        &Syscall::Getpid.number().raw().to_le_bytes(),
    );

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute fs-relative load before syscall");

    assert_eq!(trap.registers().rax, Syscall::Getpid.number().raw());
    assert_eq!(trap.site().rip, 0x461089);
}

#[test]
fn execution_core_zero_extends_32_bit_memory_load_and_writes_four_bytes() {
    let block = GuestBlock::new(
        &[
            0x8b, 0x43, 0x04, // mov eax,[rbx+4]
            0x89, 0x43, 0x0c, // mov [rbx+0xc],eax
            0x0f, 0x05, // syscall
        ],
        0x461100,
    );
    let registers = GuestRegisters {
        rax: 0xffff_ffff_ffff_ffff,
        rbx: 0x710000,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::with_bytes(0x710004, &0x89ab_cdef_u32.to_le_bytes());
    memory.write(0x71000c, &[0xaa; 8]);

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute 32-bit memory movs before syscall");

    assert_eq!(trap.registers().rax, 0x89ab_cdef);
    assert_eq!(
        memory.read::<8>(0x71000c),
        [0xef, 0xcd, 0xab, 0x89, 0xaa, 0xaa, 0xaa, 0xaa]
    );
}

#[test]
fn execution_core_zero_and_sign_extends_narrow_memory_operands() {
    let block = GuestBlock::new(
        &[
            0x0f, 0xb6, 0x03, // movzx eax, byte ptr [rbx]
            0x4c, 0x0f, 0xb7, 0x43, 0x01, // movzx r8, word ptr [rbx+1]
            0x0f, 0xbe, 0x4b, 0x03, // movsx ecx, byte ptr [rbx+3]
            0x48, 0x0f, 0xbf, 0x53, 0x04, // movsx rdx, word ptr [rbx+4]
            0x48, 0x63, 0x73, 0x06, // movsxd rsi, dword ptr [rbx+6]
            0x48, 0x98, // cdqe
            0x0f, 0x05, // syscall
        ],
        0x461180,
    );
    let registers = GuestRegisters {
        rax: 0xffff_ffff_ffff_ffff,
        rbx: 0x711000,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::with_bytes(
        0x711000,
        &[0x7f, 0x34, 0x12, 0x80, 0x00, 0x80, 0xff, 0xff, 0xff, 0xff],
    );

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute narrow extension loads before syscall");

    assert_eq!(trap.registers().rax, 0x7f);
    assert_eq!(trap.registers().r8, 0x1234);
    assert_eq!(trap.registers().rcx, 0xffff_ff80);
    assert_eq!(trap.registers().rdx, 0xffff_ffff_ffff_8000);
    assert_eq!(trap.registers().rsi, 0xffff_ffff_ffff_ffff);
    assert_eq!(trap.site().rip, 0x461197);
}

#[test]
fn execution_core_zero_and_sign_extends_narrow_register_operands() {
    let block = GuestBlock::new(
        &[
            0x0f, 0xb6, 0xc0, // movzx eax,al
            0x4c, 0x0f, 0xb7, 0xc1, // movzx r8,cx
            0x0f, 0xbe, 0xcb, // movsx ecx,bl
            0x48, 0x0f, 0xbf, 0xd2, // movsx rdx,dx
            0x48, 0x63, 0xf6, // movsxd rsi,esi
            0x0f, 0x05, // syscall
        ],
        0x4611c0,
    );
    let registers = GuestRegisters {
        rax: 0xffff_ffff_ffff_12fe,
        rbx: 0x80,
        rcx: 0xabcd,
        rdx: 0x8000,
        rsi: 0xffff_ffff,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::default();

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute narrow register extensions before syscall");

    assert_eq!(trap.registers().rax, 0xfe);
    assert_eq!(trap.registers().r8, 0xabcd);
    assert_eq!(trap.registers().rcx, 0xffff_ff80);
    assert_eq!(trap.registers().rdx, 0xffff_ffff_ffff_8000);
    assert_eq!(trap.registers().rsi, 0xffff_ffff_ffff_ffff);
    assert_eq!(trap.site().rip, 0x4611d1);
}

#[test]
fn execution_core_executes_narrow_mov_memory_and_register_operands() {
    let block = GuestBlock::new(
        &[
            0xc6, 0x03, 0x41, // mov byte ptr [rbx],0x41
            0x66, 0xc7, 0x43, 0x01, 0x80, 0x7f, // mov word ptr [rbx+1],0x7f80
            0x8a, 0x03, // mov al,byte ptr [rbx]
            0x66, 0x8b, 0x4b, 0x01, // mov cx,word ptr [rbx+1]
            0x88, 0x4b, 0x03, // mov byte ptr [rbx+3],cl
            0x66, 0x89, 0x43, 0x04, // mov word ptr [rbx+4],ax
            0x0f, 0x05, // syscall
        ],
        0x4611e0,
    );
    let registers = GuestRegisters {
        rax: 0xffff_ffff_ffff_0000,
        rbx: 0x711800,
        rcx: 0xffff_ffff_ffff_0000,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::with_bytes(0x711800, &[0; 8]);

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute narrow mov operands before syscall");

    assert_eq!(trap.registers().rax, 0xffff_ffff_ffff_0041);
    assert_eq!(trap.registers().rcx, 0xffff_ffff_ffff_7f80);
    assert_eq!(
        memory.read::<8>(0x711800),
        [0x41, 0x80, 0x7f, 0x80, 0x41, 0x00, 0x00, 0x00]
    );
    assert_eq!(trap.site().rip, 0x4611f6);
}

#[test]
fn execution_core_branches_on_narrow_memory_cmp_and_test() {
    let block = GuestBlock::new(
        &[
            0x80, 0x3b, 0x41, // cmp byte ptr [rbx],0x41
            0x75, 0x15, // jne exit
            0xf6, 0x43, 0x01, 0x80, // test byte ptr [rbx+1],0x80
            0x74, 0x0f, // je exit
            0x66, 0x81, 0x7b, 0x01, 0x80, 0x7f, // cmp word ptr [rbx+1],0x7f80
            0x75, 0x07, // jne exit
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
            0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax,60
            0x0f, 0x05, // syscall
        ],
        0x461220,
    );
    let registers = GuestRegisters {
        rbx: 0x712000,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::with_bytes(0x712000, &[0x41, 0x80, 0x7f]);

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute narrow cmp/test branches before syscall");

    assert_eq!(trap.registers().rax, Syscall::Getpid.number().raw());
    assert_eq!(trap.site().rip, 0x461238);
}

#[test]
fn execution_core_resolves_rip_relative_and_scaled_index_memory_addresses() {
    let block = GuestBlock::new(
        &[
            0x48, 0x8b, 0x05, 0xf9, 0x01, 0x00, 0x00, // mov rax,[rip+0x1f9]
            0x48, 0x89, 0x54, 0x73, 0x10, // mov [rbx+rsi*2+0x10],rdx
            0x0f, 0x05, // syscall
        ],
        0x461200,
    );
    let registers = GuestRegisters {
        rbx: 0x720000,
        rsi: 4,
        rdx: 0x1122_3344_5566_7788,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory =
        TestGuestMemory::with_bytes(0x461400, &0x8877_6655_4433_2211_u64.to_le_bytes());

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute rip-relative load and scaled-index store");

    assert_eq!(trap.registers().rax, 0x8877_6655_4433_2211);
    assert_eq!(memory.read_u64(0x720018), 0x1122_3344_5566_7788);
}

#[test]
fn execution_core_pushes_and_pops_64_bit_register_values() {
    let block = GuestBlock::new(
        &[
            0x53, // push rbx
            0x58, // pop rax
            0x0f, 0x05, // syscall
        ],
        0x461280,
    );
    let registers = GuestRegisters {
        rbx: 0x8877_6655_4433_2211,
        rsp: 0x730008,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::with_bytes(0x730000, &[0; 16]);

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute push and pop before syscall");

    assert_eq!(trap.registers().rax, 0x8877_6655_4433_2211);
    assert_eq!(trap.registers().rsp, 0x730008);
    assert_eq!(memory.read_u64(0x730000), 0x8877_6655_4433_2211);
}

#[test]
fn execution_core_pushes_sign_extended_immediate_values() {
    let block = GuestBlock::new(
        &[
            0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
            0x6a, 0xff, // push -1
            0x5f, // pop rdi
            0x5e, // pop rsi
            0x0f, 0x05, // syscall
        ],
        0x461420,
    );
    let registers = GuestRegisters {
        rsp: 0x724010,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::with_bytes(0x724000, &[0; 16]);

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("push immediate values before syscall");

    assert_eq!(trap.registers().rdi, u64::MAX);
    assert_eq!(trap.registers().rsi, 0x1234_5678);
    assert_eq!(trap.registers().rsp, 0x724010);
    assert_eq!(trap.site().rip, 0x461429);
}

#[test]
fn execution_core_push_write_fault_stops_before_syscall() {
    let block = GuestBlock::new(
        &[
            0x50, // push rax
            0x0f, 0x05, // syscall
        ],
        0x461290,
    );
    let registers = GuestRegisters {
        rax: 0x1234,
        rsp: 0x740008,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::default();

    let error = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect_err("write-denied stack push should stop before syscall");

    assert_eq!(
        error,
        ExecutionError::MemoryOperand {
            rip: 0x461290,
            address: 0x740000,
            access: crate::GuestMemoryOperandAccessKind::Write,
            error: GuestMemoryOperandError::AccessDenied,
        }
    );
}

#[test]
fn execution_core_follows_direct_call_and_return_to_syscall() {
    let block = GuestBlock::new(
        &[
            0xe8, 0x08, 0x00, 0x00, 0x00, // call 0x461405
            0x0f, 0x05, // syscall after ret
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0xc3, // ret
        ],
        0x461400,
    );
    let registers = GuestRegisters {
        rsp: 0x750008,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::with_bytes(0x750000, &[0; 16]);

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect("execute call/ret before syscall");

    assert_eq!(trap.site().rip, 0x461405);
    assert_eq!(trap.registers().rax, Syscall::Getpid.number().raw());
    assert_eq!(trap.registers().rsp, 0x750008);
    assert_eq!(memory.read_u64(0x750000), 0x461405);
}

#[test]
fn execution_core_call_stack_fault_stops_before_target() {
    let block = GuestBlock::new(
        &[
            0xe8, 0x01, 0x00, 0x00, 0x00, // call 0x461506
            0x0f, 0x05, // skipped
            0xc3, // ret
        ],
        0x461500,
    );
    let registers = GuestRegisters {
        rsp: 0x760008,
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::default();

    let error = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect_err("unmapped call stack push should stop before target");

    assert_eq!(
        error,
        ExecutionError::MemoryOperand {
            rip: 0x461500,
            address: 0x760000,
            access: crate::GuestMemoryOperandAccessKind::Write,
            error: GuestMemoryOperandError::AccessDenied,
        }
    );
}

#[test]
fn execution_core_surfaces_memory_operand_fault_without_dispatching() {
    let block = GuestBlock::new(
        &[
            0x48, 0x8b, 0x00, // mov rax,[rax]
            0x0f, 0x05, // syscall
        ],
        0x461300,
    );
    let registers = GuestRegisters {
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut memory = TestGuestMemory::default();

    let error = SameIsaExecutionCore::new()
        .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
        .expect_err("unmapped load should stop before syscall");

    assert_eq!(
        error,
        ExecutionError::MemoryOperand {
            rip: 0x461300,
            address: 0,
            access: crate::GuestMemoryOperandAccessKind::Read,
            error: GuestMemoryOperandError::NotMapped,
        }
    );
}

#[test]
fn execution_core_uses_cmp_zero_flag_for_conditional_branch() {
    let block = GuestBlock::new(
        &[
            0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax,5
            0x83, 0xf8, 0x05, // cmp eax,5
            0x74, 0x07, // je +7
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x90, 0x90, // skipped nops
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
        ],
        0x470000,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x206,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall behind cmp/je");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x470018);
}

#[test]
fn execution_core_uses_test64_zero_flag_for_conditional_branch() {
    let block = GuestBlock::new(
        &[
            0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi,1
            0x48, 0x85, 0xff, // test rdi,rdi
            0x75, 0x07, // jne +7
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x90, 0x90, // skipped nops
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
        ],
        0x471000,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x246,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall behind test64/jne");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x47101a);
}

#[test]
fn execution_core_branches_on_negative_errno_with_test64_sign_flag() {
    let block = GuestBlock::new(
        &[
            0x48, 0xb8, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // mov rax,-2
            0x48, 0x85, 0xc0, // test rax,rax
            0x78, 0x07, // js +7
            0xb8, 0x27, 0x00, 0x00, 0x00, // skipped mov eax,39
            0x90, 0x90, // skipped nops
            0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax,60
            0x0f, 0x05, // syscall
        ],
        0x471100,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x202,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(0).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute error syscall behind test64/js");

    assert_eq!(captured_number, Some(Syscall::EXIT));
    assert_eq!(registers.rip, 0x47111d);
}

#[test]
fn execution_core_uses_cmp32_signed_flags_for_jl_and_jge() {
    let block = GuestBlock::new(
        &[
            0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax,-1
            0x83, 0xf8, 0x01, // cmp eax,1
            0x7c, 0x09, // jl +9
            0xb8, 0x03, 0x00, 0x00, 0x00, // skipped mov eax,3
            0x0f, 0x05, // skipped syscall
            0x90, 0x90, // skipped nops
            0x83, 0xf8, 0x3c, // cmp eax,60
            0x7d, 0x07, // jge +7
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x0f, 0x05, // skipped syscall
        ],
        0x471200,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x202,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall behind cmp32/jl/jge");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x47121f);
}

#[test]
fn execution_core_uses_cmp32_unsigned_flags_for_jb_and_jae() {
    let block = GuestBlock::new(
        &[
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
            0x83, 0xf8, 0x02, // cmp eax,2
            0x72, 0x09, // jb +9
            0xb8, 0x03, 0x00, 0x00, 0x00, // skipped mov eax,3
            0x0f, 0x05, // skipped syscall
            0x90, 0x90, // skipped nops
            0x83, 0xf8, 0x27, // cmp eax,39
            0x73, 0x07, // jae +7
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x0f, 0x05, // skipped syscall
        ],
        0x471300,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x202,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall behind cmp32/jb/jae");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x47131f);
}

#[test]
fn execution_core_uses_initial_rflags_for_direct_condition_jump() {
    let block = GuestBlock::new(
        &[
            0x78, 0x07, // js +7
            0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
            0x90, 0x90, // skipped nops
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
            0x0f, 0x05, // syscall
        ],
        0x471400,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        rflags: 0x282,
        ..GuestRegisters::default()
    };
    let mut captured_number = None;
    let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
        captured_number = Some(context.registers.number());
        SyscallReturn::success(4242).encode_u64()
    });

    SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect("execute syscall behind initial-rflags/js");

    assert_eq!(captured_number, Some(Syscall::GETPID));
    assert_eq!(registers.rax, 4242);
    assert_eq!(registers.rip, 0x471410);
}

#[test]
fn execution_core_without_memory_adapter_rejects_memory_operand_before_syscall() {
    let block = GuestBlock::new(
        &[
            0x48, 0x8b, 0x00, // mov rax,[rax]
            0x0f, 0x05, // syscall
        ],
        0x472000,
    );
    let mut registers = GuestRegisters {
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut trampoline = TrampolineCore::new(42, 43, |_| SyscallReturn::success(4242).encode_u64());

    let error = SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect_err("memory load requires a guest memory adapter");

    assert_eq!(
        error,
        ExecutionError::MemoryOperand {
            rip: 0x472000,
            address: 0,
            access: crate::GuestMemoryOperandAccessKind::Read,
            error: GuestMemoryOperandError::NotMapped,
        }
    );
}

#[test]
fn execution_core_returns_error_when_block_has_no_syscall() {
    let block = GuestBlock::new(&[0x90], 0x420000);
    let mut registers = GuestRegisters {
        rip: block.rip(),
        ..GuestRegisters::default()
    };
    let mut trampoline = TrampolineCore::new(1, 1, |_| LinuxErrno::ENOSYS.raw() as u64);

    let error = SameIsaExecutionCore::new()
        .execute_until_syscall(block, &mut registers, &mut trampoline)
        .expect_err("missing syscall");

    assert_eq!(
        error,
        ExecutionError::MissingSyscall {
            terminator: BlockTerminator::EndOfBytes
        }
    );
}

#[test]
fn execution_error_display_reports_ud2_exception_terminator_rip() {
    let block = GuestBlock::new(&[0x0f, 0x0b], 0x402100);
    let registers = GuestRegisters {
        rip: block.rip(),
        ..GuestRegisters::default()
    };

    let error = SameIsaExecutionCore::new()
        .execute_to_syscall_trap(block, registers)
        .expect_err("ud2 exception terminator should not be treated as syscall");

    assert_eq!(
        error,
        ExecutionError::MissingSyscall {
            terminator: BlockTerminator::ControlFlow {
                rip: 0x402100,
                flow: DecodedFlowControl::Exception,
            }
        }
    );
    assert_eq!(
        error.to_string(),
        "guest block terminated with x86 exception before syscall at guest rip 0x0000000000402100 (UD2 or another exception terminator)"
    );
}

#[test]
fn execution_core_allows_long_linearized_control_flow_to_syscall() {
    let mut bytes = Vec::new();
    for _ in 0..40 {
        bytes.extend_from_slice(&[
            0x39, 0xc0, // cmp eax,eax
            0x75, 0x00, // jne next
        ]);
    }
    bytes.extend_from_slice(&[0x0f, 0x05]); // syscall

    let block = GuestBlock::new(&bytes, 0x481000);
    let registers = GuestRegisters {
        rip: block.rip(),
        ..GuestRegisters::default()
    };

    let trap = SameIsaExecutionCore::new()
        .execute_to_syscall_trap(block, registers)
        .expect("execute realistic libc startup control-flow run before syscall");

    assert_eq!(trap.registers().rax, 0);
    assert_eq!(trap.site().rip, 0x4810a0);
}
