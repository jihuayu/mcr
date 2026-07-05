use core::fmt;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind};

use crate::decoder::decoded_flow_control;
use crate::operand_memory::{
    GuestMemoryOperandAccess, GuestMemoryOperandAccessKind, GuestMemoryOperandError,
    RejectingMemoryOperandAccess, read_memory_u64, read_operand_u64, write_memory_u64,
};
use crate::registers::GuestFlags;
use crate::simple_instruction::execute_simple_instruction;
use crate::{
    BlockDecoder, BlockTerminator, DecodeError, DecodedBlock, DecodedFlowControl, GuestBlock,
    GuestRegisters, GuestSyscallDispatcher, NativeFaultInstruction, SyscallTrap, TrampolineCore,
    X86_64_BITNESS,
};
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    Decode(DecodeError),
    MissingSyscall {
        terminator: BlockTerminator,
    },
    MemoryOperand {
        rip: u64,
        address: u64,
        access: GuestMemoryOperandAccessKind,
        error: GuestMemoryOperandError,
    },
    NativeFault {
        signal: i32,
        rip: u64,
        address: u64,
        fs_base: u64,
        registers: GuestRegisters,
        instruction: Option<Box<NativeFaultInstruction>>,
        stack_words: Vec<NativeFaultStackWord>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFaultStackWord {
    pub address: u64,
    pub value: u64,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(f),
            Self::MissingSyscall {
                terminator:
                    BlockTerminator::ControlFlow {
                        rip,
                        flow: DecodedFlowControl::Exception,
                    },
            } => write!(
                f,
                "guest block terminated with x86 exception before syscall at guest rip 0x{rip:016x} (UD2 or another exception terminator)"
            ),
            Self::MissingSyscall { terminator } => write!(
                f,
                "guest block did not terminate at syscall: {terminator:?}"
            ),
            Self::MemoryOperand {
                rip,
                address,
                access,
                error,
            } => write!(
                f,
                "guest memory {access:?} fault at rip 0x{rip:016x}, address 0x{address:016x}: {error:?}"
            ),
            Self::NativeFault {
                signal,
                rip,
                address,
                fs_base,
                registers: _,
                instruction,
                stack_words: _,
            } => {
                write!(
                    f,
                    "guest native execution faulted with signal {signal} at rip 0x{rip:016x}, address 0x{address:016x}, fs_base 0x{fs_base:016x}"
                )?;
                if let Some(instruction) = instruction {
                    write!(f, ", instruction {instruction}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ExecutionError {}

impl From<DecodeError> for ExecutionError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

pub struct SameIsaExecutionCore {
    decoder: BlockDecoder,
}

impl SameIsaExecutionCore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            decoder: BlockDecoder::new(),
        }
    }

    pub fn decode_block(&self, block: GuestBlock<'_>) -> Result<DecodedBlock, DecodeError> {
        self.decoder.decode(block)
    }

    pub fn execute_until_syscall<T>(
        &self,
        block: GuestBlock<'_>,
        registers: &mut GuestRegisters,
        trampoline: &mut TrampolineCore<T>,
    ) -> Result<DecodedBlock, ExecutionError>
    where
        T: GuestSyscallDispatcher,
    {
        let trap = self.execute_to_syscall_trap(block, *registers)?;
        let mut trapped_registers = trap.registers();
        trampoline.enter_syscall(&mut trapped_registers, trap.site());
        *registers = trapped_registers;
        Ok(trap.into_decoded())
    }

    pub fn execute_to_syscall_trap(
        &self,
        block: GuestBlock<'_>,
        registers: GuestRegisters,
    ) -> Result<SyscallTrap, ExecutionError> {
        let mut memory = RejectingMemoryOperandAccess;
        self.execute_to_syscall_trap_with_memory(block, registers, &mut memory)
    }

    pub fn execute_to_syscall_trap_with_memory<M>(
        &self,
        block: GuestBlock<'_>,
        registers: GuestRegisters,
        memory: &mut M,
    ) -> Result<SyscallTrap, ExecutionError>
    where
        M: GuestMemoryOperandAccess,
    {
        const MAX_CONTROL_FLOW_STEPS: usize = 256;

        let mut registers = registers;
        let mut current_rip = registers.rip;
        let mut flags = GuestFlags::from_registers(&registers);
        for _ in 0..MAX_CONTROL_FLOW_STEPS {
            let decoded = self.decode_block(block_from_rip(block, current_rip)?)?;
            let syscall_site = decoded.syscall_site();
            for instruction in decoded.instructions() {
                if Some(instruction.rip) == syscall_site.map(|site| site.rip) {
                    break;
                }
                if matches!(
                    decoded.terminator(),
                    BlockTerminator::ControlFlow { rip, .. } if *rip == instruction.rip
                ) {
                    break;
                }
                execute_simple_instruction(
                    block,
                    &mut registers,
                    &mut flags,
                    memory,
                    instruction.rip,
                    instruction.len,
                )?;
            }

            if let Some(site) = decoded.syscall_site() {
                registers.rip = site.rip;
                return Ok(SyscallTrap::new(decoded, site, registers));
            }

            if let Some(target) =
                control_flow_target(block, &decoded, flags, &mut registers, memory)?
            {
                current_rip = target;
                registers.rip = target;
                continue;
            }

            return Err(ExecutionError::MissingSyscall {
                terminator: *decoded.terminator(),
            });
        }

        Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid { rip: current_rip },
        })
    }
}

impl Default for SameIsaExecutionCore {
    fn default() -> Self {
        Self::new()
    }
}

fn block_from_rip(block: GuestBlock<'_>, rip: u64) -> Result<GuestBlock<'_>, ExecutionError> {
    let offset = block_offset(block, rip)?;
    let bytes = block
        .bytes()
        .get(offset..)
        .ok_or(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid { rip },
        })?;
    Ok(GuestBlock::new(bytes, rip))
}

fn block_offset(block: GuestBlock<'_>, rip: u64) -> Result<usize, ExecutionError> {
    let offset = rip
        .checked_sub(block.rip())
        .ok_or(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid { rip },
        })?;
    let offset = usize::try_from(offset).map_err(|_| ExecutionError::MissingSyscall {
        terminator: BlockTerminator::Invalid { rip },
    })?;
    if offset >= block.bytes().len() {
        return Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid { rip },
        });
    }
    Ok(offset)
}

fn control_flow_target<M>(
    block: GuestBlock<'_>,
    decoded: &DecodedBlock,
    flags: GuestFlags,
    registers: &mut GuestRegisters,
    memory: &mut M,
) -> Result<Option<u64>, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let BlockTerminator::ControlFlow { flow, .. } = decoded.terminator() else {
        return Ok(None);
    };
    let Some(instruction) = decoded.instructions().last() else {
        return Err(ExecutionError::MissingSyscall {
            terminator: *decoded.terminator(),
        });
    };
    let offset = block_offset(block, instruction.rip)?;
    let instruction_bytes = block.bytes().get(offset..offset + instruction.len).ok_or(
        ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.rip,
            },
        },
    )?;
    let mut decoder = Decoder::with_ip(
        X86_64_BITNESS,
        instruction_bytes,
        instruction.rip,
        DecoderOptions::NONE,
    );
    let instruction = decoder.decode();

    match flow {
        DecodedFlowControl::UnconditionalBranch | DecodedFlowControl::ConditionalBranch => {
            if !branch_taken(&instruction, flags)? {
                return Ok(Some(instruction.next_ip()));
            }
            if !matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
                return Err(ExecutionError::MissingSyscall {
                    terminator: *decoded.terminator(),
                });
            }
            let target = instruction.near_branch_target();
            block_offset(block, target)?;
            Ok(Some(target))
        }
        DecodedFlowControl::Call if instruction.code() == Code::Call_rel32_64 => {
            let target = instruction.near_branch_target();
            block_offset(block, target)?;
            let next_rsp = registers.rsp.wrapping_sub(8);
            write_memory_u64(memory, instruction.ip(), next_rsp, instruction.next_ip())?;
            registers.rsp = next_rsp;
            Ok(Some(target))
        }
        DecodedFlowControl::Call if instruction.code() == Code::Call_rm64 => {
            let target = read_operand_u64(registers, memory, &instruction, 0)?;
            block_offset(block, target)?;
            let next_rsp = registers.rsp.wrapping_sub(8);
            write_memory_u64(memory, instruction.ip(), next_rsp, instruction.next_ip())?;
            registers.rsp = next_rsp;
            Ok(Some(target))
        }
        DecodedFlowControl::Return if instruction.code() == Code::Retnq => {
            let target = read_memory_u64(memory, instruction.ip(), registers.rsp)?;
            block_offset(block, target)?;
            registers.rsp = registers.rsp.wrapping_add(8);
            Ok(Some(target))
        }
        DecodedFlowControl::IndirectBranch if instruction.code() == Code::Jmp_rm64 => {
            let target = read_operand_u64(registers, memory, &instruction, 0)?;
            block_offset(block, target)?;
            Ok(Some(target))
        }
        DecodedFlowControl::IndirectBranch
        | DecodedFlowControl::Call
        | DecodedFlowControl::Return
        | DecodedFlowControl::Interrupt
        | DecodedFlowControl::Exception
        | DecodedFlowControl::XbeginXabortXend => Ok(None),
    }
}

fn branch_taken(instruction: &Instruction, flags: GuestFlags) -> Result<bool, ExecutionError> {
    match instruction.code() {
        Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => Ok(true),
        Code::Je_rel8_64 | Code::Je_rel32_64 => Ok(flags.zero),
        Code::Jne_rel8_64 | Code::Jne_rel32_64 => Ok(!flags.zero),
        Code::Js_rel8_64 | Code::Js_rel32_64 => Ok(flags.sign),
        Code::Jns_rel8_64 | Code::Jns_rel32_64 => Ok(!flags.sign),
        Code::Jl_rel8_64 | Code::Jl_rel32_64 => Ok(flags.sign != flags.overflow),
        Code::Jge_rel8_64 | Code::Jge_rel32_64 => Ok(flags.sign == flags.overflow),
        Code::Jg_rel8_64 | Code::Jg_rel32_64 => Ok(!flags.zero && flags.sign == flags.overflow),
        Code::Jle_rel8_64 | Code::Jle_rel32_64 => Ok(flags.zero || flags.sign != flags.overflow),
        Code::Jb_rel8_64 | Code::Jb_rel32_64 => Ok(flags.carry),
        Code::Jae_rel8_64 | Code::Jae_rel32_64 => Ok(!flags.carry),
        Code::Ja_rel8_64 | Code::Ja_rel32_64 => Ok(!flags.carry && !flags.zero),
        Code::Jbe_rel8_64 | Code::Jbe_rel32_64 => Ok(flags.carry || flags.zero),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::ControlFlow {
                rip: instruction.ip(),
                flow: decoded_flow_control(instruction.flow_control())
                    .unwrap_or(DecodedFlowControl::Exception),
            },
        }),
    }
}
