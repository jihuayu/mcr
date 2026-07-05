use iced_x86::{Instruction, OpKind, Register};

use crate::registers::{read_reg8, read_reg16, read_reg32, read_reg64, write_reg32, write_reg64};
use crate::{BlockTerminator, ExecutionError, GuestRegisters};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestMemoryOperandAccessKind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestMemoryOperandError {
    NotMapped,
    AccessDenied,
    Fault,
}

pub trait GuestMemoryOperandAccess {
    fn read_memory_operand(
        &self,
        address: u64,
        buffer: &mut [u8],
    ) -> Result<(), GuestMemoryOperandError>;

    fn write_memory_operand(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), GuestMemoryOperandError>;
}

pub(crate) struct RejectingMemoryOperandAccess;

impl GuestMemoryOperandAccess for RejectingMemoryOperandAccess {
    fn read_memory_operand(
        &self,
        _address: u64,
        _buffer: &mut [u8],
    ) -> Result<(), GuestMemoryOperandError> {
        Err(GuestMemoryOperandError::NotMapped)
    }

    fn write_memory_operand(
        &mut self,
        _address: u64,
        _bytes: &[u8],
    ) -> Result<(), GuestMemoryOperandError> {
        Err(GuestMemoryOperandError::NotMapped)
    }
}

pub(crate) fn immediate_as_u64(instruction: &Instruction) -> Result<u64, ExecutionError> {
    match instruction.op1_kind() {
        OpKind::Immediate8to64 => Ok(instruction.immediate8to64() as u64),
        OpKind::Immediate32to64 => Ok(instruction.immediate32to64() as u64),
        OpKind::Immediate64 => Ok(instruction.immediate64()),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn immediate_as_u32(instruction: &Instruction) -> Result<u32, ExecutionError> {
    match instruction.op1_kind() {
        OpKind::Immediate8to32 => Ok(instruction.immediate8to32() as u32),
        OpKind::Immediate32 => Ok(instruction.immediate32()),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn immediate_as_u16(instruction: &Instruction) -> Result<u16, ExecutionError> {
    match instruction.op1_kind() {
        OpKind::Immediate8to16 => Ok(instruction.immediate8to16() as u16),
        OpKind::Immediate16 => Ok(instruction.immediate16()),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn immediate_as_u8(instruction: &Instruction) -> Result<u8, ExecutionError> {
    match instruction.op1_kind() {
        OpKind::Immediate8 => Ok(instruction.immediate8()),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn immediate_operand_as_u64(
    instruction: &Instruction,
    operand: u32,
) -> Result<u64, ExecutionError> {
    match instruction.op_kind(operand) {
        OpKind::Immediate8to64 => Ok(instruction.immediate8to64() as u64),
        OpKind::Immediate32to64 => Ok(instruction.immediate32to64() as u64),
        OpKind::Immediate64 => Ok(instruction.immediate64()),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn effective_address(
    registers: &GuestRegisters,
    instruction: &Instruction,
) -> Result<u64, ExecutionError> {
    let segment_base = match instruction.memory_segment() {
        Register::FS => registers.fs_base,
        Register::None | Register::DS | Register::ES | Register::SS => 0,
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::Invalid {
                    rip: instruction.ip(),
                },
            });
        }
    };
    let base = match instruction.memory_base() {
        Register::None => 0,
        Register::RIP | Register::EIP => {
            return Ok(segment_base.wrapping_add(instruction.ip_rel_memory_address()));
        }
        base => read_reg64(registers, base)?,
    };
    let index = match instruction.memory_index() {
        Register::None => 0,
        index => {
            read_reg64(registers, index)?.wrapping_mul(u64::from(instruction.memory_index_scale()))
        }
    };
    Ok(segment_base
        .wrapping_add(base)
        .wrapping_add(index)
        .wrapping_add(instruction.memory_displacement64()))
}

pub(crate) fn read_operand_u8<M>(
    registers: &GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
) -> Result<u8, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Register => read_reg8(registers, instruction.op_register(operand)),
        OpKind::Memory => read_memory_u8(
            memory,
            instruction.ip(),
            effective_address(registers, instruction)?,
        ),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn read_operand_u16<M>(
    registers: &GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
) -> Result<u16, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Register => read_reg16(registers, instruction.op_register(operand)),
        OpKind::Memory => read_memory_u16(
            memory,
            instruction.ip(),
            effective_address(registers, instruction)?,
        ),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn read_operand_u32<M>(
    registers: &GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
) -> Result<u32, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Register => read_reg32(registers, instruction.op_register(operand)),
        OpKind::Memory => read_memory_u32(
            memory,
            instruction.ip(),
            effective_address(registers, instruction)?,
        ),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn read_operand_u64<M>(
    registers: &GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
) -> Result<u64, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Register => read_reg64(registers, instruction.op_register(operand)),
        OpKind::Memory => read_memory_u64(
            memory,
            instruction.ip(),
            effective_address(registers, instruction)?,
        ),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn read_operand_or_immediate_u32<M>(
    registers: &GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
) -> Result<u32, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Immediate8to32 | OpKind::Immediate32 => immediate_as_u32(instruction),
        _ => read_operand_u32(registers, memory, instruction, operand),
    }
}

pub(crate) fn read_operand_or_immediate_u64<M>(
    registers: &GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
) -> Result<u64, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate64 => {
            immediate_as_u64(instruction)
        }
        _ => read_operand_u64(registers, memory, instruction, operand),
    }
}

pub(crate) fn write_operand_u32<M>(
    registers: &mut GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
    value: u32,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Register => write_reg32(registers, instruction.op_register(operand), value),
        OpKind::Memory => write_memory_u32(
            memory,
            instruction.ip(),
            effective_address(registers, instruction)?,
            value,
        ),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn write_operand_u64<M>(
    registers: &mut GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
    value: u64,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Register => write_reg64(registers, instruction.op_register(operand), value),
        OpKind::Memory => write_memory_u64(
            memory,
            instruction.ip(),
            effective_address(registers, instruction)?,
            value,
        ),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

pub(crate) fn read_memory_u8<M>(
    memory: &mut M,
    rip: u64,
    address: u64,
) -> Result<u8, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let mut bytes = [0; 1];
    memory
        .read_memory_operand(address, &mut bytes)
        .map_err(|error| ExecutionError::MemoryOperand {
            rip,
            address,
            access: GuestMemoryOperandAccessKind::Read,
            error,
        })?;
    Ok(bytes[0])
}

pub(crate) fn read_memory_u16<M>(
    memory: &mut M,
    rip: u64,
    address: u64,
) -> Result<u16, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let mut bytes = [0; 2];
    memory
        .read_memory_operand(address, &mut bytes)
        .map_err(|error| ExecutionError::MemoryOperand {
            rip,
            address,
            access: GuestMemoryOperandAccessKind::Read,
            error,
        })?;
    Ok(u16::from_le_bytes(bytes))
}

pub(crate) fn write_memory_u8<M>(
    memory: &mut M,
    rip: u64,
    address: u64,
    value: u8,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    write_memory_bytes(memory, rip, address, &[value])
}

pub(crate) fn write_memory_u16<M>(
    memory: &mut M,
    rip: u64,
    address: u64,
    value: u16,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    write_memory_bytes(memory, rip, address, &value.to_le_bytes())
}

pub(crate) fn read_memory_u32<M>(
    memory: &mut M,
    rip: u64,
    address: u64,
) -> Result<u32, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let mut bytes = [0; 4];
    memory
        .read_memory_operand(address, &mut bytes)
        .map_err(|error| ExecutionError::MemoryOperand {
            rip,
            address,
            access: GuestMemoryOperandAccessKind::Read,
            error,
        })?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn read_memory_u64<M>(
    memory: &mut M,
    rip: u64,
    address: u64,
) -> Result<u64, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let mut bytes = [0; 8];
    memory
        .read_memory_operand(address, &mut bytes)
        .map_err(|error| ExecutionError::MemoryOperand {
            rip,
            address,
            access: GuestMemoryOperandAccessKind::Read,
            error,
        })?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn write_memory_u32<M>(
    memory: &mut M,
    rip: u64,
    address: u64,
    value: u32,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    write_memory_bytes(memory, rip, address, &value.to_le_bytes())
}

pub(crate) fn write_memory_u64<M>(
    memory: &mut M,
    rip: u64,
    address: u64,
    value: u64,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    write_memory_bytes(memory, rip, address, &value.to_le_bytes())
}

fn write_memory_bytes<M>(
    memory: &mut M,
    rip: u64,
    address: u64,
    bytes: &[u8],
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    memory
        .write_memory_operand(address, bytes)
        .map_err(|error| ExecutionError::MemoryOperand {
            rip,
            address,
            access: GuestMemoryOperandAccessKind::Write,
            error,
        })
}
