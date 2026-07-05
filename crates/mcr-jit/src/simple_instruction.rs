use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind, Register};

use crate::operand_memory::{
    effective_address, immediate_as_u8, immediate_as_u16, immediate_as_u32, immediate_as_u64,
    immediate_operand_as_u64, read_memory_u8, read_memory_u16, read_memory_u32, read_memory_u64,
    read_operand_or_immediate_u32, read_operand_or_immediate_u64, read_operand_u8,
    read_operand_u16, read_operand_u32, read_operand_u64, write_memory_u8, write_memory_u16,
    write_memory_u32, write_memory_u64, write_operand_u32, write_operand_u64,
};
use crate::registers::{
    GuestFlags, read_reg8, read_reg16, read_reg32, read_reg64, sign_extend_u64, write_reg8,
    write_reg16, write_reg32, write_reg64,
};
use crate::{
    BlockTerminator, DecodedFlowControl, ExecutionError, GuestBlock, GuestMemoryOperandAccess,
    GuestRegisters, X86_64_BITNESS,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogicOp {
    And,
    Or,
    Xor,
}

pub(crate) fn execute_simple_instruction<M>(
    block: GuestBlock<'_>,
    registers: &mut GuestRegisters,
    flags: &mut GuestFlags,
    memory: &mut M,
    rip: u64,
    len: usize,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let offset = usize::try_from(rip.saturating_sub(block.rip())).map_err(|_| {
        ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid { rip },
        }
    })?;
    let bytes = block
        .bytes()
        .get(offset..offset + len)
        .ok_or(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid { rip },
        })?;
    let mut decoder = Decoder::with_ip(X86_64_BITNESS, bytes, rip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    match instruction.code() {
        Code::Mov_r64_imm64 => {
            write_reg64(
                registers,
                instruction.op0_register(),
                instruction.immediate64(),
            )?;
        }
        Code::Mov_rm64_imm32 if instruction.op0_kind() == OpKind::Register => {
            write_reg64(
                registers,
                instruction.op0_register(),
                instruction.immediate32to64() as u64,
            )?;
        }
        Code::Mov_rm64_imm32 if instruction.op0_kind() == OpKind::Memory => {
            let address = effective_address(registers, &instruction)?;
            write_memory_u64(memory, rip, address, instruction.immediate32to64() as u64)?;
        }
        Code::Mov_r32_imm32 => {
            write_reg32(
                registers,
                instruction.op0_register(),
                instruction.immediate32(),
            )?;
        }
        Code::Mov_rm32_imm32 if instruction.op0_kind() == OpKind::Memory => {
            let address = effective_address(registers, &instruction)?;
            write_memory_u32(memory, rip, address, instruction.immediate32())?;
        }
        Code::Mov_rm64_r64 | Code::Mov_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let value = read_reg64(registers, instruction.op1_register())?;
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Mov_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory =>
        {
            let address = effective_address(registers, &instruction)?;
            let value = read_memory_u64(memory, rip, address)?;
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Mov_rm64_r64
            if instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register =>
        {
            let address = effective_address(registers, &instruction)?;
            let value = read_reg64(registers, instruction.op1_register())?;
            write_memory_u64(memory, rip, address, value)?;
        }
        Code::Mov_rm32_r32 | Code::Mov_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let value = read_reg32(registers, instruction.op1_register())?;
            write_reg32(registers, instruction.op0_register(), value)?;
        }
        Code::Mov_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory =>
        {
            let address = effective_address(registers, &instruction)?;
            let value = read_memory_u32(memory, rip, address)?;
            write_reg32(registers, instruction.op0_register(), value)?;
        }
        Code::Mov_rm32_r32
            if instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register =>
        {
            let address = effective_address(registers, &instruction)?;
            let value = read_reg32(registers, instruction.op1_register())?;
            write_memory_u32(memory, rip, address, value)?;
        }
        Code::Mov_r8_rm8 | Code::Mov_rm8_r8
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let value = read_reg8(registers, instruction.op1_register())?;
            write_reg8(registers, instruction.op0_register(), value)?;
        }
        Code::Mov_r8_rm8
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory =>
        {
            let address = effective_address(registers, &instruction)?;
            let value = read_memory_u8(memory, rip, address)?;
            write_reg8(registers, instruction.op0_register(), value)?;
        }
        Code::Mov_rm8_r8
            if instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register =>
        {
            let address = effective_address(registers, &instruction)?;
            let value = read_reg8(registers, instruction.op1_register())?;
            write_memory_u8(memory, rip, address, value)?;
        }
        Code::Mov_r16_rm16 | Code::Mov_rm16_r16
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let value = read_reg16(registers, instruction.op1_register())?;
            write_reg16(registers, instruction.op0_register(), value)?;
        }
        Code::Mov_r16_rm16
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory =>
        {
            let address = effective_address(registers, &instruction)?;
            let value = read_memory_u16(memory, rip, address)?;
            write_reg16(registers, instruction.op0_register(), value)?;
        }
        Code::Mov_rm16_r16
            if instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register =>
        {
            let address = effective_address(registers, &instruction)?;
            let value = read_reg16(registers, instruction.op1_register())?;
            write_memory_u16(memory, rip, address, value)?;
        }
        Code::Mov_r8_imm8 if instruction.op0_kind() == OpKind::Register => {
            write_reg8(
                registers,
                instruction.op0_register(),
                instruction.immediate8(),
            )?;
        }
        Code::Mov_rm8_imm8 if instruction.op0_kind() == OpKind::Memory => {
            let address = effective_address(registers, &instruction)?;
            write_memory_u8(memory, rip, address, instruction.immediate8())?;
        }
        Code::Mov_r16_imm16 if instruction.op0_kind() == OpKind::Register => {
            write_reg16(
                registers,
                instruction.op0_register(),
                instruction.immediate16(),
            )?;
        }
        Code::Mov_rm16_imm16 if instruction.op0_kind() == OpKind::Memory => {
            let address = effective_address(registers, &instruction)?;
            write_memory_u16(memory, rip, address, instruction.immediate16())?;
        }
        Code::Movzx_r32_rm8 => {
            let value = u32::from(read_operand_u8(registers, memory, &instruction, 1)?);
            write_reg32(registers, instruction.op0_register(), value)?;
        }
        Code::Movzx_r64_rm8 => {
            let value = u64::from(read_operand_u8(registers, memory, &instruction, 1)?);
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Movzx_r32_rm16 => {
            let value = u32::from(read_operand_u16(registers, memory, &instruction, 1)?);
            write_reg32(registers, instruction.op0_register(), value)?;
        }
        Code::Movzx_r64_rm16 => {
            let value = u64::from(read_operand_u16(registers, memory, &instruction, 1)?);
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Movsx_r32_rm8 => {
            let value = sign_extend_u64(
                u64::from(read_operand_u8(registers, memory, &instruction, 1)?),
                8,
            ) as u32;
            write_reg32(registers, instruction.op0_register(), value)?;
        }
        Code::Movsx_r64_rm8 => {
            let value = sign_extend_u64(
                u64::from(read_operand_u8(registers, memory, &instruction, 1)?),
                8,
            );
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Movsx_r32_rm16 => {
            let value = sign_extend_u64(
                u64::from(read_operand_u16(registers, memory, &instruction, 1)?),
                16,
            ) as u32;
            write_reg32(registers, instruction.op0_register(), value)?;
        }
        Code::Movsx_r64_rm16 => {
            let value = sign_extend_u64(
                u64::from(read_operand_u16(registers, memory, &instruction, 1)?),
                16,
            );
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Movsxd_r64_rm32 => {
            let value = sign_extend_u64(
                u64::from(read_operand_u32(registers, memory, &instruction, 1)?),
                32,
            );
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Cdqe => {
            let value = sign_extend_u64(u64::from(read_reg32(registers, Register::EAX)?), 32);
            write_reg64(registers, Register::RAX, value)?;
        }
        Code::Push_r64 if instruction.op0_kind() == OpKind::Register => {
            let value = read_reg64(registers, instruction.op0_register())?;
            registers.rsp = registers.rsp.wrapping_sub(8);
            write_memory_u64(memory, rip, registers.rsp, value)?;
        }
        Code::Pushq_imm32 | Code::Pushq_imm8 => {
            let value = immediate_operand_as_u64(&instruction, 0)?;
            registers.rsp = registers.rsp.wrapping_sub(8);
            write_memory_u64(memory, rip, registers.rsp, value)?;
        }
        Code::Pop_r64 if instruction.op0_kind() == OpKind::Register => {
            let value = read_memory_u64(memory, rip, registers.rsp)?;
            registers.rsp = registers.rsp.wrapping_add(8);
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Lea_r64_m if instruction.op1_kind() == OpKind::Memory => {
            let value = effective_address(registers, &instruction)?;
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Add_rm64_r64 | Code::Add_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            let result = lhs.wrapping_add(rhs);
            write_reg64(registers, instruction.op0_register(), result)?;
            flags.set_add_result(lhs, rhs, result, 64);
        }
        Code::Add_rm32_r32 | Code::Add_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            let result = lhs.wrapping_add(rhs);
            write_reg32(registers, instruction.op0_register(), result)?;
            flags.set_add_result(u64::from(lhs), u64::from(rhs), u64::from(result), 32);
        }
        Code::Add_rm64_imm32 | Code::Add_rm64_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = immediate_as_u64(&instruction)?;
            let result = lhs.wrapping_add(rhs);
            write_reg64(registers, instruction.op0_register(), result)?;
            flags.set_add_result(lhs, rhs, result, 64);
        }
        Code::Add_rm32_imm32 | Code::Add_rm32_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = immediate_as_u32(&instruction)?;
            let result = lhs.wrapping_add(rhs);
            write_reg32(registers, instruction.op0_register(), result)?;
            flags.set_add_result(u64::from(lhs), u64::from(rhs), u64::from(result), 32);
        }
        Code::Sub_rm64_r64 | Code::Sub_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            let result = lhs.wrapping_sub(rhs);
            write_reg64(registers, instruction.op0_register(), result)?;
            flags.set_sub_result(lhs, rhs, result, 64);
        }
        Code::Sub_rm32_r32 | Code::Sub_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            let result = lhs.wrapping_sub(rhs);
            write_reg32(registers, instruction.op0_register(), result)?;
            flags.set_sub_result(u64::from(lhs), u64::from(rhs), u64::from(result), 32);
        }
        Code::Sub_rm64_imm32 | Code::Sub_rm64_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = immediate_as_u64(&instruction)?;
            let result = lhs.wrapping_sub(rhs);
            write_reg64(registers, instruction.op0_register(), result)?;
            flags.set_sub_result(lhs, rhs, result, 64);
        }
        Code::Sub_rm32_imm32 | Code::Sub_rm32_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = immediate_as_u32(&instruction)?;
            let result = lhs.wrapping_sub(rhs);
            write_reg32(registers, instruction.op0_register(), result)?;
            flags.set_sub_result(u64::from(lhs), u64::from(rhs), u64::from(result), 32);
        }
        Code::And_rm64_r64
        | Code::And_r64_rm64
        | Code::And_rm64_imm32
        | Code::And_rm64_imm8
        | Code::And_RAX_imm32 => {
            execute_logic_u64(registers, flags, memory, &instruction, LogicOp::And)?;
        }
        Code::And_rm32_r32
        | Code::And_r32_rm32
        | Code::And_rm32_imm32
        | Code::And_rm32_imm8
        | Code::And_EAX_imm32 => {
            execute_logic_u32(registers, flags, memory, &instruction, LogicOp::And)?;
        }
        Code::Or_rm64_r64
        | Code::Or_r64_rm64
        | Code::Or_rm64_imm32
        | Code::Or_rm64_imm8
        | Code::Or_RAX_imm32 => {
            execute_logic_u64(registers, flags, memory, &instruction, LogicOp::Or)?;
        }
        Code::Or_rm32_r32
        | Code::Or_r32_rm32
        | Code::Or_rm32_imm32
        | Code::Or_rm32_imm8
        | Code::Or_EAX_imm32 => {
            execute_logic_u32(registers, flags, memory, &instruction, LogicOp::Or)?;
        }
        Code::Xor_rm64_r64
        | Code::Xor_r64_rm64
        | Code::Xor_rm64_imm32
        | Code::Xor_rm64_imm8
        | Code::Xor_RAX_imm32 => {
            execute_logic_u64(registers, flags, memory, &instruction, LogicOp::Xor)?;
        }
        Code::Xor_rm32_r32
        | Code::Xor_r32_rm32
        | Code::Xor_rm32_imm32
        | Code::Xor_rm32_imm8
        | Code::Xor_EAX_imm32 => {
            execute_logic_u32(registers, flags, memory, &instruction, LogicOp::Xor)?;
        }
        Code::Cmp_rm64_r64 | Code::Cmp_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            flags.set_sub_result(lhs, rhs, lhs.wrapping_sub(rhs), 64);
        }
        Code::Cmp_rm32_r32 | Code::Cmp_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            flags.set_sub_result(
                u64::from(lhs),
                u64::from(rhs),
                u64::from(lhs.wrapping_sub(rhs)),
                32,
            );
        }
        Code::Cmp_rm64_imm32 | Code::Cmp_rm64_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = immediate_as_u64(&instruction)?;
            flags.set_sub_result(lhs, rhs, lhs.wrapping_sub(rhs), 64);
        }
        Code::Cmp_rm32_imm32 | Code::Cmp_rm32_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = immediate_as_u32(&instruction)?;
            flags.set_sub_result(
                u64::from(lhs),
                u64::from(rhs),
                u64::from(lhs.wrapping_sub(rhs)),
                32,
            );
        }
        Code::Cmp_rm8_r8 | Code::Cmp_r8_rm8 => {
            let lhs = read_operand_u8(registers, memory, &instruction, 0)?;
            let rhs = read_operand_u8(registers, memory, &instruction, 1)?;
            flags.set_sub_result(
                u64::from(lhs),
                u64::from(rhs),
                u64::from(lhs.wrapping_sub(rhs)),
                8,
            );
        }
        Code::Cmp_rm16_r16 | Code::Cmp_r16_rm16 => {
            let lhs = read_operand_u16(registers, memory, &instruction, 0)?;
            let rhs = read_operand_u16(registers, memory, &instruction, 1)?;
            flags.set_sub_result(
                u64::from(lhs),
                u64::from(rhs),
                u64::from(lhs.wrapping_sub(rhs)),
                16,
            );
        }
        Code::Cmp_rm8_imm8 | Code::Cmp_rm8_imm8_82 => {
            let lhs = read_operand_u8(registers, memory, &instruction, 0)?;
            let rhs = immediate_as_u8(&instruction)?;
            flags.set_sub_result(
                u64::from(lhs),
                u64::from(rhs),
                u64::from(lhs.wrapping_sub(rhs)),
                8,
            );
        }
        Code::Cmp_rm16_imm16 | Code::Cmp_rm16_imm8 => {
            let lhs = read_operand_u16(registers, memory, &instruction, 0)?;
            let rhs = immediate_as_u16(&instruction)?;
            flags.set_sub_result(
                u64::from(lhs),
                u64::from(rhs),
                u64::from(lhs.wrapping_sub(rhs)),
                16,
            );
        }
        Code::Test_rm32_r32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            flags.set_logic_result(u64::from(lhs & rhs), 32);
        }
        Code::Test_rm64_r64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            flags.set_logic_result(lhs & rhs, 64);
        }
        Code::Test_rm32_imm32 | Code::Test_rm32_imm32_F7r1 | Code::Test_EAX_imm32 => {
            let lhs = read_operand_u32(registers, memory, &instruction, 0)?;
            let rhs = immediate_as_u32(&instruction)?;
            flags.set_logic_result(u64::from(lhs & rhs), 32);
        }
        Code::Test_rm64_imm32 | Code::Test_rm64_imm32_F7r1 | Code::Test_RAX_imm32 => {
            let lhs = read_operand_u64(registers, memory, &instruction, 0)?;
            let rhs = immediate_as_u64(&instruction)?;
            flags.set_logic_result(lhs & rhs, 64);
        }
        Code::Test_rm8_r8 => {
            let lhs = read_operand_u8(registers, memory, &instruction, 0)?;
            let rhs = read_operand_u8(registers, memory, &instruction, 1)?;
            flags.set_logic_result(u64::from(lhs & rhs), 8);
        }
        Code::Test_rm16_r16 => {
            let lhs = read_operand_u16(registers, memory, &instruction, 0)?;
            let rhs = read_operand_u16(registers, memory, &instruction, 1)?;
            flags.set_logic_result(u64::from(lhs & rhs), 16);
        }
        Code::Test_rm8_imm8 | Code::Test_rm8_imm8_F6r1 => {
            let lhs = read_operand_u8(registers, memory, &instruction, 0)?;
            let rhs = immediate_as_u8(&instruction)?;
            flags.set_logic_result(u64::from(lhs & rhs), 8);
        }
        Code::Test_rm16_imm16 | Code::Test_rm16_imm16_F7r1 => {
            let lhs = read_operand_u16(registers, memory, &instruction, 0)?;
            let rhs = immediate_as_u16(&instruction)?;
            flags.set_logic_result(u64::from(lhs & rhs), 16);
        }
        Code::Nopd | Code::Nopq => {}
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::ControlFlow {
                    rip,
                    flow: DecodedFlowControl::Exception,
                },
            });
        }
    }
    registers.rip = rip + len as u64;
    Ok(())
}

fn execute_logic_u64<M>(
    registers: &mut GuestRegisters,
    flags: &mut GuestFlags,
    memory: &mut M,
    instruction: &Instruction,
    operation: LogicOp,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let lhs = read_operand_u64(registers, memory, instruction, 0)?;
    let rhs = read_operand_or_immediate_u64(registers, memory, instruction, 1)?;
    let result = apply_logic(lhs, rhs, operation);
    write_operand_u64(registers, memory, instruction, 0, result)?;
    flags.set_logic_result(result, 64);
    Ok(())
}

fn execute_logic_u32<M>(
    registers: &mut GuestRegisters,
    flags: &mut GuestFlags,
    memory: &mut M,
    instruction: &Instruction,
    operation: LogicOp,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let lhs = read_operand_u32(registers, memory, instruction, 0)?;
    let rhs = read_operand_or_immediate_u32(registers, memory, instruction, 1)?;
    let result = apply_logic(u64::from(lhs), u64::from(rhs), operation) as u32;
    write_operand_u32(registers, memory, instruction, 0, result)?;
    flags.set_logic_result(u64::from(result), 32);
    Ok(())
}

const fn apply_logic(lhs: u64, rhs: u64, operation: LogicOp) -> u64 {
    match operation {
        LogicOp::And => lhs & rhs,
        LogicOp::Or => lhs | rhs,
        LogicOp::Xor => lhs ^ rhs,
    }
}
