use iced_x86::Register;
use mcr_sys::SyscallRegisters;

use crate::{BlockTerminator, ExecutionError};
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuestFlags {
    pub(crate) carry: bool,
    pub(crate) zero: bool,
    pub(crate) sign: bool,
    pub(crate) overflow: bool,
}

impl GuestRegisters {
    #[must_use]
    pub const fn syscall_registers(self) -> SyscallRegisters {
        SyscallRegisters {
            rax: self.rax,
            rdi: self.rdi,
            rsi: self.rsi,
            rdx: self.rdx,
            r10: self.r10,
            r8: self.r8,
            r9: self.r9,
            rip: self.rip,
        }
    }

    pub fn apply_syscall_return(&mut self, encoded_rax: u64, next_rip: u64) {
        self.rax = encoded_rax;
        self.rcx = next_rip;
        self.r11 = self.rflags;
        self.rip = next_rip;
    }
}

impl GuestFlags {
    const RFLAGS_CARRY: u64 = 1;
    const RFLAGS_ZERO: u64 = 1 << 6;
    const RFLAGS_SIGN: u64 = 1 << 7;
    const RFLAGS_OVERFLOW: u64 = 1 << 11;

    pub(crate) const fn from_registers(registers: &GuestRegisters) -> Self {
        Self {
            carry: registers.rflags & Self::RFLAGS_CARRY != 0,
            zero: registers.rflags & Self::RFLAGS_ZERO != 0,
            sign: registers.rflags & Self::RFLAGS_SIGN != 0,
            overflow: registers.rflags & Self::RFLAGS_OVERFLOW != 0,
        }
    }

    pub(crate) fn set_add_result(&mut self, lhs: u64, rhs: u64, result: u64, bits: u32) {
        let lhs = mask_to_width(lhs, bits);
        let rhs = mask_to_width(rhs, bits);
        let result = mask_to_width(result, bits);
        let sign_bit = sign_bit(bits);

        self.set_zero_sign(result, bits);
        self.carry = u128::from(lhs) + u128::from(rhs) > u128::from(mask_for_width(bits));
        self.overflow = (lhs ^ result) & (rhs ^ result) & sign_bit != 0;
    }

    pub(crate) fn set_sub_result(&mut self, lhs: u64, rhs: u64, result: u64, bits: u32) {
        let lhs = mask_to_width(lhs, bits);
        let rhs = mask_to_width(rhs, bits);
        let result = mask_to_width(result, bits);
        let sign_bit = sign_bit(bits);

        self.set_zero_sign(result, bits);
        self.carry = lhs < rhs;
        self.overflow = (lhs ^ rhs) & (lhs ^ result) & sign_bit != 0;
    }

    pub(crate) fn set_logic_result(&mut self, result: u64, bits: u32) {
        self.set_zero_sign(mask_to_width(result, bits), bits);
        self.carry = false;
        self.overflow = false;
    }

    fn set_zero_sign(&mut self, result: u64, bits: u32) {
        self.zero = result == 0;
        self.sign = result & sign_bit(bits) != 0;
    }
}

const fn mask_for_width(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    }
}

const fn mask_to_width(value: u64, bits: u32) -> u64 {
    value & mask_for_width(bits)
}

const fn sign_bit(bits: u32) -> u64 {
    1_u64 << (bits - 1)
}

pub(crate) fn sign_extend_u64(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    ((value << shift) as i64 >> shift) as u64
}

pub(crate) fn read_reg64(
    registers: &GuestRegisters,
    register: Register,
) -> Result<u64, ExecutionError> {
    let value = match register {
        Register::RAX => registers.rax,
        Register::RBX => registers.rbx,
        Register::RCX => registers.rcx,
        Register::RDX => registers.rdx,
        Register::RSI => registers.rsi,
        Register::RDI => registers.rdi,
        Register::RBP => registers.rbp,
        Register::RSP => registers.rsp,
        Register::R8 => registers.r8,
        Register::R9 => registers.r9,
        Register::R10 => registers.r10,
        Register::R11 => registers.r11,
        Register::R12 => registers.r12,
        Register::R13 => registers.r13,
        Register::R14 => registers.r14,
        Register::R15 => registers.r15,
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::Invalid { rip: registers.rip },
            });
        }
    };
    Ok(value)
}

pub(crate) fn read_reg8(
    registers: &GuestRegisters,
    register: Register,
) -> Result<u8, ExecutionError> {
    let value = match register {
        Register::AL => registers.rax as u8,
        Register::CL => registers.rcx as u8,
        Register::DL => registers.rdx as u8,
        Register::BL => registers.rbx as u8,
        Register::AH => (registers.rax >> 8) as u8,
        Register::CH => (registers.rcx >> 8) as u8,
        Register::DH => (registers.rdx >> 8) as u8,
        Register::BH => (registers.rbx >> 8) as u8,
        Register::SPL => registers.rsp as u8,
        Register::BPL => registers.rbp as u8,
        Register::SIL => registers.rsi as u8,
        Register::DIL => registers.rdi as u8,
        Register::R8L => registers.r8 as u8,
        Register::R9L => registers.r9 as u8,
        Register::R10L => registers.r10 as u8,
        Register::R11L => registers.r11 as u8,
        Register::R12L => registers.r12 as u8,
        Register::R13L => registers.r13 as u8,
        Register::R14L => registers.r14 as u8,
        Register::R15L => registers.r15 as u8,
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::Invalid { rip: registers.rip },
            });
        }
    };
    Ok(value)
}

pub(crate) fn read_reg16(
    registers: &GuestRegisters,
    register: Register,
) -> Result<u16, ExecutionError> {
    let value = match register {
        Register::RAX | Register::EAX | Register::AX => registers.rax,
        Register::RBX | Register::EBX | Register::BX => registers.rbx,
        Register::RCX | Register::ECX | Register::CX => registers.rcx,
        Register::RDX | Register::EDX | Register::DX => registers.rdx,
        Register::RSI | Register::ESI | Register::SI => registers.rsi,
        Register::RDI | Register::EDI | Register::DI => registers.rdi,
        Register::RBP | Register::EBP | Register::BP => registers.rbp,
        Register::RSP | Register::ESP | Register::SP => registers.rsp,
        Register::R8 | Register::R8D | Register::R8W => registers.r8,
        Register::R9 | Register::R9D | Register::R9W => registers.r9,
        Register::R10 | Register::R10D | Register::R10W => registers.r10,
        Register::R11 | Register::R11D | Register::R11W => registers.r11,
        Register::R12 | Register::R12D | Register::R12W => registers.r12,
        Register::R13 | Register::R13D | Register::R13W => registers.r13,
        Register::R14 | Register::R14D | Register::R14W => registers.r14,
        Register::R15 | Register::R15D | Register::R15W => registers.r15,
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::Invalid { rip: registers.rip },
            });
        }
    };
    Ok(value as u16)
}

pub(crate) fn read_reg32(
    registers: &GuestRegisters,
    register: Register,
) -> Result<u32, ExecutionError> {
    let value = match register {
        Register::RAX | Register::EAX => registers.rax,
        Register::RBX | Register::EBX => registers.rbx,
        Register::RCX | Register::ECX => registers.rcx,
        Register::RDX | Register::EDX => registers.rdx,
        Register::RSI | Register::ESI => registers.rsi,
        Register::RDI | Register::EDI => registers.rdi,
        Register::RBP | Register::EBP => registers.rbp,
        Register::RSP | Register::ESP => registers.rsp,
        Register::R8 | Register::R8D => registers.r8,
        Register::R9 | Register::R9D => registers.r9,
        Register::R10 | Register::R10D => registers.r10,
        Register::R11 | Register::R11D => registers.r11,
        Register::R12 | Register::R12D => registers.r12,
        Register::R13 | Register::R13D => registers.r13,
        Register::R14 | Register::R14D => registers.r14,
        Register::R15 | Register::R15D => registers.r15,
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::Invalid { rip: registers.rip },
            });
        }
    };
    Ok(value as u32)
}

pub(crate) fn write_reg8(
    registers: &mut GuestRegisters,
    register: Register,
    value: u8,
) -> Result<(), ExecutionError> {
    let value = u64::from(value);
    match register {
        Register::AL => registers.rax = (registers.rax & !0xff) | value,
        Register::CL => registers.rcx = (registers.rcx & !0xff) | value,
        Register::DL => registers.rdx = (registers.rdx & !0xff) | value,
        Register::BL => registers.rbx = (registers.rbx & !0xff) | value,
        Register::AH => registers.rax = (registers.rax & !0xff00) | (value << 8),
        Register::CH => registers.rcx = (registers.rcx & !0xff00) | (value << 8),
        Register::DH => registers.rdx = (registers.rdx & !0xff00) | (value << 8),
        Register::BH => registers.rbx = (registers.rbx & !0xff00) | (value << 8),
        Register::SPL => registers.rsp = (registers.rsp & !0xff) | value,
        Register::BPL => registers.rbp = (registers.rbp & !0xff) | value,
        Register::SIL => registers.rsi = (registers.rsi & !0xff) | value,
        Register::DIL => registers.rdi = (registers.rdi & !0xff) | value,
        Register::R8L => registers.r8 = (registers.r8 & !0xff) | value,
        Register::R9L => registers.r9 = (registers.r9 & !0xff) | value,
        Register::R10L => registers.r10 = (registers.r10 & !0xff) | value,
        Register::R11L => registers.r11 = (registers.r11 & !0xff) | value,
        Register::R12L => registers.r12 = (registers.r12 & !0xff) | value,
        Register::R13L => registers.r13 = (registers.r13 & !0xff) | value,
        Register::R14L => registers.r14 = (registers.r14 & !0xff) | value,
        Register::R15L => registers.r15 = (registers.r15 & !0xff) | value,
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::Invalid { rip: registers.rip },
            });
        }
    }
    Ok(())
}

pub(crate) fn write_reg16(
    registers: &mut GuestRegisters,
    register: Register,
    value: u16,
) -> Result<(), ExecutionError> {
    let value = u64::from(value);
    match register {
        Register::AX => registers.rax = (registers.rax & !0xffff) | value,
        Register::BX => registers.rbx = (registers.rbx & !0xffff) | value,
        Register::CX => registers.rcx = (registers.rcx & !0xffff) | value,
        Register::DX => registers.rdx = (registers.rdx & !0xffff) | value,
        Register::SI => registers.rsi = (registers.rsi & !0xffff) | value,
        Register::DI => registers.rdi = (registers.rdi & !0xffff) | value,
        Register::BP => registers.rbp = (registers.rbp & !0xffff) | value,
        Register::SP => registers.rsp = (registers.rsp & !0xffff) | value,
        Register::R8W => registers.r8 = (registers.r8 & !0xffff) | value,
        Register::R9W => registers.r9 = (registers.r9 & !0xffff) | value,
        Register::R10W => registers.r10 = (registers.r10 & !0xffff) | value,
        Register::R11W => registers.r11 = (registers.r11 & !0xffff) | value,
        Register::R12W => registers.r12 = (registers.r12 & !0xffff) | value,
        Register::R13W => registers.r13 = (registers.r13 & !0xffff) | value,
        Register::R14W => registers.r14 = (registers.r14 & !0xffff) | value,
        Register::R15W => registers.r15 = (registers.r15 & !0xffff) | value,
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::Invalid { rip: registers.rip },
            });
        }
    }
    Ok(())
}

pub(crate) fn write_reg32(
    registers: &mut GuestRegisters,
    register: Register,
    value: u32,
) -> Result<(), ExecutionError> {
    write_reg64(registers, register, u64::from(value))
}

pub(crate) fn write_reg64(
    registers: &mut GuestRegisters,
    register: Register,
    value: u64,
) -> Result<(), ExecutionError> {
    match register {
        Register::RAX | Register::EAX => registers.rax = value,
        Register::RBX | Register::EBX => registers.rbx = value,
        Register::RCX | Register::ECX => registers.rcx = value,
        Register::RDX | Register::EDX => registers.rdx = value,
        Register::RSI | Register::ESI => registers.rsi = value,
        Register::RDI | Register::EDI => registers.rdi = value,
        Register::RBP | Register::EBP => registers.rbp = value,
        Register::RSP | Register::ESP => registers.rsp = value,
        Register::R8 | Register::R8D => registers.r8 = value,
        Register::R9 | Register::R9D => registers.r9 = value,
        Register::R10 | Register::R10D => registers.r10 = value,
        Register::R11 | Register::R11D => registers.r11 = value,
        Register::R12 | Register::R12D => registers.r12 = value,
        Register::R13 | Register::R13D => registers.r13 = value,
        Register::R14 | Register::R14D => registers.r14 = value,
        Register::R15 | Register::R15D => registers.r15 = value,
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::Invalid { rip: registers.rip },
            });
        }
    }
    Ok(())
}
