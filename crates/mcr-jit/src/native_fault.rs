use core::fmt;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};

use crate::X86_64_BITNESS;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFaultInstruction {
    pub rip: u64,
    pub bytes: Vec<u8>,
    pub decoded: String,
}

impl fmt::Display for NativeFaultInstruction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "rip=0x{:016x} bytes={} decoded={}",
            self.rip,
            format_bytes(&self.bytes),
            self.decoded
        )
    }
}

pub fn decode_native_fault_instruction(bytes: &[u8], rip: u64) -> Option<NativeFaultInstruction> {
    if bytes.is_empty() {
        return None;
    }

    let mut decoder = Decoder::with_ip(X86_64_BITNESS, bytes, rip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return None;
    }
    let len = instruction.len().min(bytes.len());
    Some(NativeFaultInstruction {
        rip,
        bytes: bytes[..len].to_vec(),
        decoded: describe_instruction(&instruction),
    })
}

fn describe_instruction(instruction: &Instruction) -> String {
    let operands = (0..instruction.op_count())
        .map(|operand| describe_operand(instruction, operand))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "code={:?} mnemonic={:?} len={} operands=[{}]",
        instruction.code(),
        instruction.mnemonic(),
        instruction.len(),
        operands
    )
}

fn describe_operand(instruction: &Instruction, operand: u32) -> String {
    match instruction.op_kind(operand) {
        OpKind::Register => format!("reg={:?}", instruction.op_register(operand)),
        OpKind::Memory => format!(
            "mem(seg={:?},base={:?},index={:?},scale={},disp=0x{:x})",
            instruction.memory_segment(),
            instruction.memory_base(),
            instruction.memory_index(),
            instruction.memory_index_scale(),
            instruction.memory_displacement64()
        ),
        kind => format!("{kind:?}"),
    }
}

fn format_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
