use core::fmt;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};

use crate::X86_64_BITNESS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestBlock<'a> {
    bytes: &'a [u8],
    rip: u64,
}

impl<'a> GuestBlock<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8], rip: u64) -> Self {
        Self { bytes, rip }
    }

    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn rip(self) -> u64 {
        self.rip
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedBlock {
    instructions: Vec<DecodedInstruction>,
    terminator: BlockTerminator,
}

impl DecodedBlock {
    #[must_use]
    pub fn instructions(&self) -> &[DecodedInstruction] {
        &self.instructions
    }

    #[must_use]
    pub const fn terminator(&self) -> &BlockTerminator {
        &self.terminator
    }

    #[must_use]
    pub fn syscall_site(&self) -> Option<SyscallSite> {
        match self.terminator {
            BlockTerminator::Syscall(site) => Some(site),
            BlockTerminator::EndOfBytes
            | BlockTerminator::ControlFlow { .. }
            | BlockTerminator::Invalid { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedInstruction {
    pub rip: u64,
    pub len: usize,
    pub mnemonic: DecodedMnemonic,
}

impl DecodedInstruction {
    #[must_use]
    pub const fn end_rip(self) -> u64 {
        self.rip + self.len as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedMnemonic {
    Syscall,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockTerminator {
    Syscall(SyscallSite),
    ControlFlow { rip: u64, flow: DecodedFlowControl },
    Invalid { rip: u64 },
    EndOfBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallSite {
    pub rip: u64,
    pub next_rip: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedFlowControl {
    UnconditionalBranch,
    IndirectBranch,
    ConditionalBranch,
    Return,
    Call,
    Interrupt,
    Exception,
    XbeginXabortXend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    InvalidInstruction { rip: u64 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInstruction { rip } => {
                write!(f, "invalid x86-64 instruction at guest rip 0x{rip:016x}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

pub struct BlockDecoder;

impl BlockDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn decode(&self, block: GuestBlock<'_>) -> Result<DecodedBlock, DecodeError> {
        let mut decoder = Decoder::with_ip(
            X86_64_BITNESS,
            block.bytes(),
            block.rip(),
            DecoderOptions::NONE,
        );
        let mut instructions = Vec::new();

        while decoder.can_decode() {
            let instruction = decoder.decode();
            let rip = instruction.ip();

            if instruction.is_invalid() {
                return Err(DecodeError::InvalidInstruction { rip });
            }

            let decoded = DecodedInstruction {
                rip,
                len: instruction.len(),
                mnemonic: decoded_mnemonic(&instruction),
            };
            instructions.push(decoded);

            if instruction.mnemonic() == Mnemonic::Syscall {
                return Ok(DecodedBlock {
                    instructions,
                    terminator: BlockTerminator::Syscall(SyscallSite {
                        rip,
                        next_rip: decoded.end_rip(),
                    }),
                });
            }

            if let Some(flow) = decoded_flow_control(instruction.flow_control()) {
                return Ok(DecodedBlock {
                    instructions,
                    terminator: BlockTerminator::ControlFlow { rip, flow },
                });
            }
        }

        Ok(DecodedBlock {
            instructions,
            terminator: BlockTerminator::EndOfBytes,
        })
    }
}

impl Default for BlockDecoder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LinearInstructionScanner;

impl LinearInstructionScanner {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn scan(&self, block: GuestBlock<'_>) -> Vec<DecodedInstruction> {
        let mut decoder = Decoder::with_ip(
            X86_64_BITNESS,
            block.bytes(),
            block.rip(),
            DecoderOptions::NONE,
        );
        let mut instructions = Vec::new();

        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                continue;
            }
            instructions.push(DecodedInstruction {
                rip: instruction.ip(),
                len: instruction.len(),
                mnemonic: decoded_mnemonic(&instruction),
            });
        }

        instructions
    }
}

impl Default for LinearInstructionScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn syscall_instruction_sites(bytes: &[u8], rip: u64) -> Vec<SyscallSite> {
    let Some(last_candidate) = last_syscall_byte_pair(bytes) else {
        return Vec::new();
    };

    let mut decoder = Decoder::with_ip(X86_64_BITNESS, bytes, rip, DecoderOptions::NONE);
    let mut sites = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if !instruction.is_invalid() && instruction.mnemonic() == Mnemonic::Syscall {
            sites.push(SyscallSite {
                rip: instruction.ip(),
                next_rip: instruction.ip() + instruction.len() as u64,
            });
        }
        if decoder.position() > last_candidate {
            break;
        }
    }
    sites
}

fn last_syscall_byte_pair(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(2)
        .rposition(|window| matches!(window, [0x0f, 0x05]))
}

fn decoded_mnemonic(instruction: &Instruction) -> DecodedMnemonic {
    if instruction.mnemonic() == Mnemonic::Syscall {
        DecodedMnemonic::Syscall
    } else {
        DecodedMnemonic::Other
    }
}

pub(crate) fn decoded_flow_control(flow_control: FlowControl) -> Option<DecodedFlowControl> {
    match flow_control {
        FlowControl::Next => None,
        FlowControl::UnconditionalBranch => Some(DecodedFlowControl::UnconditionalBranch),
        FlowControl::IndirectBranch => Some(DecodedFlowControl::IndirectBranch),
        FlowControl::ConditionalBranch => Some(DecodedFlowControl::ConditionalBranch),
        FlowControl::Return => Some(DecodedFlowControl::Return),
        FlowControl::Call => Some(DecodedFlowControl::Call),
        FlowControl::IndirectCall => Some(DecodedFlowControl::Call),
        FlowControl::Interrupt => Some(DecodedFlowControl::Interrupt),
        FlowControl::XbeginXabortXend => Some(DecodedFlowControl::XbeginXabortXend),
        FlowControl::Exception => Some(DecodedFlowControl::Exception),
    }
}
