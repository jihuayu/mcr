use core::fmt;

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};
use mcr_sys::{
    GuestContext, GuestPid, GuestTid, SyscallDispatcher, SyscallRegisters, SyscallSubsystems,
    SyscallTracer,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

const X86_64_BITNESS: u32 = 64;

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

fn decoded_mnemonic(instruction: &Instruction) -> DecodedMnemonic {
    if instruction.mnemonic() == Mnemonic::Syscall {
        DecodedMnemonic::Syscall
    } else {
        DecodedMnemonic::Other
    }
}

fn decoded_flow_control(flow_control: FlowControl) -> Option<DecodedFlowControl> {
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestFlags {
    zero: bool,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrampolineResult {
    pub encoded_rax: u64,
    pub next_rip: u64,
}

pub trait SyscallTrampoline {
    fn dispatch_syscall(&mut self, context: GuestContext) -> TrampolineResult;
}

pub trait GuestSyscallDispatcher {
    fn dispatch_guest_syscall(&mut self, context: GuestContext) -> u64;
}

impl<F> GuestSyscallDispatcher for F
where
    F: FnMut(GuestContext) -> u64,
{
    fn dispatch_guest_syscall(&mut self, context: GuestContext) -> u64 {
        self(context)
    }
}

impl<S, T> GuestSyscallDispatcher for SyscallDispatcher<S, T>
where
    S: SyscallSubsystems,
    T: SyscallTracer,
{
    fn dispatch_guest_syscall(&mut self, context: GuestContext) -> u64 {
        self.dispatch(context).encoded_rax
    }
}

pub struct TrampolineCore<T> {
    pid: GuestPid,
    tid: GuestTid,
    dispatcher: T,
}

impl<T> TrampolineCore<T> {
    #[must_use]
    pub const fn new(pid: GuestPid, tid: GuestTid, dispatcher: T) -> Self {
        Self {
            pid,
            tid,
            dispatcher,
        }
    }

    #[must_use]
    pub const fn pid(&self) -> GuestPid {
        self.pid
    }

    #[must_use]
    pub const fn tid(&self) -> GuestTid {
        self.tid
    }

    #[must_use]
    pub const fn dispatcher(&self) -> &T {
        &self.dispatcher
    }

    #[must_use]
    pub const fn dispatcher_mut(&mut self) -> &mut T {
        &mut self.dispatcher
    }

    #[must_use]
    pub fn into_dispatcher(self) -> T {
        self.dispatcher
    }
}

impl<T> SyscallTrampoline for TrampolineCore<T>
where
    T: GuestSyscallDispatcher,
{
    fn dispatch_syscall(&mut self, context: GuestContext) -> TrampolineResult {
        TrampolineResult {
            encoded_rax: self.dispatcher.dispatch_guest_syscall(context),
            next_rip: context.registers.rip + 2,
        }
    }
}

impl<T> TrampolineCore<T>
where
    T: GuestSyscallDispatcher,
{
    pub fn enter_syscall(&mut self, registers: &mut GuestRegisters, site: SyscallSite) {
        let result = self.dispatch_syscall(GuestContext::new(
            self.pid,
            self.tid,
            registers.syscall_registers(),
        ));
        registers.apply_syscall_return(result.encoded_rax, site.next_rip);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    Decode(DecodeError),
    MissingSyscall { terminator: BlockTerminator },
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(f),
            Self::MissingSyscall { terminator } => {
                write!(
                    f,
                    "guest block did not terminate at syscall: {terminator:?}"
                )
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
        const MAX_CONTROL_FLOW_STEPS: usize = 32;

        let mut current_rip = block.rip();
        let mut flags = GuestFlags::from_registers(registers);
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
                    registers,
                    &mut flags,
                    instruction.rip,
                    instruction.len,
                )?;
            }

            if let Some(site) = decoded.syscall_site() {
                registers.rip = site.rip;
                trampoline.enter_syscall(registers, site);
                return Ok(decoded);
            }

            if let Some(target) = control_flow_target(block, &decoded, flags)? {
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

fn execute_simple_instruction(
    block: GuestBlock<'_>,
    registers: &mut GuestRegisters,
    flags: &mut GuestFlags,
    rip: u64,
    len: usize,
) -> Result<(), ExecutionError> {
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
        Code::Mov_r32_imm32 => {
            write_reg32(
                registers,
                instruction.op0_register(),
                instruction.immediate32(),
            )?;
        }
        Code::Mov_rm64_r64 | Code::Mov_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let value = read_reg64(registers, instruction.op1_register())?;
            write_reg64(registers, instruction.op0_register(), value)?;
        }
        Code::Mov_rm32_r32 | Code::Mov_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let value = read_reg32(registers, instruction.op1_register())?;
            write_reg32(registers, instruction.op0_register(), value)?;
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
            flags.zero = result == 0;
        }
        Code::Add_rm32_r32 | Code::Add_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            let result = lhs.wrapping_add(rhs);
            write_reg32(registers, instruction.op0_register(), result)?;
            flags.zero = result == 0;
        }
        Code::Add_rm64_imm32 | Code::Add_rm64_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = immediate_as_u64(&instruction)?;
            let result = lhs.wrapping_add(rhs);
            write_reg64(registers, instruction.op0_register(), result)?;
            flags.zero = result == 0;
        }
        Code::Add_rm32_imm32 | Code::Add_rm32_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = immediate_as_u32(&instruction)?;
            let result = lhs.wrapping_add(rhs);
            write_reg32(registers, instruction.op0_register(), result)?;
            flags.zero = result == 0;
        }
        Code::Sub_rm64_r64 | Code::Sub_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            let result = lhs.wrapping_sub(rhs);
            write_reg64(registers, instruction.op0_register(), result)?;
            flags.zero = result == 0;
        }
        Code::Sub_rm32_r32 | Code::Sub_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            let result = lhs.wrapping_sub(rhs);
            write_reg32(registers, instruction.op0_register(), result)?;
            flags.zero = result == 0;
        }
        Code::Sub_rm64_imm32 | Code::Sub_rm64_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = immediate_as_u64(&instruction)?;
            let result = lhs.wrapping_sub(rhs);
            write_reg64(registers, instruction.op0_register(), result)?;
            flags.zero = result == 0;
        }
        Code::Sub_rm32_imm32 | Code::Sub_rm32_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = immediate_as_u32(&instruction)?;
            let result = lhs.wrapping_sub(rhs);
            write_reg32(registers, instruction.op0_register(), result)?;
            flags.zero = result == 0;
        }
        Code::Cmp_rm64_r64 | Code::Cmp_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            flags.zero = lhs.wrapping_sub(rhs) == 0;
        }
        Code::Cmp_rm32_r32 | Code::Cmp_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            flags.zero = lhs.wrapping_sub(rhs) == 0;
        }
        Code::Cmp_rm64_imm32 | Code::Cmp_rm64_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = immediate_as_u64(&instruction)?;
            flags.zero = lhs.wrapping_sub(rhs) == 0;
        }
        Code::Cmp_rm32_imm32 | Code::Cmp_rm32_imm8
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = immediate_as_u32(&instruction)?;
            flags.zero = lhs.wrapping_sub(rhs) == 0;
        }
        Code::Xor_r64_rm64 | Code::Xor_r32_rm32 | Code::Xor_rm64_r64 | Code::Xor_rm32_r32
            if instruction.op1_kind() == OpKind::Register
                && instruction.op0_register() == instruction.op1_register() =>
        {
            write_reg64(registers, instruction.op0_register(), 0)?;
            flags.zero = true;
        }
        Code::Test_rm32_r32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            flags.zero = lhs & rhs == 0;
        }
        Code::Test_rm64_r64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            flags.zero = lhs & rhs == 0;
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

impl GuestFlags {
    const RFLAGS_ZERO: u64 = 1 << 6;

    const fn from_registers(registers: &GuestRegisters) -> Self {
        Self {
            zero: registers.rflags & Self::RFLAGS_ZERO != 0,
        }
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

fn control_flow_target(
    block: GuestBlock<'_>,
    decoded: &DecodedBlock,
    flags: GuestFlags,
) -> Result<Option<u64>, ExecutionError> {
    let BlockTerminator::ControlFlow { flow, .. } = decoded.terminator() else {
        return Ok(None);
    };
    if !matches!(
        flow,
        DecodedFlowControl::UnconditionalBranch | DecodedFlowControl::ConditionalBranch
    ) {
        return Ok(None);
    }
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

fn branch_taken(instruction: &Instruction, flags: GuestFlags) -> Result<bool, ExecutionError> {
    match instruction.code() {
        Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => Ok(true),
        Code::Je_rel8_64 | Code::Je_rel32_64 => Ok(flags.zero),
        Code::Jne_rel8_64 | Code::Jne_rel32_64 => Ok(!flags.zero),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::ControlFlow {
                rip: instruction.ip(),
                flow: decoded_flow_control(instruction.flow_control())
                    .unwrap_or(DecodedFlowControl::Exception),
            },
        }),
    }
}

fn immediate_as_u64(instruction: &Instruction) -> Result<u64, ExecutionError> {
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

fn immediate_as_u32(instruction: &Instruction) -> Result<u32, ExecutionError> {
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

fn effective_address(
    registers: &GuestRegisters,
    instruction: &Instruction,
) -> Result<u64, ExecutionError> {
    if instruction.memory_index() != Register::None {
        return Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::ControlFlow {
                rip: instruction.ip(),
                flow: DecodedFlowControl::Exception,
            },
        });
    }

    match instruction.memory_base() {
        Register::None => Ok(instruction.memory_displacement64()),
        Register::RIP | Register::EIP => Ok(instruction.ip_rel_memory_address()),
        base => Ok(read_reg64(registers, base)?.wrapping_add(instruction.memory_displacement64())),
    }
}

fn read_reg64(registers: &GuestRegisters, register: Register) -> Result<u64, ExecutionError> {
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

fn read_reg32(registers: &GuestRegisters, register: Register) -> Result<u32, ExecutionError> {
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

fn write_reg32(
    registers: &mut GuestRegisters,
    register: Register,
    value: u32,
) -> Result<(), ExecutionError> {
    write_reg64(registers, register, u64::from(value))
}

fn write_reg64(
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

#[cfg(test)]
mod tests {
    use super::{
        BlockDecoder, BlockTerminator, DecodedFlowControl, DecodedMnemonic, ExecutionError,
        GuestBlock, GuestRegisters, SameIsaExecutionCore, TrampolineCore,
    };
    use mcr_sys::{LinuxErrno, Syscall, SyscallReturn};

    #[test]
    fn package_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "mcr-jit");
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
            &BlockTerminator::Syscall(super::SyscallSite {
                rip: 0x400007,
                next_rip: 0x400009,
            })
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
            super::DecodeError::InvalidInstruction { rip: 0x402000 }
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
    fn trampoline_preserves_guest_state_and_applies_linux_return_registers() {
        let site = super::SyscallSite {
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
            Some(super::SyscallSite {
                rip: 0x410007,
                next_rip: 0x410009,
            })
        );
        assert_eq!(captured_number, Some(Syscall::GETPID));
        assert_eq!(registers.rax, 4242);
        assert_eq!(registers.rip, 0x410009);
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
    fn execution_core_rejects_unsupported_memory_operand_before_syscall() {
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
        let mut trampoline =
            TrampolineCore::new(42, 43, |_| SyscallReturn::success(4242).encode_u64());

        let error = SameIsaExecutionCore::new()
            .execute_until_syscall(block, &mut registers, &mut trampoline)
            .expect_err("memory load remains unsupported");

        assert_eq!(
            error,
            ExecutionError::MissingSyscall {
                terminator: BlockTerminator::ControlFlow {
                    rip: 0x472000,
                    flow: DecodedFlowControl::Exception,
                }
            }
        );
    }

    #[test]
    fn execution_core_returns_error_when_block_has_no_syscall() {
        let block = GuestBlock::new(&[0x90], 0x420000);
        let mut registers = GuestRegisters::default();
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
}
