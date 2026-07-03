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
    carry: bool,
    parity: bool,
    zero: bool,
    sign: bool,
    overflow: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogicOp {
    And,
    Or,
    Xor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShiftOp {
    Shl,
    Shr,
    Sar,
}

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

struct RejectingMemoryOperandAccess;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyscallTrap {
    decoded: DecodedBlock,
    site: SyscallSite,
    registers: GuestRegisters,
}

impl SyscallTrap {
    fn new(decoded: DecodedBlock, site: SyscallSite, registers: GuestRegisters) -> Self {
        Self {
            decoded,
            site,
            registers,
        }
    }

    #[must_use]
    pub const fn decoded(&self) -> &DecodedBlock {
        &self.decoded
    }

    #[must_use]
    pub const fn site(&self) -> SyscallSite {
        self.site
    }

    #[must_use]
    pub const fn registers(&self) -> GuestRegisters {
        self.registers
    }

    #[must_use]
    pub fn into_decoded(self) -> DecodedBlock {
        self.decoded
    }

    #[must_use]
    pub fn into_registers(self) -> GuestRegisters {
        self.registers
    }

    #[must_use]
    pub fn into_parts(self) -> (DecodedBlock, SyscallSite, GuestRegisters) {
        (self.decoded, self.site, self.registers)
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
    MissingSyscall {
        terminator: BlockTerminator,
    },
    MemoryOperand {
        rip: u64,
        address: u64,
        access: GuestMemoryOperandAccessKind,
        error: GuestMemoryOperandError,
    },
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
        const MAX_CONTROL_FLOW_STEPS: usize = 4096;

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

fn execute_simple_instruction<M>(
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
        Code::Lea_r32_m if instruction.op1_kind() == OpKind::Memory => {
            let value = effective_address(registers, &instruction)? as u32;
            write_reg32(registers, instruction.op0_register(), value)?;
        }
        Code::Lea_r16_m if instruction.op1_kind() == OpKind::Memory => {
            let value = effective_address(registers, &instruction)? as u16;
            write_reg16(registers, instruction.op0_register(), value)?;
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
        Code::Add_rm64_r64
            if instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register =>
        {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_memory_u64(memory, rip, address)?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            let result = lhs.wrapping_add(rhs);
            write_memory_u64(memory, rip, address, result)?;
            flags.set_add_result(lhs, rhs, result, 64);
        }
        Code::Add_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory =>
        {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_memory_u64(memory, rip, address)?;
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
        Code::Add_rm32_r32
            if instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register =>
        {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_memory_u32(memory, rip, address)?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            let result = lhs.wrapping_add(rhs);
            write_memory_u32(memory, rip, address, result)?;
            flags.set_add_result(u64::from(lhs), u64::from(rhs), u64::from(result), 32);
        }
        Code::Add_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory =>
        {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_memory_u32(memory, rip, address)?;
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
        Code::Shl_rm64_1
        | Code::Shl_rm64_imm8
        | Code::Shl_rm64_CL
        | Code::Sal_rm64_1
        | Code::Sal_rm64_imm8
        | Code::Sal_rm64_CL => {
            execute_shift_u64(registers, flags, memory, &instruction, ShiftOp::Shl)?;
        }
        Code::Shr_rm64_1 | Code::Shr_rm64_imm8 | Code::Shr_rm64_CL => {
            execute_shift_u64(registers, flags, memory, &instruction, ShiftOp::Shr)?;
        }
        Code::Sar_rm64_1 | Code::Sar_rm64_imm8 | Code::Sar_rm64_CL => {
            execute_shift_u64(registers, flags, memory, &instruction, ShiftOp::Sar)?;
        }
        Code::Shl_rm32_1
        | Code::Shl_rm32_imm8
        | Code::Shl_rm32_CL
        | Code::Sal_rm32_1
        | Code::Sal_rm32_imm8
        | Code::Sal_rm32_CL => {
            execute_shift_u32(registers, flags, memory, &instruction, ShiftOp::Shl)?;
        }
        Code::Shr_rm32_1 | Code::Shr_rm32_imm8 | Code::Shr_rm32_CL => {
            execute_shift_u32(registers, flags, memory, &instruction, ShiftOp::Shr)?;
        }
        Code::Sar_rm32_1 | Code::Sar_rm32_imm8 | Code::Sar_rm32_CL => {
            execute_shift_u32(registers, flags, memory, &instruction, ShiftOp::Sar)?;
        }
        Code::Shl_rm8_1
        | Code::Shl_rm8_imm8
        | Code::Shl_rm8_CL
        | Code::Sal_rm8_1
        | Code::Sal_rm8_imm8
        | Code::Sal_rm8_CL => {
            execute_shift_u8(registers, flags, memory, &instruction, ShiftOp::Shl)?;
        }
        Code::Shr_rm8_1 | Code::Shr_rm8_imm8 | Code::Shr_rm8_CL => {
            execute_shift_u8(registers, flags, memory, &instruction, ShiftOp::Shr)?;
        }
        Code::Sar_rm8_1 | Code::Sar_rm8_imm8 | Code::Sar_rm8_CL => {
            execute_shift_u8(registers, flags, memory, &instruction, ShiftOp::Sar)?;
        }
        Code::Shl_rm16_1
        | Code::Shl_rm16_imm8
        | Code::Shl_rm16_CL
        | Code::Sal_rm16_1
        | Code::Sal_rm16_imm8
        | Code::Sal_rm16_CL => {
            execute_shift_u16(registers, flags, memory, &instruction, ShiftOp::Shl)?;
        }
        Code::Shr_rm16_1 | Code::Shr_rm16_imm8 | Code::Shr_rm16_CL => {
            execute_shift_u16(registers, flags, memory, &instruction, ShiftOp::Shr)?;
        }
        Code::Sar_rm16_1 | Code::Sar_rm16_imm8 | Code::Sar_rm16_CL => {
            execute_shift_u16(registers, flags, memory, &instruction, ShiftOp::Sar)?;
        }
        Code::Cmovo_r64_rm64
        | Code::Cmovno_r64_rm64
        | Code::Cmovb_r64_rm64
        | Code::Cmovae_r64_rm64
        | Code::Cmove_r64_rm64
        | Code::Cmovne_r64_rm64
        | Code::Cmovbe_r64_rm64
        | Code::Cmova_r64_rm64
        | Code::Cmovs_r64_rm64
        | Code::Cmovns_r64_rm64
        | Code::Cmovp_r64_rm64
        | Code::Cmovnp_r64_rm64
        | Code::Cmovl_r64_rm64
        | Code::Cmovge_r64_rm64
        | Code::Cmovle_r64_rm64
        | Code::Cmovg_r64_rm64 => {
            execute_cmov_u64(registers, flags, memory, &instruction)?;
        }
        Code::Cmovo_r32_rm32
        | Code::Cmovno_r32_rm32
        | Code::Cmovb_r32_rm32
        | Code::Cmovae_r32_rm32
        | Code::Cmove_r32_rm32
        | Code::Cmovne_r32_rm32
        | Code::Cmovbe_r32_rm32
        | Code::Cmova_r32_rm32
        | Code::Cmovs_r32_rm32
        | Code::Cmovns_r32_rm32
        | Code::Cmovp_r32_rm32
        | Code::Cmovnp_r32_rm32
        | Code::Cmovl_r32_rm32
        | Code::Cmovge_r32_rm32
        | Code::Cmovle_r32_rm32
        | Code::Cmovg_r32_rm32 => {
            execute_cmov_u32(registers, flags, memory, &instruction)?;
        }
        Code::Seto_rm8
        | Code::Setno_rm8
        | Code::Setb_rm8
        | Code::Setae_rm8
        | Code::Sete_rm8
        | Code::Setne_rm8
        | Code::Setbe_rm8
        | Code::Seta_rm8
        | Code::Sets_rm8
        | Code::Setns_rm8
        | Code::Setp_rm8
        | Code::Setnp_rm8
        | Code::Setl_rm8
        | Code::Setge_rm8
        | Code::Setle_rm8
        | Code::Setg_rm8 => {
            execute_setcc_u8(registers, flags, memory, &instruction)?;
        }
        Code::Bt_rm64_r64 | Code::Bt_rm64_imm8 if instruction.op0_kind() == OpKind::Register => {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_operand_or_immediate_u64(registers, memory, &instruction, 1)?;
            flags.carry = lhs & (1_u64 << (rhs & 63)) != 0;
        }
        Code::Bt_rm32_r32 | Code::Bt_rm32_imm8 if instruction.op0_kind() == OpKind::Register => {
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_operand_or_immediate_u32(registers, memory, &instruction, 1)?;
            flags.carry = lhs & (1_u32 << (rhs & 31)) != 0;
        }
        Code::Bt_rm16_r16 | Code::Bt_rm16_imm8 if instruction.op0_kind() == OpKind::Register => {
            let lhs = read_reg16(registers, instruction.op0_register())?;
            let rhs = read_operand_or_immediate_u16(registers, memory, &instruction, 1)?;
            flags.carry = lhs & (1_u16 << (rhs & 15)) != 0;
        }
        Code::Cmp_rm64_r64 | Code::Cmp_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            flags.set_sub_result(lhs, rhs, lhs.wrapping_sub(rhs), 64);
        }
        Code::Cmp_rm64_r64
            if instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register =>
        {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_memory_u64(memory, rip, address)?;
            let rhs = read_reg64(registers, instruction.op1_register())?;
            flags.set_sub_result(lhs, rhs, lhs.wrapping_sub(rhs), 64);
        }
        Code::Cmp_r64_rm64
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory =>
        {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = read_memory_u64(memory, rip, address)?;
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
        Code::Cmp_rm32_r32
            if instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register =>
        {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_memory_u32(memory, rip, address)?;
            let rhs = read_reg32(registers, instruction.op1_register())?;
            flags.set_sub_result(
                u64::from(lhs),
                u64::from(rhs),
                u64::from(lhs.wrapping_sub(rhs)),
                32,
            );
        }
        Code::Cmp_r32_rm32
            if instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory =>
        {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_reg32(registers, instruction.op0_register())?;
            let rhs = read_memory_u32(memory, rip, address)?;
            flags.set_sub_result(
                u64::from(lhs),
                u64::from(rhs),
                u64::from(lhs.wrapping_sub(rhs)),
                32,
            );
        }
        Code::Cmp_rm64_imm32 | Code::Cmp_rm64_imm8 | Code::Cmp_RAX_imm32
            if instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = read_reg64(registers, instruction.op0_register())?;
            let rhs = immediate_as_u64(&instruction)?;
            flags.set_sub_result(lhs, rhs, lhs.wrapping_sub(rhs), 64);
        }
        Code::Cmp_rm64_imm32 | Code::Cmp_rm64_imm8 if instruction.op0_kind() == OpKind::Memory => {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_memory_u64(memory, rip, address)?;
            let rhs = immediate_as_u64(&instruction)?;
            flags.set_sub_result(lhs, rhs, lhs.wrapping_sub(rhs), 64);
        }
        Code::Cmp_rm32_imm32 | Code::Cmp_rm32_imm8 | Code::Cmp_EAX_imm32
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
        Code::Cmp_rm32_imm32 | Code::Cmp_rm32_imm8 if instruction.op0_kind() == OpKind::Memory => {
            let address = effective_address(registers, &instruction)?;
            let lhs = read_memory_u32(memory, rip, address)?;
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
        Code::Test_AL_imm8 => {
            let lhs = read_reg8(registers, Register::AL)?;
            let rhs = instruction.immediate8();
            flags.set_logic_result(u64::from(lhs & rhs), 8);
        }
        Code::Test_rm16_imm16 | Code::Test_rm16_imm16_F7r1 => {
            let lhs = read_operand_u16(registers, memory, &instruction, 0)?;
            let rhs = immediate_as_u16(&instruction)?;
            flags.set_logic_result(u64::from(lhs & rhs), 16);
        }
        Code::Test_AX_imm16 => {
            let lhs = read_reg16(registers, Register::AX)?;
            let rhs = instruction.immediate16();
            flags.set_logic_result(u64::from(lhs & rhs), 16);
        }
        Code::Nopd | Code::Nopq => {}
        _ if instruction.mnemonic() == Mnemonic::Nop => {}
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
    const RFLAGS_CARRY: u64 = 1;
    const RFLAGS_PARITY: u64 = 1 << 2;
    const RFLAGS_ZERO: u64 = 1 << 6;
    const RFLAGS_SIGN: u64 = 1 << 7;
    const RFLAGS_OVERFLOW: u64 = 1 << 11;

    const fn from_registers(registers: &GuestRegisters) -> Self {
        Self {
            carry: registers.rflags & Self::RFLAGS_CARRY != 0,
            parity: registers.rflags & Self::RFLAGS_PARITY != 0,
            zero: registers.rflags & Self::RFLAGS_ZERO != 0,
            sign: registers.rflags & Self::RFLAGS_SIGN != 0,
            overflow: registers.rflags & Self::RFLAGS_OVERFLOW != 0,
        }
    }

    fn set_add_result(&mut self, lhs: u64, rhs: u64, result: u64, bits: u32) {
        let lhs = mask_to_width(lhs, bits);
        let rhs = mask_to_width(rhs, bits);
        let result = mask_to_width(result, bits);
        let sign_bit = sign_bit(bits);

        self.set_zero_sign(result, bits);
        self.carry = u128::from(lhs) + u128::from(rhs) > u128::from(mask_for_width(bits));
        self.overflow = (lhs ^ result) & (rhs ^ result) & sign_bit != 0;
    }

    fn set_sub_result(&mut self, lhs: u64, rhs: u64, result: u64, bits: u32) {
        let lhs = mask_to_width(lhs, bits);
        let rhs = mask_to_width(rhs, bits);
        let result = mask_to_width(result, bits);
        let sign_bit = sign_bit(bits);

        self.set_zero_sign(result, bits);
        self.carry = lhs < rhs;
        self.overflow = (lhs ^ rhs) & (lhs ^ result) & sign_bit != 0;
    }

    fn set_logic_result(&mut self, result: u64, bits: u32) {
        self.set_zero_sign(mask_to_width(result, bits), bits);
        self.carry = false;
        self.overflow = false;
    }

    fn set_shift_result(
        &mut self,
        operation: ShiftOp,
        lhs: u64,
        result: u64,
        count: u32,
        bits: u32,
    ) {
        let lhs = mask_to_width(lhs, bits);
        let result = mask_to_width(result, bits);

        self.set_zero_sign(result, bits);
        self.carry = match operation {
            ShiftOp::Shl if count <= bits => lhs & (1_u64 << (bits - count)) != 0,
            ShiftOp::Shr | ShiftOp::Sar if count <= bits => lhs & (1_u64 << (count - 1)) != 0,
            _ => false,
        };
        self.overflow = match (operation, count) {
            (ShiftOp::Shl, 1) => ((result & sign_bit(bits)) != 0) ^ self.carry,
            (ShiftOp::Shr, 1) => lhs & sign_bit(bits) != 0,
            (ShiftOp::Sar, 1) => false,
            _ => false,
        };
    }

    fn set_zero_sign(&mut self, result: u64, bits: u32) {
        self.zero = result == 0;
        self.sign = result & sign_bit(bits) != 0;
        self.parity = (result as u8).count_ones() % 2 == 0;
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

fn sign_extend_u64(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    ((value << shift) as i64 >> shift) as u64
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
        Code::Jp_rel8_64 | Code::Jp_rel32_64 => Ok(flags.parity),
        Code::Jnp_rel8_64 | Code::Jnp_rel32_64 => Ok(!flags.parity),
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

fn immediate_as_u16(instruction: &Instruction) -> Result<u16, ExecutionError> {
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

fn immediate_as_u8(instruction: &Instruction) -> Result<u8, ExecutionError> {
    match instruction.op1_kind() {
        OpKind::Immediate8 => Ok(instruction.immediate8()),
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid {
                rip: instruction.ip(),
            },
        }),
    }
}

fn immediate_operand_as_u64(
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

fn execute_shift_u64<M>(
    registers: &mut GuestRegisters,
    flags: &mut GuestFlags,
    memory: &mut M,
    instruction: &Instruction,
    operation: ShiftOp,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let lhs = read_operand_u64(registers, memory, instruction, 0)?;
    let count = shift_count(registers, instruction, 64)?;
    if count == 0 {
        return Ok(());
    }

    let result = apply_shift(lhs, count, 64, operation);
    write_operand_u64(registers, memory, instruction, 0, result)?;
    flags.set_shift_result(operation, lhs, result, count, 64);
    Ok(())
}

fn execute_shift_u32<M>(
    registers: &mut GuestRegisters,
    flags: &mut GuestFlags,
    memory: &mut M,
    instruction: &Instruction,
    operation: ShiftOp,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let lhs = u64::from(read_operand_u32(registers, memory, instruction, 0)?);
    let count = shift_count(registers, instruction, 32)?;
    if count == 0 {
        return Ok(());
    }

    let result = apply_shift(lhs, count, 32, operation) as u32;
    write_operand_u32(registers, memory, instruction, 0, result)?;
    flags.set_shift_result(operation, lhs, u64::from(result), count, 32);
    Ok(())
}

fn execute_shift_u16<M>(
    registers: &mut GuestRegisters,
    flags: &mut GuestFlags,
    memory: &mut M,
    instruction: &Instruction,
    operation: ShiftOp,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let lhs = u64::from(read_operand_u16(registers, memory, instruction, 0)?);
    let count = shift_count(registers, instruction, 16)?;
    if count == 0 {
        return Ok(());
    }

    let result = apply_shift(lhs, count, 16, operation) as u16;
    write_operand_u16(registers, memory, instruction, 0, result)?;
    flags.set_shift_result(operation, lhs, u64::from(result), count, 16);
    Ok(())
}

fn execute_shift_u8<M>(
    registers: &mut GuestRegisters,
    flags: &mut GuestFlags,
    memory: &mut M,
    instruction: &Instruction,
    operation: ShiftOp,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let lhs = u64::from(read_operand_u8(registers, memory, instruction, 0)?);
    let count = shift_count(registers, instruction, 8)?;
    if count == 0 {
        return Ok(());
    }

    let result = apply_shift(lhs, count, 8, operation) as u8;
    write_operand_u8(registers, memory, instruction, 0, result)?;
    flags.set_shift_result(operation, lhs, u64::from(result), count, 8);
    Ok(())
}

fn shift_count(
    registers: &GuestRegisters,
    instruction: &Instruction,
    bits: u32,
) -> Result<u32, ExecutionError> {
    let raw = match instruction.op1_kind() {
        OpKind::Immediate8 => instruction.immediate8(),
        OpKind::Register if instruction.op1_register() == Register::CL => {
            read_reg8(registers, Register::CL)?
        }
        _ => {
            return Err(ExecutionError::MissingSyscall {
                terminator: BlockTerminator::Invalid {
                    rip: instruction.ip(),
                },
            });
        }
    };
    Ok(u32::from(raw) & if bits == 64 { 0x3f } else { 0x1f })
}

fn apply_shift(lhs: u64, count: u32, bits: u32, operation: ShiftOp) -> u64 {
    let lhs = mask_to_width(lhs, bits);
    let result = match operation {
        ShiftOp::Shl => lhs << count,
        ShiftOp::Shr => lhs >> count,
        ShiftOp::Sar => {
            let shift = 64 - bits;
            ((lhs << shift) as i64 >> shift >> count) as u64
        }
    };
    mask_to_width(result, bits)
}

fn execute_cmov_u64<M>(
    registers: &mut GuestRegisters,
    flags: &GuestFlags,
    memory: &mut M,
    instruction: &Instruction,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    if condition_satisfied(instruction.code(), *flags)? {
        let value = read_operand_u64(registers, memory, instruction, 1)?;
        write_reg64(registers, instruction.op0_register(), value)?;
    }
    Ok(())
}

fn execute_cmov_u32<M>(
    registers: &mut GuestRegisters,
    flags: &GuestFlags,
    memory: &mut M,
    instruction: &Instruction,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    if condition_satisfied(instruction.code(), *flags)? {
        let value = read_operand_u32(registers, memory, instruction, 1)?;
        write_reg32(registers, instruction.op0_register(), value)?;
    }
    Ok(())
}

fn execute_setcc_u8<M>(
    registers: &mut GuestRegisters,
    flags: &GuestFlags,
    memory: &mut M,
    instruction: &Instruction,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    let value = u8::from(condition_satisfied(instruction.code(), *flags)?);
    write_operand_u8(registers, memory, instruction, 0, value)
}

fn condition_satisfied(code: Code, flags: GuestFlags) -> Result<bool, ExecutionError> {
    match code {
        Code::Cmovo_r32_rm32 | Code::Cmovo_r64_rm64 | Code::Seto_rm8 => Ok(flags.overflow),
        Code::Cmovno_r32_rm32 | Code::Cmovno_r64_rm64 | Code::Setno_rm8 => Ok(!flags.overflow),
        Code::Cmovb_r32_rm32 | Code::Cmovb_r64_rm64 | Code::Setb_rm8 => Ok(flags.carry),
        Code::Cmovae_r32_rm32 | Code::Cmovae_r64_rm64 | Code::Setae_rm8 => Ok(!flags.carry),
        Code::Cmove_r32_rm32 | Code::Cmove_r64_rm64 | Code::Sete_rm8 => Ok(flags.zero),
        Code::Cmovne_r32_rm32 | Code::Cmovne_r64_rm64 | Code::Setne_rm8 => Ok(!flags.zero),
        Code::Cmovbe_r32_rm32 | Code::Cmovbe_r64_rm64 | Code::Setbe_rm8 => {
            Ok(flags.carry || flags.zero)
        }
        Code::Cmova_r32_rm32 | Code::Cmova_r64_rm64 | Code::Seta_rm8 => {
            Ok(!flags.carry && !flags.zero)
        }
        Code::Cmovs_r32_rm32 | Code::Cmovs_r64_rm64 | Code::Sets_rm8 => Ok(flags.sign),
        Code::Cmovns_r32_rm32 | Code::Cmovns_r64_rm64 | Code::Setns_rm8 => Ok(!flags.sign),
        Code::Cmovp_r32_rm32 | Code::Cmovp_r64_rm64 | Code::Setp_rm8 => Ok(flags.parity),
        Code::Cmovnp_r32_rm32 | Code::Cmovnp_r64_rm64 | Code::Setnp_rm8 => Ok(!flags.parity),
        Code::Cmovl_r32_rm32 | Code::Cmovl_r64_rm64 | Code::Setl_rm8 => {
            Ok(flags.sign != flags.overflow)
        }
        Code::Cmovge_r32_rm32 | Code::Cmovge_r64_rm64 | Code::Setge_rm8 => {
            Ok(flags.sign == flags.overflow)
        }
        Code::Cmovle_r32_rm32 | Code::Cmovle_r64_rm64 | Code::Setle_rm8 => {
            Ok(flags.zero || flags.sign != flags.overflow)
        }
        Code::Cmovg_r32_rm32 | Code::Cmovg_r64_rm64 | Code::Setg_rm8 => {
            Ok(!flags.zero && flags.sign == flags.overflow)
        }
        _ => Err(ExecutionError::MissingSyscall {
            terminator: BlockTerminator::Invalid { rip: 0 },
        }),
    }
}

fn effective_address(
    registers: &GuestRegisters,
    instruction: &Instruction,
) -> Result<u64, ExecutionError> {
    let base = match instruction.memory_base() {
        Register::None => 0,
        Register::RIP | Register::EIP => return Ok(instruction.ip_rel_memory_address()),
        base => read_reg64(registers, base)?,
    };
    let index = match instruction.memory_index() {
        Register::None => 0,
        index => {
            read_reg64(registers, index)?.wrapping_mul(u64::from(instruction.memory_index_scale()))
        }
    };
    Ok(base
        .wrapping_add(index)
        .wrapping_add(instruction.memory_displacement64()))
}

fn read_operand_u8<M>(
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

fn read_operand_u16<M>(
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

fn read_operand_u32<M>(
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

fn read_operand_u64<M>(
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

fn read_operand_or_immediate_u32<M>(
    registers: &GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
) -> Result<u32, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Immediate8 => Ok(u32::from(instruction.immediate8())),
        OpKind::Immediate8to32 | OpKind::Immediate32 => immediate_as_u32(instruction),
        _ => read_operand_u32(registers, memory, instruction, operand),
    }
}

fn read_operand_or_immediate_u16<M>(
    registers: &GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
) -> Result<u16, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Immediate8 => Ok(u16::from(instruction.immediate8())),
        OpKind::Immediate8to16 | OpKind::Immediate16 => immediate_as_u16(instruction),
        _ => read_operand_u16(registers, memory, instruction, operand),
    }
}

fn read_operand_or_immediate_u64<M>(
    registers: &GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
) -> Result<u64, ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Immediate8 => Ok(u64::from(instruction.immediate8())),
        OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate64 => {
            immediate_as_u64(instruction)
        }
        _ => read_operand_u64(registers, memory, instruction, operand),
    }
}

fn write_operand_u32<M>(
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

fn write_operand_u8<M>(
    registers: &mut GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
    value: u8,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Register => write_reg8(registers, instruction.op_register(operand), value),
        OpKind::Memory => write_memory_u8(
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

fn write_operand_u16<M>(
    registers: &mut GuestRegisters,
    memory: &mut M,
    instruction: &Instruction,
    operand: u32,
    value: u16,
) -> Result<(), ExecutionError>
where
    M: GuestMemoryOperandAccess,
{
    match instruction.op_kind(operand) {
        OpKind::Register => write_reg16(registers, instruction.op_register(operand), value),
        OpKind::Memory => write_memory_u16(
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

fn write_operand_u64<M>(
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

fn read_memory_u8<M>(memory: &mut M, rip: u64, address: u64) -> Result<u8, ExecutionError>
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

fn read_memory_u16<M>(memory: &mut M, rip: u64, address: u64) -> Result<u16, ExecutionError>
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

fn write_memory_u8<M>(
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

fn write_memory_u16<M>(
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

fn read_memory_u32<M>(memory: &mut M, rip: u64, address: u64) -> Result<u32, ExecutionError>
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

fn read_memory_u64<M>(memory: &mut M, rip: u64, address: u64) -> Result<u64, ExecutionError>
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

fn write_memory_u32<M>(
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

fn write_memory_u64<M>(
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

fn read_reg8(registers: &GuestRegisters, register: Register) -> Result<u8, ExecutionError> {
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

fn read_reg16(registers: &GuestRegisters, register: Register) -> Result<u16, ExecutionError> {
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

fn write_reg8(
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

fn write_reg16(
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
        GuestBlock, GuestMemoryOperandAccess, GuestMemoryOperandError, GuestRegisters,
        SameIsaExecutionCore, TrampolineCore,
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
            super::SyscallSite {
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
                0x48, 0xb8, 0x13, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00,
                0x00, // mov rax,0x430013
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
                0x48, 0xb8, 0x13, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00,
                0x00, // mov rax,0x430013
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
    fn execution_core_resolves_32_bit_lea_addresses() {
        let block = GuestBlock::new(
            &[
                0x44, 0x8d, 0x34, 0x02, // lea r14d,[rdx+rax]
                0x66, 0x8d, 0x34, 0x02, // lea si,[rdx+rax]
                0x0f, 0x05, // syscall
            ],
            0x460040,
        );
        let registers = GuestRegisters {
            rax: 0xffff_ffff_0000_0003,
            rdx: 0x1_0000_0004,
            r14: 0xffff_ffff_ffff_ffff,
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory = TestGuestMemory::default();

        let trap = SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute 32-bit lea before syscall");

        assert_eq!(trap.registers().r14, 7);
        assert_eq!(trap.registers().rsi, 7);
        assert_eq!(trap.site().rip, 0x460048);
    }

    #[test]
    fn execution_core_ignores_multibyte_nops() {
        let block = GuestBlock::new(
            &[
                0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, // nop dword ptr [rax]
                0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00,
                0x00, // nop word ptr cs:[rax+rax]
                0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
                0x0f, 0x05, // syscall
            ],
            0x468000,
        );
        let mut registers = GuestRegisters {
            rip: block.rip(),
            rflags: 0x246,
            ..GuestRegisters::default()
        };
        let mut captured_number = None;
        let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
            captured_number = Some(context.registers.number());
            SyscallReturn::success(9).encode_u64()
        });

        SameIsaExecutionCore::new()
            .execute_until_syscall(block, &mut registers, &mut trampoline)
            .expect("execute through musl-style multi-byte nops");

        assert_eq!(captured_number, Some(Syscall::GETPID));
        assert_eq!(registers.rax, 9);
    }

    #[test]
    fn execution_core_evaluates_accumulator_test_immediates() {
        let block = GuestBlock::new(
            &[
                0xb8, 0x03, 0x00, 0x00, 0x00, // mov eax,3
                0xa8, 0x01, // test al,1
                0x74, 0x07, // je skipped
                0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
                0x0f, 0x05, // syscall
            ],
            0x469000,
        );
        let mut registers = GuestRegisters {
            rip: block.rip(),
            rflags: 0x246,
            ..GuestRegisters::default()
        };
        let mut captured_number = None;
        let mut trampoline = TrampolineCore::new(42, 43, |context: mcr_sys::GuestContext| {
            captured_number = Some(context.registers.number());
            SyscallReturn::success(11).encode_u64()
        });

        SameIsaExecutionCore::new()
            .execute_until_syscall(block, &mut registers, &mut trampoline)
            .expect("execute accumulator test immediate");

        assert_eq!(captured_number, Some(Syscall::GETPID));
        assert_eq!(registers.rax, 11);
    }

    #[test]
    fn execution_core_adds_registers_into_memory_operands() {
        let block = GuestBlock::new(
            &[
                0x48, 0x01, 0x13, // add qword ptr [rbx],rdx
                0x01, 0x4b, 0x08, // add dword ptr [rbx+8],ecx
                0x0f, 0x05, // syscall
            ],
            0x469100,
        );
        let registers = GuestRegisters {
            rbx: 0x712100,
            rcx: 3,
            rdx: 5,
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory =
            TestGuestMemory::with_bytes(0x712100, &[7, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0]);

        SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute memory add operands before syscall");

        assert_eq!(
            memory.read::<12>(0x712100),
            [12, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0]
        );
    }

    #[test]
    fn execution_core_adds_memory_operands_into_registers() {
        let block = GuestBlock::new(
            &[
                0x48, 0x03, 0x78, 0x20, // add rdi,qword ptr [rax+0x20]
                0x03, 0x48, 0x28, // add ecx,dword ptr [rax+0x28]
                0x0f, 0x05, // syscall
            ],
            0x469140,
        );
        let registers = GuestRegisters {
            rax: 0x713000,
            rcx: 4,
            rdi: 5,
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory = TestGuestMemory::with_bytes(0x713020, &7_u64.to_le_bytes());
        memory.write(0x713028, &8_u32.to_le_bytes());

        let trap = SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute memory add sources before syscall");

        assert_eq!(trap.registers().rdi, 12);
        assert_eq!(trap.registers().rcx, 12);
        assert_eq!(trap.site().rip, 0x469147);
    }

    #[test]
    fn execution_core_executes_register_shift_operands() {
        let block = GuestBlock::new(
            &[
                0x48, 0xb8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x80, // mov rax,0x8000000000000004
                0x48, 0xd1, 0xe8, // shr rax,1
                0xb9, 0x03, 0x00, 0x00, 0x00, // mov ecx,3
                0xd3, 0xe0, // shl eax,cl
                0x48, 0xc1, 0xff, 0x04, // sar rdi,4
                0xb0, 0x20, // mov al,0x20
                0xc0, 0xe8, 0x04, // shr al,4
                0x66, 0xc1, 0xe6, 0x04, // shl si,4
                0x0f, 0x05, // syscall
            ],
            0x469180,
        );
        let registers = GuestRegisters {
            rdi: 0xffff_ffff_ffff_ff00,
            rsi: 3,
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory = TestGuestMemory::default();

        let trap = SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute register shifts before syscall");

        assert_eq!(trap.registers().rax, 0x02);
        assert_eq!(trap.registers().rdi, 0xffff_ffff_ffff_fff0);
        assert_eq!(trap.registers().rsi, 0x30);
        assert_eq!(trap.site().rip, 0x4691a1);
    }

    #[test]
    fn execution_core_executes_conditional_move_operands() {
        let block = GuestBlock::new(
            &[
                0x48, 0x31, 0xc0, // xor rax,rax
                0x48, 0x0f, 0x44, 0xc7, // cmove rax,rdi
                0x48, 0x0f, 0x45, 0xd6, // cmovne rdx,rsi
                0x0f, 0x05, // syscall
            ],
            0x4691c0,
        );
        let registers = GuestRegisters {
            rdx: 0x1111,
            rsi: 0x2222,
            rdi: 0x3333,
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory = TestGuestMemory::default();

        let trap = SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute conditional moves before syscall");

        assert_eq!(trap.registers().rax, 0x3333);
        assert_eq!(trap.registers().rdx, 0x1111);
        assert_eq!(trap.site().rip, 0x4691cb);
    }

    #[test]
    fn execution_core_executes_setcc_operands() {
        let block = GuestBlock::new(
            &[
                0x48, 0x83, 0x7b, 0x10, 0x07, // cmp qword ptr [rbx+0x10],7
                0x0f, 0x94, 0xc1, // sete cl
                0x0f, 0x95, 0x43, 0x18, // setne byte ptr [rbx+0x18]
                0x0f, 0x05, // syscall
            ],
            0x4691e0,
        );
        let registers = GuestRegisters {
            rbx: 0x714800,
            rcx: 0xff00,
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory = TestGuestMemory::with_bytes(0x714810, &7_u64.to_le_bytes());

        let trap = SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute setcc before syscall");

        assert_eq!(trap.registers().rcx, 0xff01);
        assert_eq!(memory.read::<1>(0x714818), [0]);
        assert_eq!(trap.site().rip, 0x4691ec);
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
                access: super::GuestMemoryOperandAccessKind::Write,
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
                access: super::GuestMemoryOperandAccessKind::Write,
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
                access: super::GuestMemoryOperandAccessKind::Read,
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
    fn execution_core_uses_accumulator_cmp_immediate_for_branch() {
        let block = GuestBlock::new(
            &[
                0x48, 0xb8, 0xf0, 0xff, 0xff, 0x6f, 0x00, 0x00, 0x00,
                0x00, // mov rax,0x6ffffff0
                0x48, 0x3d, 0xf0, 0xff, 0xff, 0x6f, // cmp rax,0x6ffffff0
                0x74, 0x07, // je success
                0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
                0x0f, 0x05, // skipped syscall
                0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
                0x0f, 0x05, // syscall
            ],
            0x470080,
        );
        let registers = GuestRegisters {
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory = TestGuestMemory::default();

        let trap = SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute accumulator cmp immediate before branch");

        assert_eq!(trap.registers().rax, Syscall::Getpid.number().raw());
        assert_eq!(trap.site().rip, 0x47009e);
    }

    #[test]
    fn execution_core_uses_memory_cmp_immediate_for_branch() {
        let block = GuestBlock::new(
            &[
                0x48, 0x83, 0x7b, 0x10, 0x07, // cmp qword ptr [rbx+0x10],7
                0x75, 0x07, // jne exit
                0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
                0x0f, 0x05, // syscall
                0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
                0x0f, 0x05, // skipped syscall
            ],
            0x4700c0,
        );
        let registers = GuestRegisters {
            rbx: 0x714000,
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory = TestGuestMemory::with_bytes(0x714010, &7_u64.to_le_bytes());

        let trap = SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute memory cmp immediate before branch");

        assert_eq!(trap.registers().rax, Syscall::Getpid.number().raw());
        assert_eq!(trap.site().rip, 0x4700cc);
    }

    #[test]
    fn execution_core_uses_memory_register_cmp_for_setcc() {
        let block = GuestBlock::new(
            &[
                0x48, 0x39, 0x73, 0x10, // cmp qword ptr [rbx+0x10],rsi
                0x0f, 0x94, 0xc0, // sete al
                0x3b, 0x4b, 0x18, // cmp ecx,dword ptr [rbx+0x18]
                0x0f, 0x95, 0xc2, // setne dl
                0x0f, 0x05, // syscall
            ],
            0x470100,
        );
        let registers = GuestRegisters {
            rbx: 0x714400,
            rcx: 8,
            rdx: 0xff00,
            rsi: 7,
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory = TestGuestMemory::with_bytes(0x714410, &7_u64.to_le_bytes());
        memory.write(0x714418, &8_u32.to_le_bytes());

        let trap = SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute memory/register cmp before setcc");

        assert_eq!(trap.registers().rax, 1);
        assert_eq!(trap.registers().rdx, 0xff00);
        assert_eq!(trap.site().rip, 0x47010d);
    }

    #[test]
    fn execution_core_uses_bit_test_carry_for_branch() {
        let block = GuestBlock::new(
            &[
                0x48, 0xb8, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, // mov rax,0x20
                0x48, 0x0f, 0xa3, 0xf8, // bt rax,rdi
                0x73, 0x07, // jae exit
                0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,39
                0x0f, 0x05, // syscall
                0xb8, 0x3c, 0x00, 0x00, 0x00, // skipped mov eax,60
                0x0f, 0x05, // skipped syscall
            ],
            0x470140,
        );
        let registers = GuestRegisters {
            rdi: 5,
            rip: block.rip(),
            ..GuestRegisters::default()
        };
        let mut memory = TestGuestMemory::default();

        let trap = SameIsaExecutionCore::new()
            .execute_to_syscall_trap_with_memory(block, registers, &mut memory)
            .expect("execute bit test before branch");

        assert_eq!(trap.registers().rax, Syscall::Getpid.number().raw());
        assert_eq!(trap.site().rip, 0x470155);
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
        let mut trampoline =
            TrampolineCore::new(42, 43, |_| SyscallReturn::success(4242).encode_u64());

        let error = SameIsaExecutionCore::new()
            .execute_until_syscall(block, &mut registers, &mut trampoline)
            .expect_err("memory load requires a guest memory adapter");

        assert_eq!(
            error,
            ExecutionError::MemoryOperand {
                rip: 0x472000,
                address: 0,
                access: super::GuestMemoryOperandAccessKind::Read,
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
        for _ in 0..300 {
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
        assert_eq!(trap.site().rip, 0x4814b0);
    }
}
