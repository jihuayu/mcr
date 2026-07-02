use core::fmt;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};
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
        let decoded = self.decode_block(block)?;
        let Some(site) = decoded.syscall_site() else {
            return Err(ExecutionError::MissingSyscall {
                terminator: *decoded.terminator(),
            });
        };

        registers.rip = site.rip;
        trampoline.enter_syscall(registers, site);

        Ok(decoded)
    }
}

impl Default for SameIsaExecutionCore {
    fn default() -> Self {
        Self::new()
    }
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
