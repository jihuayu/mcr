#![allow(clippy::result_large_err)]
//! Native fault diagnostics intentionally carry full guest register snapshots.

mod decoder;
mod execution;
mod native_fault;
mod operand_memory;
mod registers;
mod simple_instruction;
#[cfg(test)]
mod tests;
mod trampoline;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub(crate) const X86_64_BITNESS: u32 = 64;

pub use decoder::{
    BlockDecoder, BlockTerminator, DecodeError, DecodedBlock, DecodedFlowControl,
    DecodedInstruction, DecodedMnemonic, GuestBlock, LinearInstructionScanner, SyscallSite,
    syscall_instruction_sites,
};
pub use execution::{ExecutionError, NativeFaultStackWord, SameIsaExecutionCore};
pub use native_fault::{NativeFaultInstruction, decode_native_fault_instruction};
pub use operand_memory::{
    GuestMemoryOperandAccess, GuestMemoryOperandAccessKind, GuestMemoryOperandError,
};
pub use registers::GuestRegisters;
pub use trampoline::{
    GuestSyscallDispatcher, SyscallTrampoline, SyscallTrap, TrampolineCore, TrampolineResult,
};
