use mcr_jit::GuestRegisters;
use mcr_sys::LinuxErrno;
use mcr_task::GuestSignalAction;

use crate::{GuestMemoryAccess, GuestSignalAltStack, read_guest_u64};

pub(crate) const LINUX_SIGSEGV: u32 = 11;
pub(crate) const LINUX_SEGV_MAPERR: i32 = 1;
pub(crate) const LINUX_SIG_DFL: u64 = 0;
pub(crate) const LINUX_SIG_IGN: u64 = 1;
#[cfg(test)]
pub(crate) const LINUX_SA_SIGINFO: u64 = 0x0000_0004;
pub(crate) const LINUX_SA_RESTORER: u64 = 0x0400_0000;
pub(crate) const LINUX_SA_ONSTACK: u64 = 0x0800_0000;
pub(crate) const LINUX_SA_NODEFER: u64 = 0x4000_0000;

const X86_EFLAGS_TF: u64 = 0x0000_0100;
const X86_EFLAGS_DF: u64 = 0x0000_0400;
const X86_EFLAGS_RF: u64 = 0x0001_0000;
const X86_64_SIGNAL_RED_ZONE: u64 = 128;
const X86_64_FRAME_ALIGNMENT: u64 = 16;
const X86_64_RT_SIGFRAME_SIZE: u64 = 440;

const RT_SIGFRAME_PRETCODE_OFFSET: u64 = 0;
const RT_SIGFRAME_UCONTEXT_OFFSET: u64 = 8;
const RT_SIGFRAME_SIGINFO_OFFSET: u64 = 312;

const UCONTEXT_UC_FLAGS_OFFSET: u64 = 0;
const UCONTEXT_UC_LINK_OFFSET: u64 = 8;
const UCONTEXT_STACK_OFFSET: u64 = 16;
const UCONTEXT_MCONTEXT_OFFSET: u64 = 40;
const UCONTEXT_SIGMASK_OFFSET: u64 = 296;

const STACK_T_SP_OFFSET: u64 = 0;
const STACK_T_FLAGS_OFFSET: u64 = 8;
const STACK_T_SIZE_OFFSET: u64 = 16;

const SIGINFO_SIGNO_OFFSET: u64 = 0;
const SIGINFO_ERRNO_OFFSET: u64 = 4;
const SIGINFO_CODE_OFFSET: u64 = 8;
const SIGINFO_ADDR_OFFSET: u64 = 16;

const SIGCONTEXT_R8_OFFSET: u64 = 0;
const SIGCONTEXT_R9_OFFSET: u64 = 8;
const SIGCONTEXT_R10_OFFSET: u64 = 16;
const SIGCONTEXT_R11_OFFSET: u64 = 24;
const SIGCONTEXT_R12_OFFSET: u64 = 32;
const SIGCONTEXT_R13_OFFSET: u64 = 40;
const SIGCONTEXT_R14_OFFSET: u64 = 48;
const SIGCONTEXT_R15_OFFSET: u64 = 56;
const SIGCONTEXT_RDI_OFFSET: u64 = 64;
const SIGCONTEXT_RSI_OFFSET: u64 = 72;
const SIGCONTEXT_RBP_OFFSET: u64 = 80;
const SIGCONTEXT_RBX_OFFSET: u64 = 88;
const SIGCONTEXT_RDX_OFFSET: u64 = 96;
const SIGCONTEXT_RAX_OFFSET: u64 = 104;
const SIGCONTEXT_RCX_OFFSET: u64 = 112;
const SIGCONTEXT_RSP_OFFSET: u64 = 120;
const SIGCONTEXT_RIP_OFFSET: u64 = 128;
const SIGCONTEXT_EFLAGS_OFFSET: u64 = 136;
const SIGCONTEXT_CS_OFFSET: u64 = 144;
const SIGCONTEXT_GS_OFFSET: u64 = 146;
const SIGCONTEXT_FS_OFFSET: u64 = 148;
const SIGCONTEXT_SS_OFFSET: u64 = 150;
const SIGCONTEXT_ERR_OFFSET: u64 = 152;
const SIGCONTEXT_TRAPNO_OFFSET: u64 = 160;
const SIGCONTEXT_OLDMASK_OFFSET: u64 = 168;
const SIGCONTEXT_CR2_OFFSET: u64 = 176;
const SIGCONTEXT_FPSTATE_OFFSET: u64 = 184;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoredSignalFrame {
    pub(crate) registers: GuestRegisters,
    pub(crate) signal_mask: u64,
}

pub(crate) fn setup_rt_signal_frame(
    memory: &mut impl GuestMemoryAccess,
    registers: GuestRegisters,
    action: GuestSignalAction,
    signal: u32,
    signal_mask: u64,
    fault_address: u64,
    alt_stack: Option<GuestSignalAltStack>,
) -> Result<GuestRegisters, LinuxErrno> {
    if action.action() == LINUX_SIG_DFL
        || action.action() == LINUX_SIG_IGN
        || action.flags() & LINUX_SA_RESTORER == 0
        || action.restorer() == 0
    {
        return Err(LinuxErrno::EINVAL);
    }

    let frame = signal_frame_address(registers.rsp, action.flags(), alt_stack)?;
    let uc = frame
        .checked_add(RT_SIGFRAME_UCONTEXT_OFFSET)
        .ok_or(LinuxErrno::EFAULT)?;
    let mcontext = uc
        .checked_add(UCONTEXT_MCONTEXT_OFFSET)
        .ok_or(LinuxErrno::EFAULT)?;
    let siginfo = frame
        .checked_add(RT_SIGFRAME_SIGINFO_OFFSET)
        .ok_or(LinuxErrno::EFAULT)?;

    memory
        .write_bytes(frame, &vec![0; X86_64_RT_SIGFRAME_SIZE as usize])
        .map_err(|_| LinuxErrno::EFAULT)?;
    write_u64(
        memory,
        frame + RT_SIGFRAME_PRETCODE_OFFSET,
        action.restorer(),
    )?;
    write_u64(memory, uc + UCONTEXT_UC_FLAGS_OFFSET, 0)?;
    write_u64(memory, uc + UCONTEXT_UC_LINK_OFFSET, 0)?;
    write_signal_stack(memory, uc + UCONTEXT_STACK_OFFSET, alt_stack)?;
    write_sigcontext(memory, mcontext, registers, signal_mask, fault_address)?;
    write_u64(memory, uc + UCONTEXT_SIGMASK_OFFSET, signal_mask)?;
    write_siginfo(memory, siginfo, signal, LINUX_SEGV_MAPERR, fault_address)?;

    let mut handler_registers = registers;
    handler_registers.rdi = u64::from(signal);
    handler_registers.rax = 0;
    handler_registers.rsi = siginfo;
    handler_registers.rdx = uc;
    handler_registers.rip = action.action();
    handler_registers.rsp = frame;
    handler_registers.rflags &= !(X86_EFLAGS_DF | X86_EFLAGS_RF | X86_EFLAGS_TF);
    Ok(handler_registers)
}

pub(crate) fn restore_rt_signal_frame(
    memory: &impl GuestMemoryAccess,
    registers: GuestRegisters,
) -> Result<RestoredSignalFrame, LinuxErrno> {
    let frame = registers.rsp.checked_sub(8).ok_or(LinuxErrno::EFAULT)?;
    let uc = frame
        .checked_add(RT_SIGFRAME_UCONTEXT_OFFSET)
        .ok_or(LinuxErrno::EFAULT)?;
    let mcontext = uc
        .checked_add(UCONTEXT_MCONTEXT_OFFSET)
        .ok_or(LinuxErrno::EFAULT)?;
    let signal_mask = read_guest_u64(memory, uc + UCONTEXT_SIGMASK_OFFSET)?;
    let mut restored = read_sigcontext(memory, mcontext)?;
    restored.fs_base = registers.fs_base;
    Ok(RestoredSignalFrame {
        registers: restored,
        signal_mask,
    })
}

pub(crate) const fn signal_mask_for(signal: u32) -> u64 {
    if signal == 0 || signal > 64 {
        0
    } else {
        1u64 << (signal - 1)
    }
}

fn signal_frame_address(
    current_rsp: u64,
    flags: u64,
    alt_stack: Option<GuestSignalAltStack>,
) -> Result<u64, LinuxErrno> {
    let mut sp = current_rsp
        .checked_sub(X86_64_SIGNAL_RED_ZONE)
        .ok_or(LinuxErrno::EFAULT)?;
    if flags & LINUX_SA_ONSTACK != 0
        && let Some(stack) = alt_stack
        && !stack.disabled()
        && !on_signal_stack(current_rsp, stack)
    {
        sp = stack.sp.checked_add(stack.size).ok_or(LinuxErrno::EFAULT)?;
    }
    sp = sp
        .checked_sub(X86_64_RT_SIGFRAME_SIZE)
        .ok_or(LinuxErrno::EFAULT)?;
    Ok(round_down(sp, X86_64_FRAME_ALIGNMENT)
        .checked_sub(8)
        .ok_or(LinuxErrno::EFAULT)?)
}

fn on_signal_stack(rsp: u64, stack: GuestSignalAltStack) -> bool {
    stack
        .sp
        .checked_add(stack.size)
        .is_some_and(|end| rsp >= stack.sp && rsp < end)
}

const fn round_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn write_signal_stack(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    stack: Option<GuestSignalAltStack>,
) -> Result<(), LinuxErrno> {
    let stack = stack.unwrap_or_default();
    write_u64(memory, addr + STACK_T_SP_OFFSET, stack.sp)?;
    write_u32(memory, addr + STACK_T_FLAGS_OFFSET, stack.flags)?;
    write_u32(memory, addr + STACK_T_FLAGS_OFFSET + 4, 0)?;
    write_u64(memory, addr + STACK_T_SIZE_OFFSET, stack.size)
}

fn write_sigcontext(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    registers: GuestRegisters,
    signal_mask: u64,
    fault_address: u64,
) -> Result<(), LinuxErrno> {
    write_u64(memory, addr + SIGCONTEXT_R8_OFFSET, registers.r8)?;
    write_u64(memory, addr + SIGCONTEXT_R9_OFFSET, registers.r9)?;
    write_u64(memory, addr + SIGCONTEXT_R10_OFFSET, registers.r10)?;
    write_u64(memory, addr + SIGCONTEXT_R11_OFFSET, registers.r11)?;
    write_u64(memory, addr + SIGCONTEXT_R12_OFFSET, registers.r12)?;
    write_u64(memory, addr + SIGCONTEXT_R13_OFFSET, registers.r13)?;
    write_u64(memory, addr + SIGCONTEXT_R14_OFFSET, registers.r14)?;
    write_u64(memory, addr + SIGCONTEXT_R15_OFFSET, registers.r15)?;
    write_u64(memory, addr + SIGCONTEXT_RDI_OFFSET, registers.rdi)?;
    write_u64(memory, addr + SIGCONTEXT_RSI_OFFSET, registers.rsi)?;
    write_u64(memory, addr + SIGCONTEXT_RBP_OFFSET, registers.rbp)?;
    write_u64(memory, addr + SIGCONTEXT_RBX_OFFSET, registers.rbx)?;
    write_u64(memory, addr + SIGCONTEXT_RDX_OFFSET, registers.rdx)?;
    write_u64(memory, addr + SIGCONTEXT_RAX_OFFSET, registers.rax)?;
    write_u64(memory, addr + SIGCONTEXT_RCX_OFFSET, registers.rcx)?;
    write_u64(memory, addr + SIGCONTEXT_RSP_OFFSET, registers.rsp)?;
    write_u64(memory, addr + SIGCONTEXT_RIP_OFFSET, registers.rip)?;
    write_u64(memory, addr + SIGCONTEXT_EFLAGS_OFFSET, registers.rflags)?;
    write_u16(memory, addr + SIGCONTEXT_CS_OFFSET, 0x33)?;
    write_u16(memory, addr + SIGCONTEXT_GS_OFFSET, 0)?;
    write_u16(memory, addr + SIGCONTEXT_FS_OFFSET, 0)?;
    write_u16(memory, addr + SIGCONTEXT_SS_OFFSET, 0x2b)?;
    write_u64(memory, addr + SIGCONTEXT_ERR_OFFSET, 0)?;
    write_u64(memory, addr + SIGCONTEXT_TRAPNO_OFFSET, 14)?;
    write_u64(memory, addr + SIGCONTEXT_OLDMASK_OFFSET, signal_mask)?;
    write_u64(memory, addr + SIGCONTEXT_CR2_OFFSET, fault_address)?;
    write_u64(memory, addr + SIGCONTEXT_FPSTATE_OFFSET, 0)
}

fn read_sigcontext(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<GuestRegisters, LinuxErrno> {
    Ok(GuestRegisters {
        r8: read_guest_u64(memory, addr + SIGCONTEXT_R8_OFFSET)?,
        r9: read_guest_u64(memory, addr + SIGCONTEXT_R9_OFFSET)?,
        r10: read_guest_u64(memory, addr + SIGCONTEXT_R10_OFFSET)?,
        r11: read_guest_u64(memory, addr + SIGCONTEXT_R11_OFFSET)?,
        r12: read_guest_u64(memory, addr + SIGCONTEXT_R12_OFFSET)?,
        r13: read_guest_u64(memory, addr + SIGCONTEXT_R13_OFFSET)?,
        r14: read_guest_u64(memory, addr + SIGCONTEXT_R14_OFFSET)?,
        r15: read_guest_u64(memory, addr + SIGCONTEXT_R15_OFFSET)?,
        rdi: read_guest_u64(memory, addr + SIGCONTEXT_RDI_OFFSET)?,
        rsi: read_guest_u64(memory, addr + SIGCONTEXT_RSI_OFFSET)?,
        rbp: read_guest_u64(memory, addr + SIGCONTEXT_RBP_OFFSET)?,
        rbx: read_guest_u64(memory, addr + SIGCONTEXT_RBX_OFFSET)?,
        rdx: read_guest_u64(memory, addr + SIGCONTEXT_RDX_OFFSET)?,
        rax: read_guest_u64(memory, addr + SIGCONTEXT_RAX_OFFSET)?,
        rcx: read_guest_u64(memory, addr + SIGCONTEXT_RCX_OFFSET)?,
        rsp: read_guest_u64(memory, addr + SIGCONTEXT_RSP_OFFSET)?,
        rip: read_guest_u64(memory, addr + SIGCONTEXT_RIP_OFFSET)?,
        rflags: read_guest_u64(memory, addr + SIGCONTEXT_EFLAGS_OFFSET)?,
        ..GuestRegisters::default()
    })
}

fn write_siginfo(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    signal: u32,
    code: i32,
    fault_address: u64,
) -> Result<(), LinuxErrno> {
    write_u32(memory, addr + SIGINFO_SIGNO_OFFSET, signal)?;
    write_i32(memory, addr + SIGINFO_ERRNO_OFFSET, 0)?;
    write_i32(memory, addr + SIGINFO_CODE_OFFSET, code)?;
    write_u64(memory, addr + SIGINFO_ADDR_OFFSET, fault_address)
}

fn write_u16(memory: &mut impl GuestMemoryAccess, addr: u64, value: u16) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &value.to_le_bytes())
        .map_err(|_| LinuxErrno::EFAULT)
}

fn write_u32(memory: &mut impl GuestMemoryAccess, addr: u64, value: u32) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &value.to_le_bytes())
        .map_err(|_| LinuxErrno::EFAULT)
}

fn write_i32(memory: &mut impl GuestMemoryAccess, addr: u64, value: i32) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &value.to_le_bytes())
        .map_err(|_| LinuxErrno::EFAULT)
}

fn write_u64(memory: &mut impl GuestMemoryAccess, addr: u64, value: u64) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &value.to_le_bytes())
        .map_err(|_| LinuxErrno::EFAULT)
}
