use mcr_sys::GuestAddress;

use crate::X86_64_DEFAULT_RFLAGS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsState {
    pub(crate) fs_base: GuestAddress,
    pub(crate) gs_base: GuestAddress,
}

impl TlsState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fs_base: 0,
            gs_base: 0,
        }
    }

    #[must_use]
    pub const fn fs_base(self) -> GuestAddress {
        self.fs_base
    }

    #[must_use]
    pub const fn gs_base(self) -> GuestAddress {
        self.gs_base
    }
}

impl Default for TlsState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GprState {
    pub(crate) rip: GuestAddress,
    pub(crate) rsp: GuestAddress,
    pub(crate) rax: u64,
    pub(crate) rbx: u64,
    pub(crate) rcx: u64,
    pub(crate) rdi: u64,
    pub(crate) rsi: u64,
    pub(crate) rdx: u64,
    pub(crate) rbp: u64,
    pub(crate) r10: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rflags: u64,
}

impl GprState {
    #[must_use]
    pub const fn new(rip: GuestAddress, rsp: GuestAddress) -> Self {
        Self::with_syscall_registers(rip, rsp, 0, [0; 6])
    }

    #[must_use]
    pub const fn with_syscall_registers(
        rip: GuestAddress,
        rsp: GuestAddress,
        rax: u64,
        args: [u64; 6],
    ) -> Self {
        Self {
            rip,
            rsp,
            rax,
            rbx: 0,
            rcx: 0,
            rdi: args[0],
            rsi: args[1],
            rdx: args[2],
            rbp: 0,
            r10: args[3],
            r8: args[4],
            r9: args[5],
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rflags: X86_64_DEFAULT_RFLAGS,
        }
    }

    #[must_use]
    pub const fn with_full_registers(
        rip: GuestAddress,
        rsp: GuestAddress,
        registers: [u64; 15],
        rflags: u64,
    ) -> Self {
        Self {
            rip,
            rsp,
            rax: registers[0],
            rbx: registers[1],
            rcx: registers[2],
            rdx: registers[3],
            rsi: registers[4],
            rdi: registers[5],
            rbp: registers[6],
            r8: registers[7],
            r9: registers[8],
            r10: registers[9],
            r11: registers[10],
            r12: registers[11],
            r13: registers[12],
            r14: registers[13],
            r15: registers[14],
            rflags,
        }
    }

    #[must_use]
    pub const fn with_syscall_return(self, rip: GuestAddress, rax: u64) -> Self {
        Self { rip, rax, ..self }
    }

    #[must_use]
    pub const fn rip(self) -> GuestAddress {
        self.rip
    }

    #[must_use]
    pub const fn rsp(self) -> GuestAddress {
        self.rsp
    }

    #[must_use]
    pub const fn rax(self) -> u64 {
        self.rax
    }

    #[must_use]
    pub const fn rbx(self) -> u64 {
        self.rbx
    }

    #[must_use]
    pub const fn rcx(self) -> u64 {
        self.rcx
    }

    #[must_use]
    pub const fn rdi(self) -> u64 {
        self.rdi
    }

    #[must_use]
    pub const fn rsi(self) -> u64 {
        self.rsi
    }

    #[must_use]
    pub const fn rdx(self) -> u64 {
        self.rdx
    }

    #[must_use]
    pub const fn rbp(self) -> u64 {
        self.rbp
    }

    #[must_use]
    pub const fn r10(self) -> u64 {
        self.r10
    }

    #[must_use]
    pub const fn r8(self) -> u64 {
        self.r8
    }

    #[must_use]
    pub const fn r9(self) -> u64 {
        self.r9
    }

    #[must_use]
    pub const fn r11(self) -> u64 {
        self.r11
    }

    #[must_use]
    pub const fn r12(self) -> u64 {
        self.r12
    }

    #[must_use]
    pub const fn r13(self) -> u64 {
        self.r13
    }

    #[must_use]
    pub const fn r14(self) -> u64 {
        self.r14
    }

    #[must_use]
    pub const fn r15(self) -> u64 {
        self.r15
    }

    #[must_use]
    pub const fn rflags(self) -> u64 {
        self.rflags
    }
}
