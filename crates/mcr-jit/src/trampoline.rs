use mcr_sys::{
    GuestContext, GuestPid, GuestTid, SyscallDispatcher, SyscallSubsystems, SyscallTracer,
};

use crate::{DecodedBlock, GuestRegisters, SyscallSite};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyscallTrap {
    decoded: DecodedBlock,
    site: SyscallSite,
    registers: GuestRegisters,
}

impl SyscallTrap {
    pub(crate) fn new(decoded: DecodedBlock, site: SyscallSite, registers: GuestRegisters) -> Self {
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
