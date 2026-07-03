use std::fmt;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostCpuRegisters {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeExecutionError {
    UnsupportedHost,
    SignalHandler(i32),
    GuestFault { signal: i32, rip: u64, address: u64 },
    HostFs,
}

impl fmt::Display for NativeExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => write!(
                formatter,
                "native same-ISA execution is only available on Linux x86-64 hosts"
            ),
            Self::SignalHandler(signal) => {
                write!(
                    formatter,
                    "failed to install native signal handler {signal}"
                )
            }
            Self::GuestFault {
                signal,
                rip,
                address,
            } => write!(
                formatter,
                "guest native execution faulted with signal {signal} at rip 0x{rip:016x}, address 0x{address:016x}"
            ),
            Self::HostFs => write!(formatter, "failed to save host FS base"),
        }
    }
}

impl std::error::Error for NativeExecutionError {}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn execute_x86_64_until_trap(
    _registers: &mut HostCpuRegisters,
    _fs_base: u64,
) -> Result<(), NativeExecutionError> {
    Err(NativeExecutionError::UnsupportedHost)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_x86_64 {
    use std::ffi::c_void;
    use std::mem::MaybeUninit;
    use std::sync::atomic::{AtomicPtr, Ordering};

    use super::{HostCpuRegisters, NativeExecutionError};

    const ARCH_GET_FS: libc::c_ulong = 0x1003;
    #[repr(C)]
    struct NativeExecutionState {
        landing_rsp: u64,
        landing_rip: u64,
        registers: *mut HostCpuRegisters,
        host_fs: u64,
        signal: i32,
        fault_address: u64,
    }

    static ACTIVE_STATE: AtomicPtr<NativeExecutionState> = AtomicPtr::new(std::ptr::null_mut());

    core::arch::global_asm!(
        r#"
        .text
        .global mcr_enter_guest_x86_64
        .type mcr_enter_guest_x86_64, @function
    mcr_enter_guest_x86_64:
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15
        push rsi
        mov [rsi + 0], rsp
        lea rax, [rip + .Lmcr_native_trap_landing]
        mov [rsi + 8], rax

        mov r15, rdi
        mov r12, rdx
        mov eax, 158
        mov edi, 0x1002
        mov rsi, r12
        syscall

        mov rax, [r15 + 0]
        mov rbx, [r15 + 8]
        mov rcx, [r15 + 16]
        mov rdx, [r15 + 24]
        mov rsi, [r15 + 32]
        mov rdi, [r15 + 40]
        mov rbp, [r15 + 48]
        mov r8, [r15 + 64]
        mov r9, [r15 + 72]
        mov r10, [r15 + 80]
        mov r12, [r15 + 96]
        mov r13, [r15 + 104]
        mov r14, [r15 + 112]
        mov rsp, [r15 + 56]
        push qword ptr [r15 + 136]
        popfq
        mov r11, [r15 + 128]
        mov r15, [r15 + 120]
        jmp r11

    .Lmcr_native_trap_landing:
        mov r12, [rsp]
        mov rdx, [r12 + 24]
        mov eax, 158
        mov edi, 0x1002
        mov rsi, rdx
        syscall
        pop rsi
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret
        .size mcr_enter_guest_x86_64, .-mcr_enter_guest_x86_64
        "#
    );

    unsafe extern "C" {
        fn mcr_enter_guest_x86_64(
            registers: *mut HostCpuRegisters,
            state: *mut NativeExecutionState,
            fs_base: u64,
        );
    }

    pub fn execute_x86_64_until_trap(
        registers: &mut HostCpuRegisters,
        fs_base: u64,
    ) -> Result<(), NativeExecutionError> {
        let mut host_fs = 0_u64;
        // SAFETY: `arch_prctl(ARCH_GET_FS)` writes the current thread FS base into `host_fs`.
        let get_fs = unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_FS, &mut host_fs) };
        if get_fs != 0 {
            return Err(NativeExecutionError::HostFs);
        }

        let mut state = NativeExecutionState {
            landing_rsp: 0,
            landing_rip: 0,
            registers,
            host_fs,
            signal: 0,
            fault_address: 0,
        };
        let _handlers = SignalHandlers::install()?;
        ACTIVE_STATE.store(&raw mut state, Ordering::SeqCst);
        // SAFETY: Signal handlers are installed and `state` contains a landing point that the
        // handler uses to return from guest code after an INT3 syscall trap or guest fault.
        unsafe {
            mcr_enter_guest_x86_64(registers, &raw mut state, fs_base);
        }
        ACTIVE_STATE.store(std::ptr::null_mut(), Ordering::SeqCst);

        if state.signal == 0 {
            Ok(())
        } else {
            Err(NativeExecutionError::GuestFault {
                signal: state.signal,
                rip: registers.rip,
                address: state.fault_address,
            })
        }
    }

    struct SignalHandlers {
        old_trap: libc::sigaction,
        old_segv: libc::sigaction,
        old_bus: libc::sigaction,
        old_ill: libc::sigaction,
    }

    impl SignalHandlers {
        fn install() -> Result<Self, NativeExecutionError> {
            Ok(Self {
                old_trap: install_handler(libc::SIGTRAP)?,
                old_segv: install_handler(libc::SIGSEGV)?,
                old_bus: install_handler(libc::SIGBUS)?,
                old_ill: install_handler(libc::SIGILL)?,
            })
        }
    }

    impl Drop for SignalHandlers {
        fn drop(&mut self) {
            restore_handler(libc::SIGTRAP, &self.old_trap);
            restore_handler(libc::SIGSEGV, &self.old_segv);
            restore_handler(libc::SIGBUS, &self.old_bus);
            restore_handler(libc::SIGILL, &self.old_ill);
        }
    }

    fn install_handler(signal: i32) -> Result<libc::sigaction, NativeExecutionError> {
        let mut action = MaybeUninit::<libc::sigaction>::zeroed();
        let mut old = MaybeUninit::<libc::sigaction>::zeroed();
        // SAFETY: The sigaction structure is initialized before use and points at an async-signal
        // handler that only touches the active state and ucontext registers.
        unsafe {
            let action = action.assume_init_mut();
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_SIGINFO;
            action.sa_sigaction = native_signal_handler as *const () as usize;
            if libc::sigaction(signal, action, old.as_mut_ptr()) != 0 {
                return Err(NativeExecutionError::SignalHandler(signal));
            }
            Ok(old.assume_init())
        }
    }

    fn restore_handler(signal: i32, old: &libc::sigaction) {
        // SAFETY: `old` was returned by `sigaction` during install for this signal.
        unsafe {
            let _ = libc::sigaction(signal, old, std::ptr::null_mut());
        }
    }

    extern "C" fn native_signal_handler(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut c_void,
    ) {
        let state = ACTIVE_STATE.load(Ordering::SeqCst);
        if state.is_null() || context.is_null() {
            return;
        }

        // SAFETY: Linux invokes SA_SIGINFO handlers with a valid `ucontext_t` pointer. The active
        // state lives until `mcr_enter_guest_x86_64` returns through this handler.
        unsafe {
            let state = &mut *state;
            let registers = &mut *state.registers;
            let context = &mut *(context.cast::<libc::ucontext_t>());
            let gregs = &mut context.uc_mcontext.gregs;

            registers.rax = gregs[libc::REG_RAX as usize] as u64;
            registers.rbx = gregs[libc::REG_RBX as usize] as u64;
            registers.rcx = gregs[libc::REG_RCX as usize] as u64;
            registers.rdx = gregs[libc::REG_RDX as usize] as u64;
            registers.rsi = gregs[libc::REG_RSI as usize] as u64;
            registers.rdi = gregs[libc::REG_RDI as usize] as u64;
            registers.rbp = gregs[libc::REG_RBP as usize] as u64;
            registers.rsp = gregs[libc::REG_RSP as usize] as u64;
            registers.r8 = gregs[libc::REG_R8 as usize] as u64;
            registers.r9 = gregs[libc::REG_R9 as usize] as u64;
            registers.r10 = gregs[libc::REG_R10 as usize] as u64;
            registers.r11 = gregs[libc::REG_R11 as usize] as u64;
            registers.r12 = gregs[libc::REG_R12 as usize] as u64;
            registers.r13 = gregs[libc::REG_R13 as usize] as u64;
            registers.r14 = gregs[libc::REG_R14 as usize] as u64;
            registers.r15 = gregs[libc::REG_R15 as usize] as u64;
            registers.rip = gregs[libc::REG_RIP as usize] as u64;
            registers.rflags = gregs[libc::REG_EFL as usize] as u64;

            if signal == libc::SIGTRAP {
                registers.rip = registers.rip.saturating_sub(1);
                state.signal = 0;
            } else {
                state.signal = signal;
                state.fault_address = if info.is_null() {
                    0
                } else {
                    (*info).si_addr() as usize as u64
                };
            }

            gregs[libc::REG_RIP as usize] = state.landing_rip as libc::greg_t;
            gregs[libc::REG_RSP as usize] = state.landing_rsp as libc::greg_t;
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux_x86_64::execute_x86_64_until_trap;
