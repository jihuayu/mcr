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

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
)))]
pub fn execute_x86_64_until_trap(
    _registers: &mut HostCpuRegisters,
    _fs_base: u64,
) -> Result<(), NativeExecutionError> {
    Err(NativeExecutionError::UnsupportedHost)
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows_x86_64 {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicPtr, Ordering};

    use super::{HostCpuRegisters, NativeExecutionError};

    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
    const EXCEPTION_ACCESS_VIOLATION: u32 = 0xc000_0005;
    const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xc000_001d;

    #[repr(C)]
    struct NativeExecutionState {
        landing_rsp: u64,
        landing_rip: u64,
        registers: *mut HostCpuRegisters,
        host_fs: u64,
        fault_code: u32,
        fault_address: u64,
    }

    #[repr(C)]
    struct ExceptionPointers {
        exception_record: *mut ExceptionRecord,
        context_record: *mut Context,
    }

    #[repr(C)]
    struct ExceptionRecord {
        exception_code: u32,
        exception_flags: u32,
        exception_record: *mut ExceptionRecord,
        exception_address: *mut c_void,
        number_parameters: u32,
        exception_information: [usize; 15],
    }

    #[repr(C)]
    struct M128A {
        low: u64,
        high: i64,
    }

    #[repr(C)]
    struct XmmSaveArea32 {
        control_word: u16,
        status_word: u16,
        tag_word: u8,
        reserved1: u8,
        error_opcode: u16,
        error_offset: u32,
        error_selector: u16,
        reserved2: u16,
        data_offset: u32,
        data_selector: u16,
        reserved3: u16,
        mx_csr: u32,
        mx_csr_mask: u32,
        float_registers: [M128A; 8],
        xmm_registers: [M128A; 16],
        reserved4: [u8; 96],
    }

    #[repr(C)]
    struct Context {
        p1_home: u64,
        p2_home: u64,
        p3_home: u64,
        p4_home: u64,
        p5_home: u64,
        p6_home: u64,
        context_flags: u32,
        mx_csr: u32,
        seg_cs: u16,
        seg_ds: u16,
        seg_es: u16,
        seg_fs: u16,
        seg_gs: u16,
        seg_ss: u16,
        eflags: u32,
        dr0: u64,
        dr1: u64,
        dr2: u64,
        dr3: u64,
        dr6: u64,
        dr7: u64,
        rax: u64,
        rcx: u64,
        rdx: u64,
        rbx: u64,
        rsp: u64,
        rbp: u64,
        rsi: u64,
        rdi: u64,
        r8: u64,
        r9: u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rip: u64,
        xmm_save: XmmSaveArea32,
        vector_register: [M128A; 26],
        vector_control: u64,
        debug_control: u64,
        last_branch_to_rip: u64,
        last_branch_from_rip: u64,
        last_exception_to_rip: u64,
        last_exception_from_rip: u64,
    }

    static ACTIVE_STATE: AtomicPtr<NativeExecutionState> = AtomicPtr::new(std::ptr::null_mut());

    core::arch::global_asm!(
        r#"
        .text
        .global mcr_enter_guest_x86_64
    mcr_enter_guest_x86_64:
        push rbp
        push rbx
        push rdi
        push rsi
        push r12
        push r13
        push r14
        push r15
        sub rsp, 40
        mov [rsp], rdx
        mov [rdx + 0], rsp
        lea rax, [rip + .Lmcr_native_trap_landing]
        mov [rdx + 8], rax

        mov r15, rcx
        mov r12, rdx
        mov r13, r8

        rdfsbase rax
        mov [r12 + 24], rax
        wrfsbase r13

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
        mov rax, [r12 + 24]
        wrfsbase rax
        mov rsp, [r12 + 0]
        add rsp, 40
        pop r15
        pop r14
        pop r13
        pop r12
        pop rsi
        pop rdi
        pop rbx
        pop rbp
        ret
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
        let _handler = VectoredHandler::install()?;
        let mut state = NativeExecutionState {
            landing_rsp: 0,
            landing_rip: 0,
            registers,
            host_fs: 0,
            fault_code: 0,
            fault_address: 0,
        };
        ACTIVE_STATE.store(&mut state, Ordering::SeqCst);

        // SAFETY: The assembly trampoline saves host callee-saved state, switches to guest
        // registers, and returns only through the vectored exception landing path.
        unsafe {
            mcr_enter_guest_x86_64(registers, &mut state, fs_base);
        }
        ACTIVE_STATE.store(std::ptr::null_mut(), Ordering::SeqCst);

        if state.fault_code == 0 {
            Ok(())
        } else {
            Err(NativeExecutionError::GuestFault {
                signal: state.fault_code as i32,
                rip: registers.rip,
                address: state.fault_address,
            })
        }
    }

    struct VectoredHandler {
        handle: *mut c_void,
    }

    impl VectoredHandler {
        fn install() -> Result<Self, NativeExecutionError> {
            // SAFETY: The handler function has the required calling convention and remains valid
            // for the process lifetime.
            let handle = unsafe { AddVectoredExceptionHandler(1, Some(native_exception_handler)) };
            if handle.is_null() {
                return Err(NativeExecutionError::SignalHandler(0));
            }
            Ok(Self { handle })
        }
    }

    impl Drop for VectoredHandler {
        fn drop(&mut self) {
            // SAFETY: `handle` was returned by `AddVectoredExceptionHandler`.
            unsafe {
                let _ = RemoveVectoredExceptionHandler(self.handle);
            }
        }
    }

    unsafe extern "system" fn native_exception_handler(
        exception_info: *mut ExceptionPointers,
    ) -> i32 {
        let state = ACTIVE_STATE.load(Ordering::SeqCst);
        if state.is_null() || exception_info.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // SAFETY: Windows invokes vectored handlers with valid exception and context pointers.
        let state = unsafe { &mut *state };
        let pointers = unsafe { &mut *exception_info };
        if pointers.exception_record.is_null() || pointers.context_record.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let record = unsafe { &mut *pointers.exception_record };
        let context = unsafe { &mut *pointers.context_record };

        let registers = unsafe { &mut *state.registers };
        registers.rax = context.rax;
        registers.rbx = context.rbx;
        registers.rcx = context.rcx;
        registers.rdx = context.rdx;
        registers.rsi = context.rsi;
        registers.rdi = context.rdi;
        registers.rbp = context.rbp;
        registers.rsp = context.rsp;
        registers.r8 = context.r8;
        registers.r9 = context.r9;
        registers.r10 = context.r10;
        registers.r11 = context.r11;
        registers.r12 = context.r12;
        registers.r13 = context.r13;
        registers.r14 = context.r14;
        registers.r15 = context.r15;
        registers.rip = context.rip;
        registers.rflags = u64::from(context.eflags);

        if record.exception_code == EXCEPTION_BREAKPOINT {
            registers.rip = registers.rip.saturating_sub(1);
            state.fault_code = 0;
        } else {
            state.fault_code = record.exception_code;
            state.fault_address = if record.exception_code == EXCEPTION_ACCESS_VIOLATION
                && record.number_parameters >= 2
            {
                record.exception_information[1] as u64
            } else {
                record.exception_address as usize as u64
            };
            if record.exception_code != EXCEPTION_ILLEGAL_INSTRUCTION
                && record.exception_code != EXCEPTION_ACCESS_VIOLATION
            {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        context.rip = state.landing_rip;
        context.rsp = state.landing_rsp;
        EXCEPTION_CONTINUE_EXECUTION
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AddVectoredExceptionHandler(
            first: u32,
            handler: Option<unsafe extern "system" fn(*mut ExceptionPointers) -> i32>,
        ) -> *mut c_void;
        fn RemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
    }
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

#[cfg(all(windows, target_arch = "x86_64"))]
pub use windows_x86_64::execute_x86_64_until_trap;
