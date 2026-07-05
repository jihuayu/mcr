use std::fmt;

pub const DEFAULT_MXCSR: u32 = 0x1f80;
pub type HostXmmRegisters = [[u8; 16]; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostFloatingPointState {
    pub xmm: HostXmmRegisters,
    pub mxcsr: u32,
}

impl Default for HostFloatingPointState {
    fn default() -> Self {
        Self {
            xmm: HostXmmRegisters::default(),
            mxcsr: DEFAULT_MXCSR,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub xmm: HostXmmRegisters,
    pub mxcsr: u32,
}

impl Default for HostCpuRegisters {
    fn default() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0x202,
            xmm: HostFloatingPointState::default().xmm,
            mxcsr: DEFAULT_MXCSR,
        }
    }
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
                "native same-ISA execution is only available on Windows x86-64 hosts"
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

#[cfg(all(windows, not(target_arch = "x86_64")))]
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
    const EXCEPTION_PRIVILEGED_INSTRUCTION: u32 = 0xc000_0096;

    #[repr(C)]
    struct NativeExecutionState {
        landing_rsp: u64,
        landing_rip: u64,
        registers: *mut HostCpuRegisters,
        host_fs: u64,
        host_rflags: u64,
        active_thread_id: u32,
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
        sub rsp, 296
        mov [rsp], rdx
        stmxcsr dword ptr [rsp + 16]
        movdqu xmmword ptr [rsp + 40], xmm0
        movdqu xmmword ptr [rsp + 56], xmm1
        movdqu xmmword ptr [rsp + 72], xmm2
        movdqu xmmword ptr [rsp + 88], xmm3
        movdqu xmmword ptr [rsp + 104], xmm4
        movdqu xmmword ptr [rsp + 120], xmm5
        movdqu xmmword ptr [rsp + 136], xmm6
        movdqu xmmword ptr [rsp + 152], xmm7
        movdqu xmmword ptr [rsp + 168], xmm8
        movdqu xmmword ptr [rsp + 184], xmm9
        movdqu xmmword ptr [rsp + 200], xmm10
        movdqu xmmword ptr [rsp + 216], xmm11
        movdqu xmmword ptr [rsp + 232], xmm12
        movdqu xmmword ptr [rsp + 248], xmm13
        movdqu xmmword ptr [rsp + 264], xmm14
        movdqu xmmword ptr [rsp + 280], xmm15
        mov [rdx + 0], rsp
        lea rax, [rip + .Lmcr_native_trap_landing]
        mov [rdx + 8], rax

        mov r15, rcx
        mov r12, rdx
        mov r13, r8

        pushfq
        pop rax
        mov [r12 + 32], rax
        rdfsbase rax
        mov [r12 + 24], rax
        wrfsbase r13

        ldmxcsr dword ptr [r15 + 400]
        movdqu xmm0, xmmword ptr [r15 + 144]
        movdqu xmm1, xmmword ptr [r15 + 160]
        movdqu xmm2, xmmword ptr [r15 + 176]
        movdqu xmm3, xmmword ptr [r15 + 192]
        movdqu xmm4, xmmword ptr [r15 + 208]
        movdqu xmm5, xmmword ptr [r15 + 224]
        movdqu xmm6, xmmword ptr [r15 + 240]
        movdqu xmm7, xmmword ptr [r15 + 256]
        movdqu xmm8, xmmword ptr [r15 + 272]
        movdqu xmm9, xmmword ptr [r15 + 288]
        movdqu xmm10, xmmword ptr [r15 + 304]
        movdqu xmm11, xmmword ptr [r15 + 320]
        movdqu xmm12, xmmword ptr [r15 + 336]
        movdqu xmm13, xmmword ptr [r15 + 352]
        movdqu xmm14, xmmword ptr [r15 + 368]
        movdqu xmm15, xmmword ptr [r15 + 384]

        mov rax, [r15 + 136]
        and rax, 0x0000000000000ed5
        or rax, 0x202
        push rax
        popfq

        mov rax, [r15 + 56]
        sub rax, 8
        mov rsp, rax
        mov rax, [r15 + 128]
        mov [rsp], rax

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
        mov r11, [r15 + 88]
        mov r12, [r15 + 96]
        mov r13, [r15 + 104]
        mov r14, [r15 + 112]
        mov r15, [r15 + 120]
        ret

    .Lmcr_native_trap_landing:
        mov r12, [rsp]
        mov r11, [r12 + 16]
        stmxcsr dword ptr [r11 + 400]
        movdqu xmmword ptr [r11 + 144], xmm0
        movdqu xmmword ptr [r11 + 160], xmm1
        movdqu xmmword ptr [r11 + 176], xmm2
        movdqu xmmword ptr [r11 + 192], xmm3
        movdqu xmmword ptr [r11 + 208], xmm4
        movdqu xmmword ptr [r11 + 224], xmm5
        movdqu xmmword ptr [r11 + 240], xmm6
        movdqu xmmword ptr [r11 + 256], xmm7
        movdqu xmmword ptr [r11 + 272], xmm8
        movdqu xmmword ptr [r11 + 288], xmm9
        movdqu xmmword ptr [r11 + 304], xmm10
        movdqu xmmword ptr [r11 + 320], xmm11
        movdqu xmmword ptr [r11 + 336], xmm12
        movdqu xmmword ptr [r11 + 352], xmm13
        movdqu xmmword ptr [r11 + 368], xmm14
        movdqu xmmword ptr [r11 + 384], xmm15
        mov rax, [r12 + 24]
        wrfsbase rax
        mov rsp, [r12 + 0]
        ldmxcsr dword ptr [rsp + 16]
        movdqu xmm0, xmmword ptr [rsp + 40]
        movdqu xmm1, xmmword ptr [rsp + 56]
        movdqu xmm2, xmmword ptr [rsp + 72]
        movdqu xmm3, xmmword ptr [rsp + 88]
        movdqu xmm4, xmmword ptr [rsp + 104]
        movdqu xmm5, xmmword ptr [rsp + 120]
        movdqu xmm6, xmmword ptr [rsp + 136]
        movdqu xmm7, xmmword ptr [rsp + 152]
        movdqu xmm8, xmmword ptr [rsp + 168]
        movdqu xmm9, xmmword ptr [rsp + 184]
        movdqu xmm10, xmmword ptr [rsp + 200]
        movdqu xmm11, xmmword ptr [rsp + 216]
        movdqu xmm12, xmmword ptr [rsp + 232]
        movdqu xmm13, xmmword ptr [rsp + 248]
        movdqu xmm14, xmmword ptr [rsp + 264]
        movdqu xmm15, xmmword ptr [rsp + 280]
        lea rsp, [rsp + 296]
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
            host_rflags: 0x202,
            // SAFETY: `GetCurrentThreadId` has no preconditions and returns the caller's ID.
            active_thread_id: unsafe { GetCurrentThreadId() },
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
        // SAFETY: `GetCurrentThreadId` has no preconditions and returns the handler thread's ID.
        if unsafe { GetCurrentThreadId() } != state.active_thread_id {
            return EXCEPTION_CONTINUE_SEARCH;
        }
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
        registers.mxcsr = context.mx_csr;
        for (target, source) in registers
            .xmm
            .iter_mut()
            .zip(context.xmm_save.xmm_registers.iter())
        {
            target[..8].copy_from_slice(&source.low.to_le_bytes());
            target[8..].copy_from_slice(&source.high.to_le_bytes());
        }

        if record.exception_code == EXCEPTION_BREAKPOINT {
            registers.rip = record.exception_address as usize as u64;
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
                && record.exception_code != EXCEPTION_PRIVILEGED_INSTRUCTION
            {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        context.rip = state.landing_rip;
        context.rsp = state.landing_rsp;
        context.eflags = state.host_rflags as u32;
        EXCEPTION_CONTINUE_EXECUTION
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AddVectoredExceptionHandler(
            first: u32,
            handler: Option<unsafe extern "system" fn(*mut ExceptionPointers) -> i32>,
        ) -> *mut c_void;
        fn GetCurrentThreadId() -> u32;
        fn RemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub use windows_x86_64::execute_x86_64_until_trap;

#[cfg(all(test, windows, target_arch = "x86_64"))]
mod tests {
    use crate::{HostCpuRegisters, HostMemory, MemoryProtection, execute_x86_64_until_trap};

    #[test]
    fn windows_breakpoint_trap_reports_breakpoint_address() {
        let mut code =
            HostMemory::allocate(4096, MemoryProtection::ExecuteReadWrite).expect("code memory");
        code.as_mut_slice()[..3].copy_from_slice(&[0xcc, 0x90, 0xc3]);
        let stack = HostMemory::allocate(4096, MemoryProtection::ReadWrite).expect("stack memory");
        let code_addr = code.as_ptr() as u64;
        let stack_top = stack.as_ptr() as u64 + stack.len() as u64;
        let mut registers = HostCpuRegisters {
            rip: code_addr,
            rsp: stack_top,
            ..HostCpuRegisters::default()
        };

        execute_x86_64_until_trap(&mut registers, 0).expect("int3 should trap");

        assert_eq!(registers.rip, code_addr);
    }
}
