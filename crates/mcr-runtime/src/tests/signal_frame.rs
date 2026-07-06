use super::support::*;

#[test]
fn rt_signal_frame_enters_handler_and_restores_modified_context() {
    let mut memory = TestMemory::default();
    let registers = GuestRegisters {
        rip: 0x401000,
        rsp: 0x800000,
        rax: 0x11,
        rbx: 0x22,
        rcx: 0x33,
        rdx: 0x44,
        rsi: 0x55,
        rdi: 0x66,
        rbp: 0x77,
        r8: 0x88,
        r9: 0x99,
        r10: 0xaa,
        r11: 0xbb,
        r12: 0xcc,
        r13: 0xdd,
        r14: 0xee,
        r15: 0xff,
        rflags: 0x10246,
        fs_base: 0x700000,
    };
    let action = mcr_task::GuestSignalAction::from_kernel_sigaction(
        0x500000,
        LINUX_SA_RESTORER | LINUX_SA_SIGINFO,
        0x600000,
        0x20,
    );

    let handler_registers =
        setup_rt_signal_frame(&mut memory, registers, action, LINUX_SIGSEGV, 0x40, 0, None)
            .unwrap();

    assert_eq!(handler_registers.rip, 0x500000);
    assert_eq!(handler_registers.rsp % 16, 8);
    assert_eq!(handler_registers.rdi, u64::from(LINUX_SIGSEGV));
    assert_eq!(handler_registers.rax, 0);
    assert_eq!(u64_at(&memory, handler_registers.rsp), 0x600000);
    assert_eq!(u32_at(&memory, handler_registers.rsi), LINUX_SIGSEGV);
    assert_eq!(
        i32_at(&memory, handler_registers.rsi + 8),
        LINUX_SEGV_MAPERR
    );
    assert_eq!(u64_at(&memory, handler_registers.rsi + 16), 0);
    assert_eq!(u64_at(&memory, handler_registers.rdx + 296), 0x40);

    let mcontext = handler_registers.rdx + 40;
    memory.write(mcontext + 128, &0x401080u64.to_le_bytes());
    memory.write(mcontext + 104, &0x1234u64.to_le_bytes());
    let mut restorer_registers = handler_registers;
    restorer_registers.rsp = handler_registers.rsp + 8;

    let restored = restore_rt_signal_frame(&memory, restorer_registers).unwrap();

    assert_eq!(restored.signal_mask, 0x40);
    assert_eq!(restored.registers.rip, 0x401080);
    assert_eq!(restored.registers.rsp, 0x800000);
    assert_eq!(restored.registers.rax, 0x1234);
    assert_eq!(restored.registers.rbx, 0x22);
    assert_eq!(restored.registers.fs_base, 0x700000);
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn windows_native_access_and_privileged_faults_deliver_sigsegv() {
    assert!(crate::runtime::native_fault_delivers_sigsegv(
        crate::runtime::WINDOWS_EXCEPTION_ACCESS_VIOLATION
    ));
    assert!(crate::runtime::native_fault_delivers_sigsegv(
        crate::runtime::WINDOWS_EXCEPTION_PRIVILEGED_INSTRUCTION
    ));
    assert!(!crate::runtime::native_fault_delivers_sigsegv(0xc000_001d));
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn windows_native_privileged_fault_default_sigsegv_exits_guest_process() {
    let _guard = native_execution_test_guard();
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    let gpr = task.regs();
    let native_registers = mcr_win::HostCpuRegisters {
        rip: 0x401000,
        rsp: gpr.rsp(),
        ..mcr_win::HostCpuRegisters::default()
    };

    let step = crate::runtime::try_deliver_native_guest_fault_signal(
        &mut runtime.dispatcher,
        INITIAL_GUEST_TID,
        INITIAL_GUEST_PID,
        0x401000,
        gpr,
        native_registers,
        0,
        crate::runtime::WINDOWS_EXCEPTION_PRIVILEGED_INSTRUCTION,
        0x401000,
    )
    .unwrap()
    .expect("default native SIGSEGV should be delivered as a fatal guest signal");

    assert_eq!(
        step.task_state(),
        mcr_task::TaskState::Exited {
            status: mcr_task::signal_exit_status(LINUX_SIGSEGV)
        }
    );
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited {
            status: mcr_task::signal_exit_status(LINUX_SIGSEGV)
        }
    );
}
