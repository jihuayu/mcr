use super::support::*;

#[test]
fn package_name_is_stable() {
    assert_eq!(CRATE_NAME, "mcr-runtime");
}

#[test]
fn runtime_dispatch_supports_tls_and_exit_state() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let arch = runtime.dispatch_syscall(context(
        Syscall::ArchPrctl,
        [ARCH_SET_FS, 0x7000_0000, 0, 0, 0, 0],
    ));
    assert_eq!(arch.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .tls()
            .fs_base(),
        0x7000_0000
    );

    let exit = runtime.dispatch_syscall(context(Syscall::ExitGroup, [9, 0, 0, 0, 0, 0]));
    assert_eq!(exit.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 9 }
    );
}

#[test]
fn guest_registers_round_trip_preserves_argument_register_order() {
    let registers = GuestRegisters {
        rax: 1,
        rbx: 2,
        rcx: 3,
        rdx: 4,
        rsi: 5,
        rdi: 6,
        rbp: 7,
        rsp: 8,
        r8: 9,
        r9: 10,
        r10: 11,
        r11: 12,
        r12: 13,
        r13: 14,
        r14: 15,
        r15: 16,
        rip: 17,
        fs_base: 0,
        rflags: 18,
    };

    assert_eq!(registers_from_gpr(gpr_from_registers(registers)), registers);
}

#[test]
fn guest_execution_dispatch_advances_registers_and_exposes_exit_state() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    let rsp = runtime
        .kernel()
        .task(INITIAL_GUEST_TID)
        .unwrap()
        .regs()
        .rsp();
    runtime
        .kernel_mut()
        .task_mut(INITIAL_GUEST_TID)
        .unwrap()
        .set_regs(GprState::with_syscall_registers(
            0x401000,
            rsp,
            Syscall::ExitGroup.number().raw(),
            [42, 0, 0, 0, 0, 0],
        ));

    let step = runtime
        .dispatch_guest_execution()
        .expect("execute guest syscall block");

    assert_eq!(step.tid(), INITIAL_GUEST_TID);
    assert_eq!(step.before_rip(), 0x401000);
    assert_eq!(step.after_rip(), 0x401000);
    assert_eq!(step.encoded_rax(), 0);
    assert_eq!(step.task_state(), TaskState::Exited { status: 42 });
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rip(),
        0x401000
    );
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 42 }
    );
}

#[test]
fn guest_execution_preserves_non_syscall_registers_across_steps() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x48, 0xbb, 0x7f, 0x4d, 0x3c, 0x2b, 0x1a, 0x09, 0x08,
            0x07, // mov rbx,0x0708091a2b3c4d7f
            0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax,getpid
            0x0f, 0x05, // syscall
            0x48, 0x89, 0xdf, // mov rdi,rbx
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();

    let first_step = runtime
        .dispatch_guest_execution()
        .expect("getpid step executes");
    assert_eq!(first_step.before_rip(), 0x401000);
    assert_eq!(first_step.after_rip(), 0x401011);
    assert_eq!(first_step.encoded_rax(), u64::from(INITIAL_GUEST_PID));
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rbx(),
        0x0708_091a_2b3c_4d7f
    );

    let second_step = runtime
        .dispatch_guest_execution()
        .expect("exit_group step executes");

    assert_eq!(second_step.before_rip(), 0x401011);
    assert_eq!(second_step.after_rip(), 0x401019);
    assert_eq!(second_step.task_state(), TaskState::Exited { status: 0x7f });
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 0x7f }
    );
}

#[test]
fn guest_execution_dispatches_syscall_after_guest_memory_load() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x8b, 0x3d, 0xfa, 0x0f, 0x00, 0x00, // mov edi,[rip+0xffa]
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &[77, 0, 0, 0])
        .unwrap();

    let step = runtime
        .dispatch_guest_execution()
        .expect("guest memory load feeds exit_group syscall");

    assert_eq!(step.before_rip(), 0x401000);
    assert_eq!(step.after_rip(), 0x40100b);
    assert_eq!(step.task_state(), TaskState::Exited { status: 77 });
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 77 }
    );
}

#[test]
fn guest_execution_dispatches_syscall_after_fs_relative_guest_memory_load() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // mov rax,fs:[0x28]
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    runtime
        .memory_mut()
        .mmap(mcr_sys::MmapSyscallArgs {
            addr: 0x600000,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
            flags: LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
            fd: -1,
            offset: 0,
        })
        .unwrap();
    runtime
        .memory_mut()
        .write(0x600028, &Syscall::Getpid.number().raw().to_le_bytes())
        .unwrap();
    let arch = runtime.dispatch_syscall(context(
        Syscall::ArchPrctl,
        [ARCH_SET_FS, 0x600000, 0, 0, 0, 0],
    ));
    assert_eq!(arch.result, SyscallReturn::Success(0));

    let step = runtime
        .dispatch_guest_execution()
        .expect("fs-relative load feeds guest syscall dispatch");

    assert_eq!(step.before_rip(), 0x401000);
    assert_eq!(step.after_rip(), 0x40100b);
    assert_eq!(step.encoded_rax(), u64::from(INITIAL_GUEST_PID));
}

#[test]
fn guest_execution_persists_guest_memory_store_before_syscall() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x48, 0xbb, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, // mov rbx,0x1122334455667788
            0x48, 0x89, 0x1d, 0xef, 0x0f, 0x00, 0x00, // mov [rip+0xfef],rbx
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x31, 0xff, // xor edi,edi
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();

    let step = runtime
        .dispatch_guest_execution()
        .expect("guest memory store runs before exit_group");

    assert_eq!(step.task_state(), TaskState::Exited { status: 0 });
    let mut stored = [0; 8];
    runtime.memory().read(0x402000, &mut stored).unwrap();
    assert_eq!(u64::from_le_bytes(stored), 0x1122_3344_5566_7788);
}

#[test]
fn guest_execution_preserves_stack_push_pop_before_syscall() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0xbb, 0x2a, 0x00, 0x00, 0x00, // mov ebx,42
            0x53, // push rbx
            0x5f, // pop rdi
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    let initial_rsp = runtime
        .kernel()
        .task(INITIAL_GUEST_TID)
        .unwrap()
        .regs()
        .rsp();

    let step = runtime
        .dispatch_guest_execution()
        .expect("stack push/pop feeds exit_group syscall");

    assert_eq!(step.task_state(), TaskState::Exited { status: 42 });
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rsp(),
        initial_rsp
    );
}

#[test]
fn guest_execution_follows_call_ret_before_syscall() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0xe8, 0x07, 0x00, 0x00, 0x00, // call 0x40100c
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x0f, 0x05, // syscall
            0x48, 0xc7, 0xc7, 0x21, 0x00, 0x00, 0x00, // mov rdi,33
            0xc3, // ret
        ],
    ))
    .unwrap();

    let step = runtime
        .dispatch_guest_execution()
        .expect("call/ret feeds exit_group syscall");

    assert_eq!(step.task_state(), TaskState::Exited { status: 33 });
}

#[test]
fn guest_execution_surfaces_guest_memory_operand_fault() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x48, 0x8b, 0x00, // mov rax,[rax]
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();

    let error = runtime
        .dispatch_guest_execution()
        .expect_err("unmapped memory load stops guest execution");

    assert_eq!(error.linux_errno(), LinuxErrno::ENOEXEC);
    assert!(matches!(
        error,
        GuestExecutionError::Execution(ExecutionError::MemoryOperand { .. })
    ));
}

#[test]
fn guest_run_loop_returns_exit_group_status() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(
        &mut runtime,
        0x401000,
        Syscall::ExitGroup,
        [42, 0, 0, 0, 0, 0],
    );

    let status = runtime
        .run_guest_until_exit()
        .expect("guest run exits through exit_group");

    assert_eq!(status, 42);
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Exited { status: 42 }
    );
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rip(),
        0x401000
    );
}

#[test]
fn guest_run_loop_returns_exit_status_from_exit_syscall() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::Exit, [300, 0, 0, 0, 0, 0]);

    let status = runtime
        .run_guest_until_exit()
        .expect("guest run exits through exit");

    assert_eq!(status, 44);
    assert_eq!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Exited { status: 44 }
    );
}

#[test]
fn guest_run_loop_returns_existing_exit_status() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let exit = runtime.dispatch_syscall(context(Syscall::ExitGroup, [9, 0, 0, 0, 0, 0]));
    assert_eq!(exit.result, SyscallReturn::Success(0));

    let status = runtime
        .run_guest_until_exit()
        .expect("guest run returns already exited process status");

    assert_eq!(status, 9);
}

#[test]
fn guest_run_loop_surfaces_guest_execution_error() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0xc3, // ret
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::ExitGroup, [0; 6]);

    let error = runtime
        .run_guest_until_exit()
        .expect_err("guest run should stop on a block without syscall");

    assert_eq!(error.linux_errno(), LinuxErrno::ENOEXEC);
    assert!(matches!(
        error,
        GuestRunError::GuestExecution(GuestExecutionError::Execution(
            ExecutionError::MissingSyscall { .. }
        ))
    ));
}

#[test]
fn guest_run_errors_expose_linux_errno_shapes() {
    assert_eq!(
        GuestRunError::MissingInitialProcess.linux_errno(),
        LinuxErrno::ESRCH
    );
    assert_eq!(
        GuestRunError::MissingInitialTask.linux_errno(),
        LinuxErrno::ESRCH
    );
    assert_eq!(
        GuestRunError::InitialTaskNotRunnable {
            tid: INITIAL_GUEST_TID,
            state: TaskState::Exited { status: 1 },
        }
        .linux_errno(),
        LinuxErrno::ESRCH
    );
    assert_eq!(
        GuestRunError::GuestExecution(GuestExecutionError::Memory(GuestMemoryError::NotMapped))
            .linux_errno(),
        LinuxErrno::ENOMEM
    );
}

#[test]
fn guest_run_loop_surfaces_guest_memory_error() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x402000, Syscall::ExitGroup, [0; 6]);

    let error = runtime
        .run_guest_until_exit()
        .expect_err("guest run should stop on non-executable rip");

    assert_eq!(error.linux_errno(), LinuxErrno::EACCES);
    assert!(matches!(
        error,
        GuestRunError::GuestExecution(GuestExecutionError::Memory(GuestMemoryError::AccessDenied))
    ));
}

#[test]
fn runtime_unimplemented_fake_syscalls_return_enosys_and_trace_args() {
    let syscall = Syscall::Rseq;
    let args = [0x402000, 32, 0, 0x53053053, 0, 0];
    let decoded_field = ("rseq", "0x402000");
    let mut runtime = Runtime::with_tracer(
        test_program("/bin/app", 0x401000),
        InMemorySyscallTracer::new(),
    )
    .unwrap();

    let result = runtime.dispatch_syscall(context(syscall, args));

    assert_eq!(
        result.result,
        SyscallReturn::Errno(LinuxErrno::ENOSYS),
        "{syscall}"
    );
    match runtime.tracer().events() {
        [
            SyscallTraceEvent::Enter(enter),
            SyscallTraceEvent::Exit(exit),
        ] => {
            assert_eq!(enter.syscall, syscall);
            assert_eq!(exit.syscall, syscall);
            assert_eq!(exit.result, SyscallReturn::Errno(LinuxErrno::ENOSYS));
            assert!(
                exit.decoded
                    .iter()
                    .any(|field| field.name == decoded_field.0 && field.value == decoded_field.1),
                "{syscall} should preserve decoded argument {decoded_field:?}"
            );
        }
        other => panic!("expected enter and exit trace for {syscall}, got {other:?}"),
    }
}
