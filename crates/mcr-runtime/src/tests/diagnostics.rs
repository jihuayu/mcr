use super::support::*;

#[test]
fn runtime_tracer_records_task_syscall_events() {
    let mut runtime = Runtime::with_tracer(
        test_program("/bin/app", 0x401000),
        InMemorySyscallTracer::new(),
    )
    .unwrap();

    let result = runtime.dispatch_syscall(context(Syscall::Gettid, [0; 6]));

    assert_eq!(result.result, SyscallReturn::Success(1));
    assert!(matches!(
        runtime.tracer().events(),
        [SyscallTraceEvent::Enter(_), SyscallTraceEvent::Exit(_)]
    ));
}

#[test]
fn runtime_diagnostics_tracer_bounds_retained_events() {
    let mut tracer = RuntimeDiagnosticsTracer::new();
    for index in 0..(RUNTIME_DIAGNOSTICS_EVENT_LIMIT + 17) {
        tracer.record(SyscallTraceEvent::Exit(SyscallExitEvent {
            context: TraceContext {
                pid: INITIAL_GUEST_PID,
                tid: INITIAL_GUEST_TID,
                rip: index as u64,
            },
            syscall: Syscall::Getpid,
            args: SyscallArgs::new([0; 6]),
            result: SyscallReturn::Success(index as u64),
            decoded: Vec::new(),
            host_error: None,
        }));
    }

    assert_eq!(tracer.events().len(), RUNTIME_DIAGNOSTICS_EVENT_DRAIN + 17);
    assert_eq!(
        tracer.dropped_events(),
        RUNTIME_DIAGNOSTICS_EVENT_DRAIN as u64
    );
    let last = tracer.last_syscall().unwrap();
    assert_eq!(last.name(), "getpid");
    assert_eq!(
        last.result(),
        Some(SyscallReturn::Success(
            (RUNTIME_DIAGNOSTICS_EVENT_LIMIT + 16) as u64
        ))
    );
}

#[test]
fn diagnostics_capture_image_vmas_and_last_syscall() {
    let mut runtime = RuntimeWithTracer::with_diagnostics(test_program_with_args(
        "/bin/app",
        0x401000,
        ["/bin/app", "--flag"],
        ["A=B"],
    ))
    .unwrap();

    let result = runtime.dispatch_syscall(context(Syscall::Getpid, [0; 6]));
    assert_eq!(result.result, SyscallReturn::Success(1));

    let diagnostics = runtime.diagnostics();
    let last = diagnostics.last_syscall().unwrap();

    assert_eq!(diagnostics.executable_path(), b"/bin/app");
    assert_eq!(
        diagnostics.argv(),
        &[b"/bin/app".to_vec(), b"--flag".to_vec()]
    );
    assert_eq!(diagnostics.envp(), &[b"A=B".to_vec()]);
    assert_eq!(diagnostics.worker_pools().len(), 2);
    assert!(
        diagnostics
            .worker_pools()
            .iter()
            .all(|pool| pool.max_workers() > 0 && pool.active_workers() == 0)
    );
    assert!(diagnostics.vmas().iter().any(|vma| {
        vma.start() <= 0x401000
            && 0x401000 < vma.end()
            && vma.permissions().execute()
            && matches!(
                vma.kind(),
                DiagnosticVmaKind::ElfLoad {
                    program_header_index: 0,
                    ..
                }
            )
    }));
    assert!(diagnostics.vmas().iter().any(|vma| {
        matches!(vma.kind(), DiagnosticVmaKind::Stack) && vma.permissions().write()
    }));
    assert_eq!(last.name(), "getpid");
    assert_eq!(last.number(), Syscall::GETPID.raw());
    assert_eq!(last.args(), [0; 6]);
    assert_eq!(last.result(), Some(SyscallReturn::Success(1)));
    assert_eq!(last.rip(), 0x401234);
}

#[test]
fn diagnostics_capture_interpreted_block_fallback_counters() {
    let mut runtime = RuntimeWithTracer::with_diagnostics(test_program_with_entry_code(
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
            [0, 0, 0, 0, 0, 0],
        ));

    runtime
        .dispatch_guest_execution()
        .expect("guest syscall block executes");

    let perf = runtime.diagnostics().perf();
    assert_eq!(perf.interpreted_block_fallback_count(), 1);
    assert_eq!(perf.interpreted_blocks_decoded(), 1);
    assert!(perf.interpreted_block_bytes_read() >= 2);
}

#[test]
fn stall_diagnostic_identifies_guest_wait_futex() {
    let runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let events = vec![syscall_enter_event(
        Syscall::Futex,
        [0x402000, u64::from(LINUX_FUTEX_WAIT), 7, 0, 0, 0],
    )];

    let diagnostic = RuntimeDiagnostics::capture(runtime.kernel(), &events).stall_diagnostic();

    assert_eq!(diagnostic.kind(), RuntimeStallKind::GuestWaitFutex);
    assert_eq!(diagnostic.in_flight_syscall().unwrap().name(), "futex");
}

#[test]
fn stall_diagnostic_identifies_readiness_wait() {
    let mut runtime =
        RuntimeWithTracer::with_diagnostics(test_program("/bin/app", 0x401000)).unwrap();
    runtime
        .kernel_mut()
        .block_task_for_fd(INITIAL_GUEST_TID, 3, false)
        .unwrap();

    let diagnostic = runtime.stall_diagnostic();

    assert_eq!(diagnostic.kind(), RuntimeStallKind::Readiness);
    assert_eq!(diagnostic.fd_wait_tasks(), 1);
}

#[test]
fn stall_diagnostic_identifies_scheduling_wait() {
    let mut runtime =
        RuntimeWithTracer::with_diagnostics(test_program("/bin/app", 0x401000)).unwrap();
    let child_pid = runtime.kernel_mut().fork_child(INITIAL_GUEST_TID).unwrap();
    let wait = runtime.kernel_mut().wait4_current(
        INITIAL_GUEST_TID,
        Wait4SyscallArgs::new(child_pid as i32, 0x402000, 0, 0),
    );
    assert_eq!(wait.result, SyscallReturn::Success(0));

    let diagnostic = runtime.stall_diagnostic();

    assert_eq!(diagnostic.kind(), RuntimeStallKind::Scheduling);
    assert_eq!(diagnostic.child_wait_tasks(), 1);
}

#[test]
fn stall_diagnostic_identifies_native_execution_window() {
    let _guard = native_execution_test_guard();
    let mut runtime =
        RuntimeWithTracer::with_diagnostics(test_program("/bin/app", 0x401000)).unwrap();
    runtime.enable_native_execution();

    let diagnostic = runtime.stall_diagnostic();

    assert_eq!(diagnostic.kind(), RuntimeStallKind::NativeExecution);
    assert_eq!(diagnostic.runnable_tasks(), 1);
}

#[test]
fn bounded_guest_run_reports_timeout_stall_diagnostic() {
    let _guard = native_execution_test_guard();
    let mut code = vec![0xb8];
    code.extend_from_slice(&(Syscall::Getpid.number().raw() as u32).to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0xeb, 0xf7]);
    let mut runtime = RuntimeWithTracer::with_diagnostics(test_program_with_entry_code(
        "/bin/spin",
        0x401000,
        &code,
    ))
    .unwrap();
    runtime.enable_native_execution();

    let error = runtime
        .run_guest_until_exit_with_step_limit(3)
        .expect_err("looping guest should hit the diagnostic step limit");

    match error {
        GuestRunError::StepLimitExceeded { steps, diagnostic } => {
            assert_eq!(steps, 3);
            assert_eq!(diagnostic.kind(), RuntimeStallKind::NativeExecution);
            assert_eq!(diagnostic.last_syscall().unwrap().name(), "getpid");
            assert_eq!(
                diagnostic.last_syscall().unwrap().result(),
                Some(SyscallReturn::Success(1))
            );
        }
        other => panic!("expected step-limit diagnostic, got {other:?}"),
    }
}

#[test]
fn crash_report_includes_registers_and_runtime_diagnostics() {
    let mut runtime =
        RuntimeWithTracer::with_diagnostics(test_program("/bin/app", 0x401000)).unwrap();
    runtime.dispatch_syscall(context(Syscall::Gettid, [0; 6]));

    let registers = GuestRegisters {
        rax: Syscall::Gettid.number().raw(),
        rip: 0x401234,
        rsp: runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .regs()
            .rsp(),
        ..GuestRegisters::default()
    };
    let report = runtime.crash_report("invalid instruction", registers);

    assert_eq!(report.reason(), "invalid instruction");
    assert_eq!(report.registers(), registers);
    assert_eq!(report.diagnostics().executable_path(), b"/bin/app");
    assert_eq!(
        report.diagnostics().last_syscall().unwrap().name(),
        "gettid"
    );
}
