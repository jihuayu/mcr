use super::support::*;

#[test]
fn runtime_wires_task_syscalls_through_dispatcher() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let result = runtime.dispatch_syscall(context(Syscall::Getpid, [0; 6]));

    assert_eq!(result.result, SyscallReturn::Success(1));
    assert_eq!(result.encoded_rax, 1);
    assert_eq!(
        runtime.kernel().process(INITIAL_GUEST_PID).unwrap().pid(),
        1
    );
}

#[test]
fn rt_sigtimedwait_returns_eagain_after_validating_inputs() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0x2u64.to_le_bytes())
        .unwrap();
    write_timespec(runtime.memory_mut(), 0x402100, 0, 0);

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::RtSigtimedwait,
                [0x402000, 0, 0x402100, 8, 0, 0],
            ))
            .result,
        SyscallReturn::Errno(LinuxErrno::EAGAIN)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::RtSigtimedwait, [0, 0, 0x402100, 8, 0, 0],))
            .result,
        SyscallReturn::Errno(LinuxErrno::EFAULT)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::RtSigtimedwait,
                [0x402000, 0, 0x402100, 9, 0, 0],
            ))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn rt_sigtimedwait_returns_queued_signal_and_writes_siginfo() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let signal = LINUX_SIGCHLD as u32;
    let signal_mask = 1u64 << (signal - 1);
    runtime
        .memory_mut()
        .write(0x402000, &signal_mask.to_le_bytes())
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Kill,
                [INITIAL_GUEST_PID as u64, u64::from(signal), 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::RtSigtimedwait,
                [0x402000, 0x402100, 0, 8, 0, 0]
            ))
            .result,
        SyscallReturn::Success(u64::from(signal))
    );
    assert_eq!(u32_from_guest(runtime.memory(), 0x402100), signal);
}

#[test]
fn rt_sigtimedwait_blocks_when_timeout_is_null() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let signal = LINUX_SIGCHLD as u32;
    let signal_mask = 1u64 << (signal - 1);
    runtime
        .memory_mut()
        .write(0x402000, &signal_mask.to_le_bytes())
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::RtSigtimedwait, [0x402000, 0, 0, 8, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::WaitingForSignalSet { mask: signal_mask }
    );
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[test]
fn native_blocking_fd_wait_ignores_nonblocking_descriptors() {
    let mut vfs = sample_vfs();
    let blocking = vfs.eventfd(0, OpenFlags::new(0)).unwrap();
    let nonblocking = vfs.eventfd(0, OpenFlags::new(mcr_vfs::O_NONBLOCK)).unwrap();

    assert_eq!(
        blocking_fd_wait(vfs.fds(), Syscall::Read.number().raw(), blocking as u64),
        Some((blocking, false))
    );
    assert_eq!(
        blocking_fd_wait(vfs.fds(), Syscall::Read.number().raw(), nonblocking as u64),
        None
    );
}

#[test]
fn guest_run_loop_schedules_child_when_parent_waits() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, exit_group
            0xbf, 0x00, 0x00, 0x00, 0x00, // mov edi, 0
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::Fork, [0; 6]);

    let fork = runtime
        .dispatch_guest_execution()
        .expect("parent fork syscall executes");
    assert_eq!(fork.encoded_rax(), 2);
    runtime
        .kernel_mut()
        .task_mut(INITIAL_GUEST_TID)
        .unwrap()
        .set_regs(GprState::with_syscall_registers(
            0x401000,
            0x8000_0000,
            Syscall::Wait4.number().raw(),
            [-1i64 as u64, 0x402000, 0, 0, 0, 0],
        ));
    runtime
        .kernel_mut()
        .task_mut(2)
        .unwrap()
        .set_regs(GprState::with_syscall_registers(
            0x401000,
            0x8000_0000,
            Syscall::ExitGroup.number().raw(),
            [23, 0, 0, 0, 0, 0],
        ));

    let status = runtime
        .run_guest_until_exit()
        .expect("parent exits after reaping child");

    assert_eq!(status, 0);
    let parent = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(parent.state(), TaskState::Exited { status: 0 });
    assert_eq!(u32_from_guest(runtime.memory(), 0x402000), 23 << 8);
    assert!(runtime.kernel().process(2).is_none());
    assert!(runtime.memory_for_process(2).is_none());
}

#[test]
fn thread_clone_writes_tid_pointers_and_exit_keeps_process_alive() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime.memory_mut().write(0x402000, &[0xaa; 8]).unwrap();
    let flags = LINUX_CLONE_VM
        | LINUX_CLONE_FS
        | LINUX_CLONE_FILES
        | LINUX_CLONE_SIGHAND
        | LINUX_CLONE_THREAD
        | LINUX_CLONE_SYSVSEM
        | LINUX_CLONE_SETTLS
        | LINUX_CLONE_PARENT_SETTID
        | LINUX_CLONE_CHILD_SETTID
        | LINUX_CLONE_CHILD_CLEARTID;

    let clone = runtime.dispatch_syscall(context(
        Syscall::Clone,
        [flags, 0x7000_0000, 0x402000, 0x402004, 0x6000_0000, 0],
    ));

    assert_eq!(clone.result, SyscallReturn::Success(2));
    assert_eq!(u32_from_guest(runtime.memory(), 0x402000), 2);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402004), 2);
    let child = runtime.kernel().task(2).unwrap();
    assert_eq!(child.pid(), INITIAL_GUEST_PID);
    assert_eq!(child.regs().rsp(), 0x7000_0000);
    assert_eq!(child.tls().fs_base(), 0x6000_0000);

    let exit = runtime.dispatch_syscall(context_for(
        INITIAL_GUEST_PID,
        2,
        Syscall::Exit,
        [0, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exit.result, SyscallReturn::Success(0));
    assert_eq!(u32_from_guest(runtime.memory(), 0x402004), 0);
    assert_eq!(
        runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .exit_state(),
        ExitState::Running
    );
    assert_eq!(
        runtime.kernel().task(2).unwrap().state(),
        TaskState::Exited { status: 0 }
    );
    assert_eq!(runtime.kernel().task(2).unwrap().clear_child_tid(), None);
}

#[test]
fn set_tid_address_returns_current_guest_tid() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let set_tid =
        runtime.dispatch_syscall(context(Syscall::SetTidAddress, [0x402000, 0, 0, 0, 0, 0]));

    assert_eq!(
        set_tid.result,
        SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
    );
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .clear_child_tid(),
        Some(0x402000)
    );

    let clear_tid = runtime.dispatch_syscall(context(Syscall::SetTidAddress, [0, 0, 0, 0, 0, 0]));

    assert_eq!(
        clear_tid.result,
        SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
    );
    assert_eq!(
        runtime
            .kernel()
            .task(INITIAL_GUEST_TID)
            .unwrap()
            .clear_child_tid(),
        None
    );
}

#[test]
fn runtime_dispatches_fork_child_exit_and_wait4() {
    let mut runtime = Runtime::new(test_program("/bin/parent", 0x401000)).unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime.kernel().process(2).unwrap().parent(),
        Some(INITIAL_GUEST_PID)
    );

    let child_exit =
        runtime.dispatch_syscall(context_for(2, 2, Syscall::ExitGroup, [23, 0, 0, 0, 0, 0]));
    assert_eq!(child_exit.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime.kernel().process(2).unwrap().exit_state(),
        ExitState::Exited { status: 23 }
    );

    let wait = runtime.dispatch_syscall(context(Syscall::Wait4, [-1i64 as u64, 0, 0, 0, 0, 0]));
    assert_eq!(wait.result, SyscallReturn::Success(2));
    assert!(runtime.kernel().process(2).is_none());
    assert!(runtime.kernel().task(2).is_none());
    assert!(
        !runtime
            .kernel()
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .children()
            .contains(&2)
    );
}

#[test]
fn guest_execution_can_dispatch_forked_child_task() {
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    set_initial_syscall_regs(&mut runtime, 0x401000, Syscall::Fork, [0; 6]);

    let parent_step = runtime
        .dispatch_guest_execution()
        .expect("parent fork syscall executes");
    assert_eq!(parent_step.tid(), INITIAL_GUEST_TID);
    assert_eq!(parent_step.encoded_rax(), 2);

    runtime
        .kernel_mut()
        .task_mut(2)
        .unwrap()
        .set_regs(GprState::with_syscall_registers(
            0x401000,
            0x8000_0000,
            Syscall::ExitGroup.number().raw(),
            [17, 0, 0, 0, 0, 0],
        ));

    let child_step = dispatch_guest_task_with_dispatcher(&mut runtime.dispatcher, 2)
        .expect("child exit syscall executes");
    assert_eq!(child_step.tid(), 2);
    assert_eq!(child_step.task_state(), TaskState::Exited { status: 17 });
    assert_eq!(
        runtime.kernel().process(2).unwrap().exit_state(),
        ExitState::Exited { status: 17 }
    );
}

#[test]
fn forked_child_memory_is_isolated_from_parent_memory() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    let marker_addr = 0x402000;
    runtime.memory_mut().write(marker_addr, b"parent").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime
            .dispatch_syscall(context_for(
                2,
                2,
                Syscall::Write,
                [1, marker_addr, 5, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(5)
    );

    runtime
        .memory_for_process_mut(2)
        .unwrap()
        .write(marker_addr, b"child!")
        .unwrap();

    let mut parent_bytes = [0; 6];
    runtime
        .memory()
        .read(marker_addr, &mut parent_bytes)
        .unwrap();
    let mut child_bytes = [0; 6];
    runtime
        .memory_for_process(2)
        .unwrap()
        .read(marker_addr, &mut child_bytes)
        .unwrap();
    assert_eq!(&parent_bytes, b"parent");
    assert_eq!(&child_bytes, b"child!");
}

#[test]
fn runtime_fork_child_dup2_close_does_not_mutate_parent_fds() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Pipe2, [0x402000, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    let parent_read_fd = i32_from_memory(runtime.memory(), 0x402000);
    let parent_write_fd = i32_from_memory(runtime.memory(), 0x402004);
    assert_eq!(parent_read_fd, 3);
    assert_eq!(parent_write_fd, 4);

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime
            .dispatch_syscall(context_for(
                2,
                2,
                Syscall::Dup2,
                [parent_write_fd as u64, 7, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(7)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context_for(
                2,
                2,
                Syscall::Close,
                [parent_write_fd as u64, 0, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );

    runtime.memory_mut().write(0x402100, b"ok").unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Write,
                [parent_write_fd as u64, 0x402100, 2, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(2)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Read,
                [parent_read_fd as u64, 0x402200, 2, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(2)
    );
    let mut bytes = [0; 2];
    runtime.memory().read(0x402200, &mut bytes).unwrap();
    assert_eq!(&bytes, b"ok");
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Close, [7, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EBADF)
    );
}

#[test]
fn forked_child_exec_replaces_only_child_memory() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
    runtime.memory_mut().write(0x402000, b"parent").unwrap();
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/new"
    );
    assert_eq!(runtime.kernel().task(2).unwrap().regs().rip(), 0x501000);
    let mut parent_bytes = [0; 6];
    runtime.memory().read(0x402000, &mut parent_bytes).unwrap();
    assert_eq!(&parent_bytes, b"parent");

    let mut loaded_text = [0; 4];
    runtime
        .memory_for_process(2)
        .unwrap()
        .read(0x501200, &mut loaded_text)
        .unwrap();
    assert_eq!(loaded_text, [0x5a; 4]);
    assert_eq!(
        runtime
            .memory_for_process(2)
            .unwrap()
            .read(0x402000, &mut [0; 1]),
        Err(GuestMemoryError::NotMapped)
    );
}

#[test]
fn fork_exec_defers_memory_clone_until_child_execve() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
    runtime.memory_mut().write(0x402000, b"parent").unwrap();
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert!(
        runtime
            .dispatcher
            .subsystems()
            .process
            .pending_fork_exec
            .contains_key(&2)
    );
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process
            .memory
            .contains_key(&2)
    );

    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process
            .pending_fork_exec
            .contains_key(&2)
    );
    assert!(
        runtime
            .dispatcher
            .subsystems()
            .process
            .memory
            .contains_key(&2)
    );
    let mut parent_bytes = [0; 6];
    runtime.memory().read(0x402000, &mut parent_bytes).unwrap();
    assert_eq!(&parent_bytes, b"parent");
    assert_eq!(
        runtime
            .memory_for_process(2)
            .unwrap()
            .read(0x402000, &mut [0; 1]),
        Err(GuestMemoryError::NotMapped)
    );
}

#[test]
fn clone3_vfork_defers_memory_clone_until_child_execve() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();
    write_clone3_args(
        runtime.memory_mut(),
        0x402200,
        LINUX_CLONE_VM | LINUX_CLONE_VFORK,
        LINUX_SIGCHLD,
        0x7000_0000,
        0x1000,
    );

    let clone3 = runtime.dispatch_syscall(context(Syscall::Clone3, [0x402200, 88, 0, 0, 0, 0]));

    assert_eq!(clone3.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::WaitingForVfork { child_pid: 2 }
    );
    assert_eq!(runtime.kernel().task(2).unwrap().regs().rsp(), 0x7000_1000);
    assert!(
        runtime
            .dispatcher
            .subsystems()
            .process
            .pending_fork_exec
            .contains_key(&2)
    );
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process
            .memory
            .contains_key(&2)
    );

    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime.kernel().task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Runnable
    );
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/new"
    );
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process
            .pending_fork_exec
            .contains_key(&2)
    );
}

#[test]
fn parent_memory_mutation_materializes_deferred_fork_child_first() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime.memory_mut().write(0x402000, b"parent").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert!(
        runtime
            .dispatcher
            .subsystems()
            .process
            .pending_fork_exec
            .contains_key(&2)
    );

    runtime.memory_mut().write(0x402000, b"PARENT").unwrap();

    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process
            .pending_fork_exec
            .contains_key(&2)
    );
    let mut parent_bytes = [0; 6];
    runtime.memory().read(0x402000, &mut parent_bytes).unwrap();
    let mut child_bytes = [0; 6];
    runtime
        .memory_for_process(2)
        .unwrap()
        .read(0x402000, &mut child_bytes)
        .unwrap();
    assert_eq!(&parent_bytes, b"PARENT");
    assert_eq!(&child_bytes, b"parent");
}

#[test]
fn unsafe_share_until_exec_keeps_child_pending_after_parent_memory_write() {
    let _guard = env_test_guard();
    let _unsafe_share = TestUnsafeShareUntilExec::enable();
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content("/bin/new", test_program_bytes(0x501000), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();

    assert!(
        runtime
            .dispatcher
            .subsystems()
            .process
            .pending_fork_exec
            .contains_key(&2)
    );
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process
            .memory
            .contains_key(&2)
    );

    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/new"
    );
}

#[test]
fn deferred_fork_exec_failure_preserves_child_memory() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);
    runtime.memory_mut().write(0x402000, b"parent").unwrap();
    runtime
        .memory_mut()
        .write(0x402100, b"/bin/missing\0")
        .unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    let exec = runtime.dispatch_syscall(context_for(
        2,
        2,
        Syscall::Execve,
        [0x402100, 0, 0, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Errno(LinuxErrno::ENOENT));
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process
            .pending_fork_exec
            .contains_key(&2)
    );
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/old"
    );
    let mut child_bytes = [0; 6];
    runtime
        .memory_for_process(2)
        .unwrap()
        .read(0x402000, &mut child_bytes)
        .unwrap();
    assert_eq!(&child_bytes, b"parent");
}

#[test]
fn pending_fork_child_can_exec_from_read_only_parent_memory() {
    let mut exec_code = Vec::new();
    exec_code.extend_from_slice(&[0x48, 0xbf]);
    exec_code.extend_from_slice(&0x402100u64.to_le_bytes());
    exec_code.extend_from_slice(&[0x31, 0xf6, 0x31, 0xd2, 0xb8]);
    exec_code.extend_from_slice(&(Syscall::Execve.number().raw() as u32).to_le_bytes());
    exec_code.extend_from_slice(&[0x0f, 0x05]);

    let old_program = test_program_with_entry_code("/bin/old", 0x401000, &exec_code);
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", old_program.executable().bytes().to_vec(), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    let mut runtime = runtime_from_program_and_tree(old_program, tree);
    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();

    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    runtime
        .kernel_mut()
        .task_mut(2)
        .unwrap()
        .set_regs(GprState::new(0x401000, 0x8000_0000));

    let step = dispatch_guest_task_with_dispatcher(&mut runtime.dispatcher, 2)
        .expect("pending child executes execve from parent memory");

    assert_eq!(step.tid(), 2);
    assert_eq!(step.task_state(), TaskState::Runnable);
    assert_eq!(
        runtime
            .kernel()
            .process(2)
            .unwrap()
            .image()
            .executable()
            .path(),
        b"/bin/new"
    );
    assert_eq!(runtime.kernel().task(2).unwrap().regs().rip(), 0x501000);
    assert!(
        !runtime
            .dispatcher
            .subsystems()
            .process
            .pending_fork_exec
            .contains_key(&2)
    );
}

#[test]
fn native_fork_keeps_parent_and_child_memory_isolated() {
    let _guard = native_execution_test_guard();
    let mut runtime = Runtime::new(test_program_with_entry_code(
        "/bin/app",
        0x401000,
        &[
            0xb8, 0x39, 0x00, 0x00, 0x00, // mov eax,fork
            0x0f, 0x05, // syscall
            0x85, 0xc0, // test eax,eax
            0x75, 0x19, // jne parent
            0x48, 0xbb, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx,0x402000
            0xc7, 0x03, b'c', b'h', b'l', b'd', // mov dword ptr [rbx],"chld"
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x31, 0xff, // xor edi,edi
            0x0f, 0x05, // syscall
            0x48, 0xbb, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx,0x402000
            0xc7, 0x03, b'p', b'a', b'r', b'e', // mov dword ptr [rbx],"pare"
            0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,exit_group
            0x31, 0xff, // xor edi,edi
            0x0f, 0x05, // syscall
        ],
    ))
    .unwrap();
    runtime.enable_native_execution();
    runtime.memory_mut().write(0x402000, b"parent").unwrap();

    let fork = runtime
        .dispatch_guest_execution()
        .expect("parent native fork syscall executes");
    assert_eq!(fork.encoded_rax(), 2);

    let child = dispatch_guest_task_with_dispatcher(&mut runtime.dispatcher, 2)
        .expect("child native branch exits");
    assert_eq!(child.task_state(), TaskState::Exited { status: 0 });

    let mut parent_bytes = [0; 6];
    runtime.memory().read(0x402000, &mut parent_bytes).unwrap();

    assert_eq!(&parent_bytes, b"parent");
}

#[test]
fn runtime_execve_reads_filename_argv_envp_from_guest_memory_and_vfs() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/new",
        test_program_bytes_with_marker(0x501000, 0x5a),
        0o755,
    )
    .unwrap();
    tree.mount_minimal_procfs().unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

    runtime.memory_mut().write(0x402100, b"/bin/new\0").unwrap();
    runtime.memory_mut().write(0x402120, b"/bin/new\0").unwrap();
    runtime.memory_mut().write(0x402140, b"--flag\0").unwrap();
    runtime
        .memory_mut()
        .write(0x402160, b"PATH=/bin\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0x402120u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402008, &0x402140u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402010, &0u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402040, &0x402160u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402048, &0u64.to_le_bytes())
        .unwrap();

    let exec = runtime.dispatch_syscall(context(
        Syscall::Execve,
        [0x402100, 0x402000, 0x402040, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(process.image().executable().path(), b"/bin/new");
    assert_eq!(
        process.image().argv(),
        &[b"/bin/new".to_vec(), b"--flag".to_vec()]
    );
    assert_eq!(process.image().envp(), &[b"PATH=/bin".to_vec()]);
    assert_eq!(task.regs().rip(), 0x501000);
    let mut loaded_text = [0; 4];
    runtime.memory().read(0x501200, &mut loaded_text).unwrap();
    assert_eq!(loaded_text, [0x5a; 4]);

    runtime
        .memory_mut()
        .write(0x502100, b"/proc/self/cmdline\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x502140, b"/proc/self/environ\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x502180, b"/proc/self/exe\0")
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Openat,
                [AT_FDCWD as u64, 0x502100, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(3)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Read, [3, 0x502300, 64, 0, 0, 0]))
            .result,
        SyscallReturn::Success(16)
    );
    let mut cmdline = [0; 16];
    runtime.memory().read(0x502300, &mut cmdline).unwrap();
    assert_eq!(&cmdline, b"/bin/new\0--flag\0");
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Openat,
                [AT_FDCWD as u64, 0x502140, u64::from(O_RDONLY), 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(4)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Read, [4, 0x502320, 64, 0, 0, 0]))
            .result,
        SyscallReturn::Success(10)
    );
    let mut environ = [0; 10];
    runtime.memory().read(0x502320, &mut environ).unwrap();
    assert_eq!(&environ, b"PATH=/bin\0");
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Readlink,
                [0x502180, 0x502340, 64, 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(8)
    );
    let mut exe = [0; 8];
    runtime.memory().read(0x502340, &mut exe).unwrap();
    assert_eq!(&exe, b"/bin/new");
}

#[test]
fn runtime_execve_loads_interpreter_from_vfs() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_dir("/lib").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content(
        "/bin/dynamic",
        dynamic_program_bytes("/lib/ld-musl-x86_64.so.1"),
        0o755,
    )
    .unwrap();
    tree.create_file_with_content("/lib/ld-musl-x86_64.so.1", interpreter_bytes(), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

    runtime
        .memory_mut()
        .write(0x402100, b"/bin/dynamic\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402120, b"/bin/dynamic\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0x402120u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402008, &0u64.to_le_bytes())
        .unwrap();

    let exec = runtime.dispatch_syscall(context(Syscall::Execve, [0x402100, 0x402000, 0, 0, 0, 0]));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(process.image().executable().path(), b"/bin/dynamic");
    assert_eq!(
        process.image().interpreter().unwrap().path(),
        b"/lib/ld-musl-x86_64.so.1"
    );
    assert_eq!(
        task.regs().rip(),
        mcr_elf::DEFAULT_INTERPRETER_LOAD_BASE + 0x400
    );
}

#[test]
fn runtime_execve_loads_shebang_script_interpreter() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    tree.create_file_with_content("/bin/sh", test_program_bytes(0x501000), 0o755)
        .unwrap();
    tree.create_file_with_content("/bin/script", b"#!/bin/sh\nexit 0\n", 0o755)
        .unwrap();
    tree.mount_minimal_procfs().unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

    runtime
        .memory_mut()
        .write(0x402100, b"/bin/script\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402120, b"/bin/script\0")
        .unwrap();
    runtime.memory_mut().write(0x402140, b"--flag\0").unwrap();
    runtime
        .memory_mut()
        .write(0x402160, b"PATH=/bin\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402000, &0x402120u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402008, &0x402140u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402010, &0u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402040, &0x402160u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402048, &0u64.to_le_bytes())
        .unwrap();

    let exec = runtime.dispatch_syscall(context(
        Syscall::Execve,
        [0x402100, 0x402000, 0x402040, 0, 0, 0],
    ));

    assert_eq!(exec.result, SyscallReturn::Success(0));
    let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(process.image().executable().path(), b"/bin/sh");
    assert_eq!(
        process.image().argv(),
        &[
            b"/bin/sh".to_vec(),
            b"/bin/script".to_vec(),
            b"--flag".to_vec()
        ]
    );
    assert_eq!(process.image().envp(), &[b"PATH=/bin".to_vec()]);
    assert_eq!(task.regs().rip(), 0x501000);
}

#[test]
fn runtime_execve_missing_vfs_target_keeps_current_image() {
    let mut tree = PathTree::new();
    tree.create_dir("/bin").unwrap();
    tree.create_file_with_content("/bin/old", test_program_bytes(0x401000), 0o755)
        .unwrap();
    let mut runtime = runtime_from_program_and_tree(test_program("/bin/old", 0x401000), tree);

    runtime
        .memory_mut()
        .write(0x402100, b"/bin/missing\0")
        .unwrap();

    let exec = runtime.dispatch_syscall(context(Syscall::Execve, [0x402100, 0, 0, 0, 0, 0]));

    assert_eq!(exec.result, SyscallReturn::Errno(LinuxErrno::ENOENT));
    let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(process.image().executable().path(), b"/bin/old");
    assert_eq!(task.regs().rip(), 0x401000);
}

#[test]
fn runtime_getpid_gettid_fast_path_preserves_trace_and_esrch() {
    let mut runtime = Runtime::with_tracer(
        test_program("/bin/app", 0x401000),
        InMemorySyscallTracer::new(),
    )
    .unwrap();

    let getpid = runtime.dispatch_syscall(context(Syscall::Getpid, [0; 6]));
    let gettid = runtime.dispatch_syscall(context(Syscall::Gettid, [0; 6]));
    let invalid_gettid = runtime.dispatch_syscall(context_for(
        INITIAL_GUEST_PID,
        INITIAL_GUEST_TID + 99,
        Syscall::Gettid,
        [0; 6],
    ));

    assert_eq!(
        getpid.result,
        SyscallReturn::Success(u64::from(INITIAL_GUEST_PID))
    );
    assert_eq!(
        gettid.result,
        SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
    );
    assert_eq!(
        invalid_gettid.result,
        SyscallReturn::Errno(LinuxErrno::ESRCH)
    );
    assert!(matches!(
        runtime.tracer().events(),
        [
            SyscallTraceEvent::Enter(_),
            SyscallTraceEvent::Exit(_),
            SyscallTraceEvent::Enter(_),
            SyscallTraceEvent::Exit(_),
            SyscallTraceEvent::Enter(_),
            SyscallTraceEvent::Exit(_)
        ]
    ));
}

#[test]
fn runtime_exec_replaces_guest_image_and_keeps_guest_identity() {
    let mut runtime = Runtime::new(test_program("/bin/old", 0x401000)).unwrap();

    runtime
        .kernel_mut()
        .exec_task(INITIAL_GUEST_TID, test_program("/bin/new", 0x501000))
        .unwrap();

    let process = runtime.kernel().process(INITIAL_GUEST_PID).unwrap();
    let task = runtime.kernel().task(INITIAL_GUEST_TID).unwrap();

    assert_eq!(process.pid(), INITIAL_GUEST_PID);
    assert_eq!(task.tid(), INITIAL_GUEST_TID);
    assert_eq!(process.image().executable().path(), b"/bin/new");
    assert_eq!(task.regs().rip(), 0x501000);
}
