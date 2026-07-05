use mcr_sys::{
    LINUX_CLONE_CHILD_CLEARTID, LINUX_CLONE_FILES, LINUX_CLONE_FS, LINUX_CLONE_PARENT_SETTID,
    LINUX_CLONE_SETTLS, LINUX_CLONE_SIGHAND, LINUX_CLONE_SYSVSEM, LINUX_CLONE_THREAD,
    LINUX_CLONE_VFORK, LINUX_CLONE_VM, LINUX_KERNEL_SIGSET_SIZE, LINUX_ROBUST_LIST_HEAD_SIZE,
    LINUX_SIG_BLOCK, LINUX_SIG_SETMASK, LINUX_SIG_UNBLOCK, LINUX_SIGCHLD, LINUX_WNOHANG,
    LinuxErrno, Syscall, SyscallRegisters, SyscallRequest, SyscallReturn, TaskSyscalls,
    Wait4SyscallArgs,
};
use mcr_testkit::elf::{ET_DYN, Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X, PT_INTERP};

use super::*;

#[test]
fn package_name_is_stable() {
    assert_eq!(CRATE_NAME, "mcr-task");
}

#[test]
fn gpr_state_new_initializes_full_guest_register_defaults() {
    let regs = GprState::new(0x401000, 0x8000_0000);

    assert_eq!(regs.rip(), 0x401000);
    assert_eq!(regs.rsp(), 0x8000_0000);
    assert_eq!(regs.rax(), 0);
    assert_eq!(regs.rbx(), 0);
    assert_eq!(regs.rcx(), 0);
    assert_eq!(regs.rdi(), 0);
    assert_eq!(regs.rsi(), 0);
    assert_eq!(regs.rdx(), 0);
    assert_eq!(regs.rbp(), 0);
    assert_eq!(regs.r8(), 0);
    assert_eq!(regs.r9(), 0);
    assert_eq!(regs.r10(), 0);
    assert_eq!(regs.r11(), 0);
    assert_eq!(regs.r12(), 0);
    assert_eq!(regs.r13(), 0);
    assert_eq!(regs.r14(), 0);
    assert_eq!(regs.r15(), 0);
    assert_eq!(regs.rflags(), 0x202);
}

#[test]
fn gpr_state_syscall_constructor_preserves_full_guest_register_defaults() {
    let regs = GprState::with_syscall_registers(
        0x401002,
        0x8000_0008,
        Syscall::Write.number().raw(),
        [1, 0x402000, 3, 4, 5, 6],
    );

    assert_eq!(regs.rip(), 0x401002);
    assert_eq!(regs.rsp(), 0x8000_0008);
    assert_eq!(regs.rax(), Syscall::Write.number().raw());
    assert_eq!(regs.rdi(), 1);
    assert_eq!(regs.rsi(), 0x402000);
    assert_eq!(regs.rdx(), 3);
    assert_eq!(regs.r10(), 4);
    assert_eq!(regs.r8(), 5);
    assert_eq!(regs.r9(), 6);
    assert_eq!(regs.rbx(), 0);
    assert_eq!(regs.rcx(), 0);
    assert_eq!(regs.rbp(), 0);
    assert_eq!(regs.r11(), 0);
    assert_eq!(regs.r12(), 0);
    assert_eq!(regs.r13(), 0);
    assert_eq!(regs.r14(), 0);
    assert_eq!(regs.r15(), 0);
    assert_eq!(regs.rflags(), 0x202);
}

#[test]
fn initial_process_allocates_guest_ids_and_register_state() {
    let kernel = GuestKernel::new(test_program("/bin/init", 0x401000)).unwrap();

    assert_eq!(kernel.next_pid(), 2);
    assert_eq!(kernel.next_tid(), 2);

    let process = kernel.process(INITIAL_GUEST_PID).unwrap();
    let task = kernel.task(INITIAL_GUEST_TID).unwrap();

    assert_eq!(process.pid(), INITIAL_GUEST_PID);
    assert_eq!(process.parent(), None);
    assert_eq!(process.pgid(), INITIAL_GUEST_PID);
    assert_eq!(process.sid(), INITIAL_GUEST_PID);
    assert_eq!(process.exit_state(), ExitState::Running);
    assert_eq!(task.pid(), INITIAL_GUEST_PID);
    assert_eq!(task.tid(), INITIAL_GUEST_TID);
    assert_eq!(task.regs().rip(), 0x401000);
    assert_eq!(
        task.regs().rsp(),
        process.image().memory().initial_stack_pointer()
    );
    assert!(process.files().contains(0));
    assert!(process.files().contains(1));
    assert!(process.files().contains(2));
}

#[test]
fn host_worker_pool_diagnostics_are_bounded_without_scheduling_side_effects() {
    let mut kernel = GuestKernel::new(test_program("/bin/init", 0x401000)).unwrap();
    let before = kernel.host_worker_pool_diagnostics();

    assert_eq!(before[0].role(), HostWorkerPoolRole::GuestTaskExecution);
    assert_eq!(before[1].role(), HostWorkerPoolRole::IoCompletion);
    assert!(before.iter().all(|pool| pool.max_workers() > 0
        && pool.max_workers() <= HOST_WORKER_POOL_MAX_WORKERS
        && pool.max_queued_jobs() > 0));

    assert_eq!(kernel.fork_child(INITIAL_GUEST_TID).unwrap(), 2);
    assert_eq!(kernel.host_worker_pool_diagnostics(), before);
    assert_eq!(kernel.next_pid(), 3);
    assert_eq!(kernel.next_tid(), 3);
}

#[test]
fn dynamic_initial_process_enters_interpreter() {
    let kernel = GuestKernel::new(dynamic_test_program("/bin/sh")).unwrap();
    let process = kernel.process(INITIAL_GUEST_PID).unwrap();
    let task = kernel.task(INITIAL_GUEST_TID).unwrap();

    assert_eq!(process.image().executable().path(), b"/bin/sh");
    assert_eq!(
        process.image().interpreter().unwrap().path(),
        b"/lib/ld-musl-x86_64.so.1"
    );
    assert_eq!(
        task.regs().rip(),
        mcr_elf::DEFAULT_INTERPRETER_LOAD_BASE + 0x400
    );
    assert!(process.image().memory().interpreter().is_some());
}

#[test]
fn getpid_gettid_and_exit_syscalls_use_guest_state() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Getpid, [0; 6]),
        SyscallReturn::Success(u64::from(INITIAL_GUEST_PID))
    );
    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Gettid, [0; 6]),
        SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
    );

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Exit, [300, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Exited { status: 44 }
    );
    assert_eq!(
        kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
        ExitState::Exited { status: 44 }
    );
}

#[test]
fn getpgid_and_getsid_report_guest_process_groups_and_sessions() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Getpgid, [0; 6]),
        SyscallReturn::Success(u64::from(INITIAL_GUEST_PID))
    );
    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Getsid, [0; 6]),
        SyscallReturn::Success(u64::from(INITIAL_GUEST_PID))
    );

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Fork, [0; 6]),
        SyscallReturn::Success(2)
    );
    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Setpgid, [2, 2, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Getpgid, [2, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(2)
    );
    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Getsid, [2, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(u64::from(INITIAL_GUEST_PID))
    );
    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Getpgid, [999, 0, 0, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::ESRCH)
    );
    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Getsid, [999, 0, 0, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::ESRCH)
    );
}

#[test]
fn exit_group_marks_all_tasks_in_process_exited() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::ExitGroup, [7, 0, 0, 0, 0, 0]),
        SyscallReturn::Success(0)
    );

    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Exited { status: 7 }
    );
    assert_eq!(
        kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
        ExitState::Exited { status: 7 }
    );
}

#[test]
fn fork_creates_child_process_with_inherited_files() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
    kernel
        .process_mut(INITIAL_GUEST_PID)
        .unwrap()
        .files_mut()
        .insert_exact(3, GuestFdEntry::new("pipe-read"), true)
        .unwrap();

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Fork, [0; 6]),
        SyscallReturn::Success(2)
    );

    let parent = kernel.process(INITIAL_GUEST_PID).unwrap();
    let child = kernel.process(2).unwrap();
    let child_task = kernel.task(2).unwrap();

    assert!(parent.children().contains(&2));
    assert_eq!(child.parent(), Some(INITIAL_GUEST_PID));
    assert_eq!(child.pgid(), parent.pgid());
    assert_eq!(child.sid(), parent.sid());
    assert_eq!(child.image().executable().path(), b"/bin/parent");
    assert_eq!(child.files().get(3).unwrap().description(), "pipe-read");
    assert!(child.files().get(3).unwrap().cloexec());
    assert_eq!(child_task.pid(), 2);
    assert_eq!(child_task.tid(), 2);
    assert_eq!(kernel.next_pid(), 3);
    assert_eq!(kernel.next_tid(), 3);
}

#[test]
fn fork_syscall_prepares_child_zero_return_after_syscall() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Fork, [0; 6]),
        SyscallReturn::Success(2)
    );

    let child_task = kernel.task(2).unwrap();
    assert_eq!(child_task.regs().rax(), 0);
    assert_eq!(child_task.regs().rip(), 0x401236);
}

#[test]
fn clone_accepts_vfork_exec_shape_and_rejects_thread_flags() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Clone,
            [
                LINUX_CLONE_VM | LINUX_CLONE_VFORK | LINUX_SIGCHLD,
                0,
                0,
                0,
                0,
                0
            ],
        ),
        SyscallReturn::Success(2)
    );
    assert_eq!(kernel.process(2).unwrap().parent(), Some(INITIAL_GUEST_PID));
    assert_eq!(kernel.task(2).unwrap().regs().rax(), 0);
    assert_eq!(kernel.task(2).unwrap().regs().rip(), 0x401236);
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::WaitingForVfork { child_pid: 2 }
    );

    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Clone,
            [LINUX_CLONE_VM | LINUX_CLONE_THREAD, 0, 0, 0, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn clone_vfork_uses_child_stack_and_resumes_parent_after_exec() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Clone,
            [
                LINUX_CLONE_VM | LINUX_CLONE_VFORK | LINUX_SIGCHLD,
                0x7000_0000,
                0,
                0,
                0,
                0
            ],
        ),
        SyscallReturn::Success(2)
    );

    let parent = kernel.task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(parent.state(), TaskState::WaitingForVfork { child_pid: 2 });
    assert_eq!(kernel.runnable_tids(), vec![2]);
    let child = kernel.task(2).unwrap();
    assert_eq!(child.regs().rsp(), 0x7000_0000);
    assert_eq!(child.regs().rax(), 0);

    kernel
        .exec_task(2, test_program("/bin/child", 0x501000))
        .unwrap();

    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Runnable
    );
    assert_eq!(kernel.task(2).unwrap().state(), TaskState::Runnable);
    assert!(kernel.process(2).is_some());
}

#[test]
fn vfork_parent_resumes_when_child_exits_without_reaping_child() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Vfork, [0; 6]),
        SyscallReturn::Success(2)
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::WaitingForVfork { child_pid: 2 }
    );

    assert_eq!(kernel.exit_group(2, 37).result, SyscallReturn::Success(0));

    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Runnable
    );
    assert_eq!(
        kernel.process(2).unwrap().exit_state(),
        ExitState::Exited { status: 37 }
    );
    assert!(
        kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .children()
            .contains(&2)
    );
}

#[test]
fn clone_thread_shape_creates_task_in_current_process() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
    let flags = LINUX_CLONE_VM
        | LINUX_CLONE_FS
        | LINUX_CLONE_FILES
        | LINUX_CLONE_SIGHAND
        | LINUX_CLONE_THREAD
        | LINUX_CLONE_SYSVSEM
        | LINUX_CLONE_SETTLS
        | LINUX_CLONE_PARENT_SETTID
        | LINUX_CLONE_CHILD_CLEARTID;

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Clone,
            [flags, 0x7000_0000, 0x402000, 0x402004, 0x6000_0000, 0],
        ),
        SyscallReturn::Success(2)
    );

    let child = kernel.task(2).unwrap();
    assert_eq!(child.pid(), INITIAL_GUEST_PID);
    assert_eq!(child.tid(), 2);
    assert_eq!(child.regs().rax(), 0);
    assert_eq!(child.regs().rip(), 0x401236);
    assert_eq!(child.regs().rsp(), 0x7000_0000);
    assert_eq!(child.tls().fs_base(), 0x6000_0000);
    assert_eq!(child.clear_child_tid(), Some(0x402004));
    assert!(kernel.process(2).is_none());
    assert_eq!(kernel.next_pid(), 2);
    assert_eq!(kernel.next_tid(), 3);
}

#[test]
fn wait4_reaps_exited_child_and_reports_linux_status() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
    let child_pid = kernel.fork_child(INITIAL_GUEST_TID).unwrap();

    assert!(
        kernel
            .wait4_child(
                INITIAL_GUEST_PID,
                Wait4SyscallArgs::new(-1, 0x1000, LINUX_WNOHANG, 0),
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        kernel.exit_group(child_pid, 42).result,
        SyscallReturn::Success(0)
    );

    let waited = kernel
        .wait4_child(
            INITIAL_GUEST_PID,
            Wait4SyscallArgs::new(child_pid as i32, 0x1000, 0, 0),
        )
        .unwrap()
        .unwrap();

    assert_eq!(waited.pid(), child_pid);
    assert_eq!(waited.status(), 42);
    assert_eq!(waited.wait_status(), 42 << 8);
    assert!(
        !kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .children()
            .contains(&child_pid)
    );
    assert!(kernel.process(child_pid).is_none());
    assert!(kernel.task(child_pid).is_none());
}

#[test]
fn wait4_blocks_and_resumes_when_child_exits() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
    let child_pid = kernel.fork_child(INITIAL_GUEST_TID).unwrap();

    let wait = kernel.wait4_current(
        INITIAL_GUEST_TID,
        Wait4SyscallArgs::new(child_pid as i32, 0x1000, 0, 0),
    );
    assert_eq!(wait.result, SyscallReturn::Success(0));
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::WaitingForChild {
            args: Wait4SyscallArgs::new(child_pid as i32, 0x1000, 0, 0)
        }
    );

    assert_eq!(
        kernel.exit_group(child_pid, 37).result,
        SyscallReturn::Success(0)
    );
    let completed = kernel.resume_waiting_tasks();

    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].tid(), INITIAL_GUEST_TID);
    assert_eq!(completed[0].pid(), INITIAL_GUEST_PID);
    assert_eq!(completed[0].waited().pid(), child_pid);
    assert_eq!(completed[0].waited().wait_status(), 37 << 8);
    let parent = kernel.task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(parent.state(), TaskState::Runnable);
    assert_eq!(parent.regs().rax(), u64::from(child_pid));
    assert_eq!(parent.regs().rip(), 0x401002);
    assert!(kernel.process(child_pid).is_none());
    assert!(kernel.task(child_pid).is_none());
}

#[test]
fn wait4_reports_no_child_and_unsupported_options() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Wait4, [-1i64 as u64, 0, 0, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::ECHILD)
    );

    let child_pid = kernel.fork_child(INITIAL_GUEST_TID).unwrap();
    assert_eq!(
        kernel
            .wait4_child(
                INITIAL_GUEST_PID,
                Wait4SyscallArgs::new(child_pid as i32, 0, 0x8000_0000, 0),
            )
            .unwrap_err()
            .linux_errno(),
        LinuxErrno::EINVAL
    );
}

#[test]
fn arch_prctl_updates_task_tls_state() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::ArchPrctl,
            [ARCH_SET_FS, 0x7000_1234, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().tls().fs_base(),
        0x7000_1234
    );
    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::ArchPrctl,
            [ARCH_GET_FS, 0, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0x7000_1234)
    );
    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::ArchPrctl, [0xffff, 0, 0, 0, 0, 0],),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn uname_returns_linux_x86_64_identity() {
    let kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();
    let uts = kernel.uname_value();

    assert_eq!(c_field(&uts.sysname), b"Linux");
    assert_eq!(c_field(&uts.nodename), b"mcr");
    assert_eq!(c_field(&uts.release), b"6.6.0-mcr");
    assert_eq!(c_field(&uts.machine), b"x86_64");
}

#[test]
fn execve_replaces_image_preserves_identity_and_applies_close_on_exec() {
    let mut kernel = GuestKernel::new(test_program("/bin/old", 0x401000)).unwrap();
    let process = kernel.process_mut(INITIAL_GUEST_PID).unwrap();
    process
        .files_mut()
        .insert_exact(3, GuestFdEntry::new("keep"), false)
        .unwrap();
    process
        .files_mut()
        .insert_exact(4, GuestFdEntry::new("close"), true)
        .unwrap();

    assert!(
        kernel
            .arch_prctl(INITIAL_GUEST_TID, ARCH_SET_FS, 0x7fff_aaaa)
            .result
            .is_success()
    );
    kernel
        .exec_task(
            INITIAL_GUEST_TID,
            test_program("/bin/new", 0x501000)
                .with_args([b"/bin/new".to_vec(), b"--flag".to_vec()])
                .with_env([b"PATH=/bin".to_vec()]),
        )
        .unwrap();

    let process = kernel.process(INITIAL_GUEST_PID).unwrap();
    let task = kernel.task(INITIAL_GUEST_TID).unwrap();

    assert_eq!(process.pid(), INITIAL_GUEST_PID);
    assert_eq!(task.tid(), INITIAL_GUEST_TID);
    assert_eq!(process.image().executable().path(), b"/bin/new");
    assert_eq!(
        process.image().argv(),
        &[b"/bin/new".to_vec(), b"--flag".to_vec()]
    );
    assert_eq!(process.image().envp(), &[b"PATH=/bin".to_vec()]);
    assert_eq!(task.regs().rip(), 0x501000);
    assert_eq!(
        task.regs().rsp(),
        process.image().memory().initial_stack_pointer()
    );
    assert_eq!(task.tls(), TlsState::new());
    assert!(process.files().contains(3));
    assert!(!process.files().contains(4));
}

#[test]
fn rt_sigaction_saves_action_and_rejects_invalid_signal_or_sigset_size() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigaction,
            [
                LINUX_SIGTERM as u64,
                0x7000,
                0,
                LINUX_KERNEL_SIGSET_SIZE,
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .signals()
            .action(LINUX_SIGTERM)
            .unwrap()
            .action(),
        0x7000
    );

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigaction,
            [0, 0x8000, 0, LINUX_KERNEL_SIGSET_SIZE, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigaction,
            [
                LINUX_SIGTERM as u64,
                0x8000,
                0,
                LINUX_KERNEL_SIGSET_SIZE + 1,
                0,
                0
            ],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn rt_sigprocmask_updates_mask_and_rejects_invalid_how_or_sigset_size() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigprocmask,
            [
                LINUX_SIG_SETMASK as u64,
                0b1010,
                0,
                LINUX_KERNEL_SIGSET_SIZE,
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .signals()
            .blocked(),
        0b1010
    );

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigprocmask,
            [
                LINUX_SIG_BLOCK as u64,
                0b0101,
                0,
                LINUX_KERNEL_SIGSET_SIZE,
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .signals()
            .blocked(),
        0b1111
    );

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigprocmask,
            [
                LINUX_SIG_UNBLOCK as u64,
                0b0011,
                0,
                LINUX_KERNEL_SIGSET_SIZE,
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .signals()
            .blocked(),
        0b1100
    );

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigprocmask,
            [99, 0b1111, 0, LINUX_KERNEL_SIGSET_SIZE, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigprocmask,
            [
                LINUX_SIG_SETMASK as u64,
                0b1111,
                0,
                LINUX_KERNEL_SIGSET_SIZE + 1,
                0,
                0
            ],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn rt_sigtimedwait_reports_no_pending_signal_and_rejects_bad_sigset_size() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigtimedwait,
            [0x402000, 0, 0x402100, LINUX_KERNEL_SIGSET_SIZE, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EAGAIN)
    );
    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigtimedwait,
            [0x402000, 0, 0x402100, LINUX_KERNEL_SIGSET_SIZE + 1, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn rt_sigtimedwait_consumes_process_signal_queued_by_kill() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();
    let signal = LINUX_SIGCHLD as u32;
    let signal_mask = 1u64 << (signal - 1);

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Kill,
            [INITIAL_GUEST_PID as u64, LINUX_SIGCHLD as u64, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert!(
        kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .pending_signals()
            .contains(&signal)
    );

    assert_eq!(
        kernel
            .rt_sigtimedwait_current(
                INITIAL_GUEST_TID,
                signal_mask,
                LINUX_KERNEL_SIGSET_SIZE,
                false,
            )
            .result,
        SyscallReturn::Success(u64::from(signal))
    );
    assert!(
        !kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .pending_signals()
            .contains(&signal)
    );
}

#[test]
fn rt_sigtimedwait_blocks_and_tkill_wakes_matching_waiter() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();
    let signal = LINUX_SIGCHLD as u32;
    let signal_mask = 1u64 << (signal - 1);

    assert_eq!(
        kernel
            .rt_sigtimedwait_current(
                INITIAL_GUEST_TID,
                signal_mask,
                LINUX_KERNEL_SIGSET_SIZE,
                true,
            )
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::WaitingForSignalSet { mask: signal_mask }
    );

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Tkill,
            [INITIAL_GUEST_TID as u64, LINUX_SIGCHLD as u64, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    let task = kernel.task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(task.state(), TaskState::Runnable);
    assert_eq!(
        SyscallReturn::decode_rax(task.regs().rax()),
        SyscallReturn::Success(u64::from(signal))
    );
}

#[test]
fn tkill_interrupts_futex_waiter_with_eintr() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();
    kernel
        .block_task_for_futex(
            INITIAL_GUEST_TID,
            FutexWaitKey::new(INITIAL_GUEST_PID, 0x402000, true),
        )
        .unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Tkill,
            [INITIAL_GUEST_TID as u64, LINUX_SIGCHLD as u64, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    let task = kernel.task(INITIAL_GUEST_TID).unwrap();
    assert_eq!(task.state(), TaskState::Runnable);
    assert_eq!(
        SyscallReturn::decode_rax(task.regs().rax()),
        SyscallReturn::Errno(LinuxErrno::EINTR)
    );
}

#[test]
fn kill_queues_blocked_sigterm_for_sigtimedwait_instead_of_exiting() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();
    let signal_mask = 1u64 << (LINUX_SIGTERM - 1);

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigprocmask,
            [
                LINUX_SIG_SETMASK as u64,
                signal_mask,
                0,
                LINUX_KERNEL_SIGSET_SIZE,
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Kill,
            [INITIAL_GUEST_PID as u64, LINUX_SIGTERM as u64, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );

    assert_eq!(
        kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
        ExitState::Running
    );
    assert!(
        kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .pending_signals()
            .contains(&LINUX_SIGTERM)
    );

    assert_eq!(
        kernel
            .rt_sigtimedwait_current(
                INITIAL_GUEST_TID,
                signal_mask,
                LINUX_KERNEL_SIGSET_SIZE,
                false,
            )
            .result,
        SyscallReturn::Success(u64::from(LINUX_SIGTERM))
    );
    assert!(
        !kernel
            .process(INITIAL_GUEST_PID)
            .unwrap()
            .pending_signals()
            .contains(&LINUX_SIGTERM)
    );
}

#[test]
fn kill_probe_checks_process_and_sigterm_exits_group() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Kill,
            [INITIAL_GUEST_PID as u64, 0, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
        ExitState::Running
    );

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Kill, [999, 0, 0, 0, 0, 0]),
        SyscallReturn::Errno(LinuxErrno::ESRCH)
    );

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Kill,
            [INITIAL_GUEST_PID as u64, LINUX_SIGTERM as u64, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Exited { status: 143 }
    );
    assert_eq!(
        kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
        ExitState::Exited { status: 143 }
    );
}

#[test]
fn tgkill_sigkill_exits_target_task() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::Tgkill,
            [
                INITIAL_GUEST_PID as u64,
                INITIAL_GUEST_TID as u64,
                LINUX_SIGKILL as u64,
                0,
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().state(),
        TaskState::Exited { status: 137 }
    );
    assert_eq!(
        kernel.process(INITIAL_GUEST_PID).unwrap().exit_state(),
        ExitState::Exited { status: 137 }
    );
}

#[test]
fn set_tid_address_sets_and_clears_clear_child_tid() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::SetTidAddress, [0x9000, 0, 0, 0, 0, 0],),
        SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().clear_child_tid(),
        Some(0x9000)
    );

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::SetTidAddress, [0, 0, 0, 0, 0, 0],),
        SyscallReturn::Success(u64::from(INITIAL_GUEST_TID))
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().clear_child_tid(),
        None
    );
}

#[test]
fn set_robust_list_sets_list_and_rejects_invalid_len() {
    let mut kernel = GuestKernel::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::SetRobustList,
            [0xa000, LINUX_ROBUST_LIST_HEAD_SIZE, 0, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().robust_list(),
        Some(0xa000)
    );

    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::SetRobustList,
            [0xb000, LINUX_ROBUST_LIST_HEAD_SIZE + 1, 0, 0, 0, 0],
        ),
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        kernel.task(INITIAL_GUEST_TID).unwrap().robust_list(),
        Some(0xa000)
    );
}

#[test]
fn fork_child_inherits_signal_action_and_mask() {
    let mut kernel = GuestKernel::new(test_program("/bin/parent", 0x401000)).unwrap();
    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigaction,
            [
                LINUX_SIGTERM as u64,
                0x7000,
                0,
                LINUX_KERNEL_SIGSET_SIZE,
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );
    assert_eq!(
        dispatch_task_syscall(
            &mut kernel,
            Syscall::RtSigprocmask,
            [
                LINUX_SIG_SETMASK as u64,
                0x55,
                0,
                LINUX_KERNEL_SIGSET_SIZE,
                0,
                0
            ],
        ),
        SyscallReturn::Success(0)
    );

    assert_eq!(
        dispatch_task_syscall(&mut kernel, Syscall::Fork, [0; 6]),
        SyscallReturn::Success(2)
    );

    let child_signals = kernel.process(2).unwrap().signals();
    assert_eq!(
        child_signals.action(LINUX_SIGTERM).unwrap().action(),
        0x7000
    );
    assert_eq!(child_signals.blocked(), 0x55);
}

fn dispatch_task_syscall(
    kernel: &mut GuestKernel,
    syscall: Syscall,
    args: [u64; 6],
) -> SyscallReturn {
    let request = SyscallRequest::from_guest_context(mcr_sys::GuestContext::new(
        INITIAL_GUEST_PID,
        INITIAL_GUEST_TID,
        SyscallRegisters {
            rax: syscall.number().raw(),
            rdi: args[0],
            rsi: args[1],
            rdx: args[2],
            r10: args[3],
            r8: args[4],
            r9: args[5],
            rip: 0x401234,
        },
    ));

    kernel.dispatch_task(&request).result
}

fn test_program(path: &str, entrypoint: u64) -> GuestProgram {
    let elf = Elf64Builder::new()
        .entrypoint(entrypoint)
        .program_header(Elf64ProgramHeader::load(
            PF_R | PF_X,
            0,
            entrypoint & !0xfff,
            0x1000,
            0x1000,
        ))
        .program_header(Elf64ProgramHeader::load(
            PF_R | PF_W,
            0x2000,
            (entrypoint & !0xfff) + 0x1000,
            0x08,
            0x100,
        ))
        .data_at(0x1000, vec![0x90; 0x80])
        .data_at(0x2000, vec![0; 0x08])
        .build();

    GuestProgram::new(GuestExecutable::new(path.as_bytes().to_vec(), elf))
}

fn dynamic_test_program(path: &str) -> GuestProgram {
    let interpreter_path = b"/lib/ld-musl-x86_64.so.1\0";
    let executable = Elf64Builder::new()
        .object_type(ET_DYN)
        .entrypoint(0x1010)
        .program_header(Elf64ProgramHeader::new(
            PT_INTERP,
            PF_R,
            0x300,
            0,
            interpreter_path.len() as u64,
            interpreter_path.len() as u64,
            1,
        ))
        .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x2000))
        .data_at(0x300, interpreter_path.to_vec())
        .data_at(0x400, vec![0x90; 4])
        .build();
    let interpreter = Elf64Builder::new()
        .object_type(ET_DYN)
        .entrypoint(0x400)
        .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x1000))
        .data_at(0x400, vec![0x90; 4])
        .build();

    GuestProgram::new(GuestExecutable::new(path.as_bytes().to_vec(), executable)).with_interpreter(
        GuestExecutable::new(b"/lib/ld-musl-x86_64.so.1".to_vec(), interpreter),
    )
}

fn c_field(field: &[u8]) -> &[u8] {
    let len = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    &field[..len]
}
