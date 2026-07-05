use super::support::*;

#[test]
fn clock_gettime_writes_linux_timespec_for_supported_clocks() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let realtime = runtime.dispatch_syscall(context(
        Syscall::ClockGettime,
        [LINUX_CLOCK_REALTIME, 0x402000, 0, 0, 0, 0],
    ));
    let monotonic = runtime.dispatch_syscall(context(
        Syscall::ClockGettime,
        [LINUX_CLOCK_MONOTONIC, 0x402020, 0, 0, 0, 0],
    ));

    assert_eq!(realtime.result, SyscallReturn::Success(0));
    assert_eq!(monotonic.result, SyscallReturn::Success(0));
    let realtime = timespec_from_memory(runtime.memory(), 0x402000);
    let monotonic = timespec_from_memory(runtime.memory(), 0x402020);
    assert!(realtime.tv_sec > 0);
    assert!((0..1_000_000_000).contains(&realtime.tv_nsec));
    assert!(monotonic.tv_sec >= 0);
    assert!((0..1_000_000_000).contains(&monotonic.tv_nsec));
}

#[test]
fn clock_gettime_rejects_invalid_clock_and_null_timespec() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let invalid_clock =
        runtime.dispatch_syscall(context(Syscall::ClockGettime, [99, 0x402000, 0, 0, 0, 0]));
    let null_timespec = runtime.dispatch_syscall(context(
        Syscall::ClockGettime,
        [LINUX_CLOCK_REALTIME, 0, 0, 0, 0, 0],
    ));

    assert_eq!(
        invalid_clock.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        null_timespec.result,
        SyscallReturn::Errno(LinuxErrno::EFAULT)
    );
}

#[test]
fn nanosleep_rejects_null_and_invalid_timespecs() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    write_timespec(runtime.memory_mut(), 0x402000, 0, 1_000_000_000);
    write_timespec(runtime.memory_mut(), 0x402020, -1, 0);

    let null_req = runtime.dispatch_syscall(context(Syscall::Nanosleep, [0, 0, 0, 0, 0, 0]));
    let invalid_nsec =
        runtime.dispatch_syscall(context(Syscall::Nanosleep, [0x402000, 0, 0, 0, 0, 0]));
    let negative_sec =
        runtime.dispatch_syscall(context(Syscall::Nanosleep, [0x402020, 0, 0, 0, 0, 0]));

    assert_eq!(null_req.result, SyscallReturn::Errno(LinuxErrno::EFAULT));
    assert_eq!(
        invalid_nsec.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        negative_sec.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
}

#[test]
fn nanosleep_accepts_zero_duration_and_ignores_rem_on_success() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    write_timespec(runtime.memory_mut(), 0x402000, 0, 0);

    let result = runtime.dispatch_syscall(context(
        Syscall::Nanosleep,
        [0x402000, 0x7000_0000, 0, 0, 0, 0],
    ));

    assert_eq!(result.result, SyscallReturn::Success(0));
}

#[test]
fn getrandom_rejects_unknown_flags_and_null_non_empty_buffer() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let invalid_flags =
        runtime.dispatch_syscall(context(Syscall::Getrandom, [0x402000, 8, 0x4, 0, 0, 0]));
    let null_buffer = runtime.dispatch_syscall(context(Syscall::Getrandom, [0, 8, 0, 0, 0, 0]));

    assert_eq!(
        invalid_flags.result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(null_buffer.result, SyscallReturn::Errno(LinuxErrno::EFAULT));
}

#[test]
fn getrandom_fills_guest_buffer_and_accepts_linux_flags() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();
    runtime.memory_mut().write(0x402000, &[0xaa; 32]).unwrap();

    let result = runtime.dispatch_syscall(context(
        Syscall::Getrandom,
        [
            0x402000,
            32,
            LINUX_GRND_NONBLOCK | LINUX_GRND_RANDOM,
            0,
            0,
            0,
        ],
    ));

    let mut bytes = [0; 32];
    runtime.memory().read(0x402000, &mut bytes).unwrap();
    assert_eq!(result.result, SyscallReturn::Success(32));
    assert_ne!(bytes, [0xaa; 32]);
}

#[test]
fn getrandom_accepts_empty_buffer_without_touching_pointer() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    let result = runtime.dispatch_syscall(context(Syscall::Getrandom, [0, 0, 0, 0, 0, 0]));

    assert_eq!(result.result, SyscallReturn::Success(0));
}

#[test]
fn task_time_resource_fake_syscalls_write_compat_structs() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::SchedYield, [0; 6]))
            .result,
        SyscallReturn::Success(0)
    );

    let gettimeofday = runtime.dispatch_syscall(context(
        Syscall::Gettimeofday,
        [0x402000, 0x402020, 0, 0, 0, 0],
    ));
    assert_eq!(gettimeofday.result, SyscallReturn::Success(0));
    assert!(u64_from_guest(runtime.memory(), 0x402000) > 0);
    assert!(u64_from_guest(runtime.memory(), 0x402008) < 1_000_000);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402020), 0);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402024), 0);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Gettimeofday, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );

    let clock_getres =
        runtime.dispatch_syscall(context(Syscall::ClockGetres, [1, 0x402040, 0, 0, 0, 0]));
    assert_eq!(clock_getres.result, SyscallReturn::Success(0));
    assert_eq!(i64_from_guest(runtime.memory(), 0x402040), 0);
    assert_eq!(i64_from_guest(runtime.memory(), 0x402048), 1_000_000);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::ClockGetres, [99, 0x402040, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    let getrlimit =
        runtime.dispatch_syscall(context(Syscall::Getrlimit, [7, 0x402100, 0, 0, 0, 0]));
    assert_eq!(getrlimit.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402100), 1024);
    assert_eq!(u64_from_guest(runtime.memory(), 0x402108), 1024);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Getrlimit, [99, 0x402100, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    runtime.memory_mut().write(0x402180, &[0xaa; 144]).unwrap();
    let getrusage =
        runtime.dispatch_syscall(context(Syscall::Getrusage, [0, 0x402180, 0, 0, 0, 0]));
    assert_eq!(getrusage.result, SyscallReturn::Success(0));
    let mut rusage = [0xaa; 144];
    runtime.memory().read(0x402180, &mut rusage).unwrap();
    assert_eq!(rusage, [0; 144]);
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Getrusage, [9, 0x402180, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    let sysinfo = runtime.dispatch_syscall(context(Syscall::Sysinfo, [0x402300, 0, 0, 0, 0, 0]));
    assert_eq!(sysinfo.result, SyscallReturn::Success(0));
    assert_eq!(i64_from_guest(runtime.memory(), 0x402300), 3600);
    assert_eq!(
        u64_from_guest(runtime.memory(), 0x402320),
        512 * 1024 * 1024
    );
    assert_eq!(u16_from_guest(runtime.memory(), 0x402350), 1);
}

#[test]
fn task_time_resource_fake_syscalls_handle_limits_prctl_cpu_and_fallbacks() {
    let mut runtime = Runtime::new(test_program("/bin/app", 0x401000)).unwrap();

    runtime
        .memory_mut()
        .write(0x402000, &512u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402008, &1024u64.to_le_bytes())
        .unwrap();
    let prlimit64 = runtime.dispatch_syscall(context(
        Syscall::Prlimit64,
        [0, 7, 0x402000, 0x402100, 0, 0],
    ));
    assert_eq!(prlimit64.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402100), 1024);
    assert_eq!(u64_from_guest(runtime.memory(), 0x402108), 1024);

    runtime
        .memory_mut()
        .write(0x402000, &2048u64.to_le_bytes())
        .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Prlimit64, [0, 7, 0x402000, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Prlimit64, [999, 7, 0, 0x402100, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::ESRCH)
    );

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Prctl,
                [LINUX_PR_GET_DUMPABLE, 0, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(1)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Prctl,
                [LINUX_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Prctl,
                [LINUX_PR_GET_NAME, 0x402200, 0, 0, 0, 0]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    let mut name = [0; 4];
    runtime.memory().read(0x402200, &mut name).unwrap();
    assert_eq!(&name, b"mcr\0");
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Prctl, [0xffff, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    let getcpu =
        runtime.dispatch_syscall(context(Syscall::Getcpu, [0x402300, 0x402304, 0, 0, 0, 0]));
    assert_eq!(getcpu.result, SyscallReturn::Success(0));
    assert_eq!(u32_from_guest(runtime.memory(), 0x402300), 0);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402304), 0);

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Membarrier, [0, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Membarrier, [1, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::ENOSYS)
    );
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Membarrier, [0, 1, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EINVAL)
    );

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Rseq, [0x402000, 32, 0, 0x53053053, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::ENOSYS)
    );
}

#[test]
fn runtime_dispatches_fake_syscall_compat_behaviors() {
    let mut runtime = Runtime::with_tracer_and_vfs(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        InMemorySyscallTracer::new(),
    )
    .unwrap();

    let gettimeofday = runtime.dispatch_syscall(context(
        Syscall::Gettimeofday,
        [0x402000, 0x402020, 0, 0, 0, 0],
    ));
    assert_eq!(gettimeofday.result, SyscallReturn::Success(0));
    assert!(u64_from_guest(runtime.memory(), 0x402000) > 0);
    assert!(u64_from_guest(runtime.memory(), 0x402008) < 1_000_000);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402020), 0);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402024), 0);

    let getrlimit =
        runtime.dispatch_syscall(context(Syscall::Getrlimit, [7, 0x402100, 0, 0, 0, 0]));
    assert_eq!(getrlimit.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402100), 1024);
    assert_eq!(u64_from_guest(runtime.memory(), 0x402108), 1024);

    let sysinfo = runtime.dispatch_syscall(context(Syscall::Sysinfo, [0x402200, 0, 0, 0, 0, 0]));
    assert_eq!(sysinfo.result, SyscallReturn::Success(0));
    assert_eq!(i64_from_guest(runtime.memory(), 0x402200), 3600);
    assert_eq!(
        u64_from_guest(runtime.memory(), 0x402220),
        512 * 1024 * 1024
    );
    assert_eq!(u16_from_guest(runtime.memory(), 0x402250), 1);

    let getcpu =
        runtime.dispatch_syscall(context(Syscall::Getcpu, [0x402300, 0x402304, 0, 0, 0, 0]));
    assert_eq!(getcpu.result, SyscallReturn::Success(0));
    assert_eq!(u32_from_guest(runtime.memory(), 0x402300), 0);
    assert_eq!(u32_from_guest(runtime.memory(), 0x402304), 0);

    runtime
        .memory_mut()
        .write(0x402400, b"/tmp/file\0")
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402500, &u64::from(O_RDONLY).to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402508, &0u64.to_le_bytes())
        .unwrap();
    runtime
        .memory_mut()
        .write(0x402510, &0u64.to_le_bytes())
        .unwrap();
    let openat2 = runtime.dispatch_syscall(context(
        Syscall::Openat2,
        [AT_FDCWD as u64, 0x402400, 0x402500, 24, 0, 0],
    ));
    assert_eq!(openat2.result, SyscallReturn::Success(3));

    let faccessat2 = runtime.dispatch_syscall(context(
        Syscall::Faccessat2,
        [AT_FDCWD as u64, 0x402400, u64::from(mcr_vfs::R_OK), 0, 0, 0],
    ));
    assert_eq!(faccessat2.result, SyscallReturn::Success(0));

    let statfs =
        runtime.dispatch_syscall(context(Syscall::Statfs, [0x402400, 0x402600, 0, 0, 0, 0]));
    assert_eq!(statfs.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402600), 0xef53);
    assert_eq!(u64_from_guest(runtime.memory(), 0x402608), 4096);

    let fstatfs = runtime.dispatch_syscall(context(Syscall::Fstatfs, [3, 0x402700, 0, 0, 0, 0]));
    assert_eq!(fstatfs.result, SyscallReturn::Success(0));
    assert_eq!(u64_from_guest(runtime.memory(), 0x402700), 0xef53);

    let close_range = runtime.dispatch_syscall(context(Syscall::CloseRange, [3, 3, 0, 0, 0, 0]));
    assert_eq!(close_range.result, SyscallReturn::Success(0));
    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Fstatfs, [3, 0x402800, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Errno(LinuxErrno::EBADF)
    );

    assert!(runtime.tracer().events().iter().any(|event| matches!(
        event,
        SyscallTraceEvent::Exit(exit)
            if exit.syscall == Syscall::Openat2
                && exit.result == SyscallReturn::Success(3)
    )));
}
