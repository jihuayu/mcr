use super::support::*;

#[test]
fn runtime_fork_child_close_shared_socket_keeps_parent_socket_open() {
    let transport = runtime_socket_transport();
    let mut runtime = Runtime::with_vfs_and_socket_transport(
        test_program("/bin/app", 0x401000),
        sample_vfs(),
        transport.handle(),
    )
    .unwrap();
    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Socket,
                [
                    u64::from(LINUX_AF_INET),
                    u64::from(LINUX_SOCK_STREAM),
                    u64::from(LINUX_IPPROTO_TCP),
                    0,
                    0,
                    0,
                ]
            ))
            .result,
        SyscallReturn::Success(3)
    );
    runtime.memory_mut().write(0x402000, b"ping").unwrap();
    runtime
        .memory_mut()
        .write(0x402100, &ipv4_sockaddr(8080))
        .unwrap();

    assert_eq!(
        runtime
            .dispatch_syscall(context(
                Syscall::Connect,
                [3, 0x402100, SOCKADDR_IN_LEN as u64, 0, 0, 0,]
            ))
            .result,
        SyscallReturn::Success(0)
    );
    let fork = runtime.dispatch_syscall(context(Syscall::Fork, [0; 6]));
    assert_eq!(fork.result, SyscallReturn::Success(2));
    assert_eq!(
        runtime
            .dispatch_syscall(context_for(2, 2, Syscall::Close, [3, 0, 0, 0, 0, 0]))
            .result,
        SyscallReturn::Success(0)
    );

    assert_eq!(
        runtime
            .dispatch_syscall(context(Syscall::Sendto, [3, 0x402000, 4, 0, 0, 0]))
            .result,
        SyscallReturn::Success(4)
    );
}
