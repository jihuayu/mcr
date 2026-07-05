#![allow(dead_code)]
#![allow(unused_imports)]

pub(crate) use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    sync::{
        MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub(crate) use crate::*;
pub(crate) use mcr_net::SocketState;
pub(crate) use mcr_sys::{
    GuestContext, InMemorySyscallTracer, LINUX_AF_INET, LINUX_AF_INET6, LINUX_AF_UNIX,
    LINUX_CLONE_CHILD_CLEARTID, LINUX_CLONE_CHILD_SETTID, LINUX_CLONE_FILES, LINUX_CLONE_FS,
    LINUX_CLONE_PARENT_SETTID, LINUX_CLONE_SETTLS, LINUX_CLONE_SIGHAND, LINUX_CLONE_SYSVSEM,
    LINUX_CLONE_THREAD, LINUX_CLONE_VFORK, LINUX_CLONE_VM, LINUX_EPOLL_CLOEXEC,
    LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD, LINUX_EPOLLERR, LINUX_EPOLLET,
    LINUX_EPOLLEXCLUSIVE, LINUX_EPOLLHUP, LINUX_EPOLLIN, LINUX_EPOLLONESHOT, LINUX_EPOLLOUT,
    LINUX_IPPROTO_IP, LINUX_IPPROTO_TCP, LINUX_MAP_ANONYMOUS, LINUX_MAP_FIXED, LINUX_MAP_PRIVATE,
    LINUX_MSG_CMSG_CLOEXEC, LINUX_POLLHUP, LINUX_POLLIN, LINUX_POLLNVAL, LINUX_POLLOUT,
    LINUX_POLLPRI, LINUX_POLLRDNORM, LINUX_POLLWRNORM, LINUX_PROT_EXEC, LINUX_PROT_READ,
    LINUX_PROT_WRITE, LINUX_SHUT_RDWR, LINUX_SIGCHLD, LINUX_SO_ERROR, LINUX_SO_KEEPALIVE,
    LINUX_SO_REUSEADDR, LINUX_SO_TYPE, LINUX_SOCK_CLOEXEC, LINUX_SOCK_DGRAM, LINUX_SOCK_NONBLOCK,
    LINUX_SOCK_STREAM, LINUX_SOL_SOCKET, LINUX_TCP_NODELAY, Syscall, SyscallArgs,
    SyscallEnterEvent, SyscallExitEvent, SyscallRegisters, SyscallReturn, SyscallTraceEvent,
    TraceContext, Wait4SyscallArgs,
};
pub(crate) use mcr_task::{ARCH_SET_FS, ExitState, INITIAL_GUEST_PID, INITIAL_GUEST_TID};
pub(crate) use mcr_testkit::elf::{Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X};
pub(crate) use mcr_vfs::{
    AT_FDCWD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, FIONREAD, FdTable, O_CLOEXEC, O_CREAT,
    O_DIRECTORY, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, PathTree, RENAME_NOREPLACE, Rootfs,
    TIOCGWINSZ, VirtualFileSystem,
};

pub(crate) fn native_execution_test_guard() -> MutexGuard<'static, ()> {
    crate::test_support::native_execution_test_guard()
}

pub(crate) fn env_test_guard() -> MutexGuard<'static, ()> {
    crate::test_support::env_test_guard()
}

#[derive(Clone, Default)]
pub(crate) struct TestMemory {
    bytes: BTreeMap<u64, u8>,
}

impl TestMemory {
    pub(crate) fn write(&mut self, addr: u64, bytes: &[u8]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            self.bytes.insert(addr + index as u64, byte);
        }
    }

    pub(crate) fn write_cstr(&mut self, addr: u64, value: &str) {
        self.write(addr, value.as_bytes());
        self.write(addr + value.len() as u64, &[0]);
    }

    pub(crate) fn write_iovec(&mut self, addr: u64, base: u64, len: u64) {
        self.write(addr, &base.to_le_bytes());
        self.write(addr + 8, &len.to_le_bytes());
    }

    pub(crate) fn write_msghdr(
        &mut self,
        addr: u64,
        name: u64,
        namelen: u32,
        iov: u64,
        iovlen: u64,
    ) {
        self.write(addr, &name.to_le_bytes());
        self.write(addr + 8, &namelen.to_le_bytes());
        self.write(addr + 12, &0u32.to_le_bytes());
        self.write(addr + 16, &iov.to_le_bytes());
        self.write(addr + 24, &iovlen.to_le_bytes());
        self.write(addr + 32, &0u64.to_le_bytes());
        self.write(addr + 40, &0u64.to_le_bytes());
        self.write(addr + 48, &0u32.to_le_bytes());
        self.write(addr + 52, &0u32.to_le_bytes());
    }

    pub(crate) fn read(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.read_bytes(addr, &mut bytes).unwrap();
        bytes
    }
}

impl GuestMemoryAccess for TestMemory {
    fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), GuestMemoryAccessError> {
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = *self
                .bytes
                .get(&(addr + index as u64))
                .ok_or(GuestMemoryAccessError::Fault)?;
        }
        Ok(())
    }

    fn write_bytes(&mut self, addr: u64, buffer: &[u8]) -> Result<(), GuestMemoryAccessError> {
        self.write(addr, buffer);
        Ok(())
    }
}

impl RuntimeMemoryAccess for TestMemory {}

#[derive(Clone, Debug, Default)]
pub(crate) struct TestSocketTransport {
    state: Rc<RefCell<TestSocketState>>,
}

impl TestSocketTransport {
    pub(crate) fn handle(&self) -> TestSocketTransportHandle {
        TestSocketTransportHandle {
            state: self.state.clone(),
        }
    }

    pub(crate) fn sent_bytes(&self) -> Vec<u8> {
        self.state.borrow().sent.clone()
    }

    pub(crate) fn sent_calls(&self) -> Vec<Vec<u8>> {
        self.state.borrow().sent_calls.clone()
    }

    pub(crate) fn recv_calls(&self) -> usize {
        self.state.borrow().recv_calls
    }

    pub(crate) fn push_incoming(&self, bytes: &[u8]) {
        self.state.borrow_mut().incoming.extend_from_slice(bytes);
    }

    pub(crate) fn set_connect_would_block_once(&self) {
        self.state.borrow_mut().connect_would_block_once = true;
    }

    pub(crate) fn nonblocking(&self) -> bool {
        self.state.borrow().nonblocking
    }

    pub(crate) fn poll_timeouts(&self) -> Vec<Option<Duration>> {
        self.state.borrow().poll_timeouts.clone()
    }

    pub(crate) fn push_accepted(&self, peer: SocketAddress, incoming: &[u8]) {
        self.state.borrow_mut().accepted.push((
            Rc::new(RefCell::new(TestSocketState {
                incoming: incoming.to_vec(),
                connected: Some(peer),
                ..TestSocketState::default()
            })),
            peer,
        ));
    }
}

#[derive(Debug, Default)]
pub(crate) struct TestSocketState {
    sent: Vec<u8>,
    sent_calls: Vec<Vec<u8>>,
    recv_calls: usize,
    incoming: Vec<u8>,
    connected: Option<SocketAddress>,
    connect_would_block_once: bool,
    nonblocking: bool,
    accepted: Vec<(Rc<RefCell<TestSocketState>>, SocketAddress)>,
    bound: Option<SocketAddress>,
    listened: bool,
    poll_timeouts: Vec<Option<Duration>>,
}

#[derive(Clone, Debug)]
pub(crate) struct TestSocketTransportHandle {
    state: Rc<RefCell<TestSocketState>>,
}

impl HostSocketTransport for TestSocketTransportHandle {
    fn open_socket(
        &self,
        _spec: SocketSpec,
        _options: mcr_net::SocketOptions,
    ) -> Result<Box<dyn mcr_net::HostSocketHandle>, mcr_net::HostIoError> {
        Ok(Box::new(TestSocketHandle {
            state: self.state.clone(),
        }))
    }
}

#[derive(Debug)]
pub(crate) struct TestSocketHandle {
    state: Rc<RefCell<TestSocketState>>,
}

impl mcr_net::HostSocketHandle for TestSocketHandle {
    fn bind(&mut self, address: SocketAddress) -> Result<SocketAddress, mcr_net::HostIoError> {
        self.state.borrow_mut().bound = Some(address);
        Ok(address)
    }

    fn listen(&mut self, _backlog: u32) -> Result<(), mcr_net::HostIoError> {
        self.state.borrow_mut().listened = true;
        Ok(())
    }

    fn accept(
        &mut self,
    ) -> Result<(Box<dyn mcr_net::HostSocketHandle>, SocketAddress), mcr_net::HostIoError> {
        let mut state = self.state.borrow_mut();
        if state.accepted.is_empty() {
            return Err(mcr_net::HostIoError::new(
                mcr_net::LinuxErrno::OperationWouldBlock,
                "no pending test socket",
            ));
        }
        let (accepted, peer) = state.accepted.remove(0);
        Ok((Box::new(TestSocketHandle { state: accepted }), peer))
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), mcr_net::HostIoError> {
        self.state.borrow_mut().nonblocking = nonblocking;
        Ok(())
    }

    fn connect(&mut self, address: SocketAddress) -> Result<(), mcr_net::HostIoError> {
        let mut state = self.state.borrow_mut();
        if state.connect_would_block_once {
            state.connect_would_block_once = false;
            state.connected = Some(address);
            return Err(mcr_net::HostIoError::new(
                mcr_net::LinuxErrno::OperationWouldBlock,
                "connect would block",
            ));
        }
        state.connected = Some(address);
        Ok(())
    }

    fn take_error(&mut self) -> Result<Option<mcr_net::HostIoError>, mcr_net::HostIoError> {
        Ok(None)
    }

    fn local_addr(&self) -> Result<SocketAddress, mcr_net::HostIoError> {
        let state = self.state.borrow();
        Ok(state.bound.unwrap_or_else(|| {
            SocketAddress::unspecified_for_domain(
                state
                    .connected
                    .map_or(mcr_net::SocketDomain::Inet, SocketAddress::domain),
            )
        }))
    }

    fn peer_addr(&self) -> Result<SocketAddress, mcr_net::HostIoError> {
        self.state.borrow().connected.ok_or_else(|| {
            mcr_net::HostIoError::new(mcr_net::LinuxErrno::NotConnected, "socket is not connected")
        })
    }

    fn send(&mut self, buffer: &[u8]) -> Result<usize, mcr_net::HostIoError> {
        let mut state = self.state.borrow_mut();
        state.sent.extend_from_slice(buffer);
        state.sent_calls.push(buffer.to_vec());
        Ok(buffer.len())
    }

    fn send_to(
        &mut self,
        buffer: &[u8],
        address: SocketAddress,
    ) -> Result<usize, mcr_net::HostIoError> {
        self.state.borrow_mut().connected = Some(address);
        self.send(buffer)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, mcr_net::HostIoError> {
        let mut state = self.state.borrow_mut();
        state.recv_calls += 1;
        let count = buffer.len().min(state.incoming.len());
        buffer[..count].copy_from_slice(&state.incoming[..count]);
        state.incoming.drain(..count);
        Ok(count)
    }

    fn recv_from(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddress), mcr_net::HostIoError> {
        let count = self.recv(buffer)?;
        let address = self
            .state
            .borrow()
            .connected
            .unwrap_or_else(|| SocketAddress::inet([127, 0, 0, 1], 53));
        Ok((count, address))
    }

    fn poll(
        &mut self,
        interest: SocketEvents,
        timeout: Option<Duration>,
    ) -> Result<SocketEvents, mcr_net::HostIoError> {
        self.state.borrow_mut().poll_timeouts.push(timeout);
        let state = self.state.borrow();
        Ok(SocketEvents {
            readable: interest.readable && !state.incoming.is_empty(),
            writable: interest.writable,
            priority: false,
            error: false,
            hang_up: false,
            invalid: false,
        })
    }

    fn shutdown(&mut self, _how: ShutdownHow) -> Result<(), mcr_net::HostIoError> {
        Ok(())
    }
}

pub(crate) fn runtime_socket_transport() -> TestSocketTransport {
    TestSocketTransport::default()
}

pub(crate) fn sample_vfs() -> VirtualFileSystem {
    let rootfs = Rootfs::new("/host/root");
    let mut tree = PathTree::new();
    tree.create_dir("/tmp").unwrap();
    tree.create_file_with_content("/tmp/file", b"hello", 0o644)
        .unwrap();
    tree.create_dir("/private").unwrap();
    tree.create_file_with_content("/private/secret", b"secret", 0o600)
        .unwrap();
    tree.create_symlink("/link", "/tmp/file").unwrap();
    VirtualFileSystem::from_parts(rootfs, tree, FdTable::with_stdio())
}

pub(crate) fn runtime_with_sample_vfs() -> RuntimeFileSystem<TestMemory> {
    RuntimeFileSystem::new(sample_vfs(), TestMemory::default())
}

pub(crate) fn runtime_from_program_and_tree(program: GuestProgram, tree: PathTree) -> Runtime {
    Runtime::with_vfs(
        program,
        VirtualFileSystem::from_parts(Rootfs::new("/host/root"), tree, FdTable::with_stdio()),
    )
    .unwrap()
}

pub(crate) fn runtime_with_socket(domain: u32) -> RuntimeFileSystem<TestMemory> {
    let mut runtime = runtime_with_sample_vfs();
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Socket,
            [
                u64::from(domain),
                u64::from(LINUX_SOCK_STREAM),
                u64::from(LINUX_IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        SyscallReturn::Success(3)
    );
    runtime
}

pub(crate) fn runtime_with_bound_ipv4_socket(port: u16) -> RuntimeFileSystem<TestMemory> {
    let mut runtime = runtime_with_socket(LINUX_AF_INET);
    runtime.memory_mut().write(0x2000, &ipv4_sockaddr(port));
    assert_eq!(
        dispatch_network(
            &mut runtime,
            Syscall::Bind,
            [3, 0x2000, SOCKADDR_IN_LEN as u64, 0, 0, 0],
        ),
        SyscallReturn::Success(0)
    );
    runtime
}

pub(crate) fn elf_with_bss_tail_garbage() -> Vec<u8> {
    const PH_OFFSET: usize = 64;
    const LOAD_OFFSET: usize = 0x100;
    let mut bytes = vec![0; LOAD_OFFSET + 16];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&(PH_OFFSET as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

    bytes[PH_OFFSET..PH_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[PH_OFFSET + 4..PH_OFFSET + 8].copy_from_slice(&4u32.to_le_bytes());
    bytes[PH_OFFSET + 8..PH_OFFSET + 16].copy_from_slice(&(LOAD_OFFSET as u64).to_le_bytes());
    bytes[PH_OFFSET + 16..PH_OFFSET + 24].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[PH_OFFSET + 24..PH_OFFSET + 32].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[PH_OFFSET + 32..PH_OFFSET + 40].copy_from_slice(&8u64.to_le_bytes());
    bytes[PH_OFFSET + 40..PH_OFFSET + 48].copy_from_slice(&16u64.to_le_bytes());
    bytes[PH_OFFSET + 48..PH_OFFSET + 56].copy_from_slice(&8u64.to_le_bytes());

    bytes[LOAD_OFFSET..LOAD_OFFSET + 8].copy_from_slice(b"LOADDATA");
    bytes[LOAD_OFFSET + 8..LOAD_OFFSET + 16].copy_from_slice(b"garbage!");
    bytes
}

pub(crate) fn elf_with_dynsym_memcpy() -> Vec<u8> {
    const PH_OFFSET: usize = 64;
    const LOAD_OFFSET: usize = 0x1000;
    const DYNSYM_OFFSET: usize = 0x2800;
    const STRTAB_OFFSET: usize = 0x2900;
    const SH_OFFSET: usize = 0x3000;
    const MEMCPY_VADDR: u64 = 0x2010;
    let mut bytes = vec![0; SH_OFFSET + 64 * 3];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    write_test_u16(&mut bytes, 16, 3);
    write_test_u16(&mut bytes, 18, 0x3e);
    write_test_u32(&mut bytes, 20, 1);
    write_test_u64(&mut bytes, 32, PH_OFFSET as u64);
    write_test_u64(&mut bytes, 40, SH_OFFSET as u64);
    write_test_u16(&mut bytes, 52, 64);
    write_test_u16(&mut bytes, 54, 56);
    write_test_u16(&mut bytes, 56, 1);
    write_test_u16(&mut bytes, 58, 64);
    write_test_u16(&mut bytes, 60, 3);

    write_test_u32(&mut bytes, PH_OFFSET, 1);
    write_test_u32(&mut bytes, PH_OFFSET + 4, PF_R | PF_X);
    write_test_u64(&mut bytes, PH_OFFSET + 8, LOAD_OFFSET as u64);
    write_test_u64(&mut bytes, PH_OFFSET + 16, 0x2000);
    write_test_u64(&mut bytes, PH_OFFSET + 24, 0x2000);
    write_test_u64(&mut bytes, PH_OFFSET + 32, GUEST_PAGE_SIZE);
    write_test_u64(&mut bytes, PH_OFFSET + 40, GUEST_PAGE_SIZE);
    write_test_u64(&mut bytes, PH_OFFSET + 48, GUEST_PAGE_SIZE);

    bytes[LOAD_OFFSET + 0x10..LOAD_OFFSET + 0x13].copy_from_slice(&[0x90, 0x90, 0xc3]);
    bytes[STRTAB_OFFSET..STRTAB_OFFSET + 8].copy_from_slice(b"\0memcpy\0");
    write_test_u32(&mut bytes, DYNSYM_OFFSET + 24, 1);
    bytes[DYNSYM_OFFSET + 28] = 0x12;
    write_test_u64(&mut bytes, DYNSYM_OFFSET + 32, MEMCPY_VADDR);
    write_test_u64(&mut bytes, DYNSYM_OFFSET + 40, 3);

    let dynsym = SH_OFFSET + 64;
    write_test_u32(&mut bytes, dynsym + 4, 11);
    write_test_u64(&mut bytes, dynsym + 24, DYNSYM_OFFSET as u64);
    write_test_u64(&mut bytes, dynsym + 32, 48);
    write_test_u32(&mut bytes, dynsym + 40, 2);
    write_test_u64(&mut bytes, dynsym + 56, 24);

    let strtab = SH_OFFSET + 64 * 2;
    write_test_u32(&mut bytes, strtab + 4, 3);
    write_test_u64(&mut bytes, strtab + 24, STRTAB_OFFSET as u64);
    write_test_u64(&mut bytes, strtab + 32, 8);
    bytes
}

pub(crate) fn write_test_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_test_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_test_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn ipv4_sockaddr(port: u16) -> Vec<u8> {
    ipv4_sockaddr_for([127, 0, 0, 1], port)
}

pub(crate) fn ipv4_sockaddr_for(address: [u8; 4], port: u16) -> Vec<u8> {
    let mut bytes = vec![0; SOCKADDR_IN_LEN];
    bytes[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4..8].copy_from_slice(&address);
    bytes
}

pub(crate) fn ipv6_sockaddr(address: [u8; 16], port: u16, flowinfo: u32, scope_id: u32) -> Vec<u8> {
    let mut bytes = vec![0; SOCKADDR_IN6_LEN];
    bytes[0..2].copy_from_slice(&(LINUX_AF_INET6 as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4..8].copy_from_slice(&flowinfo.to_le_bytes());
    bytes[8..24].copy_from_slice(&address);
    bytes[24..28].copy_from_slice(&scope_id.to_le_bytes());
    bytes
}

pub(crate) fn unix_sockaddr(path: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 2 + path.len() + 1];
    bytes[0..2].copy_from_slice(&(LINUX_AF_UNIX as u16).to_le_bytes());
    bytes[2..2 + path.len()].copy_from_slice(path);
    bytes
}

pub(crate) fn dispatch(
    runtime: &mut RuntimeFileSystem<TestMemory>,
    syscall: Syscall,
    args: [u64; 6],
) -> SyscallReturn {
    let registers = SyscallRegisters {
        rax: syscall.number().raw(),
        rdi: args[0],
        rsi: args[1],
        rdx: args[2],
        r10: args[3],
        r8: args[4],
        r9: args[5],
        rip: 0,
    };
    let request = mcr_sys::SyscallRequest::from_guest_context(GuestContext::new(1, 1, registers));
    runtime.dispatch_file(&request).result
}

pub(crate) fn dispatch_network(
    runtime: &mut RuntimeFileSystem<TestMemory>,
    syscall: Syscall,
    args: [u64; 6],
) -> SyscallReturn {
    let registers = SyscallRegisters {
        rax: syscall.number().raw(),
        rdi: args[0],
        rsi: args[1],
        rdx: args[2],
        r10: args[3],
        r8: args[4],
        r9: args[5],
        rip: 0,
    };
    let request = mcr_sys::SyscallRequest::from_guest_context(GuestContext::new(1, 1, registers));
    runtime.dispatch_network(&request).result
}

pub(crate) fn guest_path(path: &str) -> mcr_vfs::GuestPath {
    Rootfs::new("/host")
        .resolve_path(path, &PathTree::new())
        .unwrap()
        .guest_path()
        .clone()
}

pub(crate) fn u64_at(memory: &TestMemory, addr: u64) -> u64 {
    u64::from_le_bytes(memory.read(addr, 8).try_into().expect("slice len"))
}

pub(crate) fn u32_at(memory: &TestMemory, addr: u64) -> u32 {
    u32::from_le_bytes(memory.read(addr, 4).try_into().expect("slice len"))
}

pub(crate) fn i32_at(memory: &TestMemory, addr: u64) -> i32 {
    i32::from_le_bytes(memory.read(addr, 4).try_into().expect("slice len"))
}

pub(crate) fn i32_from_memory(memory: &GuestMemory, addr: u64) -> i32 {
    let mut bytes = [0; 4];
    memory.read(addr, &mut bytes).unwrap();
    i32::from_le_bytes(bytes)
}

pub(crate) fn u64_from_guest(memory: &GuestMemory, addr: u64) -> u64 {
    let mut bytes = [0; 8];
    memory.read(addr, &mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}

pub(crate) fn i64_from_guest(memory: &GuestMemory, addr: u64) -> i64 {
    let mut bytes = [0; 8];
    memory.read(addr, &mut bytes).unwrap();
    i64::from_le_bytes(bytes)
}

pub(crate) fn u32_from_guest(memory: &GuestMemory, addr: u64) -> u32 {
    let mut bytes = [0; 4];
    memory.read(addr, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

pub(crate) fn guest_bytes(memory: &GuestMemory, addr: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    memory.read(addr, &mut bytes).unwrap();
    bytes
}

pub(crate) fn u16_from_guest(memory: &GuestMemory, addr: u64) -> u16 {
    let mut bytes = [0; 2];
    memory.read(addr, &mut bytes).unwrap();
    u16::from_le_bytes(bytes)
}

pub(crate) fn write_stack_t(memory: &mut GuestMemory, addr: u64, sp: u64, flags: u32, size: u64) {
    memory.write(addr, &sp.to_le_bytes()).unwrap();
    memory
        .write(addr + LINUX_STACK_T_FLAGS_OFFSET, &flags.to_le_bytes())
        .unwrap();
    memory
        .write(addr + LINUX_STACK_T_SIZE_OFFSET, &size.to_le_bytes())
        .unwrap();
}

pub(crate) fn write_pollfd(memory: &mut GuestMemory, addr: u64, fd: i32, events: i16) {
    memory.write(addr, &fd.to_le_bytes()).unwrap();
    memory.write(addr + 4, &events.to_le_bytes()).unwrap();
    memory.write(addr + 6, &0i16.to_le_bytes()).unwrap();
}

pub(crate) fn pollfd_revents(memory: &GuestMemory, addr: u64) -> i16 {
    let mut bytes = [0; 2];
    memory.read(addr + 6, &mut bytes).unwrap();
    i16::from_le_bytes(bytes)
}

pub(crate) fn write_select_fdset(memory: &mut GuestMemory, addr: u64, nfds: usize, fds: &[Fd]) {
    write_select_fd_set(memory, addr, nfds, fds).unwrap();
}

pub(crate) fn select_fdset_contains(memory: &GuestMemory, addr: u64, fd: usize) -> bool {
    select_fd_set_contains(memory, addr, fd).unwrap()
}

pub(crate) fn write_timeval(memory: &mut GuestMemory, addr: u64, sec: i64, usec: i64) {
    memory.write(addr, &sec.to_le_bytes()).unwrap();
    memory.write(addr + 8, &usec.to_le_bytes()).unwrap();
}

pub(crate) fn write_clone3_args(
    memory: &mut GuestMemory,
    addr: u64,
    flags: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
) {
    for (index, value) in [flags, 0, 0, 0, exit_signal, stack, stack_size, 0, 0, 0, 0]
        .into_iter()
        .enumerate()
    {
        memory
            .write(addr + (index * 8) as u64, &value.to_le_bytes())
            .unwrap();
    }
}

pub(crate) struct TestUnsafeShareUntilExec;

impl TestUnsafeShareUntilExec {
    pub(crate) fn enable() -> Self {
        UNSAFE_SHARE_UNTIL_EXEC_TEST_OVERRIDE.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for TestUnsafeShareUntilExec {
    fn drop(&mut self) {
        UNSAFE_SHARE_UNTIL_EXEC_TEST_OVERRIDE.store(false, Ordering::SeqCst);
    }
}

pub(crate) fn write_timespec(memory: &mut GuestMemory, addr: u64, sec: i64, nsec: i64) {
    memory.write(addr, &sec.to_le_bytes()).unwrap();
    memory.write(addr + 8, &nsec.to_le_bytes()).unwrap();
}

pub(crate) fn timespec_from_memory(memory: &GuestMemory, addr: u64) -> LinuxTimespec {
    let mut sec = [0; 8];
    let mut nsec = [0; 8];
    memory.read(addr, &mut sec).unwrap();
    memory.read(addr + 8, &mut nsec).unwrap();
    LinuxTimespec {
        tv_sec: i64::from_le_bytes(sec),
        tv_nsec: i64::from_le_bytes(nsec),
    }
}

pub(crate) fn write_epoll_event_for_test(
    memory: &mut GuestMemory,
    addr: u64,
    events: u32,
    data: u64,
) {
    memory.write(addr, &events.to_le_bytes()).unwrap();
    memory.write(addr + 4, &data.to_le_bytes()).unwrap();
}

pub(crate) fn epoll_event_from_memory(memory: &GuestMemory, addr: u64) -> (u32, u64) {
    let mut events = [0; 4];
    let mut data = [0; 8];
    memory.read(addr, &mut events).unwrap();
    memory.read(addr + 4, &mut data).unwrap();
    (u32::from_le_bytes(events), u64::from_le_bytes(data))
}

pub(crate) fn u16_at(memory: &TestMemory, addr: u64) -> u16 {
    u16::from_le_bytes(memory.read(addr, 2).try_into().expect("slice len"))
}

pub(crate) fn syscall_enter_event(syscall: Syscall, args: [u64; 6]) -> SyscallTraceEvent {
    SyscallTraceEvent::Enter(SyscallEnterEvent {
        context: TraceContext {
            pid: INITIAL_GUEST_PID,
            tid: INITIAL_GUEST_TID,
            rip: 0x401234,
        },
        syscall,
        args: SyscallArgs::new(args),
        decoded: Vec::new(),
    })
}

pub(crate) fn context(syscall: Syscall, args: [u64; 6]) -> GuestContext {
    context_for(INITIAL_GUEST_PID, INITIAL_GUEST_TID, syscall, args)
}

pub(crate) fn context_for(pid: u32, tid: u32, syscall: Syscall, args: [u64; 6]) -> GuestContext {
    GuestContext::new(
        pid,
        tid,
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
    )
}

pub(crate) fn set_initial_syscall_regs(
    runtime: &mut Runtime,
    rip: u64,
    syscall: Syscall,
    args: [u64; 6],
) {
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
            rip,
            rsp,
            syscall.number().raw(),
            args,
        ));
}

pub(crate) fn unique_test_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("mcr-{name}-{}-{nanos}", std::process::id()))
}

pub(crate) fn test_program(path: &str, entrypoint: u64) -> GuestProgram {
    GuestProgram::new(GuestExecutable::new(
        path.as_bytes().to_vec(),
        test_program_bytes(entrypoint),
    ))
}

pub(crate) fn test_program_bytes(entrypoint: u64) -> Vec<u8> {
    test_program_bytes_with_marker(entrypoint, 0x90)
}

pub(crate) fn test_program_with_entry_code(
    path: &str,
    entrypoint: u64,
    code: &[u8],
) -> GuestProgram {
    GuestProgram::new(GuestExecutable::new(
        path.as_bytes().to_vec(),
        test_program_bytes_with_entry_code(entrypoint, code),
    ))
}

pub(crate) fn test_program_bytes_with_entry_code(entrypoint: u64, code: &[u8]) -> Vec<u8> {
    Elf64Builder::new()
        .entrypoint(entrypoint)
        .program_header(Elf64ProgramHeader::load(
            PF_R | PF_X,
            0x1000,
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
        .program_header(Elf64ProgramHeader::load(
            PF_R,
            0,
            (entrypoint & !0xfff) + 0x2000,
            0x100,
            0x100,
        ))
        .data_at(0x1000 + (entrypoint & 0xfff), code.to_vec())
        .data_at(0x2000, vec![0; 0x08])
        .build()
}

pub(crate) fn test_program_bytes_with_marker(entrypoint: u64, marker: u8) -> Vec<u8> {
    Elf64Builder::new()
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
        .data_at(0x200, vec![marker; 0x20])
        .data_at(0x2000, vec![0; 0x08])
        .build()
}

pub(crate) fn dynamic_program_bytes(interpreter: &str) -> Vec<u8> {
    let mut interpreter_path = interpreter.as_bytes().to_vec();
    interpreter_path.push(0);
    Elf64Builder::new()
        .object_type(mcr_testkit::elf::ET_DYN)
        .entrypoint(0x1010)
        .program_header(Elf64ProgramHeader::new(
            mcr_testkit::elf::PT_INTERP,
            PF_R,
            0x300,
            0,
            interpreter_path.len() as u64,
            interpreter_path.len() as u64,
            1,
        ))
        .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x2000))
        .data_at(0x300, interpreter_path)
        .data_at(0x400, vec![0x90; 4])
        .build()
}

pub(crate) fn interpreter_bytes() -> Vec<u8> {
    Elf64Builder::new()
        .object_type(mcr_testkit::elf::ET_DYN)
        .entrypoint(0x400)
        .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x1000))
        .data_at(0x400, vec![0x90; 4])
        .build()
}

pub(crate) fn test_program_with_args<const A: usize, const E: usize>(
    path: &str,
    entrypoint: u64,
    argv: [&str; A],
    envp: [&str; E],
) -> GuestProgram {
    test_program(path, entrypoint)
        .with_args(argv.map(|value| value.as_bytes().to_vec()))
        .with_env(envp.map(|value| value.as_bytes().to_vec()))
}
