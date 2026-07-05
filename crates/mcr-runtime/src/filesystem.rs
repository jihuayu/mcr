#[allow(unused_imports)]
use super::*;

#[derive(Debug)]
pub struct RuntimeFileSystem<M> {
    vfs: VirtualFileSystem,
    memory: M,
    sockets: GuestSocketTable,
}

impl<M> RuntimeFileSystem<M> {
    pub fn new(vfs: VirtualFileSystem, memory: M) -> Self {
        Self {
            vfs,
            memory,
            sockets: GuestSocketTable::new(),
        }
    }

    pub fn with_socket_transport(
        vfs: VirtualFileSystem,
        memory: M,
        transport: impl HostSocketTransport + 'static,
    ) -> Self {
        Self {
            vfs,
            memory,
            sockets: GuestSocketTable::with_transport(transport),
        }
    }

    pub fn vfs(&self) -> &VirtualFileSystem {
        &self.vfs
    }

    pub fn vfs_mut(&mut self) -> &mut VirtualFileSystem {
        &mut self.vfs
    }

    pub fn memory(&self) -> &M {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    pub fn sockets(&self) -> &GuestSocketTable {
        &self.sockets
    }

    pub fn sockets_mut(&mut self) -> &mut GuestSocketTable {
        &mut self.sockets
    }

    pub fn into_parts(self) -> (VirtualFileSystem, M) {
        (self.vfs, self.memory)
    }
}

impl<M> FileSyscalls for RuntimeFileSystem<M>
where
    M: RuntimeMemoryAccess,
{
    fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let result = match request.syscall {
            mcr_sys::Syscall::Open => self.sys_open(request),
            mcr_sys::Syscall::Openat => self.sys_openat(request),
            mcr_sys::Syscall::Read => self.sys_read(request),
            mcr_sys::Syscall::Write => self.sys_write(request),
            mcr_sys::Syscall::Pread64 => self.sys_pread64(request),
            mcr_sys::Syscall::Readv => self.sys_readv(request),
            mcr_sys::Syscall::Writev => self.sys_writev(request),
            mcr_sys::Syscall::Close => self.sys_close(request),
            mcr_sys::Syscall::Lseek => self.sys_lseek(request),
            mcr_sys::Syscall::Stat => self.sys_stat(request),
            mcr_sys::Syscall::Fstat => self.sys_fstat(request),
            mcr_sys::Syscall::Lstat => self.sys_lstat(request),
            mcr_sys::Syscall::Statfs => self.sys_statfs(request),
            mcr_sys::Syscall::Fstatfs => self.sys_fstatfs(request),
            mcr_sys::Syscall::Fsync | mcr_sys::Syscall::Fdatasync => self.sys_sync_fd(request),
            mcr_sys::Syscall::Newfstatat => self.sys_newfstatat(request),
            mcr_sys::Syscall::Statx => self.sys_statx(request),
            mcr_sys::Syscall::Access => self.sys_access(request),
            mcr_sys::Syscall::Faccessat2 => self.sys_faccessat2(request),
            mcr_sys::Syscall::Openat2 => self.sys_openat2(request),
            mcr_sys::Syscall::Readlink => self.sys_readlink(request),
            mcr_sys::Syscall::Readlinkat => self.sys_readlinkat(request),
            mcr_sys::Syscall::Getdents64 => self.sys_getdents64(request),
            mcr_sys::Syscall::Pipe => self.sys_pipe(request),
            mcr_sys::Syscall::Pipe2 => self.sys_pipe2(request),
            mcr_sys::Syscall::CloseRange => self.sys_close_range(request),
            mcr_sys::Syscall::Dup => self.sys_dup(request),
            mcr_sys::Syscall::Dup2 => self.sys_dup2(request),
            mcr_sys::Syscall::Dup3 => self.sys_dup3(request),
            mcr_sys::Syscall::Fcntl => self.sys_fcntl(request),
            mcr_sys::Syscall::Ioctl => self.sys_ioctl(request),
            mcr_sys::Syscall::Mkdir => self.sys_mkdir(request),
            mcr_sys::Syscall::Mkdirat => self.sys_mkdirat(request),
            mcr_sys::Syscall::Rmdir => self.sys_rmdir(request),
            mcr_sys::Syscall::Unlink => self.sys_unlink(request),
            mcr_sys::Syscall::Unlinkat => self.sys_unlinkat(request),
            mcr_sys::Syscall::Rename => self.sys_rename(request),
            mcr_sys::Syscall::Renameat2 => self.sys_renameat2(request),
            mcr_sys::Syscall::Symlink => self.sys_symlink(request),
            mcr_sys::Syscall::Symlinkat => self.sys_symlinkat(request),
            mcr_sys::Syscall::Link => self.sys_link(request),
            mcr_sys::Syscall::Linkat => self.sys_linkat(request),
            mcr_sys::Syscall::Ftruncate => self.sys_ftruncate(request),
            mcr_sys::Syscall::Chmod => self.sys_chmod(request),
            mcr_sys::Syscall::Chown => self.sys_chown(request),
            mcr_sys::Syscall::Utimensat => self.sys_utimensat(request),
            mcr_sys::Syscall::Getcwd => self.sys_getcwd(request),
            mcr_sys::Syscall::Chdir => self.sys_chdir(request),
            mcr_sys::Syscall::Umask => self.sys_umask(request),
            _ => return SyscallOutcome::unsupported(),
        };
        outcome(result)
    }
}

impl<M> FileSyscalls for &mut RuntimeFileSystem<M>
where
    M: RuntimeMemoryAccess,
{
    fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        RuntimeFileSystem::dispatch_file(self, request)
    }
}

impl<M> NetworkSyscalls for RuntimeFileSystem<M>
where
    M: RuntimeMemoryAccess,
{
    fn dispatch_network(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let result = match request.syscall {
            mcr_sys::Syscall::Socket => self.sys_socket(request),
            mcr_sys::Syscall::Bind => self.sys_bind(request),
            mcr_sys::Syscall::Connect => self.sys_connect(request),
            mcr_sys::Syscall::Listen => self.sys_listen(request),
            mcr_sys::Syscall::Shutdown => self.sys_shutdown(request),
            mcr_sys::Syscall::Sendto => self.sys_sendto(request),
            mcr_sys::Syscall::Recvfrom => self.sys_recvfrom(request),
            mcr_sys::Syscall::Sendmsg => self.sys_sendmsg(request),
            mcr_sys::Syscall::Recvmsg => self.sys_recvmsg(request),
            mcr_sys::Syscall::Getsockopt => self.sys_getsockopt(request),
            mcr_sys::Syscall::Setsockopt => self.sys_setsockopt(request),
            mcr_sys::Syscall::Accept | mcr_sys::Syscall::Accept4 => self.sys_accept(request),
            mcr_sys::Syscall::Getsockname | mcr_sys::Syscall::Getpeername => {
                self.sys_getsockaddr(request)
            }
            _ => return SyscallOutcome::unsupported(),
        };
        outcome(result)
    }
}

impl<M> NetworkSyscalls for &mut RuntimeFileSystem<M>
where
    M: RuntimeMemoryAccess,
{
    fn dispatch_network(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        RuntimeFileSystem::dispatch_network(self, request)
    }
}

impl<M> RuntimeFileSystem<M> {
    pub fn load_guest_program(
        &mut self,
        filename: impl Into<Vec<u8>>,
        argv: impl IntoIterator<Item = Vec<u8>>,
        envp: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<GuestProgram, LinuxErrno> {
        let filename = filename.into();
        let executable = self.load_guest_executable(&filename)?;
        let load_plan =
            mcr_elf::parse_load_plan(executable.bytes()).map_err(|_| LinuxErrno::ENOEXEC)?;
        let mut program = GuestProgram::new(executable).with_args(argv).with_env(envp);
        if let Some(interpreter_path) = load_plan.interpreter() {
            let interpreter = self.load_guest_executable(interpreter_path.as_bytes())?;
            mcr_elf::parse_load_plan(interpreter.bytes()).map_err(|_| LinuxErrno::ENOEXEC)?;
            program = program.with_interpreter(interpreter);
        }
        Ok(program)
    }

    pub(crate) fn load_guest_executable(
        &mut self,
        path: &[u8],
    ) -> Result<GuestExecutable, LinuxErrno> {
        let path = guest_bytes_to_path(path)?;
        let fd = self
            .vfs
            .openat(
                mcr_vfs::AT_FDCWD,
                &path,
                OpenFlags::new(mcr_vfs::O_RDONLY),
                0,
            )
            .map_err(vfs_errno)?;
        let mut bytes = Vec::new();
        let read_result = read_vfs_file_to_end(&mut self.vfs, fd, &mut bytes);
        let close_result = self.vfs.close(fd).map_err(vfs_errno);
        read_result?;
        close_result?;
        Ok(GuestExecutable::new(path.into_bytes(), bytes))
    }
}

impl<M> RuntimeFileSystem<M>
where
    M: RuntimeMemoryAccess,
{
    pub(crate) fn read_guest_vector(&self, vector_addr: u64) -> Result<Vec<Vec<u8>>, LinuxErrno> {
        read_guest_vector(&self.memory, vector_addr)
    }

    fn sys_socket(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SocketSyscallArgs::new(
            arg_u32(request, 0),
            arg_u32(request, 1),
            arg_u32(request, 2),
        );
        let spec =
            SocketSpec::from_linux(args.domain, args.kind, args.protocol).map_err(net_errno)?;
        let socket_id = self
            .sockets
            .create_socket_from_spec(spec)
            .map_err(net_errno)?;
        let mut flags = mcr_vfs::O_RDWR;
        if spec.flags.cloexec {
            flags |= mcr_vfs::O_CLOEXEC;
        }
        if spec.flags.nonblocking {
            flags |= mcr_vfs::O_NONBLOCK;
        }
        let fd = self
            .vfs
            .insert_socket(socket_id.get(), OpenFlags::new(flags))
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    fn sys_bind(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args =
            SockaddrSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg_u32(request, 2));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let address = read_socket_address(&self.memory, args.sockaddr, args.addrlen)?;
        self.sockets.bind(socket_id, address).map_err(net_errno)?;
        Ok(0)
    }

    fn sys_connect(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args =
            SockaddrSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg_u32(request, 2));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let address = read_socket_address(&self.memory, args.sockaddr, args.addrlen)?;
        self.sockets
            .connect(socket_id, address)
            .map_err(net_errno)?;
        Ok(0)
    }

    fn sys_listen(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let backlog = arg_u32(request, 1);
        let socket_id = self.socket_id_for_fd(fd)?;
        self.sockets.listen(socket_id, backlog).map_err(net_errno)?;
        Ok(0)
    }

    fn sys_shutdown(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = ShutdownSyscallArgs::new(arg_i32(request, 0), arg_u32(request, 1));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let how = ShutdownHow::from_linux(args.how).map_err(net_errno)?;
        self.sockets.shutdown(socket_id, how).map_err(net_errno)?;
        Ok(0)
    }

    fn sys_sendto(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SendRecvFromSyscallArgs::new(
            arg_i32(request, 0),
            arg(request, 1),
            arg(request, 2),
            arg_u32(request, 3),
            arg(request, 4),
            arg(request, 5),
        );
        let socket_id = self.socket_id_for_fd(args.fd)?;
        validate_send_message_flags(args.flags, SocketOperation::Send)?;
        let len = usize::try_from(args.len).map_err(|_| LinuxErrno::EINVAL)?;
        let count = if let Some(buffer) = self
            .memory
            .borrowed_bytes(args.buf, len)
            .map_err(memory_errno)?
        {
            if args.sockaddr != 0 || args.addrlen != 0 {
                let addrlen = u32::try_from(args.addrlen).map_err(|_| LinuxErrno::EINVAL)?;
                let address = read_socket_address(&self.memory, args.sockaddr, addrlen)?;
                self.sockets.send_to(socket_id, buffer, address)
            } else {
                self.sockets.send_connected(socket_id, buffer)
            }
        } else {
            let mut buffer = vec![0; len];
            self.memory
                .read_bytes(args.buf, &mut buffer)
                .map_err(memory_errno)?;
            if args.sockaddr != 0 || args.addrlen != 0 {
                let addrlen = u32::try_from(args.addrlen).map_err(|_| LinuxErrno::EINVAL)?;
                let address = read_socket_address(&self.memory, args.sockaddr, addrlen)?;
                self.sockets.send_to(socket_id, &buffer, address)
            } else {
                self.sockets.send_connected(socket_id, &buffer)
            }
        }
        .map_err(net_errno)?;
        Ok(count as u64)
    }

    fn sys_recvfrom(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SendRecvFromSyscallArgs::new(
            arg_i32(request, 0),
            arg(request, 1),
            arg(request, 2),
            arg_u32(request, 3),
            arg(request, 4),
            arg(request, 5),
        );
        let socket_id = self.socket_id_for_fd(args.fd)?;
        validate_recv_message_flags(args.flags, SocketOperation::Recv)?;
        let len = usize::try_from(args.len).map_err(|_| LinuxErrno::EINVAL)?;
        if args.sockaddr == 0
            && args.addrlen == 0
            && let Ok(Some(buffer)) = self.memory.borrowed_bytes_mut(args.buf, len)
        {
            let count = self
                .sockets
                .recv_connected(socket_id, buffer)
                .map_err(net_errno)?;
            return Ok(count as u64);
        }
        let mut buffer = vec![0; len];
        let count = if args.sockaddr != 0 || args.addrlen != 0 {
            let (count, address) = self
                .sockets
                .recv_from(socket_id, &mut buffer)
                .map_err(net_errno)?;
            write_optional_socket_address(&mut self.memory, args.sockaddr, args.addrlen, address)?;
            count
        } else {
            self.sockets
                .recv_connected(socket_id, &mut buffer)
                .map_err(net_errno)?
        };
        self.memory
            .write_bytes(args.buf, &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_sendmsg(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args =
            SendRecvMsgSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg_u32(request, 2));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        validate_send_message_flags(args.flags, SocketOperation::SendMsg)?;
        let message = read_msghdr(&self.memory, args.msg)?;
        if message.msg_control != 0 || message.msg_controllen != 0 {
            return Err(net_errno(GuestSocketTable::unsupported_socket_io(
                SocketOperation::SendMsg,
            )));
        }
        let address = if message.msg_name != 0 || message.msg_namelen != 0 {
            Some(read_socket_address(
                &self.memory,
                message.msg_name,
                message.msg_namelen,
            )?)
        } else {
            None
        };
        let iovecs = self.read_iovecs(
            message.msg_iov,
            usize::try_from(message.msg_iovlen).map_err(|_| LinuxErrno::EINVAL)?,
        )?;
        let buffers = self.read_iovec_buffers(&iovecs)?;
        let slices = io_slices(&buffers);
        let count = if let Some(address) = address {
            self.sockets
                .send_to_vectored(socket_id, &slices, address)
                .map_err(net_errno)?
        } else {
            self.sockets
                .send_connected_vectored(socket_id, &slices)
                .map_err(net_errno)?
        };
        Ok(count as u64)
    }

    fn sys_recvmsg(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args =
            SendRecvMsgSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg_u32(request, 2));
        let socket_id = self.socket_id_for_fd(args.fd)?;
        validate_recv_message_flags(args.flags, SocketOperation::RecvMsg)?;
        let message = read_msghdr(&self.memory, args.msg)?;
        if message.msg_control != 0 || message.msg_controllen != 0 {
            return Err(net_errno(GuestSocketTable::unsupported_socket_io(
                SocketOperation::RecvMsg,
            )));
        }
        let iovecs = self.read_iovecs(
            message.msg_iov,
            usize::try_from(message.msg_iovlen).map_err(|_| LinuxErrno::EINVAL)?,
        )?;

        let total = if (message.msg_name != 0 || message.msg_namelen != 0)
            && self.socket_is_udp_datagram(socket_id)?
        {
            let mut buffers = iovec_output_buffers(&iovecs)?;
            let (count, address) = {
                let mut slices = io_slices_mut(&mut buffers);
                self.sockets
                    .recv_from_vectored(socket_id, &mut slices)
                    .map_err(net_errno)?
            };
            write_socket_address_to_msghdr_name(
                &mut self.memory,
                args.msg,
                message.msg_name,
                message.msg_namelen,
                address,
            )?;
            self.write_iovec_buffers(&iovecs, &buffers, count)?;
            count as u64
        } else {
            if message.msg_name != 0 {
                write_msghdr_namelen(&mut self.memory, args.msg, 0)?;
            }
            self.recv_connected_into_iovecs(socket_id, &iovecs)?
        };
        write_msghdr_flags(&mut self.memory, args.msg, 0)?;
        Ok(total)
    }

    fn sys_setsockopt(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SockoptSyscallArgs::new(
            arg_i32(request, 0),
            arg_u32(request, 1),
            arg_u32(request, 2),
            arg(request, 3),
            arg(request, 4),
        );
        if args.optlen != 4 {
            return Err(LinuxErrno::EINVAL);
        }
        let mut value = [0; 4];
        self.memory
            .read_bytes(args.optval, &mut value)
            .map_err(memory_errno)?;
        let option = SocketOptionName::from_linux(args.level, args.optname).map_err(net_errno)?;
        let socket_id = self.socket_id_for_fd(args.fd)?;
        self.sockets
            .set_option(socket_id, option, u32::from_le_bytes(value))
            .map_err(net_errno)?;
        Ok(0)
    }

    fn sys_getsockopt(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SockoptSyscallArgs::new(
            arg_i32(request, 0),
            arg_u32(request, 1),
            arg_u32(request, 2),
            arg(request, 3),
            arg(request, 4),
        );
        let len = read_guest_u32(&self.memory, args.optlen)?;
        if len < 4 {
            return Err(LinuxErrno::EINVAL);
        }
        let option = SocketOptionName::from_linux(args.level, args.optname).map_err(net_errno)?;
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let value = self
            .sockets
            .get_option(socket_id, option)
            .map_err(net_errno)?;
        self.memory
            .write_bytes(args.optval, &value.to_le_bytes())
            .map_err(memory_errno)?;
        self.memory
            .write_bytes(args.optlen, &4u32.to_le_bytes())
            .map_err(memory_errno)?;
        Ok(0)
    }

    fn sys_accept(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = match request.syscall {
            mcr_sys::Syscall::Accept => {
                Accept4SyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg(request, 2), 0)
            }
            mcr_sys::Syscall::Accept4 => Accept4SyscallArgs::new(
                arg_i32(request, 0),
                arg(request, 1),
                arg(request, 2),
                arg_u32(request, 3),
            ),
            _ => unreachable!(),
        };
        if args.flags & !(mcr_sys::LINUX_SOCK_CLOEXEC | mcr_sys::LINUX_SOCK_NONBLOCK) != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let (accepted, peer) = self.sockets.accept(socket_id).map_err(net_errno)?;
        write_optional_socket_address(&mut self.memory, args.sockaddr, args.addrlen, peer)?;
        let mut flags = mcr_vfs::O_RDWR;
        if args.flags & mcr_sys::LINUX_SOCK_CLOEXEC != 0 {
            flags |= mcr_vfs::O_CLOEXEC;
        }
        if args.flags & mcr_sys::LINUX_SOCK_NONBLOCK != 0 {
            flags |= mcr_vfs::O_NONBLOCK;
        }
        let fd = self
            .vfs
            .insert_socket(accepted.get(), OpenFlags::new(flags))
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    fn sys_getsockaddr(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = SockaddrSyscallArgs::new(arg_i32(request, 0), arg(request, 1), 0);
        let socket_id = self.socket_id_for_fd(args.fd)?;
        let address = match request.syscall {
            mcr_sys::Syscall::Getsockname => {
                self.sockets.local_address(socket_id).map_err(net_errno)?
            }
            mcr_sys::Syscall::Getpeername => {
                self.sockets.peer_address(socket_id).map_err(net_errno)?
            }
            _ => unreachable!(),
        }
        .ok_or(LinuxErrno::ENOTCONN)?;
        write_socket_address(&mut self.memory, args.sockaddr, arg(request, 2), address)?;
        Ok(0)
    }

    pub(crate) fn socket_id_for_fd(&self, fd: Fd) -> Result<SocketId, LinuxErrno> {
        let raw = self.vfs.socket_id_for_fd(fd).map_err(vfs_errno)?;
        SocketId::new(raw).ok_or(LinuxErrno::EBADF)
    }

    fn socket_id_for_fd_or_none(&self, fd: Fd) -> Result<Option<SocketId>, LinuxErrno> {
        match self.vfs.socket_id_for_fd(fd) {
            Ok(raw) => Ok(SocketId::new(raw)),
            Err(VfsError::NotSocket) => Ok(None),
            Err(error) => Err(vfs_errno(error)),
        }
    }
}

fn iovecs_are_borrowable<M>(memory: &M, iovecs: &[LinuxIovec]) -> bool
where
    M: RuntimeMemoryAccess,
{
    iovecs.iter().all(|iovec| {
        let Ok(len) = usize::try_from(iovec.iov_len) else {
            return false;
        };
        matches!(memory.borrowed_bytes(iovec.iov_base, len), Ok(Some(_)))
    })
}

fn iovecs_are_borrowable_mut<M>(memory: &mut M, iovecs: &[LinuxIovec]) -> bool
where
    M: RuntimeMemoryAccess,
{
    for iovec in iovecs {
        let Ok(len) = usize::try_from(iovec.iov_len) else {
            return false;
        };
        if !matches!(memory.borrowed_bytes_mut(iovec.iov_base, len), Ok(Some(_))) {
            return false;
        }
    }
    true
}

fn borrowed_iovec_slices<'a, M>(
    memory: &'a M,
    iovecs: &[LinuxIovec],
) -> Result<Option<Vec<IoSlice<'a>>>, LinuxErrno>
where
    M: RuntimeMemoryAccess,
{
    let mut slices = Vec::with_capacity(iovecs.len());
    for iovec in iovecs {
        let len = usize::try_from(iovec.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
        let Some(bytes) = memory
            .borrowed_bytes(iovec.iov_base, len)
            .map_err(memory_errno)?
        else {
            return Ok(None);
        };
        slices.push(IoSlice::new(bytes));
    }
    Ok(Some(slices))
}

impl<M> RuntimeFileSystem<M>
where
    M: RuntimeMemoryAccess,
{
    fn sys_openat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let dirfd = arg_i32(request, 0);
        let path = self.read_path(arg(request, 1))?;
        let flags = arg_u32(request, 2);
        let mode = arg_u32(request, 3);
        let fd = self
            .vfs
            .openat(dirfd, &path, OpenFlags::new(flags), mode)
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    fn sys_openat2(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let how = read_open_how(self.memory(), arg(request, 2), usize_arg(request, 3)?)?;
        if how.resolve != 0 {
            return Err(LinuxErrno::ENOSYS);
        }
        let dirfd = arg_i32(request, 0);
        let path = self.read_path(arg(request, 1))?;
        let flags = u32::try_from(how.flags).map_err(|_| LinuxErrno::EINVAL)?;
        let mode = u32::try_from(how.mode).map_err(|_| LinuxErrno::EINVAL)?;
        let fd = self
            .vfs
            .openat(dirfd, &path, OpenFlags::new(flags), mode)
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    fn sys_open(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        let flags = arg_u32(request, 1);
        let mode = arg_u32(request, 2);
        let fd = self
            .vfs
            .openat(mcr_vfs::AT_FDCWD, &path, OpenFlags::new(flags), mode)
            .map_err(vfs_errno)?;
        Ok(fd as u64)
    }

    fn sys_read(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let addr = arg(request, 1);
        let len = usize_arg(request, 2)?;
        let socket_id = self.socket_id_for_fd_or_none(fd)?;
        if let Ok(Some(buffer)) = self.memory.borrowed_bytes_mut(addr, len) {
            let count = if let Some(socket_id) = socket_id {
                self.sockets
                    .recv_connected(socket_id, buffer)
                    .map_err(net_errno)?
            } else {
                self.vfs.read(fd, buffer).map_err(vfs_errno)?
            };
            return Ok(count as u64);
        }
        let mut buffer = vec![0; len];
        let count = if let Some(socket_id) = socket_id {
            self.sockets
                .recv_connected(socket_id, &mut buffer)
                .map_err(net_errno)?
        } else {
            self.vfs.read(fd, &mut buffer).map_err(vfs_errno)?
        };
        self.memory
            .write_bytes(addr, &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_write(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let addr = arg(request, 1);
        let len = usize_arg(request, 2)?;
        if let Some(buffer) = self
            .memory
            .borrowed_bytes(addr, len)
            .map_err(memory_errno)?
        {
            let socket_id = match self.vfs.socket_id_for_fd(fd) {
                Ok(raw) => SocketId::new(raw),
                Err(VfsError::NotSocket) => None,
                Err(error) => return Err(vfs_errno(error)),
            };
            let count = if let Some(socket_id) = socket_id {
                self.sockets
                    .send_connected(socket_id, buffer)
                    .map_err(net_errno)?
            } else {
                self.vfs.write(fd, buffer).map_err(vfs_errno)?
            };
            return Ok(count as u64);
        }
        let mut buffer = vec![0; len];
        self.memory
            .read_bytes(addr, &mut buffer)
            .map_err(memory_errno)?;
        let socket_id = self.socket_id_for_fd_or_none(fd)?;
        let count = if let Some(socket_id) = socket_id {
            self.sockets
                .send_connected(socket_id, &buffer)
                .map_err(net_errno)?
        } else {
            self.vfs.write(fd, &buffer).map_err(vfs_errno)?
        };
        Ok(count as u64)
    }

    fn sys_sync_fd(&self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        self.vfs.sync_fd(arg_i32(request, 0)).map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_pread64(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let addr = arg(request, 1);
        let len = usize_arg(request, 2)?;
        let offset = arg(request, 3);
        if offset > i64::MAX as u64 {
            return Err(LinuxErrno::EINVAL);
        }

        if let Ok(Some(buffer)) = self.memory.borrowed_bytes_mut(addr, len) {
            let count = self.vfs.pread(fd, offset, buffer).map_err(vfs_errno)?;
            return Ok(count as u64);
        }
        let mut buffer = vec![0; len];
        let count = self.vfs.pread(fd, offset, &mut buffer).map_err(vfs_errno)?;
        self.memory
            .write_bytes(addr, &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_readv(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let iov = self.read_iovecs(arg(request, 1), usize_arg(request, 2)?)?;
        if let Some(socket_id) = self.socket_id_for_fd_or_none(fd)? {
            return self.recv_connected_into_iovecs(socket_id, &iov);
        }
        let regular_fast_path = self
            .vfs
            .can_regular_readv_fast_path(fd)
            .map_err(vfs_errno)?;
        if iovecs_are_borrowable_mut(&mut self.memory, &iov) {
            let mut total = 0u64;
            for item in iov {
                let len = usize::try_from(item.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
                let count = {
                    let buffer = self
                        .memory
                        .borrowed_bytes_mut(item.iov_base, len)
                        .map_err(memory_errno)?
                        .expect("iovec borrowability was preflighted");
                    self.vfs.read(fd, buffer).map_err(vfs_errno)?
                };
                total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
                if count < len {
                    break;
                }
            }
            return Ok(total);
        }
        if regular_fast_path {
            let mut buffers = iovec_output_buffers(&iov)?;
            let count = self
                .vfs
                .readv_regular(fd, &mut buffers)
                .map_err(vfs_errno)?
                .expect("regular readv fast path was preflighted");
            self.write_iovec_buffers(&iov, &buffers, count)?;
            return Ok(count as u64);
        }

        let mut total = 0u64;
        for item in iov {
            let len = usize::try_from(item.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
            let mut buffer = vec![0; len];
            let count = self.vfs.read(fd, &mut buffer).map_err(vfs_errno)?;
            self.memory
                .write_bytes(item.iov_base, &buffer[..count])
                .map_err(memory_errno)?;
            total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
            if count < len {
                break;
            }
        }
        Ok(total)
    }

    fn sys_writev(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let iov = self.read_iovecs(arg(request, 1), usize_arg(request, 2)?)?;
        if let Some(socket_id) = self.socket_id_for_fd_or_none(fd)? {
            if let Some(slices) = borrowed_iovec_slices(&self.memory, &iov)? {
                let count = self
                    .sockets
                    .send_connected_vectored(socket_id, &slices)
                    .map_err(net_errno)?;
                return Ok(count as u64);
            }
            let buffers = self.read_iovec_buffers(&iov)?;
            let slices = io_slices(&buffers);
            let count = self
                .sockets
                .send_connected_vectored(socket_id, &slices)
                .map_err(net_errno)?;
            return Ok(count as u64);
        }
        let regular_fast_path = self
            .vfs
            .can_regular_writev_fast_path(fd)
            .map_err(vfs_errno)?;
        if iovecs_are_borrowable(&self.memory, &iov) {
            let mut total = 0u64;
            for item in iov {
                let len = usize::try_from(item.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
                let count = {
                    let buffer = self
                        .memory
                        .borrowed_bytes(item.iov_base, len)
                        .map_err(memory_errno)?
                        .expect("iovec borrowability was preflighted");
                    self.vfs.write(fd, buffer).map_err(vfs_errno)?
                };
                total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
                if count < len {
                    break;
                }
            }
            return Ok(total);
        }
        if regular_fast_path {
            let buffers = self.read_iovec_buffers(&iov)?;
            let count = self
                .vfs
                .writev_regular(fd, &buffers)
                .map_err(vfs_errno)?
                .expect("regular writev fast path was preflighted");
            return Ok(count as u64);
        }

        let mut total = 0u64;
        for item in iov {
            let len = usize::try_from(item.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
            let mut buffer = vec![0; len];
            self.memory
                .read_bytes(item.iov_base, &mut buffer)
                .map_err(memory_errno)?;
            let count = self.vfs.write(fd, &buffer).map_err(vfs_errno)?;
            total = total.checked_add(count as u64).ok_or(LinuxErrno::EINVAL)?;
            if count < len {
                break;
            }
        }
        Ok(total)
    }

    fn sys_close(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let fd = arg_i32(request, 0);
        let file = self.vfs.close_with_file(fd).map_err(vfs_errno)?;
        self.close_unshared_file_resources(&file)?;
        Ok(0)
    }

    fn sys_close_range(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        if arg_u32(request, 2) & !LINUX_CLOSE_RANGE_SUPPORTED_FLAGS != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        self.close_fd_range(arg_u32(request, 0), arg_u32(request, 1), |runtime, file| {
            runtime.close_unshared_file_resources(file)
        })
    }

    fn close_fd_range(
        &mut self,
        first: u32,
        last: u32,
        mut close_resource: impl FnMut(&mut Self, &FileRef) -> Result<(), LinuxErrno>,
    ) -> Result<u64, LinuxErrno> {
        let Some((first, last)) = fd_range_bounds(first, last)? else {
            return Ok(0);
        };
        let fds = self.vfs.fds().fds_in_range(first, last);
        for fd in fds {
            match self.vfs.close_with_file(fd) {
                Ok(file) => close_resource(self, &file)?,
                Err(VfsError::BadFd) => {}
                Err(error) => return Err(vfs_errno(error)),
            }
        }
        Ok(0)
    }

    fn close_unshared_file_resources(&mut self, file: &FileRef) -> Result<(), LinuxErrno> {
        if file.kind() == FileKind::Socket {
            let socket_id = match file.inode().backend() {
                mcr_vfs::InodeBackend::Socket(socket) => SocketId::new(socket.id()),
                _ => None,
            };
            if let Some(socket_id) = socket_id
                && self.vfs.socket_fd_count(socket_id.get()) == 0
            {
                self.sockets.close(socket_id).map_err(net_errno)?;
            }
        }
        Ok(())
    }

    fn sys_lseek(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let offset = arg(request, 1) as i64;
        let whence = SeekWhence::from_linux(arg_u32(request, 2)).map_err(vfs_errno)?;
        self.vfs
            .lseek(arg_i32(request, 0), offset, whence)
            .map_err(vfs_errno)
    }

    fn sys_fstat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let attr = self.vfs.fstat(arg_i32(request, 0)).map_err(vfs_errno)?;
        self.write_stat(arg(request, 1), attr)?;
        Ok(0)
    }

    fn sys_statfs(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        let statfs = self.vfs.statfs(&path).map_err(vfs_errno)?;
        self.write_statfs(arg(request, 1), statfs)?;
        Ok(0)
    }

    fn sys_fstatfs(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let statfs = self.vfs.fstatfs(arg_i32(request, 0)).map_err(vfs_errno)?;
        self.write_statfs(arg(request, 1), statfs)?;
        Ok(0)
    }

    fn sys_stat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        let attr = self
            .vfs
            .newfstatat(mcr_vfs::AT_FDCWD, &path, 0)
            .map_err(vfs_errno)?;
        self.write_stat(arg(request, 1), attr)?;
        Ok(0)
    }

    fn sys_lstat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        let attr = self
            .vfs
            .newfstatat(mcr_vfs::AT_FDCWD, &path, mcr_vfs::AT_SYMLINK_NOFOLLOW)
            .map_err(vfs_errno)?;
        self.write_stat(arg(request, 1), attr)?;
        Ok(0)
    }

    fn sys_newfstatat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let attr = self
            .vfs
            .newfstatat(arg_i32(request, 0), &path, arg_u32(request, 3))
            .map_err(vfs_errno)?;
        self.write_stat(arg(request, 2), attr)?;
        Ok(0)
    }

    fn sys_statx(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let attr = self
            .vfs
            .statx(arg_i32(request, 0), &path, arg_u32(request, 2))
            .map_err(vfs_errno)?;
        self.write_statx(arg(request, 4), attr)?;
        Ok(0)
    }

    fn sys_access(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs
            .access(&path, arg_u32(request, 1))
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_faccessat2(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let flags = arg_u32(request, 3);
        if flags & !LINUX_FACCESSAT2_SUPPORTED_FLAGS != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        self.vfs
            .faccessat2(
                arg_i32(request, 0),
                &path,
                arg_u32(request, 2),
                flags & !LINUX_AT_EACCESS,
            )
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_readlink(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        let len = usize_arg(request, 2)?;
        if let Ok(Some(buffer)) = self.memory.borrowed_bytes_mut(arg(request, 1), len) {
            let count = self.vfs.readlink(&path, buffer).map_err(vfs_errno)?;
            return Ok(count as u64);
        }
        let mut buffer = vec![0; len];
        let count = self.vfs.readlink(&path, &mut buffer).map_err(vfs_errno)?;
        self.memory
            .write_bytes(arg(request, 1), &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_readlinkat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let len = usize_arg(request, 3)?;
        if let Ok(Some(buffer)) = self.memory.borrowed_bytes_mut(arg(request, 2), len) {
            let count = self
                .vfs
                .readlinkat(arg_i32(request, 0), &path, buffer)
                .map_err(vfs_errno)?;
            return Ok(count as u64);
        }
        let mut buffer = vec![0; len];
        let count = self
            .vfs
            .readlinkat(arg_i32(request, 0), &path, &mut buffer)
            .map_err(vfs_errno)?;
        self.memory
            .write_bytes(arg(request, 2), &buffer[..count])
            .map_err(memory_errno)?;
        Ok(count as u64)
    }

    fn sys_getdents64(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let max_bytes = usize_arg(request, 2)?;
        let entries = self
            .vfs
            .getdents64(arg_i32(request, 0), max_bytes)
            .map_err(vfs_errno)?;
        let encoded = encode_dirents(&entries)?;
        if encoded.len() > max_bytes {
            return Err(LinuxErrno::EINVAL);
        }
        self.memory
            .write_bytes(arg(request, 1), &encoded)
            .map_err(memory_errno)?;
        Ok(encoded.len() as u64)
    }

    fn sys_pipe(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = PipeSyscallArgs::new(arg(request, 0));
        self.create_pipe(args.pipefd, OpenFlags::new(0))
    }

    fn sys_pipe2(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = Pipe2SyscallArgs::new(arg(request, 0), arg_u32(request, 1));
        self.create_pipe(args.pipefd, OpenFlags::new(args.flags))
    }

    fn create_pipe(&mut self, pipefd_addr: u64, flags: OpenFlags) -> Result<u64, LinuxErrno> {
        let [read_fd, write_fd] = self.vfs.pipe(flags).map_err(vfs_errno)?;
        self.memory
            .write_bytes(pipefd_addr, &read_fd.to_le_bytes())
            .map_err(memory_errno)?;
        self.memory
            .write_bytes(pipefd_addr + 4, &write_fd.to_le_bytes())
            .map_err(memory_errno)?;
        Ok(0)
    }

    fn sys_dup(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = DupSyscallArgs::new(arg_i32(request, 0));
        Ok(self.vfs.dup(args.oldfd).map_err(vfs_errno)? as u64)
    }

    fn sys_dup2(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = Dup2SyscallArgs::new(arg_i32(request, 0), arg_i32(request, 1));
        Ok(self.vfs.dup2(args.oldfd, args.newfd).map_err(vfs_errno)? as u64)
    }

    fn sys_dup3(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = Dup3SyscallArgs::new(
            arg_i32(request, 0),
            arg_i32(request, 1),
            arg_u32(request, 2),
        );
        Ok(self
            .vfs
            .dup3(args.oldfd, args.newfd, OpenFlags::new(args.flags))
            .map_err(vfs_errno)? as u64)
    }

    fn sys_fcntl(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = FcntlSyscallArgs::new(arg_i32(request, 0), arg_u32(request, 1), arg(request, 2));
        if args.cmd == mcr_vfs::F_SETFL
            && let Ok(socket_id) = self.socket_id_for_fd(args.fd)
        {
            self.sockets
                .set_nonblocking(socket_id, args.arg as u32 & mcr_vfs::O_NONBLOCK != 0)
                .map_err(net_errno)?;
        }
        self.vfs
            .fcntl(args.fd, args.cmd, args.arg)
            .map_err(vfs_errno)
    }

    fn sys_ioctl(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let args = IoctlSyscallArgs::new(arg_i32(request, 0), arg(request, 1), arg(request, 2));
        match self.vfs.ioctl(args.fd, args.request).map_err(vfs_errno)? {
            mcr_vfs::IoctlReply::None => Ok(0),
            mcr_vfs::IoctlReply::U32(value) => {
                self.memory
                    .write_bytes(args.argp, &value.to_le_bytes())
                    .map_err(memory_errno)?;
                Ok(0)
            }
        }
    }

    fn sys_mkdirat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        self.vfs
            .mkdirat(arg_i32(request, 0), &path, arg_u32(request, 2))
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_mkdir(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs
            .mkdirat(mcr_vfs::AT_FDCWD, &path, arg_u32(request, 1))
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_unlinkat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 1))?;
        let flags = arg_u32(request, 2);
        if flags & !AT_REMOVEDIR != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        self.vfs
            .unlinkat(arg_i32(request, 0), &path, flags)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_rmdir(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs
            .unlinkat(mcr_vfs::AT_FDCWD, &path, AT_REMOVEDIR)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_unlink(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs
            .unlinkat(mcr_vfs::AT_FDCWD, &path, 0)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_rename(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let oldpath = self.read_path(arg(request, 0))?;
        let newpath = self.read_path(arg(request, 1))?;
        self.vfs
            .renameat2(mcr_vfs::AT_FDCWD, &oldpath, mcr_vfs::AT_FDCWD, &newpath, 0)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_renameat2(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let oldpath = self.read_path(arg(request, 1))?;
        let newpath = self.read_path(arg(request, 3))?;
        self.vfs
            .renameat2(
                arg_i32(request, 0),
                &oldpath,
                arg_i32(request, 2),
                &newpath,
                arg_u32(request, 4),
            )
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_symlinkat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let target = self.read_path(arg(request, 0))?;
        let linkpath = self.read_path(arg(request, 2))?;
        self.vfs
            .symlinkat(&target, arg_i32(request, 1), &linkpath)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_symlink(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let target = self.read_path(arg(request, 0))?;
        let linkpath = self.read_path(arg(request, 1))?;
        self.vfs
            .symlinkat(&target, mcr_vfs::AT_FDCWD, &linkpath)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_linkat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let oldpath = self.read_path(arg(request, 1))?;
        let newpath = self.read_path(arg(request, 3))?;
        let flags = arg_u32(request, 4);
        if flags & !(AT_SYMLINK_FOLLOW | mcr_vfs::AT_EMPTY_PATH) != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        self.vfs
            .linkat(
                arg_i32(request, 0),
                &oldpath,
                arg_i32(request, 2),
                &newpath,
                flags,
            )
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_link(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let oldpath = self.read_path(arg(request, 0))?;
        let newpath = self.read_path(arg(request, 1))?;
        self.vfs
            .linkat(mcr_vfs::AT_FDCWD, &oldpath, mcr_vfs::AT_FDCWD, &newpath, 0)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_ftruncate(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let length = arg(request, 1) as i64;
        if length < 0 {
            return Err(LinuxErrno::EINVAL);
        }
        self.vfs
            .ftruncate(arg_i32(request, 0), length as u64)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_chmod(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs
            .chmod(&path, arg_u32(request, 1))
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_chown(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs
            .chown(
                &path,
                optional_linux_id(arg_u32(request, 1)),
                optional_linux_id(arg_u32(request, 2)),
            )
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_utimensat(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let flags = arg_u32(request, 3);
        if flags & !(mcr_vfs::AT_SYMLINK_NOFOLLOW | mcr_vfs::AT_EMPTY_PATH) != 0 {
            return Err(LinuxErrno::EINVAL);
        }
        let path = self.read_path(arg(request, 1))?;
        let times = self.utimensat_times(arg_i32(request, 0), &path, arg(request, 2), flags)?;
        self.vfs
            .utimensat(arg_i32(request, 0), &path, times, flags)
            .map_err(vfs_errno)?;
        Ok(0)
    }

    fn utimensat_times(
        &self,
        dirfd: Fd,
        path: &str,
        times_ptr: u64,
        flags: u32,
    ) -> Result<FileTimes, LinuxErrno> {
        let current = self
            .vfs
            .newfstatat(dirfd, path, flags)
            .map_err(vfs_errno)
            .ok();
        let now = linux_timespec_from_system_time(std::time::SystemTime::now());
        if times_ptr == 0 {
            return Ok(FileTimes {
                atime_sec: now.tv_sec,
                atime_nsec: now.tv_nsec,
                mtime_sec: now.tv_sec,
                mtime_nsec: now.tv_nsec,
            });
        }

        let atime = read_guest_timespec(&self.memory, times_ptr)?;
        let mtime = read_guest_timespec(
            &self.memory,
            times_ptr.checked_add(16).ok_or(LinuxErrno::EFAULT)?,
        )?;
        let atime = resolve_utimensat_time(atime, now, current, true)?;
        let mtime = resolve_utimensat_time(mtime, now, current, false)?;
        Ok(FileTimes {
            atime_sec: atime.tv_sec,
            atime_nsec: atime.tv_nsec,
            mtime_sec: mtime.tv_sec,
            mtime_nsec: mtime.tv_nsec,
        })
    }

    fn sys_getcwd(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let cwd = self.vfs.getcwd().map_err(vfs_errno)?;
        let bytes = cwd.as_bytes();
        let size = usize_arg(request, 1)?;
        if size == 0 || bytes.len().checked_add(1).ok_or(LinuxErrno::ERANGE)? > size {
            return Err(LinuxErrno::ERANGE);
        }
        self.memory
            .write_bytes(arg(request, 0), bytes)
            .map_err(memory_errno)?;
        self.memory
            .write_bytes(arg(request, 0) + bytes.len() as u64, &[0])
            .map_err(memory_errno)?;
        Ok(arg(request, 0))
    }

    fn sys_chdir(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        let path = self.read_path(arg(request, 0))?;
        self.vfs.chdir(&path).map_err(vfs_errno)?;
        Ok(0)
    }

    fn sys_umask(&mut self, request: &SyscallRequest) -> Result<u64, LinuxErrno> {
        Ok(self.vfs.umask(arg_u32(request, 0)) as u64)
    }

    fn read_path(&self, addr: u64) -> Result<String, LinuxErrno> {
        self.memory.read_c_string(addr, 4096).map_err(memory_errno)
    }

    fn read_iovecs(&self, addr: u64, count: usize) -> Result<Vec<LinuxIovec>, LinuxErrno> {
        read_iovecs(&self.memory, addr, count)
    }

    fn read_iovec_buffers(&self, iovecs: &[LinuxIovec]) -> Result<Vec<Vec<u8>>, LinuxErrno> {
        read_iovec_buffers(&self.memory, iovecs)
    }

    fn write_iovec_buffers(
        &mut self,
        iovecs: &[LinuxIovec],
        buffers: &[Vec<u8>],
        bytes_written: usize,
    ) -> Result<(), LinuxErrno> {
        write_iovec_buffers(&mut self.memory, iovecs, buffers, bytes_written)
    }

    fn recv_connected_into_iovecs(
        &mut self,
        socket_id: SocketId,
        iovecs: &[LinuxIovec],
    ) -> Result<u64, LinuxErrno> {
        let mut buffers = iovec_output_buffers(iovecs)?;
        let count = {
            let mut slices = io_slices_mut(&mut buffers);
            self.sockets
                .recv_connected_vectored(socket_id, &mut slices)
                .map_err(net_errno)?
        };
        self.write_iovec_buffers(iovecs, &buffers, count)?;
        Ok(count as u64)
    }

    fn socket_is_udp_datagram(&self, id: SocketId) -> Result<bool, LinuxErrno> {
        let socket = self.sockets.socket(id).map_err(net_errno)?;
        Ok(socket.socket_type() == SocketType::Datagram
            && socket.effective_protocol() == SocketProtocol::Udp)
    }

    fn write_stat(&mut self, addr: u64, attr: LinuxFileAttr) -> Result<(), LinuxErrno> {
        self.memory
            .write_bytes(addr, &encode_linux_stat(attr))
            .map_err(memory_errno)
    }

    fn write_statx(&mut self, addr: u64, attr: LinuxFileAttr) -> Result<(), LinuxErrno> {
        self.memory
            .write_bytes(addr, &encode_linux_statx(attr))
            .map_err(memory_errno)
    }

    fn write_statfs(&mut self, addr: u64, statfs: LinuxStatfs) -> Result<(), LinuxErrno> {
        self.memory
            .write_bytes(addr, &encode_linux_statfs(statfs))
            .map_err(memory_errno)
    }
}
