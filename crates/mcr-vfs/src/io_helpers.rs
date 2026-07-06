use super::*;

pub(crate) fn anonymous_attr(file: &FileRef) -> LinuxFileAttr {
    match file.kind() {
        FileKind::Stdio(StdioKind::Stdin | StdioKind::Stdout | StdioKind::Stderr) => {
            LinuxFileAttr::fifo(file.inode().id())
        }
        FileKind::PipeRead | FileKind::PipeWrite => LinuxFileAttr::fifo(file.inode().id()),
        FileKind::Socket => LinuxFileAttr::socket(file.inode().id()),
        FileKind::Epoll => LinuxFileAttr::regular(file.inode().id(), 0o600, 0),
        FileKind::Eventfd => LinuxFileAttr::regular(file.inode().id(), 0o600, 0),
        FileKind::Dev(_) => LinuxFileAttr::character_device(file.inode().id(), 0o666),
        FileKind::Regular | FileKind::Directory | FileKind::Symlink => {
            LinuxFileAttr::new(0, S_IFREG | 0o666, 0)
        }
    }
}

pub(crate) fn statfs_for_path_node(node: &PathNode) -> LinuxStatfs {
    match node.kind() {
        PathNodeKind::Proc(_) | PathNodeKind::Device(_) => LinuxStatfs::tmpfs_like(),
        PathNodeKind::Directory | PathNodeKind::File | PathNodeKind::Symlink(_) => {
            LinuxStatfs::ext_like()
        }
    }
}

pub(crate) fn statfs_for_file(file: &FileRef) -> LinuxStatfs {
    match file.kind() {
        FileKind::Dev(_)
        | FileKind::PipeRead
        | FileKind::PipeWrite
        | FileKind::Socket
        | FileKind::Epoll
        | FileKind::Eventfd
        | FileKind::Stdio(_) => LinuxStatfs::tmpfs_like(),
        FileKind::Regular | FileKind::Directory | FileKind::Symlink => LinuxStatfs::ext_like(),
    }
}

pub(crate) fn is_proc_self_fd_directory(tree: &PathTree, path: &GuestPath) -> bool {
    matches!(
        tree.lookup_path(path).map(PathNode::kind),
        Some(PathNodeKind::Proc(ProcNodeKind::FdDirectory))
    )
}

pub(crate) fn proc_self_fd_path_fd(path: &GuestPath) -> Option<Fd> {
    let components = path.as_components();
    if components.len() != 4
        || components[0] != "proc"
        || components[1] != "self"
        || components[2] != "fd"
    {
        return None;
    }
    components[3].parse::<Fd>().ok().filter(|fd| *fd >= 0)
}

pub(crate) fn proc_self_fd_link_inode(fd: Fd) -> VfsResult<InodeId> {
    let fd = u64::try_from(fd).map_err(|_| VfsError::BadFd)?;
    FIRST_PROC_SELF_FD_LINK_INODE_ID
        .checked_add(fd)
        .ok_or(VfsError::BadFd)
}

pub(crate) fn read_regular_node_at(
    node: &PathNode,
    proc_self: &ProcSelfData,
    offset: u64,
    buffer: &mut [u8],
    host_file: Option<&mcr_win::HostFile>,
) -> VfsResult<usize> {
    let proc_data;
    let data = match node.kind() {
        PathNodeKind::Proc(ProcNodeKind::Cmdline) => {
            proc_data = proc_self.cmdline_bytes();
            return read_memory_at(&proc_data, offset, buffer);
        }
        PathNodeKind::Proc(ProcNodeKind::Environ) => {
            proc_data = proc_self.environ_bytes();
            return read_memory_at(&proc_data, offset, buffer);
        }
        _ => node.data(),
    };
    if let Some(path) = node.deferred_host_path() {
        return match host_file {
            Some(file) => read_host_file_at(file, offset, buffer),
            None => read_host_path_at(path, offset, buffer),
        };
    }
    read_memory_at(data, offset, buffer)
}

pub(crate) fn read_memory_at(data: &[u8], offset: u64, buffer: &mut [u8]) -> VfsResult<usize> {
    let offset = usize::try_from(offset).map_err(|_| VfsError::InvalidPath)?;
    let available = data.get(offset..).unwrap_or(&[]);
    let count = available.len().min(buffer.len());
    buffer[..count].copy_from_slice(&available[..count]);
    Ok(count)
}

pub(crate) fn vectored_len(lengths: impl IntoIterator<Item = usize>) -> VfsResult<usize> {
    lengths
        .into_iter()
        .try_fold(0usize, |total, len| total.checked_add(len))
        .ok_or(VfsError::InvalidPath)
}

pub(crate) fn scatter_vectored(source: &[u8], buffers: &mut [Vec<u8>]) {
    let mut copied = 0usize;
    for buffer in buffers {
        if copied >= source.len() {
            break;
        }
        let count = buffer.len().min(source.len() - copied);
        buffer[..count].copy_from_slice(&source[copied..copied + count]);
        copied += count;
    }
}

pub(crate) fn open_host_read_handle(path: &Path) -> VfsResult<mcr_win::HostFile> {
    mcr_win::HostFile::open(
        path,
        mcr_win::FileOptions::new(
            mcr_win::FileAccess::Read,
            mcr_win::FileCreation::OpenExisting,
        )
        .with_overlapped_io(),
    )
    .map_err(vfs_error_from_host)
}

pub(crate) fn read_host_path_at(path: &Path, offset: u64, buffer: &mut [u8]) -> VfsResult<usize> {
    let file = open_host_read_handle(path)?;
    read_host_file_at(&file, offset, buffer)
}

pub(crate) fn read_host_file_at(
    file: &mcr_win::HostFile,
    offset: u64,
    buffer: &mut [u8],
) -> VfsResult<usize> {
    if buffer.is_empty() {
        return Ok(0);
    }

    let completion = file
        .submit_overlapped_read_at(offset, vec![0; buffer.len()])
        .complete_or_fallback(file)
        .map_err(|failure| vfs_error_from_host(failure.error().clone()))?;
    let count = completion.bytes_transferred().min(buffer.len());
    buffer[..count].copy_from_slice(&completion.buffer()[..count]);
    Ok(count)
}

pub(crate) fn vfs_error_from_host(error: mcr_win::HostError) -> VfsError {
    match error.kind() {
        mcr_win::HostErrorKind::NotFound => VfsError::NoEntry,
        mcr_win::HostErrorKind::AccessDenied => VfsError::PermissionDenied,
        mcr_win::HostErrorKind::Interrupted | mcr_win::HostErrorKind::WouldBlock => {
            VfsError::WouldBlock
        }
        mcr_win::HostErrorKind::BrokenPipe => VfsError::BrokenPipe,
        mcr_win::HostErrorKind::AlreadyExists
        | mcr_win::HostErrorKind::InvalidInput
        | mcr_win::HostErrorKind::TimedOut
        | mcr_win::HostErrorKind::OutOfMemory
        | mcr_win::HostErrorKind::Unsupported
        | mcr_win::HostErrorKind::Poisoned
        | mcr_win::HostErrorKind::Unavailable
        | mcr_win::HostErrorKind::Other => VfsError::InvalidPath,
    }
}

pub(crate) fn inode_backend_for_path_node(node: &PathNode, host_path: PathBuf) -> InodeBackend {
    match node.kind() {
        PathNodeKind::Device(kind) => InodeBackend::DevVirtual(DevNode::new(*kind)),
        PathNodeKind::Proc(kind) => InodeBackend::ProcVirtual(ProcNode::new(kind.name())),
        PathNodeKind::Directory | PathNodeKind::File | PathNodeKind::Symlink(_) => {
            InodeBackend::HostPath(HostPathRef::new(host_path))
        }
    }
}

pub(crate) fn register_fd_endpoint(file: &FileRef) {
    if let Ok(pipe) = pipe_node(file) {
        pipe.state().register_endpoint(file.kind());
    }
}

pub(crate) fn unregister_fd_endpoint(file: &FileRef) {
    if let Ok(pipe) = pipe_node(file) {
        let mut state = pipe.state();
        state.unregister_endpoint(file.kind());
        drop(state);
        pipe.notify_readable();
        pipe.notify_writable();
    }
}

pub(crate) fn pipe_read(entry: &FdEntry, buffer: &mut [u8]) -> VfsResult<usize> {
    let pipe = pipe_node(entry.file())?;
    let mut state = pipe.state();
    if state.available() == 0 && !buffer.is_empty() && state.writers > 0 {
        return Err(VfsError::WouldBlock);
    }
    if let Some(host_pair) = pipe.host_pair() {
        let count = pipe_host_read(host_pair.reader(), &mut state, buffer)?;
        if count > 0 {
            pipe.notify_writable();
        }
        return Ok(count);
    }
    let count = state.read(buffer);
    if count > 0 {
        pipe.notify_writable();
    }
    Ok(count)
}

pub(crate) fn pipe_write(entry: &FdEntry, buffer: &[u8]) -> VfsResult<usize> {
    let pipe = pipe_node(entry.file())?;
    let mut state = pipe.state();
    if state.readers == 0 {
        return Err(VfsError::BrokenPipe);
    }
    if state.capacity == state.available() && !buffer.is_empty() && state.readers > 0 {
        return Err(VfsError::WouldBlock);
    }
    if let Some(host_pair) = pipe.host_pair() {
        let count = pipe_host_write(host_pair.writer(), &mut state, buffer)?;
        if count > 0 {
            pipe.notify_readable();
        }
        return Ok(count);
    }
    let count = state.write(buffer)?;
    if count > 0 {
        pipe.notify_readable();
    }
    Ok(count)
}

pub(crate) fn pipe_host_read(
    reader: &mcr_win::HostFile,
    state: &mut PipeState,
    buffer: &mut [u8],
) -> VfsResult<usize> {
    let count = state.available().min(buffer.len());
    if count == 0 {
        return Ok(0);
    }
    let completion = reader
        .submit_overlapped_read_at(0, vec![0; count])
        .complete_or_fallback(reader)
        .map_err(|failure| vfs_error_from_host(failure.error().clone()))?;
    let count = completion.bytes_transferred().min(buffer.len());
    buffer[..count].copy_from_slice(&completion.buffer()[..count]);
    state.discard_readable(count);
    Ok(count)
}

pub(crate) fn pipe_host_write(
    writer: &mcr_win::HostFile,
    state: &mut PipeState,
    buffer: &[u8],
) -> VfsResult<usize> {
    let count = state
        .capacity
        .saturating_sub(state.available())
        .min(buffer.len());
    if count == 0 {
        return Ok(0);
    }
    let completion = writer
        .submit_overlapped_write_at(0, buffer[..count].to_vec())
        .complete_or_fallback(writer)
        .map_err(|failure| vfs_error_from_host(failure.error().clone()))?;
    state.record_written(completion.bytes_transferred().min(count))
}

pub(crate) fn eventfd_read(entry: &FdEntry, buffer: &mut [u8]) -> VfsResult<usize> {
    eventfd_node(entry.file())?.state().read(buffer)
}

pub(crate) fn eventfd_write(entry: &FdEntry, buffer: &[u8]) -> VfsResult<usize> {
    eventfd_node(entry.file())?.state().write(buffer)
}

pub(crate) fn pipe_node(file: &FileRef) -> VfsResult<&PipeNode> {
    match file.inode().backend() {
        InodeBackend::Pipe(pipe) => Ok(pipe),
        _ => Err(VfsError::BadFd),
    }
}

pub(crate) fn socket_inode_id(socket_id: u64) -> VfsResult<InodeId> {
    FIRST_SOCKET_INODE_ID
        .checked_add(socket_id)
        .ok_or(VfsError::BadFd)
}

pub(crate) fn epoll_inode_id(epoll_id: u64) -> VfsResult<InodeId> {
    FIRST_EPOLL_INODE_ID
        .checked_add(epoll_id)
        .ok_or(VfsError::BadFd)
}

pub(crate) fn eventfd_inode_id(eventfd_id: u64) -> VfsResult<InodeId> {
    FIRST_EVENTFD_INODE_ID
        .checked_add(eventfd_id)
        .ok_or(VfsError::BadFd)
}

pub(crate) fn fill_urandom(buffer: &mut [u8]) -> VfsResult<()> {
    getrandom::fill(buffer).map_err(|_| VfsError::InvalidPath)
}
