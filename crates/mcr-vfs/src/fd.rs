use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileRef {
    inode: Arc<Inode>,
    kind: FileKind,
}

impl FileRef {
    pub fn new(inode: Arc<Inode>, kind: FileKind) -> Self {
        Self { inode, kind }
    }

    pub fn stdio(kind: StdioKind) -> Self {
        let id = match kind {
            StdioKind::Stdin => 0,
            StdioKind::Stdout => 1,
            StdioKind::Stderr => 2,
        };
        Self {
            inode: Arc::new(Inode::new(
                id,
                InodeBackend::DevVirtual(DevNode::new(kind.into())),
            )),
            kind: FileKind::Stdio(kind),
        }
    }

    pub fn inode(&self) -> &Arc<Inode> {
        &self.inode
    }

    pub fn kind(&self) -> FileKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Dev(DevNodeKind),
    PipeRead,
    PipeWrite,
    Socket,
    Epoll,
    Eventfd,
    Stdio(StdioKind),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FdReadiness {
    pub readable: bool,
    pub writable: bool,
    pub hang_up: bool,
    pub error: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeekWhence {
    Set,
    Cur,
    End,
}

impl SeekWhence {
    pub fn from_linux(value: u32) -> VfsResult<Self> {
        match value {
            0 => Ok(Self::Set),
            1 => Ok(Self::Cur),
            2 => Ok(Self::End),
            _ => Err(VfsError::InvalidPath),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenFlags {
    raw: u32,
}

impl OpenFlags {
    pub const fn new(raw: u32) -> Self {
        Self { raw }
    }

    pub const fn raw(self) -> u32 {
        self.raw
    }

    pub const fn access_mode(self) -> u32 {
        self.raw & O_ACCMODE
    }

    pub const fn can_read(self) -> bool {
        matches!(self.access_mode(), O_RDONLY | O_RDWR)
    }

    pub const fn can_write(self) -> bool {
        matches!(self.access_mode(), O_WRONLY | O_RDWR)
    }

    pub const fn cloexec(self) -> bool {
        self.raw & O_CLOEXEC != 0
    }

    pub const fn create(self) -> bool {
        self.raw & O_CREAT != 0
    }

    pub const fn exclusive(self) -> bool {
        self.raw & O_EXCL != 0
    }

    pub const fn truncate(self) -> bool {
        self.raw & O_TRUNC != 0
    }

    pub const fn append(self) -> bool {
        self.raw & O_APPEND != 0
    }

    pub const fn nonblock(self) -> bool {
        self.raw & O_NONBLOCK != 0
    }

    pub const fn directory(self) -> bool {
        self.raw & O_DIRECTORY != 0
    }

    pub const fn nofollow(self) -> bool {
        self.raw & O_NOFOLLOW != 0
    }

    pub const fn with_status_flags(self, status_flags: u32) -> Self {
        Self {
            raw: (self.raw & !SETFL_MUTABLE_FLAGS) | (status_flags & SETFL_MUTABLE_FLAGS),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioKind {
    Stdin,
    Stdout,
    Stderr,
}

impl StdioKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Stdin => "stdin",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

impl From<StdioKind> for DevNodeKind {
    fn from(value: StdioKind) -> Self {
        match value {
            StdioKind::Stdin => Self::Stdin,
            StdioKind::Stdout => Self::Stdout,
            StdioKind::Stderr => Self::Stderr,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct StdioCapture {
    inner: Arc<Mutex<StdioCaptureState>>,
}

impl StdioCapture {
    fn snapshot(&self, kind: StdioKind) -> Vec<u8> {
        let state = self.state();
        match kind {
            StdioKind::Stdin => Vec::new(),
            StdioKind::Stdout => state.stdout.clone(),
            StdioKind::Stderr => state.stderr.clone(),
        }
    }

    fn take(&self, kind: StdioKind) -> Vec<u8> {
        let mut state = self.state();
        match kind {
            StdioKind::Stdin => Vec::new(),
            StdioKind::Stdout => std::mem::take(&mut state.stdout),
            StdioKind::Stderr => std::mem::take(&mut state.stderr),
        }
    }

    fn write(&self, kind: StdioKind, buffer: &[u8]) -> VfsResult<usize> {
        let mut state = self.state();
        match kind {
            StdioKind::Stdin => Err(VfsError::BadFd),
            StdioKind::Stdout => {
                state.stdout.extend_from_slice(buffer);
                Ok(buffer.len())
            }
            StdioKind::Stderr => {
                state.stderr.extend_from_slice(buffer);
                Ok(buffer.len())
            }
        }
    }

    fn state(&self) -> MutexGuard<'_, StdioCaptureState> {
        self.inner.lock().expect("stdio capture mutex poisoned")
    }
}

#[derive(Debug, Default)]
struct StdioCaptureState {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct FdEntry {
    pub(crate) file: FileRef,
    pub(crate) description: Arc<Mutex<FdDescription>>,
    pub(crate) path: Option<GuestPath>,
}

impl FdEntry {
    pub fn file(&self) -> &FileRef {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut FileRef {
        &mut self.file
    }

    pub fn offset(&self) -> u64 {
        self.description().offset
    }

    pub fn flags(&self) -> OpenFlags {
        self.description().flags
    }

    pub fn set_flags(&mut self, flags: OpenFlags) {
        self.description().flags = flags;
    }

    pub fn path(&self) -> Option<&GuestPath> {
        self.path.as_ref()
    }

    pub(crate) fn inode_id(&self) -> InodeId {
        self.file.inode().id()
    }

    pub(crate) fn description(&self) -> MutexGuard<'_, FdDescription> {
        self.description
            .lock()
            .expect("fd description mutex poisoned")
    }

    fn rebind_path(&mut self, old_path: &GuestPath, new_path: &GuestPath) {
        let Some(path) = self.path.as_mut() else {
            return;
        };
        if !path.starts_with(old_path) {
            return;
        }
        *path = PathTree::replace_prefix(path, old_path, new_path);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FdDescription {
    pub(crate) offset: u64,
    pub(crate) flags: OpenFlags,
    pub(crate) dir_cursor: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoctlReply {
    None,
    U32(u32),
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct ClosedFdIds {
    pub socket_ids: Vec<u64>,
    pub epoll_ids: Vec<u64>,
}

impl ClosedFdIds {
    pub fn is_empty(&self) -> bool {
        self.socket_ids.is_empty() && self.epoll_ids.is_empty()
    }

    fn add_entry(&mut self, entry: &FdEntry) {
        if let Some(socket_id) = socket_id_for_entry(entry) {
            self.socket_ids.push(socket_id);
        }
        if let Some(epoll_id) = epoll_id_for_entry(entry) {
            self.epoll_ids.push(epoll_id);
        }
    }
}

#[derive(Debug)]
pub struct FdTable {
    entries: BTreeMap<Fd, FdEntry>,
    cloexec: HashSet<Fd>,
    next_pipe_id: u64,
    next_eventfd_id: u64,
    stdio: StdioCapture,
}

impl Clone for FdTable {
    fn clone(&self) -> Self {
        let entries = self.entries.clone();
        for entry in entries.values() {
            register_fd_endpoint(entry.file());
        }
        Self {
            entries,
            cloexec: self.cloexec.clone(),
            next_pipe_id: self.next_pipe_id,
            next_eventfd_id: self.next_eventfd_id,
            stdio: self.stdio.clone(),
        }
    }
}

impl Drop for FdTable {
    fn drop(&mut self) {
        for entry in self.entries.values() {
            unregister_fd_endpoint(entry.file());
        }
    }
}

impl FdTable {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            cloexec: HashSet::new(),
            next_pipe_id: 1,
            next_eventfd_id: 1,
            stdio: StdioCapture::default(),
        }
    }

    pub fn with_stdio() -> Self {
        let mut table = Self::new();
        table
            .insert_exact(0, FileRef::stdio(StdioKind::Stdin), false)
            .expect("stdio fd 0 is available in a new fd table");
        table
            .insert_exact(1, FileRef::stdio(StdioKind::Stdout), false)
            .expect("stdio fd 1 is available in a new fd table");
        table
            .insert_exact(2, FileRef::stdio(StdioKind::Stderr), false)
            .expect("stdio fd 2 is available in a new fd table");
        table
    }

    pub fn insert(&mut self, file: FileRef, cloexec: bool) -> VfsResult<Fd> {
        let fd = self.next_fd_from(FIRST_USER_FD)?;
        self.insert_exact(fd, file, cloexec)?;
        Ok(fd)
    }

    pub fn insert_open(
        &mut self,
        file: FileRef,
        flags: OpenFlags,
        path: Option<GuestPath>,
    ) -> VfsResult<Fd> {
        let fd = self.next_fd_from(FIRST_USER_FD)?;
        self.insert_entry(fd, file, flags.cloexec(), flags, path)
    }

    pub fn pipe(&mut self, flags: OpenFlags) -> VfsResult<[Fd; 2]> {
        if flags.raw() & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(VfsError::InvalidPath);
        }

        let read_fd = self.next_fd_from(FIRST_USER_FD)?;
        let write_fd = self.next_fd_from(read_fd.checked_add(1).ok_or(VfsError::BadFd)?)?;
        let pipe_id = self.allocate_pipe_id()?;
        let pipe_inode = Arc::new(Inode::new(
            FIRST_PIPE_INODE_ID
                .checked_add(pipe_id)
                .ok_or(VfsError::BadFd)?,
            InodeBackend::Pipe(PipeNode::new(pipe_id)),
        ));
        let cloexec = flags.cloexec();

        self.insert_entry(
            read_fd,
            FileRef::new(pipe_inode.clone(), FileKind::PipeRead),
            cloexec,
            OpenFlags::new(O_RDONLY | (flags.raw() & O_NONBLOCK)),
            None,
        )?;
        if let Err(error) = self.insert_entry(
            write_fd,
            FileRef::new(pipe_inode, FileKind::PipeWrite),
            cloexec,
            OpenFlags::new(O_WRONLY | (flags.raw() & O_NONBLOCK)),
            None,
        ) {
            let _ = self.close(read_fd);
            return Err(error);
        }

        Ok([read_fd, write_fd])
    }

    pub fn insert_socket(&mut self, socket_id: u64, flags: OpenFlags) -> VfsResult<Fd> {
        let access_mode = flags.access_mode();
        if flags.raw() & !(O_ACCMODE | O_CLOEXEC | O_NONBLOCK) != 0
            || (access_mode != 0 && access_mode != O_RDWR)
        {
            return Err(VfsError::InvalidPath);
        }

        let inode = Arc::new(Inode::new(
            socket_inode_id(socket_id)?,
            InodeBackend::Socket(SocketNode::new(socket_id)),
        ));
        let fd = self.next_fd_from(FIRST_USER_FD)?;
        self.insert_entry(
            fd,
            FileRef::new(inode, FileKind::Socket),
            flags.cloexec(),
            OpenFlags::new(O_RDWR | (flags.raw() & O_NONBLOCK)),
            None,
        )
    }

    pub fn insert_epoll(&mut self, epoll_id: u64, flags: OpenFlags) -> VfsResult<Fd> {
        let access_mode = flags.access_mode();
        if flags.raw() & !(O_ACCMODE | O_CLOEXEC) != 0 || access_mode != 0 {
            return Err(VfsError::InvalidPath);
        }

        let inode = Arc::new(Inode::new(
            epoll_inode_id(epoll_id)?,
            InodeBackend::Epoll(EpollNode::new(epoll_id)),
        ));
        let fd = self.next_fd_from(FIRST_USER_FD)?;
        self.insert_entry(
            fd,
            FileRef::new(inode, FileKind::Epoll),
            flags.cloexec(),
            OpenFlags::new(O_RDONLY | (flags.raw() & O_CLOEXEC)),
            None,
        )
    }

    pub fn eventfd(&mut self, initial: u64, flags: OpenFlags) -> VfsResult<Fd> {
        let access_mode = flags.access_mode();
        if flags.raw() & !(O_ACCMODE | O_CLOEXEC | O_NONBLOCK) != 0
            || (access_mode != 0 && access_mode != O_RDWR)
        {
            return Err(VfsError::InvalidPath);
        }

        let eventfd_id = self.allocate_eventfd_id()?;
        let inode = Arc::new(Inode::new(
            eventfd_inode_id(eventfd_id)?,
            InodeBackend::Eventfd(EventfdNode::new(eventfd_id, initial)),
        ));
        let fd = self.next_fd_from(FIRST_USER_FD)?;
        self.insert_entry(
            fd,
            FileRef::new(inode, FileKind::Eventfd),
            flags.cloexec(),
            OpenFlags::new(O_RDWR | (flags.raw() & O_NONBLOCK)),
            None,
        )
    }

    pub fn socket_id_for_fd(&self, fd: Fd) -> VfsResult<u64> {
        match self.get(fd)?.file().inode().backend() {
            InodeBackend::Socket(socket) => Ok(socket.id()),
            _ => Err(VfsError::NotSocket),
        }
    }

    pub fn epoll_id_for_fd(&self, fd: Fd) -> VfsResult<u64> {
        match self.get(fd)?.file().inode().backend() {
            InodeBackend::Epoll(epoll) => Ok(epoll.id()),
            _ => Err(VfsError::BadFd),
        }
    }

    pub fn socket_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries.values().filter_map(socket_id_for_entry)
    }

    pub fn socket_fd_count(&self, socket_id: u64) -> usize {
        self.socket_ids().filter(|id| *id == socket_id).count()
    }

    pub fn epoll_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries.values().filter_map(epoll_id_for_entry)
    }

    pub fn epoll_fd_count(&self, epoll_id: u64) -> usize {
        self.epoll_ids().filter(|id| *id == epoll_id).count()
    }

    pub fn insert_at_or_above(
        &mut self,
        min_fd: Fd,
        file: FileRef,
        cloexec: bool,
    ) -> VfsResult<Fd> {
        let fd = self.next_fd_from(min_fd)?;
        self.insert_exact(fd, file, cloexec)?;
        Ok(fd)
    }

    pub fn insert_exact(&mut self, fd: Fd, file: FileRef, cloexec: bool) -> VfsResult<()> {
        self.insert_entry(fd, file, cloexec, OpenFlags::new(O_RDWR), None)?;
        Ok(())
    }

    fn insert_entry(
        &mut self,
        fd: Fd,
        file: FileRef,
        cloexec: bool,
        flags: OpenFlags,
        path: Option<GuestPath>,
    ) -> VfsResult<Fd> {
        if fd < 0 {
            return Err(VfsError::BadFd);
        }
        if self.entries.contains_key(&fd) {
            return Err(VfsError::BadFd);
        }

        register_fd_endpoint(&file);
        self.entries.insert(
            fd,
            FdEntry {
                file,
                description: Arc::new(Mutex::new(FdDescription {
                    offset: 0,
                    flags,
                    dir_cursor: 0,
                })),
                path,
            },
        );
        self.set_cloexec(fd, cloexec)?;
        Ok(fd)
    }

    pub fn dup(&mut self, oldfd: Fd, min_fd: Fd, cloexec: bool) -> VfsResult<Fd> {
        if min_fd < 0 {
            return Err(VfsError::BadFd);
        }
        let entry = self.get(oldfd)?.clone();
        let newfd = self.next_fd_from(min_fd)?;
        register_fd_endpoint(entry.file());
        self.entries.insert(newfd, entry);
        self.set_cloexec(newfd, cloexec)?;
        Ok(newfd)
    }

    pub fn dup2(&mut self, oldfd: Fd, newfd: Fd, cloexec: bool) -> VfsResult<Fd> {
        if newfd < 0 {
            return Err(VfsError::BadFd);
        }
        let entry = self.get(oldfd)?.clone();
        if oldfd == newfd {
            return Ok(newfd);
        }
        let _ = self.close(newfd);
        register_fd_endpoint(entry.file());
        self.entries.insert(newfd, entry);
        self.set_cloexec(newfd, cloexec)?;
        Ok(newfd)
    }

    pub fn get(&self, fd: Fd) -> VfsResult<&FdEntry> {
        self.entries.get(&fd).ok_or(VfsError::BadFd)
    }

    pub fn get_mut(&mut self, fd: Fd) -> VfsResult<&mut FdEntry> {
        self.entries.get_mut(&fd).ok_or(VfsError::BadFd)
    }

    pub fn entries(&self) -> impl Iterator<Item = (Fd, &FdEntry)> {
        self.entries.iter().map(|(fd, entry)| (*fd, entry))
    }

    pub fn fds_in_range(&self, first: Fd, last: Fd) -> Vec<Fd> {
        self.entries
            .range(first..=last)
            .map(|(fd, _)| *fd)
            .collect()
    }

    pub fn close(&mut self, fd: Fd) -> VfsResult<FileRef> {
        let entry = self.entries.remove(&fd).ok_or(VfsError::BadFd)?;
        self.cloexec.remove(&fd);
        unregister_fd_endpoint(&entry.file);
        Ok(entry.file)
    }

    pub fn set_fd_flags(&mut self, fd: Fd, flags: u32) -> VfsResult<()> {
        self.set_cloexec(fd, flags & FD_CLOEXEC != 0)
    }

    pub fn fd_flags(&self, fd: Fd) -> VfsResult<u32> {
        Ok(if self.cloexec(fd)? { FD_CLOEXEC } else { 0 })
    }

    pub fn status_flags(&self, fd: Fd) -> VfsResult<u32> {
        Ok(self.get(fd)?.flags().raw())
    }

    pub fn set_status_flags(&mut self, fd: Fd, flags: u32) -> VfsResult<()> {
        let entry = self.get_mut(fd)?;
        entry.set_flags(entry.flags().with_status_flags(flags));
        Ok(())
    }

    pub fn pipe_capacity(&self, fd: Fd) -> VfsResult<usize> {
        Ok(pipe_node(self.get(fd)?.file())?.state().capacity)
    }

    pub fn set_pipe_capacity(&mut self, fd: Fd, capacity: usize) -> VfsResult<usize> {
        let pipe = pipe_node(self.get(fd)?.file())?;
        let new_capacity = pipe.state().set_capacity(capacity)?;
        pipe.notify_writable();
        Ok(new_capacity)
    }

    pub fn stdout_snapshot(&self) -> Vec<u8> {
        self.stdio.snapshot(StdioKind::Stdout)
    }

    pub fn stderr_snapshot(&self) -> Vec<u8> {
        self.stdio.snapshot(StdioKind::Stderr)
    }

    pub fn take_stdout(&mut self) -> Vec<u8> {
        self.stdio.take(StdioKind::Stdout)
    }

    pub fn take_stderr(&mut self) -> Vec<u8> {
        self.stdio.take(StdioKind::Stderr)
    }

    pub fn available_bytes(&self, tree: &PathTree, fd: Fd) -> VfsResult<usize> {
        let entry = self.get(fd)?;
        match entry.file().kind() {
            FileKind::Regular | FileKind::Symlink => {
                let attr = tree
                    .lookup_inode(entry.inode_id())
                    .ok_or(VfsError::NoEntry)?
                    .attr();
                let offset = entry.offset();
                if attr.size <= offset {
                    return Ok(0);
                }
                usize::try_from(attr.size - offset).map_err(|_| VfsError::InvalidPath)
            }
            FileKind::Directory => Ok(0),
            FileKind::Dev(DevNodeKind::Null | DevNodeKind::Zero | DevNodeKind::Urandom) => Ok(0),
            FileKind::Dev(DevNodeKind::Stdin | DevNodeKind::Stdout | DevNodeKind::Stderr) => Ok(0),
            FileKind::PipeRead | FileKind::PipeWrite => {
                Ok(pipe_node(entry.file())?.state().available())
            }
            FileKind::Socket | FileKind::Epoll | FileKind::Eventfd => Ok(0),
            FileKind::Stdio(_) => Ok(0),
        }
    }

    pub fn poll_readiness(&self, _tree: &PathTree, fd: Fd) -> VfsResult<FdReadiness> {
        let entry = self.get(fd)?;
        Ok(match entry.file().kind() {
            FileKind::Regular | FileKind::Symlink | FileKind::Directory => FdReadiness {
                readable: true,
                writable: entry.flags().can_write(),
                hang_up: false,
                error: false,
            },
            FileKind::Dev(DevNodeKind::Null | DevNodeKind::Zero | DevNodeKind::Urandom) => {
                FdReadiness {
                    readable: entry.flags().can_read(),
                    writable: entry.flags().can_write(),
                    hang_up: false,
                    error: false,
                }
            }
            FileKind::Dev(DevNodeKind::Stdin | DevNodeKind::Stdout | DevNodeKind::Stderr)
            | FileKind::Stdio(_) => FdReadiness {
                readable: false,
                writable: entry.flags().can_write(),
                hang_up: false,
                error: false,
            },
            FileKind::PipeRead | FileKind::PipeWrite => {
                let state = pipe_node(entry.file())?.state();
                FdReadiness {
                    readable: matches!(entry.file().kind(), FileKind::PipeRead)
                        && (state.available() > 0 || state.writers == 0),
                    writable: matches!(entry.file().kind(), FileKind::PipeWrite)
                        && state.readers > 0
                        && state.available() < state.capacity,
                    hang_up: (matches!(entry.file().kind(), FileKind::PipeRead)
                        && state.writers == 0)
                        || (matches!(entry.file().kind(), FileKind::PipeWrite)
                            && state.readers == 0),
                    error: false,
                }
            }
            FileKind::Socket => FdReadiness {
                readable: false,
                writable: false,
                hang_up: false,
                error: false,
            },
            FileKind::Epoll => FdReadiness {
                readable: false,
                writable: false,
                hang_up: false,
                error: false,
            },
            FileKind::Eventfd => {
                let state = eventfd_node(entry.file())?.state();
                FdReadiness {
                    readable: state.readable(),
                    writable: state.writable(),
                    hang_up: false,
                    error: false,
                }
            }
        })
    }

    pub(crate) fn open_count(&self, inode_id: InodeId) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.inode_id() == inode_id)
            .count()
    }

    pub(crate) fn rebind_paths(&mut self, old_path: &GuestPath, new_path: &GuestPath) {
        for entry in self.entries.values_mut() {
            entry.rebind_path(old_path, new_path);
        }
    }

    pub fn set_cloexec(&mut self, fd: Fd, cloexec: bool) -> VfsResult<()> {
        if !self.entries.contains_key(&fd) {
            return Err(VfsError::BadFd);
        }

        if cloexec {
            self.cloexec.insert(fd);
        } else {
            self.cloexec.remove(&fd);
        }
        Ok(())
    }

    pub fn cloexec(&self, fd: Fd) -> VfsResult<bool> {
        self.get(fd).map(|_| self.cloexec.contains(&fd))
    }

    pub fn close_on_exec(&mut self) -> ClosedFdIds {
        let cloexec = std::mem::take(&mut self.cloexec);
        let mut closed = ClosedFdIds::default();
        for fd in cloexec {
            if let Some(entry) = self.entries.remove(&fd) {
                closed.add_entry(&entry);
                unregister_fd_endpoint(&entry.file);
            }
        }
        closed
    }

    pub fn read(
        &mut self,
        tree: &PathTree,
        proc_self: &ProcSelfData,
        fd: Fd,
        buffer: &mut [u8],
    ) -> VfsResult<usize> {
        let entry = self.get_mut(fd)?;
        if !entry.flags().can_read() {
            return Err(VfsError::BadFd);
        }

        match entry.file.kind {
            FileKind::Regular | FileKind::Symlink => {
                let node = tree
                    .lookup_inode(entry.inode_id())
                    .ok_or(VfsError::NoEntry)?;
                if node.attr().is_directory() {
                    return Err(VfsError::IsDirectory);
                }
                let mut description = entry.description();
                let count = read_regular_node_at(node, proc_self, description.offset, buffer)?;
                description.offset += count as u64;
                Ok(count)
            }
            FileKind::Dev(DevNodeKind::Null) => Ok(0),
            FileKind::Dev(DevNodeKind::Zero) => {
                buffer.fill(0);
                Ok(buffer.len())
            }
            FileKind::Dev(DevNodeKind::Urandom) => {
                fill_urandom(buffer)?;
                Ok(buffer.len())
            }
            FileKind::Dev(DevNodeKind::Stdin) => Ok(0),
            FileKind::Dev(_) => Err(VfsError::BadFd),
            FileKind::PipeRead => pipe_read(entry, buffer),
            FileKind::PipeWrite => Err(VfsError::BadFd),
            FileKind::Socket => Err(VfsError::BadFd),
            FileKind::Epoll => Err(VfsError::BadFd),
            FileKind::Eventfd => eventfd_read(entry, buffer),
            FileKind::Directory => Err(VfsError::IsDirectory),
            FileKind::Stdio(StdioKind::Stdin) => Ok(0),
            FileKind::Stdio(_) => Err(VfsError::BadFd),
        }
    }

    pub fn pread(
        &self,
        tree: &PathTree,
        proc_self: &ProcSelfData,
        fd: Fd,
        offset: u64,
        buffer: &mut [u8],
    ) -> VfsResult<usize> {
        let entry = self.get(fd)?;
        if !entry.flags().can_read() {
            return Err(VfsError::BadFd);
        }

        match entry.file.kind {
            FileKind::Regular | FileKind::Symlink => {
                let node = tree
                    .lookup_inode(entry.inode_id())
                    .ok_or(VfsError::NoEntry)?;
                if node.attr().is_directory() {
                    return Err(VfsError::IsDirectory);
                }
                read_regular_node_at(node, proc_self, offset, buffer)
            }
            FileKind::Dev(DevNodeKind::Null) => Ok(0),
            FileKind::Dev(DevNodeKind::Zero) => {
                buffer.fill(0);
                Ok(buffer.len())
            }
            FileKind::Dev(DevNodeKind::Urandom) => {
                fill_urandom(buffer)?;
                Ok(buffer.len())
            }
            FileKind::Dev(DevNodeKind::Stdin) => Ok(0),
            FileKind::Dev(_) => Err(VfsError::BadFd),
            FileKind::PipeRead
            | FileKind::PipeWrite
            | FileKind::Socket
            | FileKind::Epoll
            | FileKind::Eventfd
            | FileKind::Directory
            | FileKind::Stdio(_) => Err(VfsError::BadFd),
        }
    }

    pub fn readlink_open(&self, tree: &PathTree, fd: Fd, buffer: &mut [u8]) -> VfsResult<usize> {
        let entry = self.get(fd)?;
        let node = tree
            .lookup_inode(entry.inode_id())
            .ok_or(VfsError::NoEntry)?;
        let PathNodeKind::Symlink(target) = node.kind() else {
            return Err(VfsError::InvalidPath);
        };
        let bytes = target.as_bytes();
        let count = bytes.len().min(buffer.len());
        buffer[..count].copy_from_slice(&bytes[..count]);
        Ok(count)
    }

    pub fn write(&mut self, tree: &mut PathTree, fd: Fd, buffer: &[u8]) -> VfsResult<usize> {
        let stdio = self.stdio.clone();
        let entry = self.get_mut(fd)?;
        if !entry.flags().can_write() {
            return Err(VfsError::BadFd);
        }

        match entry.file.kind {
            FileKind::Regular => {
                let inode_id = entry.inode_id();
                let node = tree.lookup_inode_mut(inode_id).ok_or(VfsError::NoEntry)?;
                let mut description = entry.description();
                let offset = if description.flags.append() {
                    node.attr().size
                } else {
                    description.offset
                };
                let count = node.write_at(offset, buffer)?;
                description.offset = offset + count as u64;
                Ok(count)
            }
            FileKind::Dev(
                DevNodeKind::Null
                | DevNodeKind::Zero
                | DevNodeKind::Urandom
                | DevNodeKind::Stdout
                | DevNodeKind::Stderr,
            ) => Ok(buffer.len()),
            FileKind::Dev(DevNodeKind::Stdin) => Err(VfsError::BadFd),
            FileKind::Directory => Err(VfsError::IsDirectory),
            FileKind::Symlink => Err(VfsError::InvalidPath),
            FileKind::PipeRead => Err(VfsError::BadFd),
            FileKind::PipeWrite => pipe_write(entry, buffer),
            FileKind::Socket => Err(VfsError::BadFd),
            FileKind::Epoll => Err(VfsError::BadFd),
            FileKind::Eventfd => eventfd_write(entry, buffer),
            FileKind::Stdio(kind) => stdio.write(kind, buffer),
        }
    }

    pub fn seek(
        &mut self,
        tree: &PathTree,
        fd: Fd,
        offset: i64,
        whence: SeekWhence,
    ) -> VfsResult<u64> {
        let entry = self.get_mut(fd)?;
        if matches!(
            entry.file.kind,
            FileKind::Dev(_)
                | FileKind::PipeRead
                | FileKind::PipeWrite
                | FileKind::Socket
                | FileKind::Epoll
                | FileKind::Eventfd
                | FileKind::Stdio(_)
        ) {
            return Err(VfsError::NotSeekable);
        }

        let size = match entry.file.kind {
            FileKind::Regular | FileKind::Symlink => {
                tree.lookup_inode(entry.inode_id())
                    .ok_or(VfsError::NoEntry)?
                    .attr()
                    .size
            }
            FileKind::Directory => 0,
            FileKind::Dev(_) => unreachable!(),
            FileKind::PipeRead | FileKind::PipeWrite => unreachable!(),
            FileKind::Socket => unreachable!(),
            FileKind::Epoll => unreachable!(),
            FileKind::Eventfd => unreachable!(),
            FileKind::Stdio(_) => unreachable!(),
        };
        let base = match whence {
            SeekWhence::Set => 0,
            SeekWhence::Cur => i128::from(entry.offset()),
            SeekWhence::End => i128::from(size),
        };
        let next = base + i128::from(offset);
        if next < 0 || next > i128::from(u64::MAX) {
            return Err(VfsError::InvalidPath);
        }
        let mut description = entry.description();
        description.offset = next as u64;
        if matches!(entry.file.kind, FileKind::Directory) {
            description.dir_cursor = usize::try_from(description.offset).unwrap_or(usize::MAX);
        }
        Ok(description.offset)
    }

    pub fn getdents64(
        &mut self,
        tree: &PathTree,
        fd: Fd,
        max_bytes: usize,
    ) -> VfsResult<Vec<DirectoryEntry>> {
        let source = self.directory_listing_source(tree, fd)?;
        let entries = self.directory_entries(tree, &source.path)?;
        self.consume_directory_entries(fd, max_bytes, &entries)
    }

    pub(crate) fn directory_listing_source(
        &self,
        tree: &PathTree,
        fd: Fd,
    ) -> VfsResult<DirectoryListingSource> {
        let entry = self.get(fd)?;
        if !matches!(entry.file.kind, FileKind::Directory) {
            return Err(VfsError::NotDirectory);
        }

        let path = entry.path.as_ref().ok_or(VfsError::BadFd)?.clone();
        let inode = tree.lookup_path(&path).ok_or(VfsError::NoEntry)?.inode_id();
        let cacheable = !is_proc_self_fd_directory(tree, &path);
        Ok(DirectoryListingSource {
            inode,
            path,
            cacheable,
        })
    }

    pub(crate) fn directory_entries(
        &self,
        tree: &PathTree,
        path: &GuestPath,
    ) -> VfsResult<Vec<DirectoryEntry>> {
        let mut children = tree.static_children(path)?;
        if is_proc_self_fd_directory(tree, path) {
            children.extend(self.proc_fd_children());
        }
        self.directory_entries_from_children(tree, path, children)
    }

    pub(crate) fn static_directory_entries(
        &self,
        tree: &PathTree,
        path: &GuestPath,
    ) -> VfsResult<Vec<DirectoryEntry>> {
        self.directory_entries_from_children(tree, path, tree.static_children(path)?)
    }

    pub(crate) fn directory_entries_from_children(
        &self,
        tree: &PathTree,
        path: &GuestPath,
        mut children: Vec<DirectoryChild>,
    ) -> VfsResult<Vec<DirectoryEntry>> {
        children.sort_by(|left, right| left.name.cmp(&right.name));

        let directory_inode = tree.lookup_path(path).ok_or(VfsError::NoEntry)?.inode_id();
        let mut entries = vec![
            DirectoryEntry {
                inode: directory_inode,
                offset: 1,
                file_type: DT_DIR,
                name: ".".to_owned(),
            },
            DirectoryEntry {
                inode: directory_inode,
                offset: 2,
                file_type: DT_DIR,
                name: "..".to_owned(),
            },
        ];
        entries.extend(
            children
                .into_iter()
                .enumerate()
                .map(|(index, child)| DirectoryEntry {
                    inode: child.inode,
                    offset: i64::try_from(index + 3).unwrap_or(i64::MAX),
                    file_type: child.file_type,
                    name: child.name,
                }),
        );
        Ok(entries)
    }

    pub(crate) fn consume_directory_entries(
        &mut self,
        fd: Fd,
        max_bytes: usize,
        entries: &[DirectoryEntry],
    ) -> VfsResult<Vec<DirectoryEntry>> {
        let mut returned = Vec::new();
        let mut used = 0usize;
        let entry = self.get_mut(fd)?;
        let description_arc = entry.description.clone();
        let mut description = description_arc
            .lock()
            .expect("fd description mutex poisoned");
        for item in entries.iter().skip(description.dir_cursor) {
            let record_len = item.record_len();
            if used + record_len > max_bytes {
                if returned.is_empty() {
                    return Err(VfsError::InvalidPath);
                }
                break;
            }
            used += record_len;
            returned.push(item.clone());
            description.dir_cursor += 1;
            description.offset = description.dir_cursor as u64;
        }
        Ok(returned)
    }

    fn next_fd_from(&self, min_fd: Fd) -> VfsResult<Fd> {
        if min_fd < 0 {
            return Err(VfsError::BadFd);
        }

        let mut fd = min_fd;
        loop {
            if !self.entries.contains_key(&fd) {
                return Ok(fd);
            }
            fd = fd.checked_add(1).ok_or(VfsError::BadFd)?;
        }
    }

    fn allocate_pipe_id(&mut self) -> VfsResult<u64> {
        let id = self.next_pipe_id;
        self.next_pipe_id = self.next_pipe_id.checked_add(1).ok_or(VfsError::BadFd)?;
        Ok(id)
    }

    fn allocate_eventfd_id(&mut self) -> VfsResult<u64> {
        let id = self.next_eventfd_id;
        self.next_eventfd_id = self.next_eventfd_id.checked_add(1).ok_or(VfsError::BadFd)?;
        Ok(id)
    }

    fn proc_fd_children(&self) -> Vec<DirectoryChild> {
        self.entries
            .keys()
            .filter_map(|fd| {
                Some(DirectoryChild {
                    name: fd.to_string(),
                    inode: proc_self_fd_link_inode(*fd).ok()?,
                    file_type: DT_LNK,
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryListingSource {
    pub(crate) inode: InodeId,
    pub(crate) path: GuestPath,
    pub(crate) cacheable: bool,
}

pub(crate) fn eventfd_node(file: &FileRef) -> VfsResult<&EventfdNode> {
    match file.inode().backend() {
        InodeBackend::Eventfd(eventfd) => Ok(eventfd),
        _ => Err(VfsError::BadFd),
    }
}

fn socket_id_for_entry(entry: &FdEntry) -> Option<u64> {
    if !matches!(entry.file().kind(), FileKind::Socket) {
        return None;
    }
    match entry.file().inode().backend() {
        InodeBackend::Socket(socket) => Some(socket.id()),
        _ => None,
    }
}

fn epoll_id_for_entry(entry: &FdEntry) -> Option<u64> {
    if !matches!(entry.file().kind(), FileKind::Epoll) {
        return None;
    }
    match entry.file().inode().backend() {
        InodeBackend::Epoll(epoll) => Some(epoll.id()),
        _ => None,
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}
