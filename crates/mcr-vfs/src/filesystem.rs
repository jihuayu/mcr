use super::*;

#[derive(Clone, Debug)]
pub struct VirtualFileSystem {
    rootfs: Rootfs,
    tree: PathTree,
    fds: FdTable,
    proc_self: ProcSelfData,
    umask: u32,
    cache: RefCell<VfsCache>,
}

impl VirtualFileSystem {
    pub fn new(host_root: impl Into<PathBuf>) -> Self {
        let mut vfs = Self {
            rootfs: Rootfs::new(host_root),
            tree: PathTree::new(),
            fds: FdTable::with_stdio(),
            proc_self: ProcSelfData::default(),
            umask: DEFAULT_UMASK,
            cache: RefCell::new(VfsCache::default()),
        };
        vfs.mount_minimal_devfs()
            .expect("minimal devfs nodes do not conflict in a new VFS");
        vfs
    }

    pub fn from_parts(rootfs: Rootfs, tree: PathTree, fds: FdTable) -> Self {
        Self {
            rootfs,
            tree,
            fds,
            proc_self: ProcSelfData::default(),
            umask: DEFAULT_UMASK,
            cache: RefCell::new(VfsCache::default()),
        }
    }

    pub fn rootfs(&self) -> &Rootfs {
        &self.rootfs
    }

    pub fn tree(&self) -> &PathTree {
        &self.tree
    }

    pub fn tree_mut(&mut self) -> &mut PathTree {
        self.invalidate_vfs_caches();
        &mut self.tree
    }

    pub fn fds(&self) -> &FdTable {
        &self.fds
    }

    pub fn fds_mut(&mut self) -> &mut FdTable {
        &mut self.fds
    }

    pub fn replace_fds(&mut self, fds: FdTable) -> FdTable {
        std::mem::replace(&mut self.fds, fds)
    }

    pub fn stdout_snapshot(&self) -> Vec<u8> {
        self.fds.stdout_snapshot()
    }

    pub fn stderr_snapshot(&self) -> Vec<u8> {
        self.fds.stderr_snapshot()
    }

    pub fn take_stdout(&mut self) -> Vec<u8> {
        self.fds.take_stdout()
    }

    pub fn take_stderr(&mut self) -> Vec<u8> {
        self.fds.take_stderr()
    }

    pub fn proc_self(&self) -> &ProcSelfData {
        &self.proc_self
    }

    pub fn set_proc_self(&mut self, proc_self: ProcSelfData) {
        self.proc_self = proc_self;
        self.invalidate_proc_caches();
    }

    pub fn mount_minimal_devfs(&mut self) -> VfsResult<()> {
        self.tree.mount_minimal_devfs()?;
        self.invalidate_vfs_caches();
        Ok(())
    }

    pub fn mount_minimal_procfs(&mut self) -> VfsResult<()> {
        self.tree.mount_minimal_procfs()?;
        self.invalidate_vfs_caches();
        Ok(())
    }

    pub fn getcwd(&self) -> VfsResult<String> {
        self.rootfs.visible_path(self.rootfs.cwd())
    }

    pub fn chdir(&mut self, path: &str) -> VfsResult<()> {
        let resolved = self.resolve_at(AT_FDCWD, path, ResolveOptions::FOLLOW, false)?;
        let node = self
            .tree
            .lookup_path(resolved.guest_path())
            .ok_or(VfsError::NoEntry)?;
        if !node.is_directory() {
            return Err(VfsError::NotDirectory);
        }
        node.attr().check_access(X_OK)?;
        self.rootfs.set_cwd(resolved.guest_path().clone())
    }

    pub fn umask(&mut self, mask: u32) -> u32 {
        let old = self.umask;
        self.umask = mask & 0o777;
        old
    }

    pub fn openat(&mut self, dirfd: Fd, path: &str, flags: OpenFlags, mode: u32) -> VfsResult<Fd> {
        let resolved = self.resolve_at(
            dirfd,
            path,
            if flags.nofollow() {
                ResolveOptions::NOFOLLOW_FINAL
            } else {
                ResolveOptions::FOLLOW
            },
            false,
        )?;
        let path = resolved.guest_path().clone();
        let node_missing = resolved.inode().is_none();
        let mut created_parent = None;
        let mut truncated_inode = None;

        if node_missing {
            if !flags.create() {
                return Err(VfsError::NoEntry);
            }
            self.tree.ensure_parent_dir(&path)?;
            self.check_parent_write_permissions(&path)?;
            self.create_resolved_file(path.clone(), mode & !self.umask)?;
            created_parent = self.parent_inode(&path);
        } else if flags.create() && flags.exclusive() {
            return Err(VfsError::AlreadyExists);
        }

        let node = self.tree.lookup_path(&path).ok_or(VfsError::NoEntry)?;
        if flags.directory() && !node.attr().is_directory() {
            return Err(VfsError::NotDirectory);
        }
        let is_regular_file = matches!(node.kind(), PathNodeKind::File);
        if node.attr().is_symlink() && flags.nofollow() {
            return Err(VfsError::Loop);
        }
        if node.attr().is_directory() && flags.can_write() {
            return Err(VfsError::IsDirectory);
        }
        let mut access_mode = F_OK;
        if flags.can_read() {
            access_mode |= R_OK;
        }
        if flags.can_write() {
            access_mode |= W_OK;
        }
        if created_parent.is_none() {
            node.attr().check_access(access_mode)?;
        }
        if flags.truncate() && flags.can_write() && is_regular_file {
            truncated_inode = Some(node.inode_id());
            self.tree
                .lookup_path_mut(&path)
                .ok_or(VfsError::NoEntry)?
                .truncate()?;
        }
        let node = self.tree.lookup_path(&path).ok_or(VfsError::NoEntry)?;
        let kind = match node.kind() {
            PathNodeKind::Directory => FileKind::Directory,
            PathNodeKind::File => FileKind::Regular,
            PathNodeKind::Device(kind) => FileKind::Dev(*kind),
            PathNodeKind::Proc(kind) => kind.file_kind(),
            PathNodeKind::Symlink(_) => FileKind::Symlink,
        };
        let fd = self.fds.insert_open(
            FileRef::new(
                Arc::new(Inode::new(
                    node.inode_id(),
                    inode_backend_for_path_node(node, self.host_path(&path)),
                )),
                kind,
            ),
            flags,
            Some(path),
        )?;
        if let Some(parent_inode) = created_parent {
            self.invalidate_inode_cache(parent_inode);
        }
        if let Some(inode_id) = truncated_inode {
            self.invalidate_inode_cache(inode_id);
        }
        Ok(fd)
    }

    pub fn close(&mut self, fd: Fd) -> VfsResult<()> {
        let file = self.fds.close(fd)?;
        let inode_id = file.inode().id();
        if self.tree.lookup_inode(inode_id).is_some() && self.tree.link_count(inode_id) == 0 {
            self.tree.inodes.remove(&inode_id);
            self.invalidate_inode_cache(inode_id);
        }
        Ok(())
    }

    pub fn close_with_file(&mut self, fd: Fd) -> VfsResult<FileRef> {
        let file = self.fds.close(fd)?;
        let inode_id = file.inode().id();
        if self.tree.lookup_inode(inode_id).is_some() && self.tree.link_count(inode_id) == 0 {
            self.tree.inodes.remove(&inode_id);
            self.invalidate_inode_cache(inode_id);
        }
        Ok(file)
    }

    pub fn read(&mut self, fd: Fd, buffer: &mut [u8]) -> VfsResult<usize> {
        if let Some(count) = self.read_from_small_cache(fd, buffer)? {
            return Ok(count);
        }
        let Some((inode_id, offset)) = self.regular_read_request(fd)? else {
            return self.fds.read(&self.tree, &self.proc_self, fd, buffer);
        };
        let count = self.read_regular_inode_at(inode_id, offset, buffer)?;
        let entry = self.fds.get(fd)?;
        entry.description().offset = offset
            .checked_add(count as u64)
            .ok_or(VfsError::InvalidPath)?;
        Ok(count)
    }

    pub fn can_regular_readv_fast_path(&self, fd: Fd) -> VfsResult<bool> {
        let entry = self.fds.get(fd)?;
        if !entry.flags().can_read() {
            return Err(VfsError::BadFd);
        }
        Ok(matches!(
            entry.file().kind(),
            FileKind::Regular | FileKind::Symlink
        ))
    }

    pub fn readv_regular(&mut self, fd: Fd, buffers: &mut [Vec<u8>]) -> VfsResult<Option<usize>> {
        let Some((inode_id, offset)) = self.regular_read_request(fd)? else {
            return Ok(None);
        };
        let total_len = vectored_len(buffers.iter().map(Vec::len))?;
        if total_len == 0 {
            return Ok(Some(0));
        }

        let mut staging = vec![0; total_len];
        let count = self.read_regular_inode_at(inode_id, offset, &mut staging)?;
        scatter_vectored(&staging[..count], buffers);
        let entry = self.fds.get(fd)?;
        entry.description().offset = offset
            .checked_add(count as u64)
            .ok_or(VfsError::InvalidPath)?;
        Ok(Some(count))
    }

    pub fn pread(&self, fd: Fd, offset: u64, buffer: &mut [u8]) -> VfsResult<usize> {
        if let Some(count) = self.cached_small_read_at(fd, offset, buffer)? {
            return Ok(count);
        }
        let Some((inode_id, _)) = self.regular_read_request(fd)? else {
            return self
                .fds
                .pread(&self.tree, &self.proc_self, fd, offset, buffer);
        };
        self.read_regular_inode_at(inode_id, offset, buffer)
    }

    pub fn regular_file_cache_key(&self, fd: Fd) -> VfsResult<Option<RegularFileCacheKey>> {
        let entry = self.fds.get(fd)?;
        if !entry.flags().can_read() {
            return Err(VfsError::BadFd);
        }
        if !matches!(entry.file().kind(), FileKind::Regular) {
            return Ok(None);
        }
        let inode = entry.inode_id();
        let Some(node) = self.tree.lookup_inode(inode) else {
            return Ok(None);
        };
        if !matches!(node.kind(), PathNodeKind::File) {
            return Ok(None);
        }
        Ok(Some(RegularFileCacheKey {
            inode,
            generation: self.cache.borrow().regular_file_generation(inode),
        }))
    }

    pub fn map_readonly_regular_file_at(
        &self,
        fd: Fd,
        offset: u64,
        len: usize,
    ) -> VfsResult<Option<mcr_win::HostFileMapping>> {
        if len == 0 {
            return Ok(None);
        }
        let entry = self.fds.get(fd)?;
        if !entry.flags().can_read() {
            return Err(VfsError::BadFd);
        }
        if !matches!(entry.file().kind(), FileKind::Regular) {
            return Ok(None);
        }
        let Some(node) = self.tree.lookup_inode(entry.inode_id()) else {
            return Ok(None);
        };
        if !matches!(node.kind(), PathNodeKind::File) {
            return Ok(None);
        }
        let Some(path) = node.deferred_host_path() else {
            return Ok(None);
        };
        let Some(available) = node.attr().size.checked_sub(offset) else {
            return Ok(None);
        };
        let map_len = len.min(usize::try_from(available).unwrap_or(usize::MAX));
        if map_len == 0 {
            return Ok(None);
        }
        let file = self.cached_host_read_handle(entry.inode_id(), path)?;
        match file.map_readonly_at(offset, map_len) {
            Ok(mapping) => Ok(Some(mapping)),
            Err(error)
                if matches!(
                    error.kind(),
                    mcr_win::HostErrorKind::InvalidInput | mcr_win::HostErrorKind::Unsupported
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(vfs_error_from_host(error)),
        }
    }

    pub fn can_regular_writev_fast_path(&self, fd: Fd) -> VfsResult<bool> {
        let entry = self.fds.get(fd)?;
        if !entry.flags().can_write() {
            return Err(VfsError::BadFd);
        }
        Ok(matches!(entry.file().kind(), FileKind::Regular))
    }

    pub fn writev_regular(&mut self, fd: Fd, buffers: &[Vec<u8>]) -> VfsResult<Option<usize>> {
        let (inode_id, count) = {
            let entry = self.fds.get_mut(fd)?;
            if !entry.flags().can_write() {
                return Err(VfsError::BadFd);
            }
            if !matches!(entry.file().kind(), FileKind::Regular) {
                return Ok(None);
            }

            let inode_id = entry.inode_id();
            let node = self
                .tree
                .lookup_inode_mut(inode_id)
                .ok_or(VfsError::NoEntry)?;
            let total_len = vectored_len(buffers.iter().map(Vec::len))?;
            if total_len == 0 {
                return Ok(Some(0));
            }

            let mut staging = Vec::with_capacity(total_len);
            for buffer in buffers {
                staging.extend_from_slice(buffer);
            }
            let mut description = entry.description();
            let offset = if description.flags.append() {
                node.attr().size
            } else {
                description.offset
            };
            let count = node.write_at(offset, &staging)?;
            description.offset = offset + count as u64;
            (inode_id, count)
        };
        if count > 0 {
            self.invalidate_inode_cache(inode_id);
        }
        Ok(Some(count))
    }

    pub fn write(&mut self, fd: Fd, buffer: &[u8]) -> VfsResult<usize> {
        let regular_inode = self
            .fds
            .get(fd)
            .ok()
            .filter(|entry| matches!(entry.file().kind(), FileKind::Regular))
            .map(FdEntry::inode_id);
        let count = self.fds.write(&mut self.tree, fd, buffer)?;
        if count > 0 {
            if let Some(inode_id) = regular_inode {
                self.invalidate_inode_cache(inode_id);
            }
        }
        Ok(count)
    }

    pub fn lseek(&mut self, fd: Fd, offset: i64, whence: SeekWhence) -> VfsResult<u64> {
        self.fds.seek(&self.tree, fd, offset, whence)
    }

    pub fn fstat(&self, fd: Fd) -> VfsResult<LinuxFileAttr> {
        let entry = self.fds.get(fd)?;
        if let Some(node) = self.tree.lookup_inode(entry.inode_id()) {
            return Ok(self.cached_metadata(node));
        }

        Ok(anonymous_attr(entry.file()))
    }

    pub fn sync_fd(&self, fd: Fd) -> VfsResult<()> {
        let entry = self.fds.get(fd)?;
        if matches!(entry.file().kind(), FileKind::Regular | FileKind::Directory) {
            Ok(())
        } else {
            Err(VfsError::InvalidPath)
        }
    }

    pub fn statfs(&self, path: &str) -> VfsResult<LinuxStatfs> {
        if path.is_empty() {
            return Err(VfsError::NoEntry);
        }
        let resolved = self.rootfs.resolve_path(path, &self.tree)?;
        self.check_traversal_permissions(resolved.guest_path())?;
        let node = self
            .tree
            .lookup_path(resolved.guest_path())
            .ok_or(VfsError::NoEntry)?;
        Ok(statfs_for_path_node(node))
    }

    pub fn fstatfs(&self, fd: Fd) -> VfsResult<LinuxStatfs> {
        let entry = self.fds.get(fd)?;
        Ok(
            if let Some(node) = self.tree.lookup_inode(entry.inode_id()) {
                statfs_for_path_node(node)
            } else {
                statfs_for_file(entry.file())
            },
        )
    }

    pub fn pipe(&mut self, flags: OpenFlags) -> VfsResult<[Fd; 2]> {
        self.fds.pipe(flags)
    }

    pub fn insert_socket(&mut self, socket_id: u64, flags: OpenFlags) -> VfsResult<Fd> {
        self.fds.insert_socket(socket_id, flags)
    }

    pub fn insert_epoll(&mut self, epoll_id: u64, flags: OpenFlags) -> VfsResult<Fd> {
        self.fds.insert_epoll(epoll_id, flags)
    }

    pub fn eventfd(&mut self, initial: u64, flags: OpenFlags) -> VfsResult<Fd> {
        self.fds.eventfd(initial, flags)
    }

    pub fn socket_id_for_fd(&self, fd: Fd) -> VfsResult<u64> {
        self.fds.socket_id_for_fd(fd)
    }

    pub fn epoll_id_for_fd(&self, fd: Fd) -> VfsResult<u64> {
        self.fds.epoll_id_for_fd(fd)
    }

    pub fn socket_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.fds.socket_ids()
    }

    pub fn socket_fd_count(&self, socket_id: u64) -> usize {
        self.fds.socket_fd_count(socket_id)
    }

    pub fn epoll_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.fds.epoll_ids()
    }

    pub fn epoll_fd_count(&self, epoll_id: u64) -> usize {
        self.fds.epoll_fd_count(epoll_id)
    }

    pub fn poll_readiness(&self, fd: Fd) -> VfsResult<FdReadiness> {
        self.fds.poll_readiness(&self.tree, fd)
    }

    pub fn dup(&mut self, oldfd: Fd) -> VfsResult<Fd> {
        self.fds.dup(oldfd, FIRST_USER_FD, false)
    }

    pub fn dup2(&mut self, oldfd: Fd, newfd: Fd) -> VfsResult<Fd> {
        self.fds.dup2(oldfd, newfd, false)
    }

    pub fn dup3(&mut self, oldfd: Fd, newfd: Fd, flags: OpenFlags) -> VfsResult<Fd> {
        if flags.raw() & !O_CLOEXEC != 0 || oldfd == newfd {
            return Err(VfsError::InvalidPath);
        }
        self.fds.dup2(oldfd, newfd, flags.cloexec())
    }

    pub fn fcntl(&mut self, fd: Fd, cmd: u32, arg: u64) -> VfsResult<u64> {
        match cmd {
            F_DUPFD => {
                let min_fd = i32::try_from(arg).map_err(|_| VfsError::BadFd)?;
                Ok(self.fds.dup(fd, min_fd, false)? as u64)
            }
            F_DUPFD_CLOEXEC => {
                let min_fd = i32::try_from(arg).map_err(|_| VfsError::BadFd)?;
                Ok(self.fds.dup(fd, min_fd, true)? as u64)
            }
            F_GETFD => Ok(self.fds.fd_flags(fd)? as u64),
            F_SETFD => {
                self.fds.set_fd_flags(fd, arg as u32)?;
                Ok(0)
            }
            F_GETFL => Ok(self.fds.status_flags(fd)? as u64),
            F_SETFL => {
                self.fds.set_status_flags(fd, arg as u32)?;
                Ok(0)
            }
            F_GETPIPE_SZ => Ok(self.fds.pipe_capacity(fd)? as u64),
            F_SETPIPE_SZ => {
                let capacity = usize::try_from(arg).map_err(|_| VfsError::InvalidPath)?;
                Ok(self.fds.set_pipe_capacity(fd, capacity)? as u64)
            }
            _ => Err(VfsError::InvalidPath),
        }
    }

    pub fn ioctl(&self, fd: Fd, request: u64) -> VfsResult<IoctlReply> {
        let entry = self.fds.get(fd)?;
        match request {
            FIONREAD => Ok(IoctlReply::U32(
                u32::try_from(self.fds.available_bytes(&self.tree, fd)?).unwrap_or(u32::MAX),
            )),
            TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGPGRP | TIOCSPGRP | TIOCGWINSZ => {
                match entry.file().kind() {
                    FileKind::Stdio(_) => Err(VfsError::NotTerminal),
                    _ => Err(VfsError::NotTerminal),
                }
            }
            _ => Err(VfsError::NotTerminal),
        }
    }

    pub fn newfstatat(&self, dirfd: Fd, path: &str, flags: u32) -> VfsResult<LinuxFileAttr> {
        if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
            return self.fstat(dirfd);
        }
        let options = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            ResolveOptions::NOFOLLOW_FINAL
        } else {
            ResolveOptions::FOLLOW
        };
        let resolved = self.resolve_at(dirfd, path, options, false)?;
        self.stat_path(resolved.guest_path())
    }

    pub fn statx(&self, dirfd: Fd, path: &str, flags: u32) -> VfsResult<LinuxFileAttr> {
        self.newfstatat(dirfd, path, flags)
    }

    pub fn chmod(&mut self, path: &str, mode: u32) -> VfsResult<()> {
        let resolved = self.resolve_at(AT_FDCWD, path, ResolveOptions::FOLLOW, false)?;
        let node = self
            .tree
            .lookup_path_mut(resolved.guest_path())
            .ok_or(VfsError::NoEntry)?;
        let inode_id = node.inode_id();
        node.metadata.set_mode(mode);
        self.invalidate_inode_cache(inode_id);
        Ok(())
    }

    pub fn chown(&mut self, path: &str, uid: Option<u32>, gid: Option<u32>) -> VfsResult<()> {
        let resolved = self.resolve_at(AT_FDCWD, path, ResolveOptions::FOLLOW, false)?;
        let node = self
            .tree
            .lookup_path_mut(resolved.guest_path())
            .ok_or(VfsError::NoEntry)?;
        let inode_id = node.inode_id();
        node.metadata.set_owner(uid, gid);
        self.invalidate_inode_cache(inode_id);
        Ok(())
    }

    pub fn utimensat(
        &mut self,
        dirfd: Fd,
        path: &str,
        times: FileTimes,
        flags: u32,
    ) -> VfsResult<()> {
        if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(VfsError::InvalidPath);
        }
        let inode_id = if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
            self.fds.get(dirfd)?.inode_id()
        } else {
            let options = if flags & AT_SYMLINK_NOFOLLOW != 0 {
                ResolveOptions::NOFOLLOW_FINAL
            } else {
                ResolveOptions::FOLLOW
            };
            self.resolve_at(dirfd, path, options, false)?
                .inode()
                .ok_or(VfsError::NoEntry)?
        };
        self.tree
            .lookup_inode_mut(inode_id)
            .ok_or(VfsError::NoEntry)?
            .metadata
            .set_times(times);
        self.invalidate_inode_cache(inode_id);
        Ok(())
    }

    pub fn access(&self, path: &str, mode: u32) -> VfsResult<()> {
        if path.is_empty() {
            return Err(VfsError::NoEntry);
        }
        let resolved = self.rootfs.resolve_path(path, &self.tree)?;
        self.check_traversal_permissions(resolved.guest_path())?;
        let attr = self.stat_path(resolved.guest_path())?;
        attr.check_access(mode)
    }

    pub fn faccessat2(&self, dirfd: Fd, path: &str, mode: u32, flags: u32) -> VfsResult<()> {
        if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
            return Err(VfsError::InvalidPath);
        }
        let attr = if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
            self.fstat(dirfd)?
        } else {
            if path.is_empty() {
                return Err(VfsError::NoEntry);
            }
            let options = if flags & AT_SYMLINK_NOFOLLOW != 0 {
                ResolveOptions::NOFOLLOW_FINAL
            } else {
                ResolveOptions::FOLLOW
            };
            let resolved = self.resolve_at(dirfd, path, options, false)?;
            self.stat_path(resolved.guest_path())?
        };
        attr.check_access(mode)
    }

    pub fn readlink(&self, path: &str, buffer: &mut [u8]) -> VfsResult<usize> {
        if path.is_empty() {
            return Err(VfsError::NoEntry);
        }
        let resolved = self.rootfs.resolve_path_with_options(
            path,
            &self.tree,
            ResolveOptions::NOFOLLOW_FINAL,
        )?;
        self.check_traversal_permissions(resolved.guest_path())?;
        self.readlink_resolved(resolved.guest_path(), buffer)
    }

    pub fn readlinkat(&self, dirfd: Fd, path: &str, buffer: &mut [u8]) -> VfsResult<usize> {
        if path.is_empty() {
            let entry = self.fds.get(dirfd)?;
            let path = entry.path().ok_or(VfsError::NoEntry)?;
            return self.readlink_resolved(path, buffer);
        }
        let resolved = self.resolve_at(dirfd, path, ResolveOptions::NOFOLLOW_FINAL, false)?;
        self.readlink_resolved(resolved.guest_path(), buffer)
    }

    pub fn getdents64(&mut self, fd: Fd, max_bytes: usize) -> VfsResult<Vec<DirectoryEntry>> {
        let source = self.fds.directory_listing_source(&self.tree, fd)?;
        let entries = if source.cacheable {
            self.cached_directory_entries(source.inode, &source.path)?
        } else {
            self.fds.directory_entries(&self.tree, &source.path)?.into()
        };
        self.fds.consume_directory_entries(fd, max_bytes, &entries)
    }

    pub fn mkdirat(&mut self, dirfd: Fd, path: &str, mode: u32) -> VfsResult<()> {
        let resolved = self.resolve_at(dirfd, path, ResolveOptions::NOFOLLOW_FINAL, false)?;
        if resolved.inode().is_some() {
            return Err(VfsError::AlreadyExists);
        }
        self.tree.ensure_parent_dir(resolved.guest_path())?;
        self.check_parent_write_permissions(resolved.guest_path())?;
        let inode_id = self.tree.allocate_inode_id();
        self.tree.insert_path_node(
            resolved.guest_path().clone(),
            PathNode {
                inode_id,
                kind: PathNodeKind::Directory,
                metadata: MetadataSidecar::new(LinuxFileAttr::directory_with_mode(
                    inode_id,
                    mode & !self.umask,
                )),
                data: Vec::new(),
                deferred_host_path: None,
            },
        )?;
        self.invalidate_parent_cache(resolved.guest_path());
        Ok(())
    }

    pub fn unlinkat(&mut self, dirfd: Fd, path: &str, flags: u32) -> VfsResult<()> {
        if flags & !AT_REMOVEDIR != 0 {
            return Err(VfsError::InvalidPath);
        }
        let remove_dir = flags & AT_REMOVEDIR != 0;
        let resolved = self.resolve_at(dirfd, path, ResolveOptions::NOFOLLOW_FINAL, false)?;
        let target = resolved.guest_path().clone();
        if target.is_root() {
            return Err(VfsError::PermissionDenied);
        }
        let node = self.tree.lookup_path(&target).ok_or(VfsError::NoEntry)?;
        if remove_dir {
            if !node.is_directory() {
                return Err(VfsError::NotDirectory);
            }
            if !self.tree.is_empty_directory(&target) {
                return Err(VfsError::NotEmpty);
            }
        } else if node.is_directory() {
            return Err(VfsError::IsDirectory);
        }
        self.check_parent_write_permissions(&target)?;
        let parent_inode = self.parent_inode(&target);
        let inode_id = self.tree.remove_path_link(&target)?;
        self.drop_link(inode_id);
        self.invalidate_inode_caches([parent_inode, Some(inode_id)].into_iter().flatten());
        Ok(())
    }

    pub fn symlinkat(&mut self, target: &str, newdirfd: Fd, linkpath: &str) -> VfsResult<()> {
        if target.is_empty() || target.as_bytes().contains(&0) {
            return Err(VfsError::InvalidPath);
        }
        let resolved =
            self.resolve_at(newdirfd, linkpath, ResolveOptions::NOFOLLOW_FINAL, false)?;
        if resolved.inode().is_some() {
            return Err(VfsError::AlreadyExists);
        }
        self.tree.ensure_parent_dir(resolved.guest_path())?;
        self.check_parent_write_permissions(resolved.guest_path())?;
        let inode_id = self.tree.allocate_inode_id();
        self.tree.insert_path_node(
            resolved.guest_path().clone(),
            PathNode {
                inode_id,
                kind: PathNodeKind::Symlink(target.to_owned()),
                metadata: MetadataSidecar::new(LinuxFileAttr::symlink(
                    inode_id,
                    target.len() as u64,
                )),
                data: Vec::new(),
                deferred_host_path: None,
            },
        )?;
        self.invalidate_parent_cache(resolved.guest_path());
        Ok(())
    }

    pub fn linkat(
        &mut self,
        olddirfd: Fd,
        oldpath: &str,
        newdirfd: Fd,
        newpath: &str,
        flags: u32,
    ) -> VfsResult<()> {
        if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(VfsError::InvalidPath);
        }
        if oldpath.is_empty() && flags & AT_EMPTY_PATH == 0 {
            return Err(VfsError::NoEntry);
        }
        let old_resolved = if oldpath.is_empty() && flags & AT_EMPTY_PATH != 0 {
            let entry = self.fds.get(olddirfd)?;
            let path = entry.path().ok_or(VfsError::NoEntry)?;
            ResolvedPath {
                guest_path: path.clone(),
                inode: Some(entry.inode_id()),
            }
        } else {
            self.resolve_at(
                olddirfd,
                oldpath,
                if flags & AT_SYMLINK_FOLLOW != 0 {
                    ResolveOptions::FOLLOW
                } else {
                    ResolveOptions::NOFOLLOW_FINAL
                },
                false,
            )?
        };
        let old_inode = old_resolved.inode().ok_or(VfsError::NoEntry)?;
        let old_node = self.tree.lookup_inode(old_inode).ok_or(VfsError::NoEntry)?;
        if old_node.is_directory() {
            return Err(VfsError::NotPermitted);
        }

        let new_resolved =
            self.resolve_at(newdirfd, newpath, ResolveOptions::NOFOLLOW_FINAL, false)?;
        if new_resolved.inode().is_some() {
            return Err(VfsError::AlreadyExists);
        }
        self.tree.ensure_parent_dir(new_resolved.guest_path())?;
        self.check_parent_write_permissions(new_resolved.guest_path())?;
        self.tree
            .lookup_inode_mut(old_inode)
            .ok_or(VfsError::NoEntry)?
            .increment_link_count()?;
        self.tree
            .insert_link(new_resolved.guest_path().clone(), old_inode)?;
        self.invalidate_inode_caches(
            [
                self.parent_inode(new_resolved.guest_path()),
                Some(old_inode),
            ]
            .into_iter()
            .flatten(),
        );
        Ok(())
    }

    pub fn renameat2(
        &mut self,
        olddirfd: Fd,
        oldpath: &str,
        newdirfd: Fd,
        newpath: &str,
        flags: u32,
    ) -> VfsResult<()> {
        if flags & !SUPPORTED_RENAME_FLAGS != 0 {
            return Err(VfsError::InvalidPath);
        }
        if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
            return Err(VfsError::InvalidPath);
        }

        let old_resolved =
            self.resolve_at(olddirfd, oldpath, ResolveOptions::NOFOLLOW_FINAL, false)?;
        let new_resolved =
            self.resolve_at(newdirfd, newpath, ResolveOptions::NOFOLLOW_FINAL, false)?;
        let old_path = old_resolved.guest_path().clone();
        let new_path = new_resolved.guest_path().clone();
        if old_path.is_root() || new_path.is_root() {
            return Err(VfsError::PermissionDenied);
        }
        let old_inode = old_resolved.inode().ok_or(VfsError::NoEntry)?;
        if old_path == new_path {
            return Ok(());
        }
        let old_node = self.tree.lookup_inode(old_inode).ok_or(VfsError::NoEntry)?;
        let new_inode = new_resolved.inode();
        if flags & RENAME_NOREPLACE != 0 && new_inode.is_some() {
            return Err(VfsError::AlreadyExists);
        }
        if old_node.is_directory()
            && new_path.starts_with(&old_path)
            && flags & RENAME_EXCHANGE == 0
        {
            return Err(VfsError::InvalidPath);
        }
        self.tree.ensure_parent_dir(&new_path)?;
        self.check_parent_write_permissions(&old_path)?;
        self.check_parent_write_permissions(&new_path)?;

        if flags & RENAME_EXCHANGE != 0 {
            let new_inode = new_inode.ok_or(VfsError::NoEntry)?;
            self.exchange_paths(&old_path, old_inode, &new_path, new_inode)?;
            self.invalidate_vfs_caches();
            return Ok(());
        }

        if let Some(target_inode) = new_inode {
            self.validate_rename_replacement(old_inode, target_inode, &new_path)?;
            self.remove_existing_rename_target(&new_path, target_inode)?;
        }
        let old_parent = self.parent_inode(&old_path);
        let new_parent = self.parent_inode(&new_path);
        self.move_path(&old_path, &new_path)?;
        self.invalidate_inode_caches([old_parent, new_parent, new_inode].into_iter().flatten());
        Ok(())
    }

    pub fn ftruncate(&mut self, fd: Fd, length: u64) -> VfsResult<()> {
        let entry = self.fds.get(fd)?;
        if !entry.flags().can_write() {
            return Err(VfsError::BadFd);
        }
        if !matches!(entry.file().kind(), FileKind::Regular) {
            return Err(VfsError::InvalidPath);
        }
        let inode_id = entry.inode_id();
        self.tree
            .lookup_inode_mut(inode_id)
            .ok_or(VfsError::NoEntry)?
            .set_len(length)?;
        self.invalidate_inode_cache(inode_id);
        Ok(())
    }

    fn read_from_small_cache(&self, fd: Fd, buffer: &mut [u8]) -> VfsResult<Option<usize>> {
        let entry = self.fds.get(fd)?;
        let offset = entry.offset();
        let Some(count) = self.cached_small_read_for_entry(entry, offset, buffer)? else {
            return Ok(None);
        };
        entry.description().offset = offset
            .checked_add(count as u64)
            .ok_or(VfsError::InvalidPath)?;
        Ok(Some(count))
    }

    fn cached_small_read_at(
        &self,
        fd: Fd,
        offset: u64,
        buffer: &mut [u8],
    ) -> VfsResult<Option<usize>> {
        let entry = self.fds.get(fd)?;
        self.cached_small_read_for_entry(entry, offset, buffer)
    }

    fn cached_small_read_for_entry(
        &self,
        entry: &FdEntry,
        offset: u64,
        buffer: &mut [u8],
    ) -> VfsResult<Option<usize>> {
        if !entry.flags().can_read() {
            return Err(VfsError::BadFd);
        }
        if !matches!(entry.file().kind(), FileKind::Regular) {
            return Ok(None);
        }
        if buffer.is_empty() {
            return Ok(Some(0));
        }

        let inode_id = entry.inode_id();
        let node = self.tree.lookup_inode(inode_id).ok_or(VfsError::NoEntry)?;
        if !matches!(node.kind(), PathNodeKind::File) {
            return Ok(None);
        }
        if node.deferred_host_path().is_some() {
            return Ok(None);
        }
        if node.data().len() > SMALL_READ_CACHE_LIMIT {
            return Ok(None);
        }

        let data = self.cached_small_read_data(inode_id, node.data());
        let offset = usize::try_from(offset).map_err(|_| VfsError::InvalidPath)?;
        let available = data.get(offset..).unwrap_or(&[]);
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(Some(count))
    }

    fn regular_read_request(&self, fd: Fd) -> VfsResult<Option<(InodeId, u64)>> {
        let entry = self.fds.get(fd)?;
        if !entry.flags().can_read() {
            return Err(VfsError::BadFd);
        }
        if !matches!(entry.file().kind(), FileKind::Regular | FileKind::Symlink) {
            return Ok(None);
        }
        Ok(Some((entry.inode_id(), entry.offset())))
    }

    fn read_regular_inode_at(
        &self,
        inode_id: InodeId,
        offset: u64,
        buffer: &mut [u8],
    ) -> VfsResult<usize> {
        let node = self.tree.lookup_inode(inode_id).ok_or(VfsError::NoEntry)?;
        if node.attr().is_directory() {
            return Err(VfsError::IsDirectory);
        }
        let host_file = node
            .deferred_host_path()
            .map(|path| self.cached_host_read_handle(inode_id, path))
            .transpose()?;
        read_regular_node_at(node, &self.proc_self, offset, buffer, host_file.as_deref())
    }

    fn cached_host_read_handle(
        &self,
        inode_id: InodeId,
        path: &Path,
    ) -> VfsResult<Rc<mcr_win::HostFile>> {
        self.cache.borrow_mut().host_read_handle(inode_id, path)
    }

    fn resolve_at(
        &self,
        dirfd: Fd,
        path: &str,
        options: ResolveOptions,
        require_directory_base: bool,
    ) -> VfsResult<ResolvedPath> {
        if path.is_empty() {
            return Err(VfsError::NoEntry);
        }
        if path.starts_with('/') || dirfd == AT_FDCWD {
            let resolved = self
                .rootfs
                .resolve_path_with_options(path, &self.tree, options)?;
            self.check_traversal_permissions(resolved.guest_path())?;
            return Ok(resolved);
        }

        let entry = self.fds.get(dirfd)?;
        let base = entry.path().ok_or(VfsError::NotDirectory)?;
        let base_node = self.tree.lookup_path(base).ok_or(VfsError::NoEntry)?;
        if !base_node.is_directory() {
            return Err(VfsError::NotDirectory);
        }
        if require_directory_base {
            base_node.attr().check_access(X_OK)?;
        }

        let mut scoped_rootfs = self.rootfs.clone();
        scoped_rootfs.set_cwd(base.clone())?;
        let resolved = scoped_rootfs.resolve_path_with_options(path, &self.tree, options)?;
        self.check_traversal_permissions(resolved.guest_path())?;
        Ok(resolved)
    }

    fn create_resolved_file(&mut self, path: GuestPath, mode: u32) -> VfsResult<()> {
        self.tree.ensure_parent_dir(&path)?;
        let inode_id = self.tree.allocate_inode_id();
        self.tree.insert_path_node(
            path,
            PathNode {
                inode_id,
                kind: PathNodeKind::File,
                metadata: MetadataSidecar::new(LinuxFileAttr::regular(inode_id, mode, 0)),
                data: Vec::new(),
                deferred_host_path: None,
            },
        )
    }

    fn parent_inode(&self, path: &GuestPath) -> Option<InodeId> {
        let parent = path.parent()?;
        self.tree.lookup_path(&parent).map(PathNode::inode_id)
    }

    fn validate_rename_replacement(
        &self,
        old_inode: InodeId,
        target_inode: InodeId,
        target_path: &GuestPath,
    ) -> VfsResult<()> {
        let old_node = self.tree.lookup_inode(old_inode).ok_or(VfsError::NoEntry)?;
        let target_node = self
            .tree
            .lookup_inode(target_inode)
            .ok_or(VfsError::NoEntry)?;
        match (old_node.is_directory(), target_node.is_directory()) {
            (true, false) => Err(VfsError::NotDirectory),
            (false, true) => Err(VfsError::IsDirectory),
            (true, true) if !self.tree.is_empty_directory(target_path) => Err(VfsError::NotEmpty),
            _ => Ok(()),
        }
    }

    fn remove_existing_rename_target(
        &mut self,
        target_path: &GuestPath,
        target_inode: InodeId,
    ) -> VfsResult<()> {
        let target_node = self
            .tree
            .lookup_inode(target_inode)
            .ok_or(VfsError::NoEntry)?;
        if target_node.is_directory() {
            if !self.tree.is_empty_directory(target_path) {
                return Err(VfsError::NotEmpty);
            }
            self.tree.remove_path_link(target_path)?;
            self.drop_link(target_inode);
            return Ok(());
        }

        self.tree.remove_path_link(target_path)?;
        self.drop_link(target_inode);
        Ok(())
    }

    fn move_path(&mut self, old_path: &GuestPath, new_path: &GuestPath) -> VfsResult<()> {
        let moving_paths = self.tree.paths_under_prefix(old_path);
        let mut updates = Vec::with_capacity(moving_paths.len());
        for path in moving_paths {
            let inode_id = self.tree.remove_path_link(&path)?;
            updates.push((
                PathTree::replace_prefix(&path, old_path, new_path),
                inode_id,
            ));
        }
        for (path, inode_id) in updates {
            self.tree.insert_link(path, inode_id)?;
        }
        self.fds.rebind_paths(old_path, new_path);
        Ok(())
    }

    fn exchange_paths(
        &mut self,
        old_path: &GuestPath,
        old_inode: InodeId,
        new_path: &GuestPath,
        new_inode: InodeId,
    ) -> VfsResult<()> {
        let old_is_dir = self
            .tree
            .lookup_inode(old_inode)
            .ok_or(VfsError::NoEntry)?
            .is_directory();
        let new_is_dir = self
            .tree
            .lookup_inode(new_inode)
            .ok_or(VfsError::NoEntry)?
            .is_directory();
        if old_is_dir && new_path.starts_with(old_path) {
            return Err(VfsError::InvalidPath);
        }
        if new_is_dir && old_path.starts_with(new_path) {
            return Err(VfsError::InvalidPath);
        }

        let old_paths = if old_is_dir {
            self.tree.paths_under_prefix(old_path)
        } else {
            vec![old_path.clone()]
        };
        let new_paths = if new_is_dir {
            self.tree.paths_under_prefix(new_path)
        } else {
            vec![new_path.clone()]
        };
        let mut updates = Vec::with_capacity(old_paths.len() + new_paths.len());
        for path in old_paths {
            let inode_id = self.tree.remove_path_link(&path)?;
            updates.push((
                PathTree::replace_prefix(&path, old_path, new_path),
                inode_id,
            ));
        }
        for path in new_paths {
            let inode_id = self.tree.remove_path_link(&path)?;
            updates.push((
                PathTree::replace_prefix(&path, new_path, old_path),
                inode_id,
            ));
        }
        for (path, inode_id) in updates {
            self.tree.insert_link(path, inode_id)?;
        }
        self.fds.rebind_paths(old_path, new_path);
        self.fds.rebind_paths(new_path, old_path);
        Ok(())
    }

    fn drop_link(&mut self, inode_id: InodeId) {
        if let Some(node) = self.tree.lookup_inode_mut(inode_id) {
            node.decrement_link_count();
        }
        if self.tree.link_count(inode_id) == 0 && self.fds.open_count(inode_id) == 0 {
            self.tree.inodes.remove(&inode_id);
        }
    }

    fn stat_path(&self, path: &GuestPath) -> VfsResult<LinuxFileAttr> {
        if let Some(fd) = proc_self_fd_path_fd(path) {
            let target = self.proc_fd_target(fd)?;
            return Ok(LinuxFileAttr::symlink(
                proc_self_fd_link_inode(fd)?,
                target.len() as u64,
            ));
        }

        self.tree
            .lookup_path(path)
            .map(|node| self.cached_metadata(node))
            .ok_or(VfsError::NoEntry)
    }

    fn readlink_resolved(&self, path: &GuestPath, buffer: &mut [u8]) -> VfsResult<usize> {
        let target = if let Some(fd) = proc_self_fd_path_fd(path) {
            Cow::Owned(self.proc_fd_target(fd)?.into_owned().into_bytes())
        } else {
            let node = self.tree.lookup_path(path).ok_or(VfsError::NoEntry)?;
            match node.kind() {
                PathNodeKind::Symlink(target) => Cow::Borrowed(target.as_bytes()),
                PathNodeKind::Proc(ProcNodeKind::Exe) => {
                    Cow::Borrowed(self.proc_self.executable_path())
                }
                PathNodeKind::Proc(ProcNodeKind::FdLink(fd)) => {
                    Cow::Owned(self.proc_fd_target(*fd)?.into_owned().into_bytes())
                }
                _ => return Err(VfsError::InvalidPath),
            }
        };
        let count = target.len().min(buffer.len());
        buffer[..count].copy_from_slice(&target[..count]);
        Ok(count)
    }

    fn proc_fd_target(&self, fd: Fd) -> VfsResult<Cow<'_, str>> {
        let entry = self.fds.get(fd).map_err(|_| VfsError::NoEntry)?;
        match entry.file().kind() {
            FileKind::Regular | FileKind::Directory | FileKind::Symlink => {
                let path = entry.path().ok_or(VfsError::NoEntry)?;
                self.rootfs.visible_path(path).map(Cow::Owned)
            }
            FileKind::Dev(kind) => Ok(Cow::Owned(format!("/dev/{}", kind.name()))),
            FileKind::PipeRead | FileKind::PipeWrite => {
                Ok(Cow::Owned(format!("pipe:[{}]", entry.inode_id())))
            }
            FileKind::Socket => Ok(Cow::Owned(format!("socket:[{}]", entry.inode_id()))),
            FileKind::Epoll => Ok(Cow::Owned(format!(
                "anon_inode:[eventpoll:{}]",
                entry.inode_id()
            ))),
            FileKind::Eventfd => Ok(Cow::Owned(format!(
                "anon_inode:[eventfd:{}]",
                entry.inode_id()
            ))),
            FileKind::Stdio(kind) => Ok(Cow::Owned(format!("/dev/{}", kind.name()))),
        }
    }

    fn check_traversal_permissions(&self, path: &GuestPath) -> VfsResult<()> {
        let mut ancestor = GuestPath::root();
        let components = path.as_components();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            ancestor.push_component(component.clone());
            let Some(node) = self.tree.lookup_path(&ancestor) else {
                break;
            };
            if node.attr().is_directory() {
                node.attr().check_access(X_OK)?;
            }
        }
        Ok(())
    }

    fn check_parent_write_permissions(&self, path: &GuestPath) -> VfsResult<()> {
        let parent = path.parent().ok_or(VfsError::InvalidPath)?;
        let node = self.tree.lookup_path(&parent).ok_or(VfsError::NoEntry)?;
        if !node.is_directory() {
            return Err(VfsError::NotDirectory);
        }
        node.attr().check_access(W_OK | X_OK)
    }

    fn cached_metadata(&self, node: &PathNode) -> LinuxFileAttr {
        let inode_id = node.inode_id();
        if let Some(attr) = self.cache.borrow().metadata(inode_id) {
            return attr;
        }

        let attr = node.attr();
        self.cache.borrow_mut().insert_metadata(inode_id, attr);
        attr
    }

    fn cached_directory_entries(
        &self,
        inode_id: InodeId,
        path: &GuestPath,
    ) -> VfsResult<Arc<[DirectoryEntry]>> {
        if let Some(entries) = self.cache.borrow().directory_listing(inode_id) {
            return Ok(entries);
        }

        let entries: Arc<[DirectoryEntry]> =
            self.fds.static_directory_entries(&self.tree, path)?.into();
        self.cache
            .borrow_mut()
            .insert_directory_listing(inode_id, entries.clone());
        Ok(entries)
    }

    fn cached_small_read_data(&self, inode_id: InodeId, data: &[u8]) -> Arc<[u8]> {
        if let Some(cached) = self.cache.borrow().small_read(inode_id) {
            return cached;
        }

        let cached: Arc<[u8]> = data.into();
        self.cache
            .borrow_mut()
            .insert_small_read(inode_id, cached.clone());
        cached
    }

    fn invalidate_vfs_caches(&self) {
        self.cache.borrow_mut().invalidate_all();
    }

    fn invalidate_proc_caches(&self) {
        self.cache.borrow_mut().invalidate_proc_views();
    }

    fn invalidate_inode_cache(&self, inode_id: InodeId) {
        self.cache.borrow_mut().invalidate_inode(inode_id);
    }

    fn invalidate_inode_caches(&self, inode_ids: impl IntoIterator<Item = InodeId>) {
        self.cache.borrow_mut().invalidate_inodes(inode_ids);
    }

    fn invalidate_parent_cache(&self, path: &GuestPath) {
        if let Some(parent_inode) = self.parent_inode(path) {
            self.invalidate_inode_cache(parent_inode);
        }
    }

    #[cfg(test)]
    pub(crate) fn cache_snapshot(&self) -> VfsCacheSnapshot {
        self.cache.borrow().snapshot()
    }

    fn host_path(&self, path: &GuestPath) -> PathBuf {
        let mut host = self.rootfs.host_root().clone();
        for component in path.as_components() {
            host.push(component);
        }
        host
    }
}
