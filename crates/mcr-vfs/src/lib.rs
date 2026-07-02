use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub type Fd = i32;
pub type InodeId = u64;

const FIRST_USER_FD: Fd = 3;
const ROOT_INODE_ID: InodeId = 1;
const SYMLINK_LIMIT: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsError {
    BadFd,
    InvalidPath,
    Loop,
    NameTooLong,
    NoEntry,
    NotDirectory,
}

impl VfsError {
    pub fn linux_errno(self) -> u16 {
        match self {
            Self::BadFd => 9,
            Self::InvalidPath => 22,
            Self::Loop => 40,
            Self::NameTooLong => 36,
            Self::NoEntry => 2,
            Self::NotDirectory => 20,
        }
    }
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BadFd => "bad file descriptor",
            Self::InvalidPath => "invalid path",
            Self::Loop => "too many symbolic links",
            Self::NameTooLong => "path name is too long",
            Self::NoEntry => "no such file or directory",
            Self::NotDirectory => "not a directory",
        };
        f.write_str(message)
    }
}

impl std::error::Error for VfsError {}

pub type VfsResult<T> = Result<T, VfsError>;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GuestPath {
    components: Vec<String>,
}

impl GuestPath {
    pub fn root() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    pub fn from_components(components: Vec<String>) -> Self {
        Self { components }
    }

    pub fn as_components(&self) -> &[String] {
        &self.components
    }

    pub fn parent(&self) -> Option<Self> {
        let mut components = self.components.clone();
        components.pop()?;
        Some(Self { components })
    }

    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    pub fn starts_with(&self, other: &GuestPath) -> bool {
        self.components.starts_with(&other.components)
    }

    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    pub fn push_component(&mut self, component: String) {
        self.components.push(component);
    }

    pub fn pop_component(&mut self) {
        self.components.pop();
    }

    fn join_component(&self, component: String) -> Self {
        let mut path = self.clone();
        path.push_component(component);
        path
    }
}

impl fmt::Display for GuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.components.is_empty() {
            return f.write_str("/");
        }

        f.write_str("/")?;
        f.write_str(&self.components.join("/"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rootfs {
    host_root: PathBuf,
    root: GuestPath,
    cwd: GuestPath,
}

impl Rootfs {
    pub fn new(host_root: impl Into<PathBuf>) -> Self {
        Self {
            host_root: host_root.into(),
            root: GuestPath::root(),
            cwd: GuestPath::root(),
        }
    }

    pub fn with_guest_root(host_root: impl Into<PathBuf>, root: GuestPath) -> Self {
        Self {
            host_root: host_root.into(),
            cwd: root.clone(),
            root,
        }
    }

    pub fn host_root(&self) -> &PathBuf {
        &self.host_root
    }

    pub fn guest_root(&self) -> &GuestPath {
        &self.root
    }

    pub fn cwd(&self) -> &GuestPath {
        &self.cwd
    }

    pub fn set_cwd(&mut self, cwd: GuestPath) -> VfsResult<()> {
        if cwd.starts_with(&self.root) {
            self.cwd = cwd;
            Ok(())
        } else {
            Err(VfsError::NoEntry)
        }
    }

    pub fn resolve_path(&self, path: impl AsRef<str>, tree: &PathTree) -> VfsResult<ResolvedPath> {
        let resolved = PathResolver::new(self, tree).resolve(path.as_ref())?;
        let inode = tree.lookup_path(&resolved).map(|node| node.inode_id);
        Ok(ResolvedPath {
            guest_path: resolved,
            inode,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPath {
    guest_path: GuestPath,
    inode: Option<InodeId>,
}

impl ResolvedPath {
    pub fn guest_path(&self) -> &GuestPath {
        &self.guest_path
    }

    pub fn inode(&self) -> Option<InodeId> {
        self.inode
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathTree {
    nodes: BTreeMap<GuestPath, PathNode>,
    next_inode_id: InodeId,
}

impl PathTree {
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(GuestPath::root(), PathNode::directory(ROOT_INODE_ID));
        Self {
            nodes,
            next_inode_id: ROOT_INODE_ID + 1,
        }
    }

    pub fn create_dir(&mut self, path: impl AsRef<str>) -> VfsResult<InodeId> {
        let path = parse_absolute_path(path.as_ref())?;
        self.ensure_parent_dir(&path)?;
        self.insert_node(path, PathNodeKind::Directory)
    }

    pub fn create_file(&mut self, path: impl AsRef<str>) -> VfsResult<InodeId> {
        let path = parse_absolute_path(path.as_ref())?;
        self.ensure_parent_dir(&path)?;
        self.insert_node(path, PathNodeKind::File)
    }

    pub fn create_symlink(
        &mut self,
        path: impl AsRef<str>,
        target: impl Into<String>,
    ) -> VfsResult<InodeId> {
        let path = parse_absolute_path(path.as_ref())?;
        let parent = path.parent().ok_or(VfsError::InvalidPath)?;
        if self
            .lookup_path(&parent)
            .is_some_and(|node| !node.is_directory())
        {
            return Err(VfsError::NotDirectory);
        }
        self.insert_node(path, PathNodeKind::Symlink(target.into()))
    }

    pub fn lookup_path(&self, path: &GuestPath) -> Option<&PathNode> {
        self.nodes.get(path)
    }

    fn lookup_symlink_placeholder(&self, path: &GuestPath) -> Option<SymlinkPlaceholder> {
        for ancestor_len in (1..=path.components.len()).rev() {
            let ancestor = GuestPath::from_components(path.components[..ancestor_len].to_vec());
            let Some(node) = self.lookup_path(&ancestor) else {
                continue;
            };
            match node.kind() {
                PathNodeKind::Directory => continue,
                PathNodeKind::File => return None,
                PathNodeKind::Symlink(target) => {
                    let suffix = &path.components[ancestor_len..];
                    let mut rewritten = target.clone();
                    for component in suffix {
                        if !rewritten.ends_with('/') {
                            rewritten.push('/');
                        }
                        rewritten.push_str(component);
                    }
                    return Some(SymlinkPlaceholder {
                        parent: ancestor.parent().unwrap_or_else(GuestPath::root),
                        target: rewritten,
                    });
                }
            }
        }

        None
    }

    fn ensure_parent_dir(&self, path: &GuestPath) -> VfsResult<()> {
        if path.is_root() {
            return Err(VfsError::InvalidPath);
        }

        let parent = path.parent().ok_or(VfsError::InvalidPath)?;
        match self.lookup_path(&parent) {
            Some(node) if node.is_directory() => Ok(()),
            Some(_) => Err(VfsError::NotDirectory),
            None => Err(VfsError::NoEntry),
        }
    }

    fn insert_node(&mut self, path: GuestPath, kind: PathNodeKind) -> VfsResult<InodeId> {
        if self.nodes.contains_key(&path) {
            return Err(VfsError::InvalidPath);
        }

        let inode_id = self.allocate_inode_id();
        self.nodes.insert(path, PathNode { inode_id, kind });
        Ok(inode_id)
    }

    fn allocate_inode_id(&mut self) -> InodeId {
        let inode_id = self.next_inode_id;
        self.next_inode_id += 1;
        inode_id
    }
}

impl Default for PathTree {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathNode {
    inode_id: InodeId,
    kind: PathNodeKind,
}

impl PathNode {
    pub fn directory(inode_id: InodeId) -> Self {
        Self {
            inode_id,
            kind: PathNodeKind::Directory,
        }
    }

    pub fn inode_id(&self) -> InodeId {
        self.inode_id
    }

    pub fn kind(&self) -> &PathNodeKind {
        &self.kind
    }

    pub fn is_directory(&self) -> bool {
        self.kind == PathNodeKind::Directory
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathNodeKind {
    Directory,
    File,
    Symlink(String),
}

#[derive(Debug)]
struct PathResolver<'a> {
    rootfs: &'a Rootfs,
    tree: &'a PathTree,
    symlink_count: usize,
}

impl<'a> PathResolver<'a> {
    fn new(rootfs: &'a Rootfs, tree: &'a PathTree) -> Self {
        Self {
            rootfs,
            tree,
            symlink_count: 0,
        }
    }

    fn resolve(mut self, path: &str) -> VfsResult<GuestPath> {
        if path.is_empty() || path.as_bytes().contains(&0) {
            return Err(VfsError::InvalidPath);
        }

        let mut base = if path.starts_with('/') {
            self.rootfs.root.clone()
        } else {
            self.rootfs.cwd.clone()
        };
        let components = split_guest_components(path)?;
        self.walk(&mut base, components.into_iter())
    }

    fn walk(
        &mut self,
        current: &mut GuestPath,
        components: impl Iterator<Item = String>,
    ) -> VfsResult<GuestPath> {
        let mut pending = components.collect::<Vec<_>>();
        pending.reverse();

        while let Some(component) = pending.pop() {
            match component.as_str() {
                "" | "." => {}
                ".." => {
                    if current.components.len() > self.rootfs.root.components.len() {
                        current.pop_component();
                    }
                }
                _ => {
                    let next_path = current.join_component(component);
                    self.enforce_jail(&next_path)?;
                    if let Some(link) = self.tree.lookup_symlink_placeholder(&next_path) {
                        self.symlink_count += 1;
                        if self.symlink_count > SYMLINK_LIMIT {
                            return Err(VfsError::Loop);
                        }

                        *current = if link.target.starts_with('/') {
                            self.rootfs.root.clone()
                        } else {
                            link.parent.clone()
                        };

                        for next in split_guest_components(&link.target)?.into_iter().rev() {
                            pending.push(next);
                        }
                    } else if let Some(node) = self.tree.lookup_path(&next_path) {
                        if !node.is_directory() && !pending.is_empty() {
                            return Err(VfsError::NotDirectory);
                        }
                        *current = next_path;
                        continue;
                    } else if self.allow_missing_leaf(&next_path, &pending) {
                        *current = next_path;
                        return Ok(current.clone());
                    } else {
                        return Err(VfsError::NoEntry);
                    }
                }
            }
            self.enforce_jail(current)?;
        }

        Ok(current.clone())
    }

    fn enforce_jail(&self, path: &GuestPath) -> VfsResult<()> {
        if path.starts_with(&self.rootfs.root) {
            Ok(())
        } else {
            Err(VfsError::NoEntry)
        }
    }

    fn allow_missing_leaf(&self, current: &GuestPath, pending: &[String]) -> bool {
        current.starts_with(&self.rootfs.root) && pending.is_empty()
    }
}

#[derive(Debug)]
struct SymlinkPlaceholder {
    parent: GuestPath,
    target: String,
}

fn parse_absolute_path(path: &str) -> VfsResult<GuestPath> {
    if !path.starts_with('/') {
        return Err(VfsError::InvalidPath);
    }

    Ok(GuestPath::from_components(split_guest_components(path)?))
}

fn split_guest_components(path: &str) -> VfsResult<Vec<String>> {
    if path.as_bytes().contains(&0) {
        return Err(VfsError::InvalidPath);
    }

    path.split('/')
        .filter(|part| !part.is_empty())
        .map(|part| {
            if part.len() > 255 {
                Err(VfsError::NameTooLong)
            } else {
                Ok(part.to_owned())
            }
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inode {
    id: InodeId,
    backend: InodeBackend,
    link_count: u32,
}

impl Inode {
    pub fn new(id: InodeId, backend: InodeBackend) -> Self {
        Self {
            id,
            backend,
            link_count: 1,
        }
    }

    pub fn id(&self) -> InodeId {
        self.id
    }

    pub fn backend(&self) -> &InodeBackend {
        &self.backend
    }

    pub fn link_count(&self) -> u32 {
        self.link_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InodeBackend {
    HostPath(HostPathRef),
    ProcVirtual(ProcNode),
    DevVirtual(DevNode),
    Pipe(PipeNode),
    Socket(SocketNode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPathRef {
    path: Arc<PathBuf>,
}

impl HostPathRef {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcNode {
    name: String,
}

impl ProcNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevNode {
    name: String,
}

impl DevNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipeNode {
    id: u64,
}

impl PipeNode {
    pub fn new(id: u64) -> Self {
        Self { id }
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketNode {
    id: u64,
}

impl SocketNode {
    pub fn new(id: u64) -> Self {
        Self { id }
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

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
                InodeBackend::DevVirtual(DevNode::new(kind.name())),
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
    Stdio(StdioKind),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdEntry {
    file: FileRef,
    cloexec: bool,
}

impl FdEntry {
    pub fn file(&self) -> &FileRef {
        &self.file
    }

    pub fn cloexec(&self) -> bool {
        self.cloexec
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdTable {
    entries: BTreeMap<Fd, FdEntry>,
    cloexec: HashSet<Fd>,
}

impl FdTable {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            cloexec: HashSet::new(),
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
        if fd < 0 {
            return Err(VfsError::BadFd);
        }
        if self.entries.contains_key(&fd) {
            return Err(VfsError::BadFd);
        }

        self.entries.insert(fd, FdEntry { file, cloexec });
        self.set_cloexec(fd, cloexec)?;
        Ok(())
    }

    pub fn get(&self, fd: Fd) -> VfsResult<&FdEntry> {
        self.entries.get(&fd).ok_or(VfsError::BadFd)
    }

    pub fn close(&mut self, fd: Fd) -> VfsResult<FileRef> {
        let entry = self.entries.remove(&fd).ok_or(VfsError::BadFd)?;
        self.cloexec.remove(&fd);
        Ok(entry.file)
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

        if let Some(entry) = self.entries.get_mut(&fd) {
            entry.cloexec = cloexec;
        }
        Ok(())
    }

    pub fn cloexec(&self, fd: Fd) -> VfsResult<bool> {
        self.get(fd).map(|entry| entry.cloexec)
    }

    pub fn close_on_exec(&mut self) {
        let cloexec = std::mem::take(&mut self.cloexec);
        for fd in cloexec {
            self.entries.remove(&fd);
        }
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
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-vfs");
    }

    #[test]
    fn canonicalizes_dot_and_dot_dot_without_escaping_rootfs() {
        let rootfs = Rootfs::with_guest_root("/host/root", guest_path("/jail"));
        let mut tree = PathTree::new();
        tree.create_dir("/jail").unwrap();
        tree.create_dir("/jail/usr").unwrap();
        tree.create_dir("/jail/usr/local").unwrap();
        tree.create_dir("/jail/usr/bin").unwrap();

        let resolved = rootfs.resolve_path("/usr/./local/../bin", &tree).unwrap();

        assert_eq!(resolved.guest_path().to_string(), "/jail/usr/bin");
        assert_eq!(
            resolved.inode(),
            Some(
                tree.lookup_path(&guest_path("/jail/usr/bin"))
                    .unwrap()
                    .inode_id()
            )
        );
    }

    #[test]
    fn root_escape_via_dot_dot_is_clamped_to_jail_root() {
        let mut rootfs = Rootfs::with_guest_root("/host/root", guest_path("/containers/rootfs"));
        let mut tree = PathTree::new();
        tree.create_dir("/containers").unwrap();
        tree.create_dir("/containers/rootfs").unwrap();
        tree.create_dir("/containers/rootfs/tmp").unwrap();
        rootfs
            .set_cwd(guest_path("/containers/rootfs/tmp"))
            .unwrap();

        let resolved = rootfs.resolve_path("../../../../etc", &tree).unwrap();

        assert_eq!(resolved.guest_path().to_string(), "/containers/rootfs/etc");
        assert_eq!(resolved.inode(), None);
    }

    #[test]
    fn symlink_loop_placeholder_returns_eloop_shape() {
        let rootfs = Rootfs::new("/host/root");
        let mut tree = PathTree::new();
        tree.create_symlink("/loop-a", "/loop-b").unwrap();
        tree.create_symlink("/loop-b", "/loop-a").unwrap();

        let error = rootfs.resolve_path("/loop-a", &tree).unwrap_err();

        assert_eq!(error, VfsError::Loop);
    }

    #[test]
    fn absolute_symlink_target_cannot_escape_guest_root() {
        let rootfs = Rootfs::with_guest_root("/host/root", guest_path("/jail"));
        let mut tree = PathTree::new();
        tree.create_dir("/jail").unwrap();
        tree.create_symlink("/jail/out", "/../../host-secret")
            .unwrap();

        let resolved = rootfs.resolve_path("/out", &tree).unwrap();

        assert_eq!(resolved.guest_path().to_string(), "/jail/host-secret");
        assert_eq!(resolved.inode(), None);
    }

    #[test]
    fn host_paths_are_not_guest_inode_ids() {
        let host_path = PathBuf::from("/tmp/mcr-rootfs/bin/sh");
        let host_path_len = host_path.as_os_str().len() as u64;
        let inode = Inode::new(42, InodeBackend::HostPath(HostPathRef::new(host_path)));

        assert_eq!(inode.id(), 42);
        assert_ne!(inode.id(), host_path_len);
    }

    #[test]
    fn fd_table_initializes_stdio_descriptors() {
        let table = FdTable::with_stdio();

        assert_eq!(
            table.get(0).unwrap().file().kind(),
            FileKind::Stdio(StdioKind::Stdin)
        );
        assert_eq!(
            table.get(1).unwrap().file().kind(),
            FileKind::Stdio(StdioKind::Stdout)
        );
        assert_eq!(
            table.get(2).unwrap().file().kind(),
            FileKind::Stdio(StdioKind::Stderr)
        );
        assert!(!table.cloexec(0).unwrap());
        assert!(!table.cloexec(1).unwrap());
        assert!(!table.cloexec(2).unwrap());
    }

    #[test]
    fn fd_allocation_reuses_lowest_closed_descriptor() {
        let mut table = FdTable::with_stdio();
        let first = table.insert(regular_file(10), false).unwrap();
        let second = table.insert(regular_file(11), false).unwrap();
        table.close(first).unwrap();

        let reused = table.insert(regular_file(12), false).unwrap();

        assert_eq!(first, 3);
        assert_eq!(second, 4);
        assert_eq!(reused, first);
    }

    #[test]
    fn fd_lookup_and_close_report_bad_fd() {
        let mut table = FdTable::with_stdio();

        assert_eq!(table.get(99).unwrap_err(), VfsError::BadFd);
        assert_eq!(table.close(99).unwrap_err(), VfsError::BadFd);
        assert_eq!(
            table.insert_exact(-1, regular_file(1), false).unwrap_err(),
            VfsError::BadFd
        );
    }

    #[test]
    fn cloexec_flags_are_tracked_and_closed_on_exec() {
        let mut table = FdTable::with_stdio();
        let keep = table.insert(regular_file(20), false).unwrap();
        let close = table.insert(regular_file(21), true).unwrap();

        assert!(!table.cloexec(keep).unwrap());
        assert!(table.cloexec(close).unwrap());

        table.set_cloexec(keep, true).unwrap();
        table.set_cloexec(close, false).unwrap();
        table.close_on_exec();

        assert_eq!(table.get(keep).unwrap_err(), VfsError::BadFd);
        assert!(table.get(close).is_ok());
        assert!(table.get(0).is_ok());
    }

    fn guest_path(path: &str) -> GuestPath {
        parse_absolute_path(path).unwrap()
    }

    fn regular_file(inode_id: InodeId) -> FileRef {
        FileRef::new(
            Arc::new(Inode::new(
                inode_id,
                InodeBackend::HostPath(HostPathRef::new(format!("/host/{inode_id}"))),
            )),
            FileKind::Regular,
        )
    }
}
