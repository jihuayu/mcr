use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub type Fd = i32;
pub type InodeId = u64;

pub const AT_FDCWD: Fd = -100;
pub const AT_EMPTY_PATH: u32 = 0x1000;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;
pub const F_OK: u32 = 0;
pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const R_OK: u32 = 4;
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const W_OK: u32 = 2;
pub const X_OK: u32 = 1;

const FIRST_USER_FD: Fd = 3;
const ROOT_INODE_ID: InodeId = 1;
const SYMLINK_LIMIT: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsError {
    AlreadyExists,
    BadFd,
    InvalidPath,
    IsDirectory,
    Loop,
    NameTooLong,
    NoEntry,
    NoSpace,
    NotSeekable,
    NotDirectory,
    PermissionDenied,
}

impl VfsError {
    pub fn linux_errno(self) -> u16 {
        match self {
            Self::AlreadyExists => 17,
            Self::BadFd => 9,
            Self::InvalidPath => 22,
            Self::IsDirectory => 21,
            Self::Loop => 40,
            Self::NameTooLong => 36,
            Self::NoEntry => 2,
            Self::NoSpace => 28,
            Self::NotSeekable => 29,
            Self::NotDirectory => 20,
            Self::PermissionDenied => 13,
        }
    }
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AlreadyExists => "file exists",
            Self::BadFd => "bad file descriptor",
            Self::InvalidPath => "invalid path",
            Self::IsDirectory => "is a directory",
            Self::Loop => "too many symbolic links",
            Self::NameTooLong => "path name is too long",
            Self::NoEntry => "no such file or directory",
            Self::NoSpace => "no space left on device",
            Self::NotSeekable => "illegal seek",
            Self::NotDirectory => "not a directory",
            Self::PermissionDenied => "permission denied",
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

    pub fn resolve_path_with_options(
        &self,
        path: impl AsRef<str>,
        tree: &PathTree,
        options: ResolveOptions,
    ) -> VfsResult<ResolvedPath> {
        let resolved = PathResolver::new(self, tree)
            .with_follow_final_symlink(options.follow_final_symlink)
            .resolve(path.as_ref())?;
        let inode = tree.lookup_path(&resolved).map(|node| node.inode_id);
        Ok(ResolvedPath {
            guest_path: resolved,
            inode,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolveOptions {
    follow_final_symlink: bool,
}

impl ResolveOptions {
    pub const FOLLOW: Self = Self {
        follow_final_symlink: true,
    };
    pub const NOFOLLOW_FINAL: Self = Self {
        follow_final_symlink: false,
    };

    pub const fn follow_final_symlink(self) -> bool {
        self.follow_final_symlink
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

    pub fn create_file_with_content(
        &mut self,
        path: impl AsRef<str>,
        content: impl Into<Vec<u8>>,
        mode: u32,
    ) -> VfsResult<InodeId> {
        let path = parse_absolute_path(path.as_ref())?;
        self.ensure_parent_dir(&path)?;
        let inode_id = self.allocate_inode_id();
        let data = content.into();
        let attr = LinuxFileAttr::regular(inode_id, mode, data.len() as u64);
        self.insert_path_node(
            path,
            PathNode {
                inode_id,
                kind: PathNodeKind::File,
                attr,
                data,
            },
        )?;
        Ok(inode_id)
    }

    pub fn create_symlink(
        &mut self,
        path: impl AsRef<str>,
        target: impl Into<String>,
    ) -> VfsResult<InodeId> {
        let path = parse_absolute_path(path.as_ref())?;
        self.ensure_parent_dir(&path)?;
        self.insert_node(path, PathNodeKind::Symlink(target.into()))
    }

    pub fn lookup_path(&self, path: &GuestPath) -> Option<&PathNode> {
        self.nodes.get(path)
    }

    pub fn lookup_path_mut(&mut self, path: &GuestPath) -> Option<&mut PathNode> {
        self.nodes.get_mut(path)
    }

    pub fn children(&self, path: &GuestPath) -> VfsResult<Vec<DirectoryChild>> {
        let node = self.lookup_path(path).ok_or(VfsError::NoEntry)?;
        if !node.is_directory() {
            return Err(VfsError::NotDirectory);
        }

        let parent_len = path.components.len();
        let mut children = Vec::new();
        for (child_path, child_node) in &self.nodes {
            if child_path.components.len() != parent_len + 1 {
                continue;
            }
            if !child_path.starts_with(path) {
                continue;
            }
            let Some(name) = child_path.file_name() else {
                continue;
            };
            children.push(DirectoryChild {
                name: name.to_owned(),
                inode: child_node.inode_id,
                file_type: child_node.attr.dirent_type(),
            });
        }
        Ok(children)
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
            return Err(VfsError::AlreadyExists);
        }

        let inode_id = self.allocate_inode_id();
        let attr = match &kind {
            PathNodeKind::Directory => LinuxFileAttr::directory(inode_id),
            PathNodeKind::File => LinuxFileAttr::regular(inode_id, 0o644, 0),
            PathNodeKind::Symlink(target) => LinuxFileAttr::symlink(inode_id, target.len() as u64),
        };
        self.nodes.insert(
            path,
            PathNode {
                inode_id,
                kind,
                attr,
                data: Vec::new(),
            },
        );
        Ok(inode_id)
    }

    fn insert_path_node(&mut self, path: GuestPath, node: PathNode) -> VfsResult<()> {
        if self.nodes.contains_key(&path) {
            return Err(VfsError::AlreadyExists);
        }
        self.nodes.insert(path, node);
        Ok(())
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
    attr: LinuxFileAttr,
    data: Vec<u8>,
}

impl PathNode {
    pub fn directory(inode_id: InodeId) -> Self {
        Self {
            inode_id,
            kind: PathNodeKind::Directory,
            attr: LinuxFileAttr::directory(inode_id),
            data: Vec::new(),
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

    pub fn attr(&self) -> LinuxFileAttr {
        self.attr
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn set_mode(&mut self, mode: u32) {
        self.attr.mode = (self.attr.mode & S_IFMT) | (mode & 0o7777);
    }

    fn truncate(&mut self) -> VfsResult<()> {
        if !matches!(self.kind, PathNodeKind::File) {
            return Err(VfsError::InvalidPath);
        }
        self.data.clear();
        self.attr.size = 0;
        self.attr.blocks = 0;
        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> VfsResult<usize> {
        if !matches!(self.kind, PathNodeKind::File) {
            return Err(VfsError::InvalidPath);
        }

        let offset = usize::try_from(offset).map_err(|_| VfsError::InvalidPath)?;
        let end = offset
            .checked_add(data.len())
            .ok_or(VfsError::InvalidPath)?;
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data[offset..end].copy_from_slice(data);
        self.attr.size = self.data.len() as u64;
        self.attr.blocks = self.attr.size.div_ceil(512);
        Ok(data.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathNodeKind {
    Directory,
    File,
    Symlink(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryChild {
    pub name: String,
    pub inode: InodeId,
    pub file_type: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub inode: InodeId,
    pub offset: i64,
    pub file_type: u8,
    pub name: String,
}

impl DirectoryEntry {
    pub fn record_len(&self) -> usize {
        align_up(19 + self.name.len() + 1, 8)
    }

    pub fn encode_linux_dirent64(&self, buffer: &mut Vec<u8>) -> VfsResult<()> {
        let record_len = self.record_len();
        let record_len_u16 = u16::try_from(record_len).map_err(|_| VfsError::InvalidPath)?;
        buffer.extend_from_slice(&self.inode.to_le_bytes());
        buffer.extend_from_slice(&self.offset.to_le_bytes());
        buffer.extend_from_slice(&record_len_u16.to_le_bytes());
        buffer.push(self.file_type);
        buffer.extend_from_slice(self.name.as_bytes());
        buffer.push(0);
        buffer.resize(buffer.len() + record_len - 19 - self.name.len() - 1, 0);
        Ok(())
    }
}

fn align_up(value: usize, alignment: usize) -> usize {
    debug_assert!(alignment.is_power_of_two());
    (value + alignment - 1) & !(alignment - 1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxFileAttr {
    pub inode: InodeId,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl LinuxFileAttr {
    pub fn directory(inode: InodeId) -> Self {
        Self::new(inode, S_IFDIR | 0o755, 0)
    }

    pub fn regular(inode: InodeId, mode: u32, size: u64) -> Self {
        Self::new(inode, S_IFREG | (mode & 0o7777), size)
    }

    pub fn symlink(inode: InodeId, size: u64) -> Self {
        Self::new(inode, S_IFLNK | 0o777, size)
    }

    fn new(inode: InodeId, mode: u32, size: u64) -> Self {
        Self {
            inode,
            mode,
            uid: 0,
            gid: 0,
            nlink: if mode & S_IFMT == S_IFDIR { 2 } else { 1 },
            size,
            blksize: 4096,
            blocks: size.div_ceil(512),
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        }
    }

    pub fn kind_bits(self) -> u32 {
        self.mode & S_IFMT
    }

    pub fn is_directory(self) -> bool {
        self.kind_bits() == S_IFDIR
    }

    pub fn is_regular(self) -> bool {
        self.kind_bits() == S_IFREG
    }

    pub fn is_symlink(self) -> bool {
        self.kind_bits() == S_IFLNK
    }

    pub fn dirent_type(self) -> u8 {
        match self.kind_bits() {
            S_IFDIR => DT_DIR,
            S_IFREG => DT_REG,
            S_IFLNK => DT_LNK,
            _ => DT_UNKNOWN,
        }
    }

    pub fn check_access(self, mode: u32) -> VfsResult<()> {
        if mode & !(R_OK | W_OK | X_OK) != 0 {
            return Err(VfsError::InvalidPath);
        }
        if mode == F_OK {
            return Ok(());
        }

        let permissions = self.mode & 0o777;
        if mode & R_OK != 0 && permissions & 0o444 == 0 {
            return Err(VfsError::PermissionDenied);
        }
        if mode & W_OK != 0 && permissions & 0o222 == 0 {
            return Err(VfsError::PermissionDenied);
        }
        if mode & X_OK != 0 && permissions & 0o111 == 0 {
            return Err(VfsError::PermissionDenied);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PathResolver<'a> {
    rootfs: &'a Rootfs,
    tree: &'a PathTree,
    follow_final_symlink: bool,
    symlink_count: usize,
}

impl<'a> PathResolver<'a> {
    fn new(rootfs: &'a Rootfs, tree: &'a PathTree) -> Self {
        Self {
            rootfs,
            tree,
            follow_final_symlink: true,
            symlink_count: 0,
        }
    }

    fn with_follow_final_symlink(mut self, follow_final_symlink: bool) -> Self {
        self.follow_final_symlink = follow_final_symlink;
        self
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
                        if !self.follow_final_symlink && pending.is_empty() {
                            *current = next_path;
                            continue;
                        }

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
    Symlink,
    Stdio(StdioKind),
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

    pub const fn directory(self) -> bool {
        self.raw & O_DIRECTORY != 0
    }

    pub const fn nofollow(self) -> bool {
        self.raw & O_NOFOLLOW != 0
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdEntry {
    file: FileRef,
    cloexec: bool,
    offset: u64,
    flags: OpenFlags,
    dir_cursor: usize,
    path: Option<GuestPath>,
}

impl FdEntry {
    pub fn file(&self) -> &FileRef {
        &self.file
    }

    pub fn cloexec(&self) -> bool {
        self.cloexec
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn flags(&self) -> OpenFlags {
        self.flags
    }

    pub fn path(&self) -> Option<&GuestPath> {
        self.path.as_ref()
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

    pub fn insert_open(
        &mut self,
        file: FileRef,
        flags: OpenFlags,
        path: Option<GuestPath>,
    ) -> VfsResult<Fd> {
        let fd = self.next_fd_from(FIRST_USER_FD)?;
        self.insert_entry(fd, file, flags.cloexec(), flags, path)
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

        self.entries.insert(
            fd,
            FdEntry {
                file,
                cloexec,
                offset: 0,
                flags,
                dir_cursor: 0,
                path,
            },
        );
        self.set_cloexec(fd, cloexec)?;
        Ok(fd)
    }

    pub fn get(&self, fd: Fd) -> VfsResult<&FdEntry> {
        self.entries.get(&fd).ok_or(VfsError::BadFd)
    }

    pub fn get_mut(&mut self, fd: Fd) -> VfsResult<&mut FdEntry> {
        self.entries.get_mut(&fd).ok_or(VfsError::BadFd)
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

    pub fn read(&mut self, tree: &PathTree, fd: Fd, buffer: &mut [u8]) -> VfsResult<usize> {
        let entry = self.get_mut(fd)?;
        if !entry.flags.can_read() {
            return Err(VfsError::BadFd);
        }

        match entry.file.kind {
            FileKind::Regular | FileKind::Symlink => {
                let path = entry.path.as_ref().ok_or(VfsError::BadFd)?;
                let node = tree.lookup_path(path).ok_or(VfsError::NoEntry)?;
                if node.attr.is_directory() {
                    return Err(VfsError::IsDirectory);
                }
                let offset = usize::try_from(entry.offset).map_err(|_| VfsError::InvalidPath)?;
                let available = node.data().get(offset..).unwrap_or(&[]);
                let count = available.len().min(buffer.len());
                buffer[..count].copy_from_slice(&available[..count]);
                entry.offset += count as u64;
                Ok(count)
            }
            FileKind::Directory => Err(VfsError::IsDirectory),
            FileKind::Stdio(StdioKind::Stdin) => Ok(0),
            FileKind::Stdio(_) => Err(VfsError::BadFd),
        }
    }

    pub fn write(&mut self, tree: &mut PathTree, fd: Fd, buffer: &[u8]) -> VfsResult<usize> {
        let entry = self.get_mut(fd)?;
        if !entry.flags.can_write() {
            return Err(VfsError::BadFd);
        }

        match entry.file.kind {
            FileKind::Regular => {
                let path = entry.path.as_ref().ok_or(VfsError::BadFd)?;
                let node = tree.lookup_path_mut(path).ok_or(VfsError::NoEntry)?;
                let offset = if entry.flags.append() {
                    node.attr.size
                } else {
                    entry.offset
                };
                let count = node.write_at(offset, buffer)?;
                entry.offset = offset + count as u64;
                Ok(count)
            }
            FileKind::Directory => Err(VfsError::IsDirectory),
            FileKind::Symlink => Err(VfsError::InvalidPath),
            FileKind::Stdio(StdioKind::Stdout | StdioKind::Stderr) => Ok(buffer.len()),
            FileKind::Stdio(StdioKind::Stdin) => Err(VfsError::BadFd),
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
        if matches!(entry.file.kind, FileKind::Stdio(_)) {
            return Err(VfsError::NotSeekable);
        }

        let size = match entry.file.kind {
            FileKind::Regular | FileKind::Symlink => {
                let path = entry.path.as_ref().ok_or(VfsError::BadFd)?;
                tree.lookup_path(path).ok_or(VfsError::NoEntry)?.attr.size
            }
            FileKind::Directory => 0,
            FileKind::Stdio(_) => unreachable!(),
        };
        let base = match whence {
            SeekWhence::Set => 0,
            SeekWhence::Cur => i128::from(entry.offset),
            SeekWhence::End => i128::from(size),
        };
        let next = base + i128::from(offset);
        if next < 0 || next > i128::from(u64::MAX) {
            return Err(VfsError::InvalidPath);
        }
        entry.offset = next as u64;
        if matches!(entry.file.kind, FileKind::Directory) {
            entry.dir_cursor = usize::try_from(entry.offset).unwrap_or(usize::MAX);
        }
        Ok(entry.offset)
    }

    pub fn getdents64(
        &mut self,
        tree: &PathTree,
        fd: Fd,
        max_bytes: usize,
    ) -> VfsResult<Vec<DirectoryEntry>> {
        let entry = self.get_mut(fd)?;
        if !matches!(entry.file.kind, FileKind::Directory) {
            return Err(VfsError::NotDirectory);
        }

        let path = entry.path.as_ref().ok_or(VfsError::BadFd)?;
        let mut children = tree.children(path)?;
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

        let mut returned = Vec::new();
        let mut used = 0usize;
        for item in entries.into_iter().skip(entry.dir_cursor) {
            let record_len = item.record_len();
            if used + record_len > max_bytes {
                if returned.is_empty() {
                    return Err(VfsError::InvalidPath);
                }
                break;
            }
            used += record_len;
            returned.push(item);
            entry.dir_cursor += 1;
            entry.offset = entry.dir_cursor as u64;
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
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualFileSystem {
    rootfs: Rootfs,
    tree: PathTree,
    fds: FdTable,
}

impl VirtualFileSystem {
    pub fn new(host_root: impl Into<PathBuf>) -> Self {
        Self {
            rootfs: Rootfs::new(host_root),
            tree: PathTree::new(),
            fds: FdTable::with_stdio(),
        }
    }

    pub fn from_parts(rootfs: Rootfs, tree: PathTree, fds: FdTable) -> Self {
        Self { rootfs, tree, fds }
    }

    pub fn rootfs(&self) -> &Rootfs {
        &self.rootfs
    }

    pub fn tree(&self) -> &PathTree {
        &self.tree
    }

    pub fn tree_mut(&mut self) -> &mut PathTree {
        &mut self.tree
    }

    pub fn fds(&self) -> &FdTable {
        &self.fds
    }

    pub fn fds_mut(&mut self) -> &mut FdTable {
        &mut self.fds
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

        if node_missing {
            if !flags.create() {
                return Err(VfsError::NoEntry);
            }
            self.create_resolved_file(path.clone(), mode)?;
        } else if flags.create() && flags.exclusive() {
            return Err(VfsError::AlreadyExists);
        }

        let node = self.tree.lookup_path(&path).ok_or(VfsError::NoEntry)?;
        if flags.directory() && !node.attr.is_directory() {
            return Err(VfsError::NotDirectory);
        }
        if node.attr.is_symlink() && flags.nofollow() {
            return Err(VfsError::Loop);
        }
        if node.attr.is_directory() && flags.can_write() {
            return Err(VfsError::IsDirectory);
        }

        let mut access_mode = F_OK;
        if flags.can_read() {
            access_mode |= R_OK;
        }
        if flags.can_write() {
            access_mode |= W_OK;
        }
        node.attr.check_access(access_mode)?;
        if flags.truncate() && flags.can_write() {
            self.tree
                .lookup_path_mut(&path)
                .ok_or(VfsError::NoEntry)?
                .truncate()?;
        }

        let node = self.tree.lookup_path(&path).ok_or(VfsError::NoEntry)?;
        let kind = match node.kind() {
            PathNodeKind::Directory => FileKind::Directory,
            PathNodeKind::File => FileKind::Regular,
            PathNodeKind::Symlink(_) => FileKind::Symlink,
        };
        self.fds.insert_open(
            FileRef::new(
                Arc::new(Inode::new(
                    node.inode_id(),
                    InodeBackend::HostPath(HostPathRef::new(self.host_path(&path))),
                )),
                kind,
            ),
            flags,
            Some(path),
        )
    }

    pub fn close(&mut self, fd: Fd) -> VfsResult<()> {
        self.fds.close(fd)?;
        Ok(())
    }

    pub fn read(&mut self, fd: Fd, buffer: &mut [u8]) -> VfsResult<usize> {
        self.fds.read(&self.tree, fd, buffer)
    }

    pub fn write(&mut self, fd: Fd, buffer: &[u8]) -> VfsResult<usize> {
        self.fds.write(&mut self.tree, fd, buffer)
    }

    pub fn lseek(&mut self, fd: Fd, offset: i64, whence: SeekWhence) -> VfsResult<u64> {
        self.fds.seek(&self.tree, fd, offset, whence)
    }

    pub fn fstat(&self, fd: Fd) -> VfsResult<LinuxFileAttr> {
        let entry = self.fds.get(fd)?;
        if let Some(path) = entry.path() {
            return self.stat_path(path);
        }

        Ok(stdio_attr(entry.file().kind()))
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

    pub fn access(&self, path: &str, mode: u32) -> VfsResult<()> {
        if path.is_empty() {
            return Err(VfsError::NoEntry);
        }
        let resolved = self.rootfs.resolve_path(path, &self.tree)?;
        self.check_traversal_permissions(resolved.guest_path())?;
        let attr = self.stat_path(resolved.guest_path())?;
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
        let node = self
            .tree
            .lookup_path(resolved.guest_path())
            .ok_or(VfsError::NoEntry)?;
        let PathNodeKind::Symlink(target) = node.kind() else {
            return Err(VfsError::InvalidPath);
        };
        let bytes = target.as_bytes();
        let count = bytes.len().min(buffer.len());
        buffer[..count].copy_from_slice(&bytes[..count]);
        Ok(count)
    }

    pub fn getdents64(&mut self, fd: Fd, max_bytes: usize) -> VfsResult<Vec<DirectoryEntry>> {
        self.fds.getdents64(&self.tree, fd, max_bytes)
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
            base_node.attr.check_access(X_OK)?;
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
                attr: LinuxFileAttr::regular(inode_id, mode, 0),
                data: Vec::new(),
            },
        )
    }

    fn stat_path(&self, path: &GuestPath) -> VfsResult<LinuxFileAttr> {
        self.tree
            .lookup_path(path)
            .map(PathNode::attr)
            .ok_or(VfsError::NoEntry)
    }

    fn check_traversal_permissions(&self, path: &GuestPath) -> VfsResult<()> {
        let mut ancestor = GuestPath::root();
        let components = path.as_components();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            ancestor.push_component(component.clone());
            let Some(node) = self.tree.lookup_path(&ancestor) else {
                break;
            };
            if node.attr.is_directory() {
                node.attr.check_access(X_OK)?;
            }
        }
        Ok(())
    }

    fn host_path(&self, path: &GuestPath) -> PathBuf {
        let mut host = self.rootfs.host_root().clone();
        for component in path.as_components() {
            host.push(component);
        }
        host
    }
}

fn stdio_attr(kind: FileKind) -> LinuxFileAttr {
    match kind {
        FileKind::Stdio(StdioKind::Stdin | StdioKind::Stdout | StdioKind::Stderr) => {
            LinuxFileAttr::new(0, S_IFREG | 0o666, 0)
        }
        FileKind::Regular | FileKind::Directory | FileKind::Symlink => {
            LinuxFileAttr::new(0, S_IFREG | 0o666, 0)
        }
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

    #[test]
    fn vfs_open_read_write_lseek_and_close_follow_linux_fd_errors() {
        let mut vfs = sample_vfs();
        let fd = vfs
            .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDWR), 0)
            .unwrap();
        let mut buffer = [0; 5];

        assert_eq!(vfs.read(fd, &mut buffer).unwrap(), 5);
        assert_eq!(&buffer, b"hello");
        assert_eq!(vfs.lseek(fd, -2, SeekWhence::Cur).unwrap(), 3);
        assert_eq!(vfs.write(fd, b"p!").unwrap(), 2);
        assert_eq!(vfs.lseek(fd, 0, SeekWhence::Set).unwrap(), 0);

        let mut all = [0; 5];
        assert_eq!(vfs.read(fd, &mut all).unwrap(), 5);
        assert_eq!(&all, b"help!");
        vfs.close(fd).unwrap();
        assert_eq!(vfs.read(fd, &mut all).unwrap_err(), VfsError::BadFd);
    }

    #[test]
    fn vfs_openat_creates_truncates_and_checks_directory_flags() {
        let mut vfs = sample_vfs();
        let created = vfs
            .openat(
                AT_FDCWD,
                "/tmp/new",
                OpenFlags::new(O_CREAT | O_EXCL | O_WRONLY),
                0o600,
            )
            .unwrap();

        assert_eq!(vfs.write(created, b"new").unwrap(), 3);
        assert_eq!(
            vfs.openat(
                AT_FDCWD,
                "/tmp/new",
                OpenFlags::new(O_CREAT | O_EXCL | O_WRONLY),
                0o600,
            )
            .unwrap_err(),
            VfsError::AlreadyExists
        );

        let truncated = vfs
            .openat(AT_FDCWD, "/tmp/new", OpenFlags::new(O_WRONLY | O_TRUNC), 0)
            .unwrap();
        assert_eq!(vfs.fstat(truncated).unwrap().size, 0);
        assert_eq!(
            vfs.openat(AT_FDCWD, "/tmp/new", OpenFlags::new(O_DIRECTORY), 0)
                .unwrap_err(),
            VfsError::NotDirectory
        );
    }

    #[test]
    fn vfs_reports_linux_errno_shapes_for_paths_fds_and_permissions() {
        let mut vfs = sample_vfs();
        vfs.tree_mut()
            .lookup_path_mut(&guest_path("/private"))
            .unwrap()
            .set_mode(0o600);

        assert_eq!(
            vfs.openat(AT_FDCWD, "/missing", OpenFlags::new(O_RDONLY), 0)
                .unwrap_err(),
            VfsError::NoEntry
        );
        assert_eq!(
            vfs.openat(99, "child", OpenFlags::new(O_RDONLY), 0)
                .unwrap_err(),
            VfsError::BadFd
        );
        let file_fd = vfs
            .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDONLY), 0)
            .unwrap();
        assert_eq!(
            vfs.openat(file_fd, "child", OpenFlags::new(O_RDONLY), 0)
                .unwrap_err(),
            VfsError::NotDirectory
        );
        assert_eq!(
            vfs.access("/private/secret", R_OK).unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(VfsError::PermissionDenied.linux_errno(), 13);
        assert_eq!(VfsError::NotDirectory.linux_errno(), 20);
        assert_eq!(VfsError::NoEntry.linux_errno(), 2);
        assert_eq!(VfsError::BadFd.linux_errno(), 9);
    }

    #[test]
    fn stat_access_and_readlink_use_linux_metadata_shapes() {
        let mut vfs = sample_vfs();
        let fd = vfs
            .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDONLY), 0)
            .unwrap();

        let stat = vfs.fstat(fd).unwrap();
        assert_eq!(stat.size, 5);
        assert_eq!(stat.kind_bits(), S_IFREG);
        assert!(vfs.access("/tmp/file", R_OK).is_ok());
        assert_eq!(
            vfs.access("/tmp/file", X_OK).unwrap_err(),
            VfsError::PermissionDenied
        );

        let link_stat = vfs
            .newfstatat(AT_FDCWD, "/link", AT_SYMLINK_NOFOLLOW)
            .unwrap();
        assert!(link_stat.is_symlink());
        assert_eq!(vfs.statx(AT_FDCWD, "/link", 0).unwrap().size, 5);

        let mut link = [0; 32];
        let count = vfs.readlink("/link", &mut link).unwrap();
        assert_eq!(&link[..count], b"/tmp/file");
    }

    #[test]
    fn getdents64_entries_match_linux_record_layout() {
        let mut vfs = sample_vfs();
        let fd = vfs
            .openat(AT_FDCWD, "/tmp", OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)
            .unwrap();
        let entries = vfs.getdents64(fd, 4096).unwrap();
        let names = entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(names, vec![".", "..", "file"]);
        let mut bytes = Vec::new();
        for entry in &entries {
            let before = bytes.len();
            entry.encode_linux_dirent64(&mut bytes).unwrap();
            assert_eq!(entry.record_len() % 8, 0);
            assert_eq!(
                usize::from(u16::from_le_bytes([bytes[before + 16], bytes[before + 17]])),
                entry.record_len()
            );
            assert_eq!(bytes[before + 18], entry.file_type);
            assert_eq!(bytes[before + 19 + entry.name.len()], 0);
        }
        assert_eq!(entries.last().unwrap().file_type, DT_REG);
        vfs.lseek(fd, 0, SeekWhence::Set).unwrap();
        assert_eq!(vfs.getdents64(fd, 1).unwrap_err(), VfsError::InvalidPath);
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

    fn sample_vfs() -> VirtualFileSystem {
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
}
