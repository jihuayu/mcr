use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub type Fd = i32;
pub type InodeId = u64;

pub const AT_FDCWD: Fd = -100;
pub const AT_EMPTY_PATH: u32 = 0x1000;
pub const AT_REMOVEDIR: u32 = 0x200;
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const DEFAULT_UMASK: u32 = 0o022;
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;
pub const F_DUPFD: u32 = 0;
pub const F_GETFD: u32 = 1;
pub const F_SETFD: u32 = 2;
pub const F_GETFL: u32 = 3;
pub const F_SETFL: u32 = 4;
pub const F_DUPFD_CLOEXEC: u32 = 1030;
pub const F_SETPIPE_SZ: u32 = 1031;
pub const F_GETPIPE_SZ: u32 = 1032;
pub const FD_CLOEXEC: u32 = 1;
pub const F_OK: u32 = 0;
pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const FIONREAD: u64 = 0x541b;
pub const TCGETS: u64 = 0x5401;
pub const TCSETS: u64 = 0x5402;
pub const TCSETSW: u64 = 0x5403;
pub const TCSETSF: u64 = 0x5404;
pub const TIOCGPGRP: u64 = 0x540f;
pub const TIOCSPGRP: u64 = 0x5410;
pub const TIOCGWINSZ: u64 = 0x5413;
pub const R_OK: u32 = 4;
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const RENAME_WHITEOUT: u32 = 4;
pub const SUPPORTED_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;
pub const S_IFMT: u32 = 0o170000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFCHR: u32 = 0o020000;
pub const W_OK: u32 = 2;
pub const X_OK: u32 = 1;

const DEV_NULL_INODE_ID: InodeId = 1 << 61;
const DEV_ZERO_INODE_ID: InodeId = DEV_NULL_INODE_ID + 1;
const DEV_URANDOM_INODE_ID: InodeId = DEV_NULL_INODE_ID + 2;
const FIRST_USER_FD: Fd = 3;
const FIRST_PIPE_INODE_ID: InodeId = 1 << 62;
const DEFAULT_PIPE_CAPACITY: usize = 65_536;
const MIN_PIPE_CAPACITY: usize = 4096;
const ROOT_INODE_ID: InodeId = 1;
const SETFL_MUTABLE_FLAGS: u32 = O_APPEND | O_NONBLOCK;
const SYMLINK_LIMIT: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsError {
    AlreadyExists,
    BadFd,
    BrokenPipe,
    Busy,
    InvalidPath,
    IsDirectory,
    Loop,
    NameTooLong,
    NoEntry,
    NotEmpty,
    NoSpace,
    NotSeekable,
    NotTerminal,
    NotDirectory,
    NotPermitted,
    PermissionDenied,
    WouldBlock,
}

impl VfsError {
    pub fn linux_errno(self) -> u16 {
        match self {
            Self::AlreadyExists => 17,
            Self::BadFd => 9,
            Self::BrokenPipe => 32,
            Self::Busy => 16,
            Self::InvalidPath => 22,
            Self::IsDirectory => 21,
            Self::Loop => 40,
            Self::NameTooLong => 36,
            Self::NoEntry => 2,
            Self::NotEmpty => 39,
            Self::NoSpace => 28,
            Self::NotSeekable => 29,
            Self::NotTerminal => 25,
            Self::NotDirectory => 20,
            Self::NotPermitted => 1,
            Self::PermissionDenied => 13,
            Self::WouldBlock => 11,
        }
    }
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AlreadyExists => "file exists",
            Self::BadFd => "bad file descriptor",
            Self::BrokenPipe => "broken pipe",
            Self::Busy => "device or resource busy",
            Self::InvalidPath => "invalid path",
            Self::IsDirectory => "is a directory",
            Self::Loop => "too many symbolic links",
            Self::NameTooLong => "path name is too long",
            Self::NoEntry => "no such file or directory",
            Self::NotEmpty => "directory not empty",
            Self::NoSpace => "no space left on device",
            Self::NotSeekable => "illegal seek",
            Self::NotTerminal => "inappropriate ioctl for device",
            Self::NotDirectory => "not a directory",
            Self::NotPermitted => "operation not permitted",
            Self::PermissionDenied => "permission denied",
            Self::WouldBlock => "resource temporarily unavailable",
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

    pub fn visible_path(&self, path: &GuestPath) -> VfsResult<String> {
        if !path.starts_with(&self.root) {
            return Err(VfsError::NoEntry);
        }
        let suffix = &path.components[self.root.components.len()..];
        if suffix.is_empty() {
            return Ok("/".to_owned());
        }
        Ok(format!("/{}", suffix.join("/")))
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
    nodes: BTreeMap<GuestPath, InodeId>,
    inodes: BTreeMap<InodeId, PathNode>,
    next_inode_id: InodeId,
}

impl PathTree {
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        let mut inodes = BTreeMap::new();
        nodes.insert(GuestPath::root(), ROOT_INODE_ID);
        inodes.insert(ROOT_INODE_ID, PathNode::directory(ROOT_INODE_ID));
        Self {
            nodes,
            inodes,
            next_inode_id: ROOT_INODE_ID + 1,
        }
    }

    pub fn create_dir(&mut self, path: impl AsRef<str>) -> VfsResult<InodeId> {
        let path = parse_absolute_path(path.as_ref())?;
        self.ensure_parent_dir(&path)?;
        self.insert_node(path, PathNodeKind::Directory, 0o755)
    }

    pub fn create_file(&mut self, path: impl AsRef<str>) -> VfsResult<InodeId> {
        let path = parse_absolute_path(path.as_ref())?;
        self.ensure_parent_dir(&path)?;
        self.insert_node(path, PathNodeKind::File, 0o644)
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
                metadata: MetadataSidecar::new(attr),
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
        self.insert_node(path, PathNodeKind::Symlink(target.into()), 0o777)
    }

    pub fn mount_minimal_devfs(&mut self) -> VfsResult<()> {
        self.create_dir_if_missing("/dev")?;
        self.insert_dev_node("/dev/null", DEV_NULL_INODE_ID, DevNodeKind::Null)?;
        self.insert_dev_node("/dev/zero", DEV_ZERO_INODE_ID, DevNodeKind::Zero)?;
        self.insert_dev_node("/dev/urandom", DEV_URANDOM_INODE_ID, DevNodeKind::Urandom)
    }

    pub fn lookup_path(&self, path: &GuestPath) -> Option<&PathNode> {
        let inode_id = self.nodes.get(path)?;
        self.inodes.get(inode_id)
    }

    pub fn lookup_path_mut(&mut self, path: &GuestPath) -> Option<&mut PathNode> {
        let inode_id = *self.nodes.get(path)?;
        self.inodes.get_mut(&inode_id)
    }

    pub fn lookup_inode(&self, inode_id: InodeId) -> Option<&PathNode> {
        self.inodes.get(&inode_id)
    }

    pub fn lookup_inode_mut(&mut self, inode_id: InodeId) -> Option<&mut PathNode> {
        self.inodes.get_mut(&inode_id)
    }

    pub fn first_path_for_inode(&self, inode_id: InodeId) -> Option<&GuestPath> {
        self.nodes
            .iter()
            .find_map(|(path, node_inode)| (*node_inode == inode_id).then_some(path))
    }

    pub fn children(&self, path: &GuestPath) -> VfsResult<Vec<DirectoryChild>> {
        let node = self.lookup_path(path).ok_or(VfsError::NoEntry)?;
        if !node.is_directory() {
            return Err(VfsError::NotDirectory);
        }

        let parent_len = path.components.len();
        let mut children = Vec::new();
        for (child_path, child_inode) in &self.nodes {
            if child_path.components.len() != parent_len + 1 {
                continue;
            }
            if !child_path.starts_with(path) {
                continue;
            }
            let child_node = self.inodes.get(child_inode).ok_or(VfsError::InvalidPath)?;
            let Some(name) = child_path.file_name() else {
                continue;
            };
            children.push(DirectoryChild {
                name: name.to_owned(),
                inode: child_node.inode_id,
                file_type: child_node.attr().dirent_type(),
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
                PathNodeKind::File | PathNodeKind::Device(_) => return None,
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

    fn insert_node(
        &mut self,
        path: GuestPath,
        kind: PathNodeKind,
        mode: u32,
    ) -> VfsResult<InodeId> {
        if self.nodes.contains_key(&path) {
            return Err(VfsError::AlreadyExists);
        }

        let inode_id = self.allocate_inode_id();
        let attr = match &kind {
            PathNodeKind::Directory => LinuxFileAttr::directory_with_mode(inode_id, mode),
            PathNodeKind::File => LinuxFileAttr::regular(inode_id, mode, 0),
            PathNodeKind::Device(_) => LinuxFileAttr::character_device(inode_id, mode),
            PathNodeKind::Symlink(target) => LinuxFileAttr::symlink(inode_id, target.len() as u64),
        };
        self.insert_path_node(
            path,
            PathNode {
                inode_id,
                kind,
                metadata: MetadataSidecar::new(attr),
                data: Vec::new(),
            },
        )?;
        Ok(inode_id)
    }

    fn insert_path_node(&mut self, path: GuestPath, node: PathNode) -> VfsResult<()> {
        if self.nodes.contains_key(&path) {
            return Err(VfsError::AlreadyExists);
        }
        let inode_id = node.inode_id;
        self.inodes.insert(inode_id, node);
        self.nodes.insert(path, inode_id);
        Ok(())
    }

    fn insert_link(&mut self, path: GuestPath, inode_id: InodeId) -> VfsResult<()> {
        if self.nodes.contains_key(&path) {
            return Err(VfsError::AlreadyExists);
        }
        if !self.inodes.contains_key(&inode_id) {
            return Err(VfsError::NoEntry);
        }
        self.nodes.insert(path, inode_id);
        Ok(())
    }

    fn create_dir_if_missing(&mut self, path: &str) -> VfsResult<InodeId> {
        let path = parse_absolute_path(path)?;
        if let Some(node) = self.lookup_path(&path) {
            if node.is_directory() {
                return Ok(node.inode_id());
            }
            return Err(VfsError::NotDirectory);
        }
        self.ensure_parent_dir(&path)?;
        self.insert_node(path, PathNodeKind::Directory, 0o755)
    }

    fn insert_dev_node(
        &mut self,
        path: &str,
        inode_id: InodeId,
        kind: DevNodeKind,
    ) -> VfsResult<()> {
        let path = parse_absolute_path(path)?;
        if let Some(node) = self.lookup_path(&path) {
            if matches!(node.kind(), PathNodeKind::Device(existing) if *existing == kind) {
                return Ok(());
            }
            return Err(VfsError::AlreadyExists);
        }
        self.ensure_parent_dir(&path)?;
        self.insert_path_node(
            path,
            PathNode {
                inode_id,
                kind: PathNodeKind::Device(kind),
                metadata: MetadataSidecar::new(LinuxFileAttr::character_device(inode_id, 0o666)),
                data: Vec::new(),
            },
        )
    }

    fn remove_path_link(&mut self, path: &GuestPath) -> VfsResult<InodeId> {
        self.nodes.remove(path).ok_or(VfsError::NoEntry)
    }

    fn is_empty_directory(&self, path: &GuestPath) -> bool {
        let child_len = path.components.len() + 1;
        !self.nodes.keys().any(|child_path| {
            child_path.components.len() == child_len && child_path.starts_with(path)
        })
    }

    fn paths_under_prefix(&self, prefix: &GuestPath) -> Vec<GuestPath> {
        self.nodes
            .keys()
            .filter(|path| path.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn link_count(&self, inode_id: InodeId) -> usize {
        self.nodes
            .values()
            .filter(|node_inode| **node_inode == inode_id)
            .count()
    }

    fn replace_prefix(
        path: &GuestPath,
        old_prefix: &GuestPath,
        new_prefix: &GuestPath,
    ) -> GuestPath {
        let mut components = new_prefix.components.clone();
        components.extend_from_slice(&path.components[old_prefix.components.len()..]);
        GuestPath::from_components(components)
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
    metadata: MetadataSidecar,
    data: Vec<u8>,
}

impl PathNode {
    pub fn directory(inode_id: InodeId) -> Self {
        Self {
            inode_id,
            kind: PathNodeKind::Directory,
            metadata: MetadataSidecar::new(LinuxFileAttr::directory(inode_id)),
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
        self.metadata.attr()
    }

    pub fn metadata(&self) -> MetadataSidecar {
        self.metadata
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn set_mode(&mut self, mode: u32) {
        self.metadata.set_mode(mode);
    }

    fn truncate(&mut self) -> VfsResult<()> {
        self.set_len(0)
    }

    fn set_len(&mut self, length: u64) -> VfsResult<()> {
        if !matches!(self.kind, PathNodeKind::File) {
            return Err(VfsError::InvalidPath);
        }
        let length = usize::try_from(length).map_err(|_| VfsError::NoSpace)?;
        self.data.resize(length, 0);
        self.metadata.set_size(length as u64);
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
        self.metadata.set_size(self.data.len() as u64);
        Ok(data.len())
    }

    fn increment_link_count(&mut self) -> VfsResult<()> {
        self.metadata.increment_link_count()
    }

    fn decrement_link_count(&mut self) {
        self.metadata.decrement_link_count();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathNodeKind {
    Directory,
    File,
    Device(DevNodeKind),
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
pub struct MetadataSidecar {
    attr: LinuxFileAttr,
}

impl MetadataSidecar {
    pub fn new(attr: LinuxFileAttr) -> Self {
        Self { attr }
    }

    pub fn attr(self) -> LinuxFileAttr {
        self.attr
    }

    pub fn set_mode(&mut self, mode: u32) {
        self.attr.mode = (self.attr.mode & S_IFMT) | (mode & 0o7777);
        self.touch_ctime();
    }

    pub fn set_size(&mut self, size: u64) {
        self.attr.size = size;
        self.attr.blocks = size.div_ceil(512);
        self.touch_mtime();
        self.touch_ctime();
    }

    pub fn increment_link_count(&mut self) -> VfsResult<()> {
        self.attr.nlink = self.attr.nlink.checked_add(1).ok_or(VfsError::NoSpace)?;
        self.touch_ctime();
        Ok(())
    }

    pub fn decrement_link_count(&mut self) {
        self.attr.nlink = self.attr.nlink.saturating_sub(1);
        self.touch_ctime();
    }

    fn touch_mtime(&mut self) {
        self.attr.mtime_nsec = self.attr.mtime_nsec.saturating_add(1);
    }

    fn touch_ctime(&mut self) {
        self.attr.ctime_nsec = self.attr.ctime_nsec.saturating_add(1);
    }
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
        Self::directory_with_mode(inode, 0o755)
    }

    pub fn directory_with_mode(inode: InodeId, mode: u32) -> Self {
        Self::new(inode, S_IFDIR | (mode & 0o7777), 0)
    }

    pub fn regular(inode: InodeId, mode: u32, size: u64) -> Self {
        Self::new(inode, S_IFREG | (mode & 0o7777), size)
    }

    pub fn symlink(inode: InodeId, size: u64) -> Self {
        Self::new(inode, S_IFLNK | 0o777, size)
    }

    pub fn character_device(inode: InodeId, mode: u32) -> Self {
        Self::new(inode, S_IFCHR | (mode & 0o7777), 0)
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

    pub fn fifo(inode: InodeId) -> Self {
        Self::new(inode, S_IFIFO | 0o600, 0)
    }

    pub fn kind_bits(self) -> u32 {
        self.mode & S_IFMT
    }

    pub fn is_directory(self) -> bool {
        self.kind_bits() == S_IFDIR
    }

    pub fn is_fifo(self) -> bool {
        self.kind_bits() == S_IFIFO
    }

    pub fn is_regular(self) -> bool {
        self.kind_bits() == S_IFREG
    }

    pub fn is_character_device(self) -> bool {
        self.kind_bits() == S_IFCHR
    }

    pub fn is_symlink(self) -> bool {
        self.kind_bits() == S_IFLNK
    }

    pub fn dirent_type(self) -> u8 {
        match self.kind_bits() {
            S_IFDIR => DT_DIR,
            S_IFREG => DT_REG,
            S_IFLNK => DT_LNK,
            S_IFCHR => DT_CHR,
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
    kind: DevNodeKind,
}

impl DevNode {
    pub fn new(kind: DevNodeKind) -> Self {
        Self { kind }
    }

    pub fn name(&self) -> &str {
        self.kind.name()
    }

    pub fn kind(&self) -> DevNodeKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevNodeKind {
    Null,
    Zero,
    Urandom,
    Stdin,
    Stdout,
    Stderr,
}

impl DevNodeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Zero => "zero",
            Self::Urandom => "urandom",
            Self::Stdin => "stdin",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PipeNode {
    id: u64,
    inner: Arc<PipeInner>,
}

impl PartialEq for PipeNode {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PipeNode {}

impl PipeNode {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            inner: Arc::new(PipeInner::new(DEFAULT_PIPE_CAPACITY)),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    fn state(&self) -> MutexGuard<'_, PipeState> {
        self.inner.state.lock().expect("pipe mutex poisoned")
    }

    fn wait_readable<'a>(&self, state: MutexGuard<'a, PipeState>) -> MutexGuard<'a, PipeState> {
        self.inner
            .readable
            .wait(state)
            .expect("pipe mutex poisoned while waiting for readable state")
    }

    fn wait_writable<'a>(&self, state: MutexGuard<'a, PipeState>) -> MutexGuard<'a, PipeState> {
        self.inner
            .writable
            .wait(state)
            .expect("pipe mutex poisoned while waiting for writable state")
    }

    fn notify_readable(&self) {
        self.inner.readable.notify_all();
    }

    fn notify_writable(&self) {
        self.inner.writable.notify_all();
    }
}

impl Drop for PipeNode {
    fn drop(&mut self) {
        self.inner.readable.notify_all();
        self.inner.writable.notify_all();
    }
}

#[derive(Debug)]
struct PipeInner {
    state: Mutex<PipeState>,
    readable: Condvar,
    writable: Condvar,
}

impl PipeInner {
    fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(PipeState::new(capacity)),
            readable: Condvar::new(),
            writable: Condvar::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PipeState {
    buffer: VecDeque<u8>,
    capacity: usize,
    readers: usize,
    writers: usize,
}

impl PipeState {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::new(),
            capacity,
            readers: 0,
            writers: 0,
        }
    }

    fn available(&self) -> usize {
        self.buffer.len()
    }

    fn read(&mut self, buffer: &mut [u8]) -> usize {
        let count = self.buffer.len().min(buffer.len());
        for item in buffer.iter_mut().take(count) {
            *item = self
                .buffer
                .pop_front()
                .expect("pipe buffer length was checked");
        }
        count
    }

    fn set_capacity(&mut self, capacity: usize) -> VfsResult<usize> {
        let capacity = capacity.max(MIN_PIPE_CAPACITY);
        if capacity < self.buffer.len() {
            return Err(VfsError::Busy);
        }
        self.capacity = capacity;
        Ok(self.capacity)
    }

    fn write(&mut self, buffer: &[u8]) -> VfsResult<usize> {
        let available = self.capacity.saturating_sub(self.buffer.len());
        if available == 0 && !buffer.is_empty() {
            return Err(VfsError::WouldBlock);
        }

        let count = available.min(buffer.len());
        self.buffer.extend(buffer[..count].iter().copied());
        Ok(count)
    }

    fn register_endpoint(&mut self, kind: FileKind) {
        match kind {
            FileKind::PipeRead => self.readers += 1,
            FileKind::PipeWrite => self.writers += 1,
            _ => {}
        }
    }

    fn unregister_endpoint(&mut self, kind: FileKind) {
        match kind {
            FileKind::PipeRead => self.readers = self.readers.saturating_sub(1),
            FileKind::PipeWrite => self.writers = self.writers.saturating_sub(1),
            _ => {}
        }
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

#[derive(Clone, Debug)]
pub struct FdEntry {
    file: FileRef,
    description: Arc<Mutex<FdDescription>>,
    path: Option<GuestPath>,
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

    fn inode_id(&self) -> InodeId {
        self.file.inode().id()
    }

    fn description(&self) -> MutexGuard<'_, FdDescription> {
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
struct FdDescription {
    offset: u64,
    flags: OpenFlags,
    dir_cursor: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoctlReply {
    None,
    U32(u32),
}

#[derive(Debug)]
pub struct FdTable {
    entries: BTreeMap<Fd, FdEntry>,
    cloexec: HashSet<Fd>,
    next_pipe_id: u64,
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
            FileKind::Stdio(_) => Ok(0),
        }
    }

    fn open_count(&self, inode_id: InodeId) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.inode_id() == inode_id)
            .count()
    }

    fn rebind_paths(&mut self, old_path: &GuestPath, new_path: &GuestPath) {
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

    pub fn close_on_exec(&mut self) {
        let cloexec = std::mem::take(&mut self.cloexec);
        for fd in cloexec {
            self.entries.remove(&fd);
        }
    }

    pub fn read(&mut self, tree: &PathTree, fd: Fd, buffer: &mut [u8]) -> VfsResult<usize> {
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
                let offset =
                    usize::try_from(description.offset).map_err(|_| VfsError::InvalidPath)?;
                let available = node.data().get(offset..).unwrap_or(&[]);
                let count = available.len().min(buffer.len());
                buffer[..count].copy_from_slice(&available[..count]);
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
            FileKind::Directory => Err(VfsError::IsDirectory),
            FileKind::Stdio(StdioKind::Stdin) => Ok(0),
            FileKind::Stdio(_) => Err(VfsError::BadFd),
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
        if matches!(
            entry.file.kind,
            FileKind::Dev(_) | FileKind::PipeRead | FileKind::PipeWrite | FileKind::Stdio(_)
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
        let description_arc = entry.description.clone();
        let mut description = description_arc
            .lock()
            .expect("fd description mutex poisoned");
        for item in entries.into_iter().skip(description.dir_cursor) {
            let record_len = item.record_len();
            if used + record_len > max_bytes {
                if returned.is_empty() {
                    return Err(VfsError::InvalidPath);
                }
                break;
            }
            used += record_len;
            returned.push(item);
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
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct VirtualFileSystem {
    rootfs: Rootfs,
    tree: PathTree,
    fds: FdTable,
    umask: u32,
}

impl VirtualFileSystem {
    pub fn new(host_root: impl Into<PathBuf>) -> Self {
        let mut vfs = Self {
            rootfs: Rootfs::new(host_root),
            tree: PathTree::new(),
            fds: FdTable::with_stdio(),
            umask: DEFAULT_UMASK,
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
            umask: DEFAULT_UMASK,
        }
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

    pub fn mount_minimal_devfs(&mut self) -> VfsResult<()> {
        self.tree.mount_minimal_devfs()
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

        if node_missing {
            if !flags.create() {
                return Err(VfsError::NoEntry);
            }
            self.tree.ensure_parent_dir(&path)?;
            self.check_parent_write_permissions(&path)?;
            self.create_resolved_file(path.clone(), mode & !self.umask)?;
        } else if flags.create() && flags.exclusive() {
            return Err(VfsError::AlreadyExists);
        }

        let node = self.tree.lookup_path(&path).ok_or(VfsError::NoEntry)?;
        if flags.directory() && !node.attr().is_directory() {
            return Err(VfsError::NotDirectory);
        }
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
        node.attr().check_access(access_mode)?;
        if flags.truncate() && flags.can_write() && matches!(node.kind(), PathNodeKind::File) {
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
            PathNodeKind::Symlink(_) => FileKind::Symlink,
        };
        self.fds.insert_open(
            FileRef::new(
                Arc::new(Inode::new(
                    node.inode_id(),
                    inode_backend_for_path_node(node, self.host_path(&path)),
                )),
                kind,
            ),
            flags,
            Some(path),
        )
    }

    pub fn close(&mut self, fd: Fd) -> VfsResult<()> {
        let file = self.fds.close(fd)?;
        let inode_id = file.inode().id();
        if self.tree.lookup_inode(inode_id).is_some() && self.tree.link_count(inode_id) == 0 {
            self.tree.inodes.remove(&inode_id);
        }
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
        if let Some(node) = self.tree.lookup_inode(entry.inode_id()) {
            return Ok(node.attr());
        }

        Ok(anonymous_attr(entry.file()))
    }

    pub fn pipe(&mut self, flags: OpenFlags) -> VfsResult<[Fd; 2]> {
        self.fds.pipe(flags)
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

    pub fn readlinkat(&self, dirfd: Fd, path: &str, buffer: &mut [u8]) -> VfsResult<usize> {
        if path.is_empty() {
            return self.fds.readlink_open(&self.tree, dirfd, buffer);
        }
        let resolved = self.resolve_at(dirfd, path, ResolveOptions::NOFOLLOW_FINAL, false)?;
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
            },
        )
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
        let inode_id = self.tree.remove_path_link(&target)?;
        self.drop_link(inode_id);
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
            },
        )
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
            .insert_link(new_resolved.guest_path().clone(), old_inode)
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
            return Ok(());
        }

        if let Some(target_inode) = new_inode {
            self.validate_rename_replacement(old_inode, target_inode, &new_path)?;
            self.remove_existing_rename_target(&new_path, target_inode)?;
        }
        self.move_path(&old_path, &new_path)
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
            .set_len(length)
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
            },
        )
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

    fn host_path(&self, path: &GuestPath) -> PathBuf {
        let mut host = self.rootfs.host_root().clone();
        for component in path.as_components() {
            host.push(component);
        }
        host
    }
}

fn anonymous_attr(file: &FileRef) -> LinuxFileAttr {
    match file.kind() {
        FileKind::Stdio(StdioKind::Stdin | StdioKind::Stdout | StdioKind::Stderr) => {
            LinuxFileAttr::new(0, S_IFREG | 0o666, 0)
        }
        FileKind::PipeRead | FileKind::PipeWrite => LinuxFileAttr::fifo(file.inode().id()),
        FileKind::Dev(_) => LinuxFileAttr::character_device(file.inode().id(), 0o666),
        FileKind::Regular | FileKind::Directory | FileKind::Symlink => {
            LinuxFileAttr::new(0, S_IFREG | 0o666, 0)
        }
    }
}

fn inode_backend_for_path_node(node: &PathNode, host_path: PathBuf) -> InodeBackend {
    match node.kind() {
        PathNodeKind::Device(kind) => InodeBackend::DevVirtual(DevNode::new(*kind)),
        PathNodeKind::Directory | PathNodeKind::File | PathNodeKind::Symlink(_) => {
            InodeBackend::HostPath(HostPathRef::new(host_path))
        }
    }
}

fn register_fd_endpoint(file: &FileRef) {
    if let Ok(pipe) = pipe_node(file) {
        pipe.state().register_endpoint(file.kind());
    }
}

fn unregister_fd_endpoint(file: &FileRef) {
    if let Ok(pipe) = pipe_node(file) {
        let mut state = pipe.state();
        state.unregister_endpoint(file.kind());
        drop(state);
        pipe.notify_readable();
        pipe.notify_writable();
    }
}

fn pipe_read(entry: &FdEntry, buffer: &mut [u8]) -> VfsResult<usize> {
    let pipe = pipe_node(entry.file())?;
    let mut state = pipe.state();
    while state.available() == 0 && !buffer.is_empty() && state.writers > 0 {
        if entry.flags().nonblock() {
            return Err(VfsError::WouldBlock);
        }
        state = pipe.wait_readable(state);
    }
    let count = state.read(buffer);
    if count > 0 {
        pipe.notify_writable();
    }
    Ok(count)
}

fn pipe_write(entry: &FdEntry, buffer: &[u8]) -> VfsResult<usize> {
    let pipe = pipe_node(entry.file())?;
    let mut state = pipe.state();
    if state.readers == 0 {
        return Err(VfsError::BrokenPipe);
    }
    while state.capacity == state.available() && !buffer.is_empty() && state.readers > 0 {
        if entry.flags().nonblock() {
            return Err(VfsError::WouldBlock);
        }
        state = pipe.wait_writable(state);
    }
    let count = state.write(buffer)?;
    if count > 0 {
        pipe.notify_readable();
    }
    Ok(count)
}

fn pipe_node(file: &FileRef) -> VfsResult<&PipeNode> {
    match file.inode().backend() {
        InodeBackend::Pipe(pipe) => Ok(pipe),
        _ => Err(VfsError::BadFd),
    }
}

#[cfg(not(windows))]
fn fill_urandom(buffer: &mut [u8]) -> VfsResult<()> {
    use std::io::Read;

    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(buffer))
        .map_err(|_| VfsError::InvalidPath)
}

#[cfg(windows)]
fn fill_urandom(buffer: &mut [u8]) -> VfsResult<()> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    const MAX_CHUNK: usize = u32::MAX as usize;

    unsafe extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    for chunk in buffer.chunks_mut(MAX_CHUNK) {
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(VfsError::InvalidPath);
        }
    }
    Ok(())
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
    fn fd_duplication_clones_open_file_state_and_tracks_descriptor_flags() {
        let mut vfs = sample_vfs();
        let fd = vfs
            .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDWR | O_CLOEXEC), 0)
            .unwrap();
        assert_eq!(fd, 3);
        let dup = vfs.dup(fd).unwrap();
        let dup_min = vfs.fcntl(fd, F_DUPFD_CLOEXEC, 10).unwrap() as Fd;

        assert_eq!(dup, 4);
        assert_eq!(dup_min, 10);
        assert!(!vfs.fds().cloexec(dup).unwrap());
        assert!(vfs.fds().cloexec(dup_min).unwrap());

        assert_eq!(vfs.lseek(fd, 2, SeekWhence::Set).unwrap(), 2);
        assert_eq!(vfs.fds().get(dup).unwrap().offset(), 2);
        assert_eq!(vfs.fcntl(dup, F_GETFD, 0).unwrap(), 0);
        assert_eq!(
            vfs.fcntl(dup_min, F_GETFD, 0).unwrap(),
            u64::from(FD_CLOEXEC)
        );
        assert_eq!(vfs.fcntl(dup, F_SETFD, u64::from(FD_CLOEXEC)).unwrap(), 0);
        assert!(vfs.fds().cloexec(dup).unwrap());

        assert_eq!(
            vfs.fcntl(fd, F_SETFL, u64::from(O_APPEND | O_NONBLOCK))
                .unwrap(),
            0
        );
        assert_eq!(
            vfs.fcntl(dup, F_GETFL, 0).unwrap() as u32 & (O_APPEND | O_NONBLOCK),
            O_APPEND | O_NONBLOCK
        );

        assert_eq!(vfs.dup2(fd, 1).unwrap(), 1);
        assert_eq!(vfs.dup3(fd, 11, OpenFlags::new(O_CLOEXEC)).unwrap(), 11);
        assert!(vfs.fds().cloexec(11).unwrap());
        assert_eq!(
            vfs.dup3(fd, fd, OpenFlags::new(O_CLOEXEC)).unwrap_err(),
            VfsError::InvalidPath
        );
    }

    #[test]
    fn pipes_move_bytes_and_report_nonblocking_and_capacity_state() {
        let mut vfs = sample_vfs();
        let [read_fd, write_fd] = vfs.pipe(OpenFlags::new(O_CLOEXEC | O_NONBLOCK)).unwrap();
        let mut buffer = [0; 5];

        assert!(vfs.fds().cloexec(read_fd).unwrap());
        assert!(vfs.fds().cloexec(write_fd).unwrap());
        assert_eq!(
            vfs.fds().get(read_fd).unwrap().flags().raw(),
            O_RDONLY | O_NONBLOCK
        );
        assert_eq!(
            vfs.fds().get(write_fd).unwrap().flags().raw(),
            O_WRONLY | O_NONBLOCK
        );
        assert_eq!(
            vfs.read(read_fd, &mut buffer).unwrap_err(),
            VfsError::WouldBlock
        );

        assert_eq!(vfs.write(write_fd, b"hello").unwrap(), 5);
        assert_eq!(vfs.ioctl(read_fd, FIONREAD).unwrap(), IoctlReply::U32(5));
        assert_eq!(vfs.read(read_fd, &mut buffer).unwrap(), 5);
        assert_eq!(&buffer, b"hello");
        assert_eq!(
            vfs.fcntl(read_fd, F_GETPIPE_SZ, 0).unwrap(),
            DEFAULT_PIPE_CAPACITY as u64
        );
        assert_eq!(vfs.fcntl(read_fd, F_SETPIPE_SZ, 1024).unwrap(), 4096);

        vfs.close(read_fd).unwrap();
        assert_eq!(vfs.write(write_fd, b"!").unwrap_err(), VfsError::BrokenPipe);
    }

    #[test]
    fn ioctl_subset_reports_terminal_errors_without_tty_completeness() {
        let vfs = sample_vfs();

        assert_eq!(vfs.ioctl(1, TIOCGWINSZ).unwrap_err(), VfsError::NotTerminal);
        assert_eq!(vfs.ioctl(1, TCGETS).unwrap_err(), VfsError::NotTerminal);
        assert_eq!(vfs.ioctl(99, FIONREAD).unwrap_err(), VfsError::BadFd);
    }

    #[test]
    fn minimal_devfs_nodes_have_linux_device_behaviors() {
        let mut vfs = VirtualFileSystem::new("/host/root");
        let null_fd = vfs
            .openat(AT_FDCWD, "/dev/null", OpenFlags::new(O_RDWR), 0)
            .unwrap();
        let zero_fd = vfs
            .openat(AT_FDCWD, "/dev/zero", OpenFlags::new(O_RDWR), 0)
            .unwrap();
        let urandom_fd = vfs
            .openat(AT_FDCWD, "/dev/urandom", OpenFlags::new(O_RDONLY), 0)
            .unwrap();
        let mut buffer = [0xaa; 16];

        assert_eq!(vfs.read(null_fd, &mut buffer).unwrap(), 0);
        assert_eq!(buffer, [0xaa; 16]);
        assert_eq!(vfs.write(null_fd, b"discarded").unwrap(), 9);
        assert_eq!(
            vfs.lseek(null_fd, 0, SeekWhence::Set).unwrap_err(),
            VfsError::NotSeekable
        );
        assert!(vfs.fstat(null_fd).unwrap().is_character_device());

        assert_eq!(vfs.read(zero_fd, &mut buffer).unwrap(), buffer.len());
        assert_eq!(buffer, [0; 16]);
        assert_eq!(vfs.write(zero_fd, b"ignored").unwrap(), 7);

        buffer.fill(0);
        assert_eq!(vfs.read(urandom_fd, &mut buffer).unwrap(), buffer.len());
        assert_ne!(buffer, [0; 16]);
        assert!(vfs.fstat(urandom_fd).unwrap().is_character_device());
    }

    #[test]
    fn minimal_devfs_directory_lists_character_devices() {
        let mut vfs = VirtualFileSystem::new("/host/root");
        let dev_fd = vfs
            .openat(AT_FDCWD, "/dev", OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)
            .unwrap();
        let entries = vfs.getdents64(dev_fd, 4096).unwrap();
        let entries = entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry.file_type))
            .collect::<Vec<_>>();

        assert_eq!(
            entries,
            vec![
                (".", DT_DIR),
                ("..", DT_DIR),
                ("null", DT_CHR),
                ("urandom", DT_CHR),
                ("zero", DT_CHR),
            ]
        );
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
        vfs.tree_mut().create_dir("/readonly").unwrap();
        vfs.tree_mut()
            .lookup_path_mut(&guest_path("/readonly"))
            .unwrap()
            .set_mode(0o500);
        assert_eq!(
            vfs.openat(
                AT_FDCWD,
                "/readonly/created",
                OpenFlags::new(O_CREAT | O_WRONLY),
                0o600,
            )
            .unwrap_err(),
            VfsError::PermissionDenied
        );
        assert_eq!(
            vfs.newfstatat(AT_FDCWD, "/readonly/created", 0)
                .unwrap_err(),
            VfsError::NoEntry
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

    #[test]
    fn writable_mutations_cover_mkdir_links_rename_and_metadata() {
        let mut vfs = sample_vfs();

        vfs.mkdirat(AT_FDCWD, "/tmp/pkg", 0o777).unwrap();
        assert_eq!(
            vfs.newfstatat(AT_FDCWD, "/tmp/pkg", 0).unwrap().mode & 0o777,
            0o755
        );
        assert_eq!(vfs.chdir("/tmp/pkg"), Ok(()));
        assert_eq!(vfs.getcwd().unwrap(), "/tmp/pkg");
        assert_eq!(vfs.umask(0o077), 0o022);

        vfs.symlinkat("../file", AT_FDCWD, "file-link").unwrap();
        let mut target = [0; 16];
        let count = vfs
            .readlinkat(AT_FDCWD, "/tmp/pkg/file-link", &mut target)
            .unwrap();
        assert_eq!(&target[..count], b"../file");

        vfs.linkat(AT_FDCWD, "/tmp/file", AT_FDCWD, "hard", 0)
            .unwrap();
        let original = vfs.newfstatat(AT_FDCWD, "/tmp/file", 0).unwrap();
        let linked = vfs.newfstatat(AT_FDCWD, "hard", 0).unwrap();
        assert_eq!(original.inode, linked.inode);
        assert_eq!(linked.nlink, 2);

        vfs.renameat2(AT_FDCWD, "hard", AT_FDCWD, "renamed", 0)
            .unwrap();
        assert_eq!(
            vfs.newfstatat(AT_FDCWD, "hard", 0).unwrap_err(),
            VfsError::NoEntry
        );
        assert_eq!(
            vfs.renameat2(AT_FDCWD, "renamed", AT_FDCWD, "/tmp/file", RENAME_NOREPLACE,)
                .unwrap_err(),
            VfsError::AlreadyExists
        );

        let before = vfs.newfstatat(AT_FDCWD, "renamed", 0).unwrap();
        let fd = vfs
            .openat(AT_FDCWD, "renamed", OpenFlags::new(O_RDWR), 0)
            .unwrap();
        vfs.ftruncate(fd, 9).unwrap();
        let after = vfs.fstat(fd).unwrap();
        assert_eq!(after.size, 9);
        assert!(after.ctime_nsec > before.ctime_nsec);
        assert!(after.mtime_nsec > before.mtime_nsec);
        vfs.close(fd).unwrap();
    }

    #[test]
    fn rename_over_existing_and_exchange_follow_linux_shapes() {
        let mut vfs = sample_vfs();
        vfs.mkdirat(AT_FDCWD, "/tmp/a", 0o755).unwrap();
        vfs.mkdirat(AT_FDCWD, "/tmp/b", 0o755).unwrap();
        vfs.openat(
            AT_FDCWD,
            "/tmp/a/file",
            OpenFlags::new(O_CREAT | O_WRONLY),
            0o644,
        )
        .unwrap();
        vfs.openat(
            AT_FDCWD,
            "/tmp/b/file",
            OpenFlags::new(O_CREAT | O_WRONLY),
            0o644,
        )
        .unwrap();

        vfs.renameat2(AT_FDCWD, "/tmp/a/file", AT_FDCWD, "/tmp/b/file", 0)
            .unwrap();
        assert_eq!(
            vfs.newfstatat(AT_FDCWD, "/tmp/a/file", 0).unwrap_err(),
            VfsError::NoEntry
        );
        assert!(vfs.newfstatat(AT_FDCWD, "/tmp/b/file", 0).is_ok());
        assert_eq!(
            vfs.renameat2(AT_FDCWD, "/tmp/a", AT_FDCWD, "/tmp/b", 0)
                .unwrap_err(),
            VfsError::NotEmpty
        );

        vfs.openat(
            AT_FDCWD,
            "/tmp/a/other",
            OpenFlags::new(O_CREAT | O_WRONLY),
            0o644,
        )
        .unwrap();
        vfs.renameat2(
            AT_FDCWD,
            "/tmp/a/other",
            AT_FDCWD,
            "/tmp/b/file",
            RENAME_EXCHANGE,
        )
        .unwrap();
        assert!(vfs.newfstatat(AT_FDCWD, "/tmp/a/other", 0).is_ok());
        assert!(vfs.newfstatat(AT_FDCWD, "/tmp/b/file", 0).is_ok());
    }

    #[test]
    fn delayed_unlink_keeps_open_inode_until_close() {
        let mut vfs = sample_vfs();
        let fd = vfs
            .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDWR), 0)
            .unwrap();
        vfs.unlinkat(AT_FDCWD, "/tmp/file", 0).unwrap();
        assert_eq!(
            vfs.newfstatat(AT_FDCWD, "/tmp/file", 0).unwrap_err(),
            VfsError::NoEntry
        );

        vfs.lseek(fd, 0, SeekWhence::Set).unwrap();
        let mut buffer = [0; 5];
        assert_eq!(vfs.read(fd, &mut buffer).unwrap(), 5);
        assert_eq!(&buffer, b"hello");
        assert_eq!(vfs.fstat(fd).unwrap().nlink, 0);

        let inode = vfs.fstat(fd).unwrap().inode;
        vfs.close(fd).unwrap();
        assert!(vfs.tree().lookup_inode(inode).is_none());
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
