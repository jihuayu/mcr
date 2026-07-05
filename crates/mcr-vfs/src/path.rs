use super::*;

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
    pub(crate) guest_path: GuestPath,
    pub(crate) inode: Option<InodeId>,
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
    pub(crate) nodes: BTreeMap<GuestPath, InodeId>,
    pub(crate) inodes: BTreeMap<InodeId, PathNode>,
    pub(crate) next_inode_id: InodeId,
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
                deferred_host_path: None,
            },
        )?;
        Ok(inode_id)
    }

    pub fn create_file_with_host_content(
        &mut self,
        path: impl AsRef<str>,
        host_path: impl Into<PathBuf>,
        size: u64,
        mode: u32,
    ) -> VfsResult<InodeId> {
        let path = parse_absolute_path(path.as_ref())?;
        self.ensure_parent_dir(&path)?;
        let inode_id = self.allocate_inode_id();
        self.insert_path_node(
            path,
            PathNode {
                inode_id,
                kind: PathNodeKind::File,
                metadata: MetadataSidecar::new(LinuxFileAttr::regular(inode_id, mode, size)),
                data: Vec::new(),
                deferred_host_path: Some(host_path.into()),
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

    pub fn mount_minimal_procfs(&mut self) -> VfsResult<()> {
        self.insert_proc_static_node("/proc", PROC_INODE_ID, ProcNodeKind::Directory, 0o555)?;
        self.insert_proc_static_node(
            "/proc/self",
            PROC_SELF_INODE_ID,
            ProcNodeKind::Directory,
            0o555,
        )?;
        self.insert_proc_static_node(
            "/proc/self/exe",
            PROC_SELF_EXE_INODE_ID,
            ProcNodeKind::Exe,
            0o777,
        )?;
        self.insert_proc_static_node(
            "/proc/self/cmdline",
            PROC_SELF_CMDLINE_INODE_ID,
            ProcNodeKind::Cmdline,
            0o444,
        )?;
        self.insert_proc_static_node(
            "/proc/self/environ",
            PROC_SELF_ENVIRON_INODE_ID,
            ProcNodeKind::Environ,
            0o400,
        )?;
        self.insert_proc_static_node(
            "/proc/self/fd",
            PROC_SELF_FD_INODE_ID,
            ProcNodeKind::FdDirectory,
            0o555,
        )
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
        self.static_children(path)
    }

    pub(crate) fn static_children(&self, path: &GuestPath) -> VfsResult<Vec<DirectoryChild>> {
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
                PathNodeKind::Directory
                | PathNodeKind::Proc(ProcNodeKind::Directory | ProcNodeKind::FdDirectory) => {
                    continue;
                }
                PathNodeKind::File | PathNodeKind::Device(_) => return None,
                PathNodeKind::Proc(_) => return None,
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

    pub(crate) fn ensure_parent_dir(&self, path: &GuestPath) -> VfsResult<()> {
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

    pub(crate) fn insert_node(
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
            PathNodeKind::Proc(kind) => kind.attr(inode_id, mode),
            PathNodeKind::Symlink(target) => LinuxFileAttr::symlink(inode_id, target.len() as u64),
        };
        self.insert_path_node(
            path,
            PathNode {
                inode_id,
                kind,
                metadata: MetadataSidecar::new(attr),
                data: Vec::new(),
                deferred_host_path: None,
            },
        )?;
        Ok(inode_id)
    }

    pub(crate) fn insert_path_node(&mut self, path: GuestPath, node: PathNode) -> VfsResult<()> {
        if self.nodes.contains_key(&path) {
            return Err(VfsError::AlreadyExists);
        }
        let inode_id = node.inode_id;
        self.inodes.insert(inode_id, node);
        self.nodes.insert(path, inode_id);
        Ok(())
    }

    pub(crate) fn insert_link(&mut self, path: GuestPath, inode_id: InodeId) -> VfsResult<()> {
        if self.nodes.contains_key(&path) {
            return Err(VfsError::AlreadyExists);
        }
        if !self.inodes.contains_key(&inode_id) {
            return Err(VfsError::NoEntry);
        }
        self.nodes.insert(path, inode_id);
        Ok(())
    }

    pub(crate) fn create_dir_if_missing(&mut self, path: &str) -> VfsResult<InodeId> {
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

    pub(crate) fn insert_dev_node(
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
                deferred_host_path: None,
            },
        )
    }

    pub(crate) fn insert_proc_static_node(
        &mut self,
        path: &str,
        inode_id: InodeId,
        kind: ProcNodeKind,
        mode: u32,
    ) -> VfsResult<()> {
        let path = parse_absolute_path(path)?;
        if let Some(node) = self.lookup_path(&path) {
            if matches!(node.kind(), PathNodeKind::Proc(existing) if *existing == kind) {
                return Ok(());
            }
            if matches!(
                (node.kind(), kind),
                (
                    PathNodeKind::Directory,
                    ProcNodeKind::Directory | ProcNodeKind::FdDirectory
                )
            ) {
                self.replace_path_node(
                    path,
                    PathNode {
                        inode_id,
                        kind: PathNodeKind::Proc(kind),
                        metadata: MetadataSidecar::new(kind.attr(inode_id, mode)),
                        data: Vec::new(),
                        deferred_host_path: None,
                    },
                );
                return Ok(());
            }
            return Err(VfsError::AlreadyExists);
        }
        if !path.is_root() {
            self.ensure_parent_dir(&path)?;
        }
        self.insert_path_node(
            path,
            PathNode {
                inode_id,
                kind: PathNodeKind::Proc(kind),
                metadata: MetadataSidecar::new(kind.attr(inode_id, mode)),
                data: Vec::new(),
                deferred_host_path: None,
            },
        )
    }

    pub(crate) fn replace_path_node(&mut self, path: GuestPath, node: PathNode) {
        if let Some(existing_inode_id) = self.nodes.insert(path, node.inode_id) {
            self.inodes.remove(&existing_inode_id);
        }
        self.inodes.insert(node.inode_id, node);
    }

    pub(crate) fn remove_path_link(&mut self, path: &GuestPath) -> VfsResult<InodeId> {
        self.nodes.remove(path).ok_or(VfsError::NoEntry)
    }

    pub(crate) fn is_empty_directory(&self, path: &GuestPath) -> bool {
        let child_len = path.components.len() + 1;
        !self.nodes.keys().any(|child_path| {
            child_path.components.len() == child_len && child_path.starts_with(path)
        })
    }

    pub(crate) fn paths_under_prefix(&self, prefix: &GuestPath) -> Vec<GuestPath> {
        self.nodes
            .keys()
            .filter(|path| path.starts_with(prefix))
            .cloned()
            .collect()
    }

    pub(crate) fn link_count(&self, inode_id: InodeId) -> usize {
        self.nodes
            .values()
            .filter(|node_inode| **node_inode == inode_id)
            .count()
    }

    pub(crate) fn replace_prefix(
        path: &GuestPath,
        old_prefix: &GuestPath,
        new_prefix: &GuestPath,
    ) -> GuestPath {
        let mut components = new_prefix.components.clone();
        components.extend_from_slice(&path.components[old_prefix.components.len()..]);
        GuestPath::from_components(components)
    }

    pub(crate) fn allocate_inode_id(&mut self) -> InodeId {
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
    pub(crate) inode_id: InodeId,
    pub(crate) kind: PathNodeKind,
    pub(crate) metadata: MetadataSidecar,
    pub(crate) data: Vec<u8>,
    pub(crate) deferred_host_path: Option<PathBuf>,
}

impl PathNode {
    pub fn directory(inode_id: InodeId) -> Self {
        Self {
            inode_id,
            kind: PathNodeKind::Directory,
            metadata: MetadataSidecar::new(LinuxFileAttr::directory(inode_id)),
            data: Vec::new(),
            deferred_host_path: None,
        }
    }

    pub fn inode_id(&self) -> InodeId {
        self.inode_id
    }

    pub fn kind(&self) -> &PathNodeKind {
        &self.kind
    }

    pub fn is_directory(&self) -> bool {
        is_directory_kind(&self.kind)
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

    pub(crate) fn deferred_host_path(&self) -> Option<&Path> {
        self.deferred_host_path.as_deref()
    }

    pub fn set_mode(&mut self, mode: u32) {
        self.metadata.set_mode(mode);
    }

    pub(crate) fn truncate(&mut self) -> VfsResult<()> {
        self.set_len(0)
    }

    pub(crate) fn set_len(&mut self, length: u64) -> VfsResult<()> {
        if !matches!(self.kind, PathNodeKind::File) {
            return Err(VfsError::InvalidPath);
        }
        self.materialize_deferred_content()?;
        let length = usize::try_from(length).map_err(|_| VfsError::NoSpace)?;
        self.data.resize(length, 0);
        self.metadata.set_size(length as u64);
        Ok(())
    }

    pub(crate) fn write_at(&mut self, offset: u64, data: &[u8]) -> VfsResult<usize> {
        if !matches!(self.kind, PathNodeKind::File) {
            return Err(VfsError::InvalidPath);
        }
        self.materialize_deferred_content()?;

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

    pub(crate) fn materialize_deferred_content(&mut self) -> VfsResult<()> {
        let Some(path) = self.deferred_host_path.clone() else {
            return Ok(());
        };
        let data = fs::read(&path).map_err(|_| VfsError::NoEntry)?;
        self.data = data;
        self.deferred_host_path = None;
        Ok(())
    }

    pub(crate) fn increment_link_count(&mut self) -> VfsResult<()> {
        self.metadata.increment_link_count()
    }

    pub(crate) fn decrement_link_count(&mut self) {
        self.metadata.decrement_link_count();
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcSelfData {
    executable_path: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
}

impl ProcSelfData {
    #[must_use]
    pub fn new(
        executable_path: impl Into<Vec<u8>>,
        argv: impl IntoIterator<Item = Vec<u8>>,
        envp: impl IntoIterator<Item = Vec<u8>>,
    ) -> Self {
        Self {
            executable_path: executable_path.into(),
            argv: argv.into_iter().collect(),
            envp: envp.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn executable_path(&self) -> &[u8] {
        &self.executable_path
    }

    #[must_use]
    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    #[must_use]
    pub fn envp(&self) -> &[Vec<u8>] {
        &self.envp
    }

    #[must_use]
    pub fn cmdline_bytes(&self) -> Vec<u8> {
        nul_joined_entries(&self.argv)
    }

    #[must_use]
    pub fn environ_bytes(&self) -> Vec<u8> {
        nul_joined_entries(&self.envp)
    }
}

fn nul_joined_entries(entries: &[Vec<u8>]) -> Vec<u8> {
    let total_len = entries.iter().map(|entry| entry.len() + 1).sum();
    let mut bytes = Vec::with_capacity(total_len);
    for entry in entries {
        bytes.extend_from_slice(entry);
        bytes.push(0);
    }
    bytes
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathNodeKind {
    Directory,
    File,
    Device(DevNodeKind),
    Proc(ProcNodeKind),
    Symlink(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcNodeKind {
    Directory,
    Exe,
    Cmdline,
    Environ,
    FdDirectory,
    FdLink(Fd),
}

impl ProcNodeKind {
    fn attr(self, inode: InodeId, mode: u32) -> LinuxFileAttr {
        match self {
            Self::Directory | Self::FdDirectory => LinuxFileAttr::directory_with_mode(inode, mode),
            Self::Exe | Self::FdLink(_) => LinuxFileAttr::symlink(inode, 0),
            Self::Cmdline | Self::Environ => LinuxFileAttr::regular(inode, mode, 0),
        }
    }

    pub(crate) fn file_kind(self) -> FileKind {
        match self {
            Self::Directory | Self::FdDirectory => FileKind::Directory,
            Self::Exe | Self::FdLink(_) => FileKind::Symlink,
            Self::Cmdline | Self::Environ => FileKind::Regular,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::Exe => "self/exe",
            Self::Cmdline => "self/cmdline",
            Self::Environ => "self/environ",
            Self::FdDirectory => "self/fd",
            Self::FdLink(_) => "self/fd",
        }
    }
}

fn is_directory_kind(kind: &PathNodeKind) -> bool {
    matches!(
        kind,
        PathNodeKind::Directory
            | PathNodeKind::Proc(ProcNodeKind::Directory | ProcNodeKind::FdDirectory)
    )
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileTimes {
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
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

    pub fn set_owner(&mut self, uid: Option<u32>, gid: Option<u32>) {
        if let Some(uid) = uid {
            self.attr.uid = uid;
        }
        if let Some(gid) = gid {
            self.attr.gid = gid;
        }
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

    pub fn set_times(&mut self, times: FileTimes) {
        self.attr.atime_sec = times.atime_sec;
        self.attr.atime_nsec = times.atime_nsec;
        self.attr.mtime_sec = times.mtime_sec;
        self.attr.mtime_nsec = times.mtime_nsec;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxFsKind {
    ExtLike,
    TmpfsLike,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxStatfs {
    pub kind: LinuxFsKind,
    pub block_size: u64,
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub files: u64,
    pub files_free: u64,
    pub name_max: u64,
}

impl LinuxStatfs {
    pub(crate) const fn ext_like() -> Self {
        Self {
            kind: LinuxFsKind::ExtLike,
            block_size: 4096,
            blocks: 262_144,
            blocks_free: 196_608,
            blocks_available: 196_608,
            files: 65_536,
            files_free: 49_152,
            name_max: 255,
        }
    }

    pub(crate) const fn tmpfs_like() -> Self {
        Self {
            kind: LinuxFsKind::TmpfsLike,
            block_size: 4096,
            blocks: 65_536,
            blocks_free: 49_152,
            blocks_available: 49_152,
            files: 32_768,
            files_free: 24_576,
            name_max: 255,
        }
    }
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

    pub fn socket(inode: InodeId) -> Self {
        Self::new(inode, S_IFSOCK | 0o666, 0)
    }

    pub(crate) fn new(inode: InodeId, mode: u32, size: u64) -> Self {
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

    pub fn is_socket(self) -> bool {
        self.kind_bits() == S_IFSOCK
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
            S_IFSOCK => DT_SOCK,
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
                        if !is_directory_kind(node.kind()) && !pending.is_empty() {
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

pub(crate) fn parse_absolute_path(path: &str) -> VfsResult<GuestPath> {
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
