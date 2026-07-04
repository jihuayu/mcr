use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotId(String);

impl SnapshotId {
    pub fn new(value: impl Into<String>) -> Result<Self, SnapshotError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SnapshotError::EmptySnapshotId);
        }
        if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(SnapshotError::InvalidSnapshotId(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayerRef {
    id: SnapshotId,
}

impl LayerRef {
    #[must_use]
    pub const fn new(id: SnapshotId) -> Self {
        Self { id }
    }

    #[must_use]
    pub const fn id(&self) -> &SnapshotId {
        &self.id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WritableUpperRoot {
    host_path: PathBuf,
}

impl WritableUpperRoot {
    pub fn new(host_path: impl Into<PathBuf>) -> Result<Self, SnapshotError> {
        let host_path = host_path.into();
        if host_path.as_os_str().is_empty() {
            return Err(SnapshotError::EmptyUpperRoot);
        }
        Ok(Self { host_path })
    }

    #[must_use]
    pub fn host_path(&self) -> &Path {
        &self.host_path
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotPath(String);

impl SnapshotPath {
    pub fn new(path: impl Into<String>) -> Result<Self, SnapshotError> {
        let path = path.into();
        if !path.starts_with('/') {
            return Err(SnapshotError::RelativeSnapshotPath(path));
        }
        if path.len() > 1
            && path
                .split('/')
                .skip(1)
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(SnapshotError::InvalidSnapshotPath(path));
        }
        Ok(Self(path))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SnapshotPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEntry {
    path: SnapshotPath,
    metadata: LinuxMetadata,
}

impl SnapshotEntry {
    #[must_use]
    pub const fn new(path: SnapshotPath, metadata: LinuxMetadata) -> Self {
        Self { path, metadata }
    }

    #[must_use]
    pub const fn path(&self) -> &SnapshotPath {
        &self.path
    }

    #[must_use]
    pub const fn metadata(&self) -> &LinuxMetadata {
        &self.metadata
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxMetadata {
    kind: SnapshotFileKind,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_unix_nanos: i128,
}

impl LinuxMetadata {
    #[must_use]
    pub const fn new(
        kind: SnapshotFileKind,
        mode: u32,
        uid: u32,
        gid: u32,
        mtime_unix_nanos: i128,
    ) -> Self {
        Self {
            kind,
            mode,
            uid,
            gid,
            mtime_unix_nanos,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &SnapshotFileKind {
        &self.kind
    }

    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    #[must_use]
    pub const fn mtime_unix_nanos(&self) -> i128 {
        self.mtime_unix_nanos
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotFileKind {
    Directory,
    Regular { size: u64 },
    Symlink { target: String },
    Hardlink { target: SnapshotPath },
    CharacterDevice { major: u32, minor: u32 },
    BlockDevice { major: u32, minor: u32 },
    Fifo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotSpec {
    id: SnapshotId,
    lower_layers: Vec<LayerRef>,
    upper_root: WritableUpperRoot,
    sidecar_records: BTreeMap<SnapshotPath, LinuxMetadata>,
}

impl SnapshotSpec {
    #[must_use]
    pub fn new(id: SnapshotId, upper_root: WritableUpperRoot) -> Self {
        Self {
            id,
            lower_layers: Vec::new(),
            upper_root,
            sidecar_records: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn id(&self) -> &SnapshotId {
        &self.id
    }

    #[must_use]
    pub fn lower_layers(&self) -> &[LayerRef] {
        &self.lower_layers
    }

    #[must_use]
    pub const fn upper_root(&self) -> &WritableUpperRoot {
        &self.upper_root
    }

    pub fn add_lower_layer(&mut self, lower: LayerRef) {
        self.lower_layers.push(lower);
    }

    pub fn upsert_sidecar(&mut self, path: SnapshotPath, metadata: LinuxMetadata) {
        self.sidecar_records.insert(path, metadata);
    }

    #[must_use]
    pub fn sidecar_records(&self) -> impl ExactSizeIterator<Item = SnapshotEntry> + '_ {
        self.sidecar_records
            .iter()
            .map(|(path, metadata)| SnapshotEntry::new(path.clone(), metadata.clone()))
    }

    #[must_use]
    pub fn deterministic_view(&self) -> SnapshotView {
        SnapshotView {
            entries: self.sidecar_records().collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotView {
    entries: Vec<SnapshotEntry>,
}

impl SnapshotView {
    #[must_use]
    pub fn entries(&self) -> &[SnapshotEntry] {
        &self.entries
    }

    #[must_use]
    pub fn get(&self, path: &SnapshotPath) -> Option<&SnapshotEntry> {
        self.entries.iter().find(|entry| entry.path() == path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    EmptySnapshotId,
    InvalidSnapshotId(String),
    EmptyUpperRoot,
    RelativeSnapshotPath(String),
    InvalidSnapshotPath(String),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySnapshotId => formatter.write_str("snapshot id cannot be empty"),
            Self::InvalidSnapshotId(value) => write!(formatter, "invalid snapshot id: {value}"),
            Self::EmptyUpperRoot => formatter.write_str("writable upper root cannot be empty"),
            Self::RelativeSnapshotPath(path) => {
                write!(formatter, "snapshot path must be absolute: {path}")
            }
            Self::InvalidSnapshotPath(path) => write!(formatter, "invalid snapshot path: {path}"),
        }
    }
}

impl Error for SnapshotError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-snapshot");
    }

    #[test]
    fn snapshot_model_preserves_identity_layers_and_upper_root() {
        let mut spec = SnapshotSpec::new(
            SnapshotId::new("build-step-2").unwrap(),
            WritableUpperRoot::new("target/mcr/upper").unwrap(),
        );
        spec.add_lower_layer(LayerRef::new(SnapshotId::new("base").unwrap()));
        spec.add_lower_layer(LayerRef::new(SnapshotId::new("build-step-1").unwrap()));

        assert_eq!(spec.id().as_str(), "build-step-2");
        assert_eq!(spec.upper_root().host_path(), Path::new("target/mcr/upper"));
        assert_eq!(
            spec.lower_layers()
                .iter()
                .map(|layer| layer.id().as_str())
                .collect::<Vec<_>>(),
            vec!["base", "build-step-1"]
        );
    }

    #[test]
    fn deterministic_view_orders_sidecar_records_by_guest_path() {
        let mut spec = SnapshotSpec::new(
            SnapshotId::new("snapshot").unwrap(),
            WritableUpperRoot::new("upper").unwrap(),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/usr/bin/app").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Regular { size: 7 }, 0o755, 1000, 1000, 42),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/etc").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 1),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/lib/ld-musl-x86_64.so.1").unwrap(),
            LinuxMetadata::new(
                SnapshotFileKind::Symlink {
                    target: "/lib/libc.musl-x86_64.so.1".to_owned(),
                },
                0o777,
                0,
                0,
                2,
            ),
        );

        let view = spec.deterministic_view();
        assert_eq!(
            view.entries()
                .iter()
                .map(|entry| entry.path().as_str())
                .collect::<Vec<_>>(),
            vec!["/etc", "/lib/ld-musl-x86_64.so.1", "/usr/bin/app"]
        );
        assert_eq!(
            view.get(&SnapshotPath::new("/usr/bin/app").unwrap())
                .unwrap()
                .metadata()
                .mode(),
            0o755
        );
    }

    #[test]
    fn metadata_represents_linux_shapes_host_filesystems_may_not_store() {
        let hardlink_target = SnapshotPath::new("/usr/bin/tool").unwrap();
        let entries = [
            LinuxMetadata::new(
                SnapshotFileKind::Hardlink {
                    target: hardlink_target.clone(),
                },
                0o755,
                0,
                0,
                10,
            ),
            LinuxMetadata::new(
                SnapshotFileKind::CharacterDevice { major: 1, minor: 3 },
                0o666,
                0,
                0,
                11,
            ),
            LinuxMetadata::new(SnapshotFileKind::Fifo, 0o644, 100, 200, 12),
        ];

        assert!(matches!(
            entries[0].kind(),
            SnapshotFileKind::Hardlink { target } if target == &hardlink_target
        ));
        assert!(matches!(
            entries[1].kind(),
            SnapshotFileKind::CharacterDevice { major: 1, minor: 3 }
        ));
        assert!(matches!(entries[2].kind(), SnapshotFileKind::Fifo));
    }

    #[test]
    fn invalid_identity_and_paths_are_rejected() {
        assert_eq!(SnapshotId::new(""), Err(SnapshotError::EmptySnapshotId));
        assert_eq!(
            SnapshotId::new("has space"),
            Err(SnapshotError::InvalidSnapshotId("has space".to_owned()))
        );
        assert_eq!(
            WritableUpperRoot::new(""),
            Err(SnapshotError::EmptyUpperRoot)
        );
        assert_eq!(
            SnapshotPath::new("relative"),
            Err(SnapshotError::RelativeSnapshotPath("relative".to_owned()))
        );
        assert_eq!(
            SnapshotPath::new("/a/../b"),
            Err(SnapshotError::InvalidSnapshotPath("/a/../b".to_owned()))
        );
        assert_eq!(
            SnapshotPath::new("/a//b"),
            Err(SnapshotError::InvalidSnapshotPath("/a//b".to_owned()))
        );
    }
}
