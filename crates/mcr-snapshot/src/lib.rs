use std::{
    collections::{BTreeMap, BTreeSet},
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
    deleted_lower_paths: BTreeSet<SnapshotPath>,
    opaque_directories: BTreeSet<SnapshotPath>,
}

impl SnapshotSpec {
    #[must_use]
    pub fn new(id: SnapshotId, upper_root: WritableUpperRoot) -> Self {
        Self {
            id,
            lower_layers: Vec::new(),
            upper_root,
            sidecar_records: BTreeMap::new(),
            deleted_lower_paths: BTreeSet::new(),
            opaque_directories: BTreeSet::new(),
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

    pub fn delete_lower_path(&mut self, path: SnapshotPath) -> Result<(), SnapshotError> {
        if path.as_str() == "/" {
            return Err(SnapshotError::CannotWhiteoutRoot);
        }
        self.deleted_lower_paths.insert(path);
        Ok(())
    }

    pub fn mark_opaque_directory(&mut self, path: SnapshotPath) {
        self.opaque_directories.insert(path);
    }

    #[must_use]
    pub fn sidecar_records(&self) -> impl ExactSizeIterator<Item = SnapshotEntry> + '_ {
        self.sidecar_records
            .iter()
            .map(|(path, metadata)| SnapshotEntry::new(path.clone(), metadata.clone()))
    }

    #[must_use]
    pub fn deleted_lower_paths(&self) -> impl ExactSizeIterator<Item = SnapshotPath> + '_ {
        self.deleted_lower_paths.iter().cloned()
    }

    #[must_use]
    pub fn opaque_directories(&self) -> impl ExactSizeIterator<Item = SnapshotPath> + '_ {
        self.opaque_directories.iter().cloned()
    }

    #[must_use]
    pub fn deterministic_view(&self) -> SnapshotView {
        SnapshotView {
            entries: self.sidecar_records().collect(),
        }
    }

    pub fn deterministic_layer_plan(&self) -> Result<SnapshotLayerPlan, SnapshotError> {
        SnapshotLayerPlan::from_parts(
            self.sidecar_records(),
            self.deleted_lower_paths(),
            self.opaque_directories(),
        )
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
pub struct SnapshotLayerPlan {
    entries: Vec<LayerEntry>,
}

impl SnapshotLayerPlan {
    pub fn from_parts(
        entries: impl IntoIterator<Item = SnapshotEntry>,
        deleted_lower_paths: impl IntoIterator<Item = SnapshotPath>,
        opaque_directories: impl IntoIterator<Item = SnapshotPath>,
    ) -> Result<Self, SnapshotError> {
        let mut planned = BTreeMap::new();

        for entry in entries {
            insert_layer_entry(
                &mut planned,
                entry.path().clone(),
                LayerEntryKind::Filesystem {
                    metadata: entry.metadata().clone(),
                },
            )?;
        }

        for deleted_path in deleted_lower_paths {
            let path = whiteout_path_for_deleted(&deleted_path)?;
            insert_layer_entry(
                &mut planned,
                path,
                LayerEntryKind::Whiteout { deleted_path },
            )?;
        }

        for directory_path in opaque_directories {
            let path = opaque_whiteout_path_for_directory(&directory_path)?;
            insert_layer_entry(
                &mut planned,
                path,
                LayerEntryKind::OpaqueDirectory { directory_path },
            )?;
        }

        Ok(Self {
            entries: planned
                .into_iter()
                .map(|(path, kind)| LayerEntry::new(path, kind))
                .collect(),
        })
    }

    #[must_use]
    pub fn entries(&self) -> &[LayerEntry] {
        &self.entries
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayerEntry {
    path: SnapshotPath,
    kind: LayerEntryKind,
}

impl LayerEntry {
    #[must_use]
    pub const fn new(path: SnapshotPath, kind: LayerEntryKind) -> Self {
        Self { path, kind }
    }

    #[must_use]
    pub const fn path(&self) -> &SnapshotPath {
        &self.path
    }

    #[must_use]
    pub const fn kind(&self) -> &LayerEntryKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LayerEntryKind {
    Filesystem { metadata: LinuxMetadata },
    Whiteout { deleted_path: SnapshotPath },
    OpaqueDirectory { directory_path: SnapshotPath },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    EmptySnapshotId,
    InvalidSnapshotId(String),
    EmptyUpperRoot,
    RelativeSnapshotPath(String),
    InvalidSnapshotPath(String),
    CannotWhiteoutRoot,
    ConflictingLayerEntry(SnapshotPath),
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
            Self::CannotWhiteoutRoot => formatter.write_str("cannot whiteout snapshot root"),
            Self::ConflictingLayerEntry(path) => {
                write!(formatter, "conflicting layer entry path: {path}")
            }
        }
    }
}

impl Error for SnapshotError {}

fn insert_layer_entry(
    entries: &mut BTreeMap<SnapshotPath, LayerEntryKind>,
    path: SnapshotPath,
    kind: LayerEntryKind,
) -> Result<(), SnapshotError> {
    if entries.contains_key(&path) {
        return Err(SnapshotError::ConflictingLayerEntry(path));
    }
    entries.insert(path, kind);
    Ok(())
}

fn whiteout_path_for_deleted(deleted_path: &SnapshotPath) -> Result<SnapshotPath, SnapshotError> {
    let (parent, name) = split_parent_and_name(deleted_path)?;
    SnapshotPath::new(join_snapshot_child(parent, &format!(".wh.{name}")))
}

fn opaque_whiteout_path_for_directory(
    directory_path: &SnapshotPath,
) -> Result<SnapshotPath, SnapshotError> {
    SnapshotPath::new(join_snapshot_child(directory_path.as_str(), ".wh..wh..opq"))
}

fn split_parent_and_name(path: &SnapshotPath) -> Result<(&str, &str), SnapshotError> {
    let path = path.as_str();
    if path == "/" {
        return Err(SnapshotError::CannotWhiteoutRoot);
    }
    let index = path.rfind('/').expect("absolute snapshot path has a slash");
    let parent = if index == 0 { "/" } else { &path[..index] };
    Ok((parent, &path[index + 1..]))
}

fn join_snapshot_child(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{parent}/{child}")
    }
}

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
    fn layer_plan_emits_deleted_lower_file_whiteouts() {
        let mut spec = SnapshotSpec::new(
            SnapshotId::new("delete-step").unwrap(),
            WritableUpperRoot::new("upper").unwrap(),
        );
        spec.delete_lower_path(SnapshotPath::new("/etc/removed.conf").unwrap())
            .unwrap();

        let plan = spec.deterministic_layer_plan().unwrap();
        assert_eq!(layer_paths(&plan), vec!["/etc/.wh.removed.conf"]);
        assert_eq!(
            plan.entries()[0].kind(),
            &LayerEntryKind::Whiteout {
                deleted_path: SnapshotPath::new("/etc/removed.conf").unwrap()
            }
        );
    }

    #[test]
    fn layer_plan_emits_opaque_directory_markers() {
        let mut spec = SnapshotSpec::new(
            SnapshotId::new("opaque-step").unwrap(),
            WritableUpperRoot::new("upper").unwrap(),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/var/cache").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 5),
        );
        spec.mark_opaque_directory(SnapshotPath::new("/var/cache").unwrap());

        let plan = spec.deterministic_layer_plan().unwrap();
        assert_eq!(
            layer_paths(&plan),
            vec!["/var/cache", "/var/cache/.wh..wh..opq"]
        );
        assert_eq!(
            plan.entries()[1].kind(),
            &LayerEntryKind::OpaqueDirectory {
                directory_path: SnapshotPath::new("/var/cache").unwrap()
            }
        );
    }

    #[test]
    fn layer_plan_preserves_symlink_and_hardlink_targets() {
        let mut spec = SnapshotSpec::new(
            SnapshotId::new("links-step").unwrap(),
            WritableUpperRoot::new("upper").unwrap(),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/lib/libc.so").unwrap(),
            LinuxMetadata::new(
                SnapshotFileKind::Symlink {
                    target: "/lib/libc.musl-x86_64.so.1".to_owned(),
                },
                0o777,
                0,
                0,
                7,
            ),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/usr/bin/tool-copy").unwrap(),
            LinuxMetadata::new(
                SnapshotFileKind::Hardlink {
                    target: SnapshotPath::new("/usr/bin/tool").unwrap(),
                },
                0o755,
                0,
                0,
                7,
            ),
        );

        let plan = spec.deterministic_layer_plan().unwrap();
        assert_eq!(
            plan.entries()[0].kind(),
            &LayerEntryKind::Filesystem {
                metadata: LinuxMetadata::new(
                    SnapshotFileKind::Symlink {
                        target: "/lib/libc.musl-x86_64.so.1".to_owned(),
                    },
                    0o777,
                    0,
                    0,
                    7,
                )
            }
        );
        assert_eq!(
            plan.entries()[1].kind(),
            &LayerEntryKind::Filesystem {
                metadata: LinuxMetadata::new(
                    SnapshotFileKind::Hardlink {
                        target: SnapshotPath::new("/usr/bin/tool").unwrap(),
                    },
                    0o755,
                    0,
                    0,
                    7,
                )
            }
        );
    }

    #[test]
    fn layer_plan_models_rename_over_existing_as_final_entry_plus_source_whiteout() {
        let mut spec = SnapshotSpec::new(
            SnapshotId::new("rename-step").unwrap(),
            WritableUpperRoot::new("upper").unwrap(),
        );
        spec.delete_lower_path(SnapshotPath::new("/usr/bin/old-tool").unwrap())
            .unwrap();
        spec.upsert_sidecar(
            SnapshotPath::new("/usr/bin/tool").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Regular { size: 11 }, 0o755, 0, 0, 9),
        );

        let plan = spec.deterministic_layer_plan().unwrap();
        assert_eq!(
            layer_paths(&plan),
            vec!["/usr/bin/.wh.old-tool", "/usr/bin/tool"]
        );
        assert_eq!(
            plan.entries()[1].kind(),
            &LayerEntryKind::Filesystem {
                metadata: LinuxMetadata::new(
                    SnapshotFileKind::Regular { size: 11 },
                    0o755,
                    0,
                    0,
                    9
                )
            }
        );
    }

    #[test]
    fn layer_plan_ordering_is_stable_across_insert_order() {
        let mut first = SnapshotSpec::new(
            SnapshotId::new("first").unwrap(),
            WritableUpperRoot::new("upper-a").unwrap(),
        );
        first.upsert_sidecar(
            SnapshotPath::new("/usr/bin/app").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Regular { size: 7 }, 0o755, 1000, 1000, 42),
        );
        first.upsert_sidecar(
            SnapshotPath::new("/etc/new.conf").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Regular { size: 2 }, 0o644, 0, 0, 3),
        );
        first
            .delete_lower_path(SnapshotPath::new("/etc/old.conf").unwrap())
            .unwrap();
        first.mark_opaque_directory(SnapshotPath::new("/var/cache").unwrap());

        let mut second = SnapshotSpec::new(
            SnapshotId::new("second").unwrap(),
            WritableUpperRoot::new("upper-b").unwrap(),
        );
        second.mark_opaque_directory(SnapshotPath::new("/var/cache").unwrap());
        second
            .delete_lower_path(SnapshotPath::new("/etc/old.conf").unwrap())
            .unwrap();
        second.upsert_sidecar(
            SnapshotPath::new("/etc/new.conf").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Regular { size: 2 }, 0o644, 0, 0, 3),
        );
        second.upsert_sidecar(
            SnapshotPath::new("/usr/bin/app").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Regular { size: 7 }, 0o755, 1000, 1000, 42),
        );

        let first_plan = first.deterministic_layer_plan().unwrap();
        let second_plan = second.deterministic_layer_plan().unwrap();
        assert_eq!(first_plan, second_plan);
        assert_eq!(
            layer_paths(&first_plan),
            vec![
                "/etc/.wh.old.conf",
                "/etc/new.conf",
                "/usr/bin/app",
                "/var/cache/.wh..wh..opq"
            ]
        );
    }

    #[test]
    fn layer_plan_rejects_root_whiteouts_and_path_conflicts() {
        let mut root_delete = SnapshotSpec::new(
            SnapshotId::new("bad-delete").unwrap(),
            WritableUpperRoot::new("upper").unwrap(),
        );
        assert_eq!(
            root_delete.delete_lower_path(SnapshotPath::new("/").unwrap()),
            Err(SnapshotError::CannotWhiteoutRoot)
        );

        let mut conflict = SnapshotSpec::new(
            SnapshotId::new("conflict").unwrap(),
            WritableUpperRoot::new("upper").unwrap(),
        );
        conflict.upsert_sidecar(
            SnapshotPath::new("/etc/.wh.shadow").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Regular { size: 0 }, 0o644, 0, 0, 1),
        );
        conflict
            .delete_lower_path(SnapshotPath::new("/etc/shadow").unwrap())
            .unwrap();
        assert_eq!(
            conflict.deterministic_layer_plan(),
            Err(SnapshotError::ConflictingLayerEntry(
                SnapshotPath::new("/etc/.wh.shadow").unwrap()
            ))
        );
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

    fn layer_paths(plan: &SnapshotLayerPlan) -> Vec<&str> {
        plan.entries()
            .iter()
            .map(|entry| entry.path().as_str())
            .collect()
    }
}
