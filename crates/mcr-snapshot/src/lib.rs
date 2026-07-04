use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs, io,
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

    pub fn export_upper_layer_tar(&self) -> Result<Vec<u8>, SnapshotExportError> {
        let plan = self.deterministic_layer_plan()?;
        let regular_contents = read_upper_regular_contents(self.upper_root(), &plan)?;
        plan.to_uncompressed_tar(&regular_contents)
            .map_err(SnapshotExportError::Layer)
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

    pub fn to_uncompressed_tar(
        &self,
        regular_contents: &BTreeMap<SnapshotPath, Vec<u8>>,
    ) -> Result<Vec<u8>, LayerExportError> {
        let mut archive = Vec::new();
        for entry in &self.entries {
            append_layer_tar_entry(&mut archive, entry, regular_contents)?;
        }
        archive.extend(std::iter::repeat_n(0, TAR_BLOCK_SIZE * 2));
        Ok(archive)
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
pub enum LayerExportError {
    CannotExportRootEntry,
    MissingRegularContent(SnapshotPath),
    RegularContentSizeMismatch {
        path: SnapshotPath,
        expected: u64,
        actual: u64,
    },
    NegativeMtime(SnapshotPath),
    HeaderFieldTooLarge(&'static str),
    PathTooLong(String),
    LinkNameTooLong(String),
}

impl fmt::Display for LayerExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotExportRootEntry => formatter.write_str("cannot export snapshot root entry"),
            Self::MissingRegularContent(path) => {
                write!(
                    formatter,
                    "missing regular file content for layer path: {path}"
                )
            }
            Self::RegularContentSizeMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "regular file content size mismatch for {path}: expected {expected}, got {actual}"
            ),
            Self::NegativeMtime(path) => {
                write!(
                    formatter,
                    "negative mtime cannot be encoded in tar for: {path}"
                )
            }
            Self::HeaderFieldTooLarge(field) => {
                write!(formatter, "tar header field is too large: {field}")
            }
            Self::PathTooLong(path) => write!(formatter, "tar path is too long: {path}"),
            Self::LinkNameTooLong(path) => write!(formatter, "tar link name is too long: {path}"),
        }
    }
}

impl Error for LayerExportError {}

#[derive(Debug)]
pub enum SnapshotExportError {
    Snapshot(SnapshotError),
    Layer(LayerExportError),
    Io { path: PathBuf, source: io::Error },
}

impl fmt::Display for SnapshotExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot(error) => error.fmt(formatter),
            Self::Layer(error) => error.fmt(formatter),
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "failed to read upper root content `{}`: {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for SnapshotExportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Snapshot(error) => Some(error),
            Self::Layer(error) => Some(error),
            Self::Io { source, .. } => Some(source),
        }
    }
}

impl From<SnapshotError> for SnapshotExportError {
    fn from(error: SnapshotError) -> Self {
        Self::Snapshot(error)
    }
}

fn read_upper_regular_contents(
    upper_root: &WritableUpperRoot,
    plan: &SnapshotLayerPlan,
) -> Result<BTreeMap<SnapshotPath, Vec<u8>>, SnapshotExportError> {
    let mut contents = BTreeMap::new();
    for entry in plan.entries() {
        let LayerEntryKind::Filesystem { metadata } = entry.kind() else {
            continue;
        };
        if !matches!(metadata.kind(), SnapshotFileKind::Regular { .. }) {
            continue;
        }
        let host_path = upper_host_path(upper_root, entry.path());
        let bytes = fs::read(&host_path).map_err(|source| SnapshotExportError::Io {
            path: host_path,
            source,
        })?;
        contents.insert(entry.path().clone(), bytes);
    }
    Ok(contents)
}

fn upper_host_path(upper_root: &WritableUpperRoot, path: &SnapshotPath) -> PathBuf {
    upper_root
        .host_path()
        .join(path.as_str().trim_start_matches('/'))
}

fn append_layer_tar_entry(
    archive: &mut Vec<u8>,
    entry: &LayerEntry,
    regular_contents: &BTreeMap<SnapshotPath, Vec<u8>>,
) -> Result<(), LayerExportError> {
    match entry.kind() {
        LayerEntryKind::Filesystem { metadata } => {
            let content = regular_content_for(entry.path(), metadata, regular_contents)?;
            append_tar_header(archive, entry.path(), metadata)?;
            append_tar_content(archive, content);
        }
        LayerEntryKind::Whiteout { .. } | LayerEntryKind::OpaqueDirectory { .. } => {
            let metadata = LinuxMetadata::new(SnapshotFileKind::Regular { size: 0 }, 0, 0, 0, 0);
            append_tar_header(archive, entry.path(), &metadata)?;
        }
    }
    Ok(())
}

fn regular_content_for<'a>(
    path: &SnapshotPath,
    metadata: &LinuxMetadata,
    regular_contents: &'a BTreeMap<SnapshotPath, Vec<u8>>,
) -> Result<&'a [u8], LayerExportError> {
    let SnapshotFileKind::Regular { size } = metadata.kind() else {
        return Ok(&[]);
    };
    let Some(content) = regular_contents.get(path) else {
        if *size == 0 {
            return Ok(&[]);
        }
        return Err(LayerExportError::MissingRegularContent(path.clone()));
    };
    let actual = u64::try_from(content.len()).expect("usize fits in u64");
    if actual != *size {
        return Err(LayerExportError::RegularContentSizeMismatch {
            path: path.clone(),
            expected: *size,
            actual,
        });
    }
    Ok(content)
}

fn append_tar_header(
    archive: &mut Vec<u8>,
    path: &SnapshotPath,
    metadata: &LinuxMetadata,
) -> Result<(), LayerExportError> {
    let mut header = [0u8; TAR_BLOCK_SIZE];
    let tar_path = layer_tar_path(path)?;
    let path_parts = split_tar_path(&tar_path)?;
    write_tar_field_string(&mut header[0..100], path_parts.name, "name")?;
    if let Some(prefix) = path_parts.prefix {
        write_tar_field_string(&mut header[345..500], prefix, "prefix")?;
    }
    write_tar_field_octal(&mut header[100..108], u64::from(metadata.mode()), "mode")?;
    write_tar_field_octal(&mut header[108..116], u64::from(metadata.uid()), "uid")?;
    write_tar_field_octal(&mut header[116..124], u64::from(metadata.gid()), "gid")?;
    write_tar_field_octal(&mut header[124..136], tar_size(metadata), "size")?;
    write_tar_field_octal(
        &mut header[136..148],
        tar_mtime_seconds(path, metadata)?,
        "mtime",
    )?;
    header[148..156].fill(b' ');
    header[156] = tar_typeflag(metadata);
    match metadata.kind() {
        SnapshotFileKind::Symlink { target } => {
            write_tar_link_name(&mut header[157..257], target)?;
        }
        SnapshotFileKind::Hardlink { target } => {
            let target = layer_tar_path(target)?;
            write_tar_link_name(&mut header[157..257], &target)?;
        }
        SnapshotFileKind::CharacterDevice { major, minor }
        | SnapshotFileKind::BlockDevice { major, minor } => {
            write_tar_field_octal(&mut header[329..337], u64::from(*major), "devmajor")?;
            write_tar_field_octal(&mut header[337..345], u64::from(*minor), "devminor")?;
        }
        SnapshotFileKind::Directory | SnapshotFileKind::Regular { .. } | SnapshotFileKind::Fifo => {
        }
    }
    write_tar_field_string(&mut header[257..263], "ustar", "magic")?;
    write_tar_field_string(&mut header[263..265], "00", "version")?;
    write_tar_checksum(&mut header);
    archive.extend_from_slice(&header);
    Ok(())
}

fn append_tar_content(archive: &mut Vec<u8>, content: &[u8]) {
    if content.is_empty() {
        return;
    }
    archive.extend_from_slice(content);
    let padding = (TAR_BLOCK_SIZE - (content.len() % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
    archive.extend(std::iter::repeat_n(0, padding));
}

fn tar_size(metadata: &LinuxMetadata) -> u64 {
    match metadata.kind() {
        SnapshotFileKind::Regular { size } => *size,
        _ => 0,
    }
}

fn tar_typeflag(metadata: &LinuxMetadata) -> u8 {
    match metadata.kind() {
        SnapshotFileKind::Regular { .. } => b'0',
        SnapshotFileKind::Hardlink { .. } => b'1',
        SnapshotFileKind::Symlink { .. } => b'2',
        SnapshotFileKind::CharacterDevice { .. } => b'3',
        SnapshotFileKind::BlockDevice { .. } => b'4',
        SnapshotFileKind::Directory => b'5',
        SnapshotFileKind::Fifo => b'6',
    }
}

fn tar_mtime_seconds(
    path: &SnapshotPath,
    metadata: &LinuxMetadata,
) -> Result<u64, LayerExportError> {
    let nanos = metadata.mtime_unix_nanos();
    if nanos < 0 {
        return Err(LayerExportError::NegativeMtime(path.clone()));
    }
    u64::try_from(nanos / 1_000_000_000).map_err(|_| LayerExportError::HeaderFieldTooLarge("mtime"))
}

fn layer_tar_path(path: &SnapshotPath) -> Result<String, LayerExportError> {
    let path = path.as_str();
    if path == "/" {
        return Err(LayerExportError::CannotExportRootEntry);
    }
    Ok(path.trim_start_matches('/').to_owned())
}

struct TarPathParts<'a> {
    prefix: Option<&'a str>,
    name: &'a str,
}

fn split_tar_path(path: &str) -> Result<TarPathParts<'_>, LayerExportError> {
    if path.len() <= 100 {
        return Ok(TarPathParts {
            prefix: None,
            name: path,
        });
    }
    for index in path.match_indices('/').map(|(index, _)| index).rev() {
        let prefix = &path[..index];
        let name = &path[index + 1..];
        if !prefix.is_empty() && !name.is_empty() && prefix.len() <= 155 && name.len() <= 100 {
            return Ok(TarPathParts {
                prefix: Some(prefix),
                name,
            });
        }
    }
    Err(LayerExportError::PathTooLong(path.to_owned()))
}

fn write_tar_link_name(field: &mut [u8], value: &str) -> Result<(), LayerExportError> {
    if value.len() > field.len() {
        return Err(LayerExportError::LinkNameTooLong(value.to_owned()));
    }
    field[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

fn write_tar_field_string(
    field: &mut [u8],
    value: &str,
    field_name: &'static str,
) -> Result<(), LayerExportError> {
    if value.len() > field.len() {
        return Err(LayerExportError::HeaderFieldTooLarge(field_name));
    }
    field[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

fn write_tar_field_octal(
    field: &mut [u8],
    value: u64,
    field_name: &'static str,
) -> Result<(), LayerExportError> {
    let encoded = format!("{value:0width$o}", width = field.len() - 1);
    if encoded.len() >= field.len() {
        return Err(LayerExportError::HeaderFieldTooLarge(field_name));
    }
    field[..encoded.len()].copy_from_slice(encoded.as_bytes());
    Ok(())
}

fn write_tar_checksum(header: &mut [u8; TAR_BLOCK_SIZE]) {
    let checksum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
    let encoded = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(encoded.as_bytes());
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaseLayerSnapshot {
    layer: LayerRef,
    entries: Vec<SnapshotEntry>,
}

impl BaseLayerSnapshot {
    pub fn from_uncompressed_tar(layer: LayerRef, bytes: &[u8]) -> Result<Self, LayerUnpackError> {
        let mut offset = 0usize;
        let mut entries = Vec::new();

        while offset < bytes.len() {
            let header_end = offset
                .checked_add(TAR_BLOCK_SIZE)
                .ok_or(LayerUnpackError::ArchiveTooLarge)?;
            if header_end > bytes.len() {
                return Err(LayerUnpackError::TruncatedHeader);
            }

            let header = &bytes[offset..header_end];
            if header.iter().all(|byte| *byte == 0) {
                break;
            }

            let path = tar_entry_path(header)?;
            let mode = u32::try_from(tar_octal(&header[100..108], "mode")?)
                .map_err(|_| LayerUnpackError::FieldTooLarge("mode"))?;
            let uid = u32::try_from(tar_octal(&header[108..116], "uid")?)
                .map_err(|_| LayerUnpackError::FieldTooLarge("uid"))?;
            let gid = u32::try_from(tar_octal(&header[116..124], "gid")?)
                .map_err(|_| LayerUnpackError::FieldTooLarge("gid"))?;
            let size = tar_octal(&header[124..136], "size")?;
            let mtime_seconds = tar_octal(&header[136..148], "mtime")?;
            let mtime_unix_nanos = i128::from(mtime_seconds) * 1_000_000_000;

            let metadata = LinuxMetadata::new(
                tar_entry_kind(header, size)?,
                mode,
                uid,
                gid,
                mtime_unix_nanos,
            );
            entries.push(SnapshotEntry::new(path, metadata));

            offset = header_end;
            let data_len = padded_tar_len(size)?;
            let data_end = offset
                .checked_add(data_len)
                .ok_or(LayerUnpackError::ArchiveTooLarge)?;
            if data_end > bytes.len() {
                return Err(LayerUnpackError::TruncatedEntryData);
            }
            offset = data_end;
        }

        entries.sort_by(|left, right| left.path().cmp(right.path()));
        Ok(Self { layer, entries })
    }

    #[must_use]
    pub const fn layer(&self) -> &LayerRef {
        &self.layer
    }

    #[must_use]
    pub fn entries(&self) -> &[SnapshotEntry] {
        &self.entries
    }

    #[must_use]
    pub fn get(&self, path: &SnapshotPath) -> Option<&SnapshotEntry> {
        self.entries.iter().find(|entry| entry.path() == path)
    }
}

const TAR_BLOCK_SIZE: usize = 512;

fn tar_entry_kind(header: &[u8], size: u64) -> Result<SnapshotFileKind, LayerUnpackError> {
    match header[156] {
        0 | b'0' => Ok(SnapshotFileKind::Regular { size }),
        b'1' => Ok(SnapshotFileKind::Hardlink {
            target: tar_link_snapshot_path(&header[157..257])?,
        }),
        b'2' => Ok(SnapshotFileKind::Symlink {
            target: tar_string(&header[157..257], "linkname")?,
        }),
        b'3' => Ok(SnapshotFileKind::CharacterDevice {
            major: u32::try_from(tar_octal(&header[329..337], "devmajor")?)
                .map_err(|_| LayerUnpackError::FieldTooLarge("devmajor"))?,
            minor: u32::try_from(tar_octal(&header[337..345], "devminor")?)
                .map_err(|_| LayerUnpackError::FieldTooLarge("devminor"))?,
        }),
        b'4' => Ok(SnapshotFileKind::BlockDevice {
            major: u32::try_from(tar_octal(&header[329..337], "devmajor")?)
                .map_err(|_| LayerUnpackError::FieldTooLarge("devmajor"))?,
            minor: u32::try_from(tar_octal(&header[337..345], "devminor")?)
                .map_err(|_| LayerUnpackError::FieldTooLarge("devminor"))?,
        }),
        b'5' => Ok(SnapshotFileKind::Directory),
        b'6' => Ok(SnapshotFileKind::Fifo),
        other => Err(LayerUnpackError::UnsupportedEntryType(other)),
    }
}

fn tar_entry_path(header: &[u8]) -> Result<SnapshotPath, LayerUnpackError> {
    let name = tar_string(&header[0..100], "name")?;
    let prefix = tar_string(&header[345..500], "prefix")?;
    let mut path = if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    };
    trim_trailing_slashes(&mut path);
    relative_tar_path_to_snapshot_path(path)
}

fn tar_link_snapshot_path(field: &[u8]) -> Result<SnapshotPath, LayerUnpackError> {
    let mut path = tar_string(field, "linkname")?;
    trim_trailing_slashes(&mut path);
    relative_tar_path_to_snapshot_path(path)
}

fn relative_tar_path_to_snapshot_path(path: String) -> Result<SnapshotPath, LayerUnpackError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err(LayerUnpackError::InvalidEntryPath(path));
    }
    SnapshotPath::new(format!("/{path}")).map_err(LayerUnpackError::SnapshotPath)
}

fn trim_trailing_slashes(path: &mut String) {
    while path.ends_with('/') {
        path.pop();
    }
}

fn tar_string(field: &[u8], field_name: &'static str) -> Result<String, LayerUnpackError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let mut value = &field[..end];
    while value.last() == Some(&b' ') {
        value = &value[..value.len() - 1];
    }
    if !value.is_ascii() {
        return Err(LayerUnpackError::InvalidStringField(field_name));
    }
    String::from_utf8(value.to_vec()).map_err(|_| LayerUnpackError::InvalidStringField(field_name))
}

fn tar_octal(field: &[u8], field_name: &'static str) -> Result<u64, LayerUnpackError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let mut value = &field[..end];
    while value.first() == Some(&b' ') {
        value = &value[1..];
    }
    while value.last() == Some(&b' ') {
        value = &value[..value.len() - 1];
    }
    if value.is_empty() {
        return Ok(0);
    }

    let mut parsed = 0u64;
    for byte in value {
        if !(b'0'..=b'7').contains(byte) {
            return Err(LayerUnpackError::InvalidOctalField(field_name));
        }
        parsed = parsed
            .checked_mul(8)
            .and_then(|current| current.checked_add(u64::from(byte - b'0')))
            .ok_or(LayerUnpackError::FieldTooLarge(field_name))?;
    }
    Ok(parsed)
}

fn padded_tar_len(size: u64) -> Result<usize, LayerUnpackError> {
    let size = usize::try_from(size).map_err(|_| LayerUnpackError::ArchiveTooLarge)?;
    let padding = (TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
    size.checked_add(padding)
        .ok_or(LayerUnpackError::ArchiveTooLarge)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LayerUnpackError {
    ArchiveTooLarge,
    TruncatedHeader,
    TruncatedEntryData,
    InvalidEntryPath(String),
    InvalidStringField(&'static str),
    InvalidOctalField(&'static str),
    FieldTooLarge(&'static str),
    UnsupportedEntryType(u8),
    SnapshotPath(SnapshotError),
}

impl fmt::Display for LayerUnpackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchiveTooLarge => formatter.write_str("layer archive is too large"),
            Self::TruncatedHeader => formatter.write_str("layer archive has a truncated header"),
            Self::TruncatedEntryData => {
                formatter.write_str("layer archive has truncated entry data")
            }
            Self::InvalidEntryPath(path) => write!(formatter, "invalid layer entry path: {path}"),
            Self::InvalidStringField(field) => {
                write!(formatter, "invalid layer archive string field: {field}")
            }
            Self::InvalidOctalField(field) => {
                write!(formatter, "invalid layer archive octal field: {field}")
            }
            Self::FieldTooLarge(field) => {
                write!(formatter, "layer archive field is too large: {field}")
            }
            Self::UnsupportedEntryType(entry_type) => {
                write!(
                    formatter,
                    "unsupported layer archive entry type: {entry_type}"
                )
            }
            Self::SnapshotPath(error) => error.fmt(formatter),
        }
    }
}

impl Error for LayerUnpackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SnapshotPath(error) => Some(error),
            _ => None,
        }
    }
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
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

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

    #[test]
    fn layer_plan_exports_deterministic_uncompressed_tar() {
        let mut spec = SnapshotSpec::new(
            SnapshotId::new("tar-step").unwrap(),
            WritableUpperRoot::new("upper").unwrap(),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/etc").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 1_000_000_000),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/etc/config").unwrap(),
            LinuxMetadata::new(
                SnapshotFileKind::Regular { size: 9 },
                0o640,
                100,
                200,
                2_000_000_000,
            ),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/bin/sh").unwrap(),
            LinuxMetadata::new(
                SnapshotFileKind::Symlink {
                    target: "../busybox".to_owned(),
                },
                0o777,
                0,
                0,
                3_000_000_000,
            ),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/bin/tool-copy").unwrap(),
            LinuxMetadata::new(
                SnapshotFileKind::Hardlink {
                    target: SnapshotPath::new("/bin/tool").unwrap(),
                },
                0o755,
                0,
                0,
                4_000_000_000,
            ),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/var/cache").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 5_000_000_000),
        );
        spec.delete_lower_path(SnapshotPath::new("/etc/old").unwrap())
            .unwrap();
        spec.mark_opaque_directory(SnapshotPath::new("/var/cache").unwrap());

        let plan = spec.deterministic_layer_plan().unwrap();
        let mut content = BTreeMap::new();
        content.insert(
            SnapshotPath::new("/etc/config").unwrap(),
            b"name=mcr\n".to_vec(),
        );

        let first = plan.to_uncompressed_tar(&content).unwrap();
        let second = plan.to_uncompressed_tar(&content).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            tar_entry_names(&first),
            vec![
                "bin/sh",
                "bin/tool-copy",
                "etc",
                "etc/.wh.old",
                "etc/config",
                "var/cache",
                "var/cache/.wh..wh..opq"
            ]
        );
        assert_eq!(
            tar_entry_payload(&first, "etc/config"),
            Some(b"name=mcr\n".as_slice())
        );

        let layer = BaseLayerSnapshot::from_uncompressed_tar(
            LayerRef::new(SnapshotId::new("exported").unwrap()),
            &first,
        )
        .unwrap();
        assert_eq!(
            layer
                .entries()
                .iter()
                .map(|entry| entry.path().as_str())
                .collect::<Vec<_>>(),
            vec![
                "/bin/sh",
                "/bin/tool-copy",
                "/etc",
                "/etc/.wh.old",
                "/etc/config",
                "/var/cache",
                "/var/cache/.wh..wh..opq"
            ]
        );
        assert_eq!(
            layer
                .get(&SnapshotPath::new("/etc/.wh.old").unwrap())
                .unwrap()
                .metadata()
                .kind(),
            &SnapshotFileKind::Regular { size: 0 }
        );
        assert_eq!(
            layer
                .get(&SnapshotPath::new("/bin/tool-copy").unwrap())
                .unwrap()
                .metadata()
                .kind(),
            &SnapshotFileKind::Hardlink {
                target: SnapshotPath::new("/bin/tool").unwrap()
            }
        );
    }

    #[test]
    fn snapshot_spec_exports_upper_root_regular_content_to_layer_tar() {
        let upper = temp_root("upper-export");
        std::fs::create_dir_all(upper.join("etc")).unwrap();
        std::fs::write(upper.join("etc/config"), b"name=mcr\n").unwrap();

        let mut spec = SnapshotSpec::new(
            SnapshotId::new("upper-step").unwrap(),
            WritableUpperRoot::new(&upper).unwrap(),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/etc").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 0),
        );
        spec.upsert_sidecar(
            SnapshotPath::new("/etc/config").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Regular { size: 9 }, 0o640, 100, 200, 0),
        );
        spec.delete_lower_path(SnapshotPath::new("/etc/old").unwrap())
            .unwrap();

        let archive = spec.export_upper_layer_tar().unwrap();

        assert_eq!(
            tar_entry_names(&archive),
            vec!["etc", "etc/.wh.old", "etc/config"]
        );
        assert_eq!(
            tar_entry_payload(&archive, "etc/config"),
            Some(b"name=mcr\n".as_slice())
        );
        std::fs::remove_dir_all(upper).unwrap();
    }

    #[test]
    fn layer_plan_export_rejects_missing_or_mismatched_regular_content() {
        let plan = SnapshotLayerPlan::from_parts(
            [SnapshotEntry::new(
                SnapshotPath::new("/payload").unwrap(),
                LinuxMetadata::new(SnapshotFileKind::Regular { size: 4 }, 0o644, 0, 0, 0),
            )],
            [],
            [],
        )
        .unwrap();

        assert_eq!(
            plan.to_uncompressed_tar(&BTreeMap::new()),
            Err(LayerExportError::MissingRegularContent(
                SnapshotPath::new("/payload").unwrap()
            ))
        );

        let mut content = BTreeMap::new();
        content.insert(SnapshotPath::new("/payload").unwrap(), b"too long".to_vec());
        assert_eq!(
            plan.to_uncompressed_tar(&content),
            Err(LayerExportError::RegularContentSizeMismatch {
                path: SnapshotPath::new("/payload").unwrap(),
                expected: 4,
                actual: 8,
            })
        );
    }

    #[test]
    fn layer_plan_export_rejects_root_tar_entry() {
        let plan = SnapshotLayerPlan::from_parts(
            [SnapshotEntry::new(
                SnapshotPath::new("/").unwrap(),
                LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 0),
            )],
            [],
            [],
        )
        .unwrap();

        assert_eq!(
            plan.to_uncompressed_tar(&BTreeMap::new()),
            Err(LayerExportError::CannotExportRootEntry)
        );
    }

    fn layer_paths(plan: &SnapshotLayerPlan) -> Vec<&str> {
        plan.entries()
            .iter()
            .map(|entry| entry.path().as_str())
            .collect()
    }

    #[test]
    fn base_layer_unpack_reads_uncompressed_tar_metadata() {
        let mut archive = Vec::new();
        append_tar_dir(&mut archive, "etc/", 0o755, 0, 0, 1);
        append_tar_file(&mut archive, "etc/hostname", b"mcr\n", 0o644, 100, 200, 2);
        append_tar_symlink(&mut archive, "bin/sh", "../busybox", 3);
        finish_tar(&mut archive);

        let layer = BaseLayerSnapshot::from_uncompressed_tar(
            LayerRef::new(SnapshotId::new("sha256-base").unwrap()),
            &archive,
        )
        .unwrap();

        assert_eq!(layer.layer().id().as_str(), "sha256-base");
        assert_eq!(
            layer
                .entries()
                .iter()
                .map(|entry| entry.path().as_str())
                .collect::<Vec<_>>(),
            vec!["/bin/sh", "/etc", "/etc/hostname"]
        );

        let hostname = layer
            .get(&SnapshotPath::new("/etc/hostname").unwrap())
            .unwrap();
        assert_eq!(
            hostname.metadata().kind(),
            &SnapshotFileKind::Regular { size: 4 }
        );
        assert_eq!(hostname.metadata().mode(), 0o644);
        assert_eq!(hostname.metadata().uid(), 100);
        assert_eq!(hostname.metadata().gid(), 200);
        assert_eq!(hostname.metadata().mtime_unix_nanos(), 2_000_000_000);

        let shell = layer.get(&SnapshotPath::new("/bin/sh").unwrap()).unwrap();
        assert_eq!(
            shell.metadata().kind(),
            &SnapshotFileKind::Symlink {
                target: "../busybox".to_owned()
            }
        );
    }

    #[test]
    fn base_layer_unpack_rejects_paths_that_escape_guest_root() {
        let mut archive = Vec::new();
        append_tar_file(&mut archive, "../escape", b"x", 0o644, 0, 0, 1);
        finish_tar(&mut archive);

        assert!(matches!(
            BaseLayerSnapshot::from_uncompressed_tar(
                LayerRef::new(SnapshotId::new("bad").unwrap()),
                &archive,
            ),
            Err(LayerUnpackError::SnapshotPath(
                SnapshotError::InvalidSnapshotPath(_)
            ))
        ));
    }

    #[test]
    fn base_layer_unpack_rejects_truncated_entry_data() {
        let mut archive = Vec::new();
        append_tar_file(&mut archive, "file", b"payload", 0o644, 0, 0, 1);
        archive.truncate(TAR_BLOCK_SIZE + 1);

        assert_eq!(
            BaseLayerSnapshot::from_uncompressed_tar(
                LayerRef::new(SnapshotId::new("truncated").unwrap()),
                &archive,
            ),
            Err(LayerUnpackError::TruncatedEntryData)
        );
    }

    fn append_tar_dir(
        archive: &mut Vec<u8>,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
        mtime: u64,
    ) {
        append_tar_entry(
            archive,
            name,
            b'5',
            &[],
            "",
            TarEntryMeta {
                mode,
                uid,
                gid,
                mtime,
            },
        );
    }

    fn append_tar_file(
        archive: &mut Vec<u8>,
        name: &str,
        data: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        mtime: u64,
    ) {
        append_tar_entry(
            archive,
            name,
            b'0',
            data,
            "",
            TarEntryMeta {
                mode,
                uid,
                gid,
                mtime,
            },
        );
    }

    fn append_tar_symlink(archive: &mut Vec<u8>, name: &str, target: &str, mtime: u64) {
        append_tar_entry(
            archive,
            name,
            b'2',
            &[],
            target,
            TarEntryMeta {
                mode: 0o777,
                uid: 0,
                gid: 0,
                mtime,
            },
        );
    }

    fn append_tar_entry(
        archive: &mut Vec<u8>,
        name: &str,
        entry_type: u8,
        data: &[u8],
        linkname: &str,
        meta: TarEntryMeta,
    ) {
        let mut header = [0u8; TAR_BLOCK_SIZE];
        write_tar_string(&mut header[0..100], name);
        write_tar_octal(&mut header[100..108], u64::from(meta.mode));
        write_tar_octal(&mut header[108..116], u64::from(meta.uid));
        write_tar_octal(&mut header[116..124], u64::from(meta.gid));
        write_tar_octal(&mut header[124..136], data.len() as u64);
        write_tar_octal(&mut header[136..148], meta.mtime);
        header[156] = entry_type;
        write_tar_string(&mut header[157..257], linkname);
        write_tar_string(&mut header[257..263], "ustar");
        write_tar_string(&mut header[263..265], "00");

        archive.extend_from_slice(&header);
        archive.extend_from_slice(data);
        let padding = (TAR_BLOCK_SIZE - (data.len() % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
        archive.extend(std::iter::repeat_n(0, padding));
    }

    #[derive(Clone, Copy)]
    struct TarEntryMeta {
        mode: u32,
        uid: u32,
        gid: u32,
        mtime: u64,
    }

    fn finish_tar(archive: &mut Vec<u8>) {
        archive.extend(std::iter::repeat_n(0, TAR_BLOCK_SIZE * 2));
    }

    fn write_tar_string(field: &mut [u8], value: &str) {
        let bytes = value.as_bytes();
        assert!(bytes.len() <= field.len());
        field[..bytes.len()].copy_from_slice(bytes);
    }

    fn write_tar_octal(field: &mut [u8], value: u64) {
        let encoded = format!("{value:0width$o}", width = field.len() - 1);
        field[..encoded.len()].copy_from_slice(encoded.as_bytes());
    }

    fn tar_entry_names(archive: &[u8]) -> Vec<String> {
        tar_entries(archive)
            .into_iter()
            .map(|entry| entry.name)
            .collect()
    }

    fn tar_entry_payload<'a>(archive: &'a [u8], name: &str) -> Option<&'a [u8]> {
        tar_entries(archive)
            .into_iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.payload)
    }

    fn tar_entries(archive: &[u8]) -> Vec<TarEntryView<'_>> {
        let mut offset = 0usize;
        let mut entries = Vec::new();
        while offset < archive.len() {
            let header_end = offset + TAR_BLOCK_SIZE;
            let header = &archive[offset..header_end];
            if header.iter().all(|byte| *byte == 0) {
                break;
            }
            let name = tar_string(&header[0..100], "name").unwrap();
            let prefix = tar_string(&header[345..500], "prefix").unwrap();
            let name = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let size = tar_octal(&header[124..136], "size").unwrap();
            let data_start = header_end;
            let data_len = usize::try_from(size).unwrap();
            let data_end = data_start + data_len;
            entries.push(TarEntryView {
                name,
                payload: &archive[data_start..data_end],
            });
            offset = data_start + padded_tar_len(size).unwrap();
        }
        entries
    }

    struct TarEntryView<'a> {
        name: String,
        payload: &'a [u8],
    }

    fn temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mcr-snapshot-{label}-{}-{nanos}",
            std::process::id()
        ))
    }
}
