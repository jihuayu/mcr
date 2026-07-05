use super::*;

pub(crate) const TAR_BLOCK_SIZE: usize = 512;

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
pub(crate) fn read_upper_regular_contents(
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
pub(crate) fn append_layer_tar_entry(
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
