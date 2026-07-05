use super::*;

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
pub(crate) fn tar_string(
    field: &[u8],
    field_name: &'static str,
) -> Result<String, LayerUnpackError> {
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
pub(crate) fn tar_octal(field: &[u8], field_name: &'static str) -> Result<u64, LayerUnpackError> {
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
pub(crate) fn padded_tar_len(size: u64) -> Result<usize, LayerUnpackError> {
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
