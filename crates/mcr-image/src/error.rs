use super::*;

#[derive(Debug)]
pub enum ImageError {
    InvalidReference(String),
    InvalidRepository(String),
    InvalidTag(String),
    InvalidDigest(String),
    UnsupportedDigestAlgorithm(String),
    NoCompatibleManifest {
        platform: OciPlatform,
    },
    UnsupportedManifestMediaType(String),
    UnsupportedLayerMediaType(String),
    DigestMismatch {
        expected: OciDigest,
        actual: OciDigest,
    },
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    InvalidTarEntryPath(String),
    TarEntryPathTooLong(String),
    TarFieldOverflow {
        field: &'static str,
        value: u64,
    },
    Snapshot(SnapshotError),
    LayerUnpack(LayerUnpackError),
    Io(io::Error),
}
impl fmt::Display for ImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReference(value) => {
                write!(formatter, "invalid OCI image reference: {value}")
            }
            Self::InvalidRepository(value) => {
                write!(formatter, "invalid OCI repository name: {value}")
            }
            Self::InvalidTag(value) => write!(formatter, "invalid OCI reference tag: {value}"),
            Self::InvalidDigest(value) => write!(formatter, "invalid OCI digest: {value}"),
            Self::UnsupportedDigestAlgorithm(value) => {
                write!(formatter, "unsupported OCI digest algorithm: {value}")
            }
            Self::NoCompatibleManifest { platform } => {
                write!(
                    formatter,
                    "no compatible OCI manifest for platform {platform}"
                )
            }
            Self::UnsupportedManifestMediaType(value) => {
                write!(formatter, "unsupported OCI manifest media type: {value}")
            }
            Self::UnsupportedLayerMediaType(value) => {
                write!(formatter, "unsupported OCI layer media type: {value}")
            }
            Self::DigestMismatch { expected, actual } => {
                write!(
                    formatter,
                    "digest mismatch: expected {expected}, got {actual}"
                )
            }
            Self::SizeMismatch { expected, actual } => {
                write!(
                    formatter,
                    "blob size mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidTarEntryPath(value) => {
                write!(formatter, "invalid tar entry path: {value}")
            }
            Self::TarEntryPathTooLong(value) => {
                write!(formatter, "tar entry path is too long: {value}")
            }
            Self::TarFieldOverflow { field, value } => {
                write!(formatter, "tar {field} value is too large: {value}")
            }
            Self::Snapshot(error) => error.fmt(formatter),
            Self::LayerUnpack(error) => error.fmt(formatter),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}
impl Error for ImageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Snapshot(error) => Some(error),
            Self::LayerUnpack(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for ImageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
