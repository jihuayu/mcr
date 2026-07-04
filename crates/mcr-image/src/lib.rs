use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub const MEDIA_TYPE_OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
pub const MEDIA_TYPE_OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const MEDIA_TYPE_OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MEDIA_TYPE_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciDescriptor {
    media_type: String,
    digest: OciDigest,
    size: u64,
    annotations: BTreeMap<String, String>,
}

impl OciDescriptor {
    #[must_use]
    pub fn new(media_type: impl Into<String>, digest: OciDigest, size: u64) -> Self {
        Self {
            media_type: media_type.into(),
            digest,
            size,
            annotations: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    #[must_use]
    pub const fn digest(&self) -> &OciDigest {
        &self.digest
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }

    pub fn insert_annotation(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.annotations.insert(key.into(), value.into());
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OciDigest {
    algorithm: DigestAlgorithm,
    encoded: String,
}

impl OciDigest {
    pub fn parse(value: &str) -> Result<Self, ImageError> {
        let Some((algorithm, encoded)) = value.split_once(':') else {
            return Err(ImageError::InvalidDigest(value.to_owned()));
        };
        let algorithm = DigestAlgorithm::parse(algorithm)?;
        validate_digest_hex(encoded)?;
        Ok(Self {
            algorithm,
            encoded: encoded.to_ascii_lowercase(),
        })
    }

    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let output = hasher.finalize();
        Self {
            algorithm: DigestAlgorithm::Sha256,
            encoded: hex_lower(&output),
        }
    }

    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

impl fmt::Display for OciDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.algorithm.as_str(), self.encoded)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DigestAlgorithm {
    Sha256,
}

impl DigestAlgorithm {
    fn parse(value: &str) -> Result<Self, ImageError> {
        match value {
            "sha256" => Ok(Self::Sha256),
            other => Err(ImageError::UnsupportedDigestAlgorithm(other.to_owned())),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalContentStore {
    root: PathBuf,
}

impl LocalContentStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write_blob(
        &self,
        media_type: impl Into<String>,
        bytes: &[u8],
    ) -> Result<OciDescriptor, ImageError> {
        let digest = OciDigest::sha256(bytes);
        let path = self.blob_path(&digest)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, bytes)?;
        self.verify_blob_bytes(&digest, bytes)?;
        Ok(OciDescriptor::new(
            media_type,
            digest,
            u64::try_from(bytes.len()).expect("usize fits in u64"),
        ))
    }

    pub fn read_blob(&self, descriptor: &OciDescriptor) -> Result<Vec<u8>, ImageError> {
        let path = self.blob_path(descriptor.digest())?;
        let bytes = fs::read(path)?;
        if u64::try_from(bytes.len()).expect("usize fits in u64") != descriptor.size() {
            return Err(ImageError::SizeMismatch {
                expected: descriptor.size(),
                actual: u64::try_from(bytes.len()).expect("usize fits in u64"),
            });
        }
        self.verify_blob_bytes(descriptor.digest(), &bytes)?;
        Ok(bytes)
    }

    pub fn blob_path(&self, digest: &OciDigest) -> Result<PathBuf, ImageError> {
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(ImageError::UnsupportedDigestAlgorithm(
                digest.algorithm().as_str().to_owned(),
            ));
        }
        Ok(self
            .root
            .join("blobs")
            .join(digest.algorithm().as_str())
            .join(digest.encoded()))
    }

    fn verify_blob_bytes(&self, expected: &OciDigest, bytes: &[u8]) -> Result<(), ImageError> {
        let actual = OciDigest::sha256(bytes);
        if &actual != expected {
            return Err(ImageError::DigestMismatch {
                expected: expected.clone(),
                actual,
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ImageError {
    InvalidDigest(String),
    UnsupportedDigestAlgorithm(String),
    DigestMismatch {
        expected: OciDigest,
        actual: OciDigest,
    },
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    Io(io::Error),
}

impl fmt::Display for ImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDigest(value) => write!(formatter, "invalid OCI digest: {value}"),
            Self::UnsupportedDigestAlgorithm(value) => {
                write!(formatter, "unsupported OCI digest algorithm: {value}")
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
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl Error for ImageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
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

fn validate_digest_hex(encoded: &str) -> Result<(), ImageError> {
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ImageError::InvalidDigest(encoded.to_owned()));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-image");
    }

    #[test]
    fn descriptor_parses_and_renders_sha256_digest() {
        let digest = OciDigest::parse(
            "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let mut descriptor = OciDescriptor::new(MEDIA_TYPE_OCI_CONFIG, digest, 12);
        descriptor.insert_annotation("org.opencontainers.image.title", "config");

        assert_eq!(descriptor.media_type(), MEDIA_TYPE_OCI_CONFIG);
        assert_eq!(descriptor.digest().algorithm(), DigestAlgorithm::Sha256);
        assert_eq!(
            descriptor.digest().to_string(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(descriptor.size(), 12);
        assert_eq!(
            descriptor
                .annotations()
                .get("org.opencontainers.image.title"),
            Some(&"config".to_owned())
        );
    }

    #[test]
    fn digest_validation_rejects_unsupported_or_malformed_values() {
        assert!(matches!(
            OciDigest::parse("sha512:0123"),
            Err(ImageError::UnsupportedDigestAlgorithm(_))
        ));
        assert!(matches!(
            OciDigest::parse("sha256:not-hex"),
            Err(ImageError::InvalidDigest(_))
        ));
        assert!(matches!(
            OciDigest::parse("missing-separator"),
            Err(ImageError::InvalidDigest(_))
        ));
    }

    #[test]
    fn local_content_store_writes_by_digest_and_verifies_reads() {
        let root = temp_root("content-store");
        let store = LocalContentStore::new(&root);
        let bytes = br#"{"architecture":"amd64","os":"linux"}"#;

        let descriptor = store.write_blob(MEDIA_TYPE_OCI_CONFIG, bytes).unwrap();
        assert_eq!(
            store.blob_path(descriptor.digest()).unwrap(),
            root.join("blobs")
                .join("sha256")
                .join(descriptor.digest().encoded())
        );
        assert_eq!(descriptor.size(), bytes.len() as u64);
        assert_eq!(store.read_blob(&descriptor).unwrap(), bytes);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_content_store_rejects_tampered_content_and_size_mismatch() {
        let root = temp_root("content-store-tampered");
        let store = LocalContentStore::new(&root);
        let descriptor = store.write_blob(MEDIA_TYPE_OCI_LAYER, b"original").unwrap();
        let path = store.blob_path(descriptor.digest()).unwrap();
        fs::write(&path, b"tampered").unwrap();

        assert!(matches!(
            store.read_blob(&descriptor),
            Err(ImageError::DigestMismatch { .. })
        ));

        let wrong_size = OciDescriptor::new(MEDIA_TYPE_OCI_LAYER, descriptor.digest().clone(), 99);
        assert!(matches!(
            store.read_blob(&wrong_size),
            Err(ImageError::SizeMismatch {
                expected: 99,
                actual: 8
            })
        ));

        fs::remove_dir_all(root).unwrap();
    }

    fn temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mcr-image-{label}-{}-{nanos}", std::process::id()))
    }
}
