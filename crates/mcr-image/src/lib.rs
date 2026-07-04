use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use mcr_snapshot::{BaseLayerSnapshot, LayerRef, LayerUnpackError, SnapshotError, SnapshotId};
use sha2::{Digest, Sha256};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub const DEFAULT_REGISTRY: &str = "registry-1.docker.io";
pub const DEFAULT_TAG: &str = "latest";

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciReference {
    registry: String,
    repository: String,
    tag: Option<String>,
    digest: Option<OciDigest>,
}

impl OciReference {
    pub fn parse(value: &str) -> Result<Self, ImageError> {
        let value = value.trim();
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(ImageError::InvalidReference(value.to_owned()));
        }

        let (name_and_tag, digest) = if let Some((name, digest)) = value.split_once('@') {
            if name.is_empty() || digest.is_empty() || digest.contains('@') {
                return Err(ImageError::InvalidReference(value.to_owned()));
            }
            (name, Some(OciDigest::parse(digest)?))
        } else {
            (value, None)
        };
        let (name, parsed_tag) = split_tag(name_and_tag)?;
        let (registry, repository) = split_registry_repository(name)?;
        validate_repository(&repository)?;

        let tag = if let Some(tag) = parsed_tag {
            validate_tag(&tag)?;
            Some(tag)
        } else if digest.is_none() {
            Some(DEFAULT_TAG.to_owned())
        } else {
            None
        };

        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    #[must_use]
    pub fn registry(&self) -> &str {
        &self.registry
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    #[must_use]
    pub const fn digest(&self) -> Option<&OciDigest> {
        self.digest.as_ref()
    }
}

impl fmt::Display for OciReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.registry, self.repository)?;
        if let Some(tag) = &self.tag {
            write!(formatter, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(formatter, "@{digest}")?;
        }
        Ok(())
    }
}

fn split_tag(value: &str) -> Result<(&str, Option<String>), ImageError> {
    let last_path_start = value.rfind('/').map_or(0, |index| index + 1);
    let Some(tag_separator) = value[last_path_start..].rfind(':') else {
        return Ok((value, None));
    };
    let tag_separator = last_path_start + tag_separator;
    let name = &value[..tag_separator];
    let tag = &value[tag_separator + 1..];
    if name.is_empty() || tag.is_empty() {
        return Err(ImageError::InvalidReference(value.to_owned()));
    }
    Ok((name, Some(tag.to_owned())))
}

fn split_registry_repository(value: &str) -> Result<(String, String), ImageError> {
    if value.is_empty() {
        return Err(ImageError::InvalidReference(value.to_owned()));
    }

    let (registry, mut repository) = if let Some((first, rest)) = value.split_once('/') {
        if first.contains('.') || first.contains(':') || first == "localhost" {
            if rest.is_empty() {
                return Err(ImageError::InvalidReference(value.to_owned()));
            }
            (first.to_owned(), rest.to_owned())
        } else {
            (DEFAULT_REGISTRY.to_owned(), value.to_owned())
        }
    } else {
        (DEFAULT_REGISTRY.to_owned(), value.to_owned())
    };

    if registry == DEFAULT_REGISTRY && !repository.contains('/') {
        repository = format!("library/{repository}");
    }

    if registry.is_empty() || registry.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(ImageError::InvalidReference(value.to_owned()));
    }

    Ok((registry, repository))
}

fn validate_repository(repository: &str) -> Result<(), ImageError> {
    if repository.is_empty()
        || repository.split('/').any(str::is_empty)
        || repository.bytes().any(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        })
    {
        return Err(ImageError::InvalidRepository(repository.to_owned()));
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), ImageError> {
    let Some(first) = tag.as_bytes().first() else {
        return Err(ImageError::InvalidTag(tag.to_owned()));
    };
    if tag.len() > 128
        || !(*first == b'_' || first.is_ascii_alphanumeric())
        || tag
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')))
    {
        return Err(ImageError::InvalidTag(tag.to_owned()));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciPlatform {
    os: String,
    architecture: String,
    variant: Option<String>,
}

impl OciPlatform {
    #[must_use]
    pub fn new(
        os: impl Into<String>,
        architecture: impl Into<String>,
        variant: Option<impl Into<String>>,
    ) -> Self {
        Self {
            os: os.into(),
            architecture: architecture.into(),
            variant: variant.map(Into::into),
        }
    }

    #[must_use]
    pub fn linux_amd64() -> Self {
        Self::new("linux", "amd64", Option::<String>::None)
    }

    #[must_use]
    pub fn os(&self) -> &str {
        &self.os
    }

    #[must_use]
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    #[must_use]
    pub fn variant(&self) -> Option<&str> {
        self.variant.as_deref()
    }

    #[must_use]
    pub fn matches(&self, candidate: &Self) -> bool {
        self.os == candidate.os
            && self.architecture == candidate.architecture
            && self
                .variant
                .as_ref()
                .is_none_or(|variant| Some(variant.as_str()) == candidate.variant())
    }
}

impl fmt::Display for OciPlatform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.os, self.architecture)?;
        if let Some(variant) = &self.variant {
            write!(formatter, "/{variant}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciIndexManifest {
    descriptor: OciDescriptor,
    platform: OciPlatform,
}

impl OciIndexManifest {
    #[must_use]
    pub const fn new(descriptor: OciDescriptor, platform: OciPlatform) -> Self {
        Self {
            descriptor,
            platform,
        }
    }

    #[must_use]
    pub const fn descriptor(&self) -> &OciDescriptor {
        &self.descriptor
    }

    #[must_use]
    pub const fn platform(&self) -> &OciPlatform {
        &self.platform
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciImageIndex {
    manifests: Vec<OciIndexManifest>,
}

impl OciImageIndex {
    #[must_use]
    pub fn new(manifests: Vec<OciIndexManifest>) -> Self {
        Self { manifests }
    }

    #[must_use]
    pub fn manifests(&self) -> &[OciIndexManifest] {
        &self.manifests
    }

    pub fn select_manifest(&self, platform: &OciPlatform) -> Result<&OciDescriptor, ImageError> {
        self.manifests
            .iter()
            .find(|manifest| {
                manifest.descriptor().media_type() == MEDIA_TYPE_OCI_MANIFEST
                    && platform.matches(manifest.platform())
            })
            .map(OciIndexManifest::descriptor)
            .ok_or_else(|| ImageError::NoCompatibleManifest {
                platform: platform.clone(),
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciImageManifest {
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
}

impl OciImageManifest {
    #[must_use]
    pub fn new(config: OciDescriptor, layers: Vec<OciDescriptor>) -> Self {
        Self { config, layers }
    }

    #[must_use]
    pub const fn config(&self) -> &OciDescriptor {
        &self.config
    }

    #[must_use]
    pub fn layers(&self) -> &[OciDescriptor] {
        &self.layers
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryPullPlan {
    reference: OciReference,
    platform: OciPlatform,
    manifest_descriptor: OciDescriptor,
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
}

impl RegistryPullPlan {
    pub fn from_manifest(
        reference: OciReference,
        platform: OciPlatform,
        manifest_descriptor: OciDescriptor,
        manifest: OciImageManifest,
    ) -> Result<Self, ImageError> {
        if manifest_descriptor.media_type() != MEDIA_TYPE_OCI_MANIFEST {
            return Err(ImageError::UnsupportedManifestMediaType(
                manifest_descriptor.media_type().to_owned(),
            ));
        }
        if manifest.config().media_type() != MEDIA_TYPE_OCI_CONFIG {
            return Err(ImageError::UnsupportedManifestMediaType(
                manifest.config().media_type().to_owned(),
            ));
        }
        for layer in manifest.layers() {
            validate_layer_media_type(layer.media_type())?;
        }

        Ok(Self {
            reference,
            platform,
            manifest_descriptor,
            config: manifest.config().clone(),
            layers: manifest.layers().to_vec(),
        })
    }

    #[must_use]
    pub const fn reference(&self) -> &OciReference {
        &self.reference
    }

    #[must_use]
    pub const fn platform(&self) -> &OciPlatform {
        &self.platform
    }

    #[must_use]
    pub const fn manifest_descriptor(&self) -> &OciDescriptor {
        &self.manifest_descriptor
    }

    #[must_use]
    pub const fn config(&self) -> &OciDescriptor {
        &self.config
    }

    #[must_use]
    pub fn layers(&self) -> &[OciDescriptor] {
        &self.layers
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLayerBlob {
    descriptor: OciDescriptor,
    bytes: Vec<u8>,
}

impl VerifiedLayerBlob {
    pub fn new(descriptor: OciDescriptor, bytes: Vec<u8>) -> Result<Self, ImageError> {
        validate_layer_media_type(descriptor.media_type())?;
        verify_descriptor_bytes(&descriptor, &bytes)?;
        Ok(Self { descriptor, bytes })
    }

    #[must_use]
    pub const fn descriptor(&self) -> &OciDescriptor {
        &self.descriptor
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn unpack_uncompressed_base_layer(
        &self,
        layer_id: impl Into<String>,
    ) -> Result<BaseLayerSnapshot, ImageError> {
        if self.descriptor.media_type() != MEDIA_TYPE_OCI_LAYER {
            return Err(ImageError::UnsupportedLayerMediaType(
                self.descriptor.media_type().to_owned(),
            ));
        }
        let layer_id = SnapshotId::new(layer_id).map_err(ImageError::Snapshot)?;
        BaseLayerSnapshot::from_uncompressed_tar(LayerRef::new(layer_id), self.bytes())
            .map_err(ImageError::LayerUnpack)
    }
}

fn validate_layer_media_type(media_type: &str) -> Result<(), ImageError> {
    if media_type == MEDIA_TYPE_OCI_LAYER || media_type == MEDIA_TYPE_OCI_LAYER_GZIP {
        Ok(())
    } else {
        Err(ImageError::UnsupportedLayerMediaType(media_type.to_owned()))
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

fn verify_descriptor_bytes(descriptor: &OciDescriptor, bytes: &[u8]) -> Result<(), ImageError> {
    let actual_size = u64::try_from(bytes.len()).expect("usize fits in u64");
    if actual_size != descriptor.size() {
        return Err(ImageError::SizeMismatch {
            expected: descriptor.size(),
            actual: actual_size,
        });
    }

    let actual_digest = OciDigest::sha256(bytes);
    if &actual_digest != descriptor.digest() {
        return Err(ImageError::DigestMismatch {
            expected: descriptor.digest().clone(),
            actual: actual_digest,
        });
    }

    Ok(())
}

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
    fn image_reference_normalizes_registry_repository_and_target() {
        let docker_hub = OciReference::parse("alpine:3.20").unwrap();
        assert_eq!(docker_hub.registry(), DEFAULT_REGISTRY);
        assert_eq!(docker_hub.repository(), "library/alpine");
        assert_eq!(docker_hub.tag(), Some("3.20"));
        assert_eq!(docker_hub.digest(), None);
        assert_eq!(
            docker_hub.to_string(),
            "registry-1.docker.io/library/alpine:3.20"
        );

        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let pinned = OciReference::parse(&format!("localhost:5000/team/app@{digest}")).unwrap();
        assert_eq!(pinned.registry(), "localhost:5000");
        assert_eq!(pinned.repository(), "team/app");
        assert_eq!(pinned.tag(), None);
        assert_eq!(pinned.digest().unwrap().to_string(), digest);
        assert_eq!(
            pinned.to_string(),
            format!("localhost:5000/team/app@{digest}")
        );
    }

    #[test]
    fn image_reference_rejects_invalid_repository_or_tag() {
        assert!(matches!(
            OciReference::parse("Team/App:latest"),
            Err(ImageError::InvalidRepository(_))
        ));
        assert!(matches!(
            OciReference::parse("team/app:bad tag"),
            Err(ImageError::InvalidReference(_))
        ));
        assert!(matches!(
            OciReference::parse("team/app:!"),
            Err(ImageError::InvalidTag(_))
        ));
    }

    #[test]
    fn image_index_selects_linux_amd64_manifest() {
        let linux_amd64 = descriptor_for(MEDIA_TYPE_OCI_MANIFEST, b"amd64 manifest");
        let linux_arm64 = descriptor_for(MEDIA_TYPE_OCI_MANIFEST, b"arm64 manifest");
        let index = OciImageIndex::new(vec![
            OciIndexManifest::new(
                linux_arm64.clone(),
                OciPlatform::new("linux", "arm64", Option::<String>::None),
            ),
            OciIndexManifest::new(linux_amd64.clone(), OciPlatform::linux_amd64()),
        ]);

        assert_eq!(
            index.select_manifest(&OciPlatform::linux_amd64()).unwrap(),
            &linux_amd64
        );
    }

    #[test]
    fn image_index_rejects_missing_linux_amd64_manifest() {
        let index = OciImageIndex::new(vec![OciIndexManifest::new(
            descriptor_for(MEDIA_TYPE_OCI_MANIFEST, b"arm64 manifest"),
            OciPlatform::new("linux", "arm64", Option::<String>::None),
        )]);

        assert!(matches!(
            index.select_manifest(&OciPlatform::linux_amd64()),
            Err(ImageError::NoCompatibleManifest { .. })
        ));
    }

    #[test]
    fn registry_pull_plan_preserves_manifest_layer_order() {
        let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
        let layer_one = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"layer-one");
        let layer_two = descriptor_for(MEDIA_TYPE_OCI_LAYER_GZIP, b"layer-two");
        let manifest = OciImageManifest::new(config.clone(), vec![layer_one.clone(), layer_two]);
        let manifest_descriptor = descriptor_for(MEDIA_TYPE_OCI_MANIFEST, b"manifest");

        let plan = RegistryPullPlan::from_manifest(
            OciReference::parse("alpine:3.20").unwrap(),
            OciPlatform::linux_amd64(),
            manifest_descriptor.clone(),
            manifest,
        )
        .unwrap();

        assert_eq!(plan.reference().repository(), "library/alpine");
        assert_eq!(plan.platform(), &OciPlatform::linux_amd64());
        assert_eq!(plan.manifest_descriptor(), &manifest_descriptor);
        assert_eq!(plan.config(), &config);
        assert_eq!(
            plan.layers()
                .iter()
                .map(OciDescriptor::media_type)
                .collect::<Vec<_>>(),
            vec![MEDIA_TYPE_OCI_LAYER, MEDIA_TYPE_OCI_LAYER_GZIP]
        );
        assert_eq!(plan.layers()[0], layer_one);
    }

    #[test]
    fn verified_layer_blob_checks_digest_before_snapshot_unpack() {
        let archive = single_file_tar("etc/os-release", b"ID=mcr\n");
        let descriptor = descriptor_for(MEDIA_TYPE_OCI_LAYER, &archive);
        let verified = VerifiedLayerBlob::new(descriptor.clone(), archive.clone()).unwrap();
        let snapshot = verified
            .unpack_uncompressed_base_layer("sha256-layer")
            .unwrap();
        let os_release = snapshot
            .get(&mcr_snapshot::SnapshotPath::new("/etc/os-release").unwrap())
            .unwrap();

        assert_eq!(
            os_release.metadata().kind(),
            &mcr_snapshot::SnapshotFileKind::Regular { size: 7 }
        );
        assert_eq!(snapshot.layer().id().as_str(), "sha256-layer");

        let mut tampered = archive;
        tampered[0] = b'X';
        assert!(matches!(
            VerifiedLayerBlob::new(descriptor, tampered),
            Err(ImageError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn verified_layer_blob_keeps_compressed_layers_out_of_uncompressed_unpack_boundary() {
        let compressed_bytes = b"not actually gzip yet".to_vec();
        let descriptor = descriptor_for(MEDIA_TYPE_OCI_LAYER_GZIP, &compressed_bytes);
        let verified = VerifiedLayerBlob::new(descriptor, compressed_bytes).unwrap();

        assert!(matches!(
            verified.unpack_uncompressed_base_layer("gzip-layer"),
            Err(ImageError::UnsupportedLayerMediaType(_))
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

    fn descriptor_for(media_type: &str, bytes: &[u8]) -> OciDescriptor {
        OciDescriptor::new(media_type, OciDigest::sha256(bytes), bytes.len() as u64)
    }

    fn single_file_tar(path: &str, data: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();
        let mut header = [0u8; 512];
        write_tar_string(&mut header[0..100], path);
        write_tar_octal(&mut header[100..108], 0o644);
        write_tar_octal(&mut header[108..116], 0);
        write_tar_octal(&mut header[116..124], 0);
        write_tar_octal(&mut header[124..136], data.len() as u64);
        write_tar_octal(&mut header[136..148], 1);
        header[156] = b'0';
        write_tar_string(&mut header[257..263], "ustar");
        write_tar_string(&mut header[263..265], "00");

        archive.extend_from_slice(&header);
        archive.extend_from_slice(data);
        let padding = (512 - (data.len() % 512)) % 512;
        archive.extend(std::iter::repeat_n(0, padding));
        archive.extend(std::iter::repeat_n(0, 1024));
        archive
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
}
