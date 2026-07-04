use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt::{self, Write as _},
    fs, io,
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
pub const OCI_IMAGE_LAYOUT_VERSION: &str = "1.0.0";
pub const ANNOTATION_REF_NAME: &str = "org.opencontainers.image.ref.name";
const TAR_BLOCK_SIZE: usize = 512;

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

    #[must_use]
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut output = String::new();
        output.push_str("{\"schemaVersion\":2,\"mediaType\":");
        push_json_string(&mut output, MEDIA_TYPE_OCI_MANIFEST);
        output.push_str(",\"config\":");
        push_descriptor_json(&mut output, &self.config);
        output.push_str(",\"layers\":[");
        for (index, layer) in self.layers.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            push_descriptor_json(&mut output, layer);
        }
        output.push_str("]}");
        output.into_bytes()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OciContainerConfig {
    env: Vec<String>,
    working_dir: Option<String>,
    entrypoint: Vec<String>,
    command: Vec<String>,
}

impl OciContainerConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_env<I, S>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.env = env.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_working_dir(mut self, working_dir: impl Into<String>) -> Self {
        self.working_dir = Some(working_dir.into());
        self
    }

    #[must_use]
    pub fn with_entrypoint<I, S>(mut self, entrypoint: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entrypoint = entrypoint.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_command<I, S>(mut self, command: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command = command.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn env(&self) -> &[String] {
        &self.env
    }

    #[must_use]
    pub fn working_dir(&self) -> Option<&str> {
        self.working_dir.as_deref()
    }

    #[must_use]
    pub fn entrypoint(&self) -> &[String] {
        &self.entrypoint
    }

    #[must_use]
    pub fn command(&self) -> &[String] {
        &self.command
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciHistoryEntry {
    created_by: String,
    comment: Option<String>,
    empty_layer: bool,
}

impl OciHistoryEntry {
    #[must_use]
    pub fn new(created_by: impl Into<String>) -> Self {
        Self {
            created_by: created_by.into(),
            comment: None,
            empty_layer: false,
        }
    }

    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    #[must_use]
    pub const fn with_empty_layer(mut self, empty_layer: bool) -> Self {
        self.empty_layer = empty_layer;
        self
    }

    #[must_use]
    pub fn created_by(&self) -> &str {
        &self.created_by
    }

    #[must_use]
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    #[must_use]
    pub const fn empty_layer(&self) -> bool {
        self.empty_layer
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciImageConfig {
    platform: OciPlatform,
    config: OciContainerConfig,
    history: Vec<OciHistoryEntry>,
    rootfs_diff_ids: Vec<OciDigest>,
}

impl OciImageConfig {
    #[must_use]
    pub const fn new(
        platform: OciPlatform,
        config: OciContainerConfig,
        history: Vec<OciHistoryEntry>,
        rootfs_diff_ids: Vec<OciDigest>,
    ) -> Self {
        Self {
            platform,
            config,
            history,
            rootfs_diff_ids,
        }
    }

    #[must_use]
    pub const fn platform(&self) -> &OciPlatform {
        &self.platform
    }

    #[must_use]
    pub const fn config(&self) -> &OciContainerConfig {
        &self.config
    }

    #[must_use]
    pub fn history(&self) -> &[OciHistoryEntry] {
        &self.history
    }

    #[must_use]
    pub fn rootfs_diff_ids(&self) -> &[OciDigest] {
        &self.rootfs_diff_ids
    }

    #[must_use]
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut output = String::new();
        output.push_str("{\"architecture\":");
        push_json_string(&mut output, self.platform.architecture());
        output.push_str(",\"config\":");
        push_container_config_json(&mut output, &self.config);
        output.push_str(",\"history\":[");
        for (index, entry) in self.history.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            push_history_entry_json(&mut output, entry);
        }
        output.push_str("],\"os\":");
        push_json_string(&mut output, self.platform.os());
        if let Some(variant) = self.platform.variant() {
            output.push_str(",\"variant\":");
            push_json_string(&mut output, variant);
        }
        output.push_str(",\"rootfs\":{\"diff_ids\":[");
        for (index, diff_id) in self.rootfs_diff_ids.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            push_json_string(&mut output, &diff_id.to_string());
        }
        output.push_str("],\"type\":\"layers\"}}");
        output.into_bytes()
    }
}

fn push_container_config_json(output: &mut String, config: &OciContainerConfig) {
    output.push_str("{\"Cmd\":");
    push_json_string_array(output, config.command());
    output.push_str(",\"Entrypoint\":");
    push_json_string_array(output, config.entrypoint());
    output.push_str(",\"Env\":");
    push_json_string_array(output, config.env());
    if let Some(working_dir) = config.working_dir() {
        output.push_str(",\"WorkingDir\":");
        push_json_string(output, working_dir);
    }
    output.push('}');
}

fn push_history_entry_json(output: &mut String, entry: &OciHistoryEntry) {
    output.push_str("{\"created_by\":");
    push_json_string(output, entry.created_by());
    if let Some(comment) = entry.comment() {
        output.push_str(",\"comment\":");
        push_json_string(output, comment);
    }
    if entry.empty_layer() {
        output.push_str(",\"empty_layer\":true");
    }
    output.push('}');
}

fn push_descriptor_json(output: &mut String, descriptor: &OciDescriptor) {
    output.push_str("{\"mediaType\":");
    push_json_string(output, descriptor.media_type());
    output.push_str(",\"digest\":");
    push_json_string(output, &descriptor.digest().to_string());
    output.push_str(",\"size\":");
    write!(output, "{}", descriptor.size()).expect("writing to String cannot fail");
    if !descriptor.annotations().is_empty() {
        output.push_str(",\"annotations\":{");
        for (index, (key, value)) in descriptor.annotations().iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            push_json_string(output, key);
            output.push(':');
            push_json_string(output, value);
        }
        output.push('}');
    }
    output.push('}');
}

fn push_json_string_array(output: &mut String, values: &[String]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, value);
    }
    output.push(']');
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{00}'..='\u{1f}' => {
                write!(output, "\\u{:04x}", u32::from(ch)).expect("writing to String cannot fail");
            }
            _ => output.push(ch),
        }
    }
    output.push('"');
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryPushUploadKind {
    Blob,
    Manifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryPushUpload {
    kind: RegistryPushUploadKind,
    descriptor: OciDescriptor,
}

impl RegistryPushUpload {
    #[must_use]
    pub const fn new(kind: RegistryPushUploadKind, descriptor: OciDescriptor) -> Self {
        Self { kind, descriptor }
    }

    #[must_use]
    pub const fn kind(&self) -> RegistryPushUploadKind {
        self.kind
    }

    #[must_use]
    pub const fn descriptor(&self) -> &OciDescriptor {
        &self.descriptor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryPushPlan {
    reference: OciReference,
    manifest_descriptor: OciDescriptor,
    uploads: Vec<RegistryPushUpload>,
}

impl RegistryPushPlan {
    pub fn from_manifest(
        reference: OciReference,
        manifest_descriptor: OciDescriptor,
        manifest: OciImageManifest,
        remote_blobs: impl IntoIterator<Item = OciDigest>,
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

        let remote_blobs = remote_blobs.into_iter().collect::<BTreeSet<_>>();
        let mut planned_blobs = BTreeSet::new();
        let mut uploads = Vec::with_capacity(1 + manifest.layers().len() + 1);
        for descriptor in std::iter::once(manifest.config()).chain(manifest.layers()) {
            if remote_blobs.contains(descriptor.digest()) {
                continue;
            }
            if planned_blobs.insert(descriptor.digest().clone()) {
                uploads.push(RegistryPushUpload::new(
                    RegistryPushUploadKind::Blob,
                    descriptor.clone(),
                ));
            }
        }
        uploads.push(RegistryPushUpload::new(
            RegistryPushUploadKind::Manifest,
            manifest_descriptor.clone(),
        ));

        Ok(Self {
            reference,
            manifest_descriptor,
            uploads,
        })
    }

    #[must_use]
    pub const fn reference(&self) -> &OciReference {
        &self.reference
    }

    #[must_use]
    pub const fn manifest_descriptor(&self) -> &OciDescriptor {
        &self.manifest_descriptor
    }

    #[must_use]
    pub fn uploads(&self) -> &[RegistryPushUpload] {
        &self.uploads
    }
}

pub trait RegistryPushTarget {
    fn blob_exists(&self, digest: &OciDigest) -> Result<bool, ImageError>;

    fn upload_blob(&mut self, descriptor: &OciDescriptor, bytes: &[u8]) -> Result<(), ImageError>;

    fn upload_manifest(
        &mut self,
        reference: &OciReference,
        descriptor: &OciDescriptor,
        bytes: &[u8],
    ) -> Result<(), ImageError>;
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

    pub fn write_oci_layout(
        &self,
        manifest: &OciImageManifest,
        reference_name: Option<&str>,
    ) -> Result<OciDescriptor, ImageError> {
        if manifest.config().media_type() != MEDIA_TYPE_OCI_CONFIG {
            return Err(ImageError::UnsupportedManifestMediaType(
                manifest.config().media_type().to_owned(),
            ));
        }
        self.read_blob(manifest.config())?;
        for layer in manifest.layers() {
            validate_layer_media_type(layer.media_type())?;
            self.read_blob(layer)?;
        }

        fs::create_dir_all(self.root())?;
        let manifest_bytes = manifest.to_json_bytes();
        let mut manifest_descriptor = self.write_blob(MEDIA_TYPE_OCI_MANIFEST, &manifest_bytes)?;
        if let Some(reference_name) = reference_name {
            manifest_descriptor.insert_annotation(ANNOTATION_REF_NAME, reference_name);
        }

        fs::write(self.root.join("oci-layout"), oci_layout_json_bytes())?;
        fs::write(
            self.root.join("index.json"),
            oci_index_json_bytes(&manifest_descriptor),
        )?;
        Ok(manifest_descriptor)
    }

    pub fn push_to_registry<T>(
        &self,
        reference: OciReference,
        manifest: &OciImageManifest,
        target: &mut T,
    ) -> Result<RegistryPushPlan, ImageError>
    where
        T: RegistryPushTarget,
    {
        if manifest.config().media_type() != MEDIA_TYPE_OCI_CONFIG {
            return Err(ImageError::UnsupportedManifestMediaType(
                manifest.config().media_type().to_owned(),
            ));
        }

        let mut local_blobs = BTreeMap::new();
        let mut remote_blobs = Vec::new();
        let config = manifest.config();
        let config_bytes = self.read_blob(config)?;
        if target.blob_exists(config.digest())? {
            remote_blobs.push(config.digest().clone());
        }
        local_blobs.insert(config.digest().clone(), (config.clone(), config_bytes));

        for layer in manifest.layers() {
            validate_layer_media_type(layer.media_type())?;
            let bytes = self.read_blob(layer)?;
            if target.blob_exists(layer.digest())? {
                remote_blobs.push(layer.digest().clone());
            }
            local_blobs
                .entry(layer.digest().clone())
                .or_insert_with(|| (layer.clone(), bytes));
        }

        let manifest_bytes = manifest.to_json_bytes();
        let manifest_descriptor = OciDescriptor::new(
            MEDIA_TYPE_OCI_MANIFEST,
            OciDigest::sha256(&manifest_bytes),
            u64::try_from(manifest_bytes.len()).expect("usize fits in u64"),
        );
        let plan = RegistryPushPlan::from_manifest(
            reference,
            manifest_descriptor,
            manifest.clone(),
            remote_blobs,
        )?;

        for upload in plan.uploads() {
            match upload.kind() {
                RegistryPushUploadKind::Blob => {
                    let (_, bytes) = local_blobs
                        .get(upload.descriptor().digest())
                        .expect("registry push plan only contains verified local blobs");
                    target.upload_blob(upload.descriptor(), bytes)?;
                }
                RegistryPushUploadKind::Manifest => {
                    target.upload_manifest(
                        plan.reference(),
                        upload.descriptor(),
                        &manifest_bytes,
                    )?;
                }
            }
        }

        Ok(plan)
    }

    pub fn docker_tar_bytes(
        &self,
        manifest: &OciImageManifest,
        repository_tag: Option<&str>,
    ) -> Result<Vec<u8>, ImageError> {
        if manifest.config().media_type() != MEDIA_TYPE_OCI_CONFIG {
            return Err(ImageError::UnsupportedManifestMediaType(
                manifest.config().media_type().to_owned(),
            ));
        }

        let config_bytes = self.read_blob(manifest.config())?;
        let config_file = docker_config_filename(manifest.config());
        let mut layer_entries = Vec::with_capacity(manifest.layers().len());
        for layer in manifest.layers() {
            if layer.media_type() != MEDIA_TYPE_OCI_LAYER {
                return Err(ImageError::UnsupportedLayerMediaType(
                    layer.media_type().to_owned(),
                ));
            }
            let layer_bytes = self.read_blob(layer)?;
            layer_entries.push(DockerLayerArchiveEntry {
                path: docker_layer_filename(layer),
                bytes: layer_bytes,
            });
        }

        if let Some(repository_tag) = repository_tag {
            validate_docker_repository_tag(repository_tag)?;
        }

        let layer_paths = layer_entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();
        let manifest_bytes = docker_manifest_json_bytes(&config_file, &layer_paths, repository_tag);
        let repositories_bytes = if let Some(repository_tag) = repository_tag {
            let image_id = layer_entries
                .last()
                .and_then(|entry| entry.path.split_once('/').map(|(directory, _)| directory))
                .unwrap_or_else(|| manifest.config().digest().encoded());
            Some(docker_repositories_json_bytes(repository_tag, image_id)?)
        } else {
            None
        };

        let mut archive = Vec::new();
        append_tar_file(&mut archive, "manifest.json", &manifest_bytes)?;
        append_tar_file(&mut archive, &config_file, &config_bytes)?;
        for entry in &layer_entries {
            append_tar_file(&mut archive, &entry.path, &entry.bytes)?;
        }
        if let Some(repositories_bytes) = repositories_bytes {
            append_tar_file(&mut archive, "repositories", &repositories_bytes)?;
        }
        archive.extend(std::iter::repeat_n(0, TAR_BLOCK_SIZE * 2));
        Ok(archive)
    }

    pub fn write_docker_tar(
        &self,
        manifest: &OciImageManifest,
        repository_tag: Option<&str>,
        output_path: impl AsRef<Path>,
    ) -> Result<(), ImageError> {
        let archive = self.docker_tar_bytes(manifest, repository_tag)?;
        if let Some(parent) = output_path.as_ref().parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(output_path, archive)?;
        Ok(())
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

struct DockerLayerArchiveEntry {
    path: String,
    bytes: Vec<u8>,
}

fn oci_layout_json_bytes() -> Vec<u8> {
    let mut output = String::new();
    output.push_str("{\"imageLayoutVersion\":");
    push_json_string(&mut output, OCI_IMAGE_LAYOUT_VERSION);
    output.push('}');
    output.into_bytes()
}

fn oci_index_json_bytes(manifest_descriptor: &OciDescriptor) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("{\"schemaVersion\":2,\"manifests\":[");
    push_descriptor_json(&mut output, manifest_descriptor);
    output.push_str("]}");
    output.into_bytes()
}

fn docker_config_filename(config: &OciDescriptor) -> String {
    format!("{}.json", config.digest().encoded())
}

fn docker_layer_filename(layer: &OciDescriptor) -> String {
    format!("{}/layer.tar", layer.digest().encoded())
}

fn docker_manifest_json_bytes(
    config_file: &str,
    layer_paths: &[&str],
    repository_tag: Option<&str>,
) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("[{\"Config\":");
    push_json_string(&mut output, config_file);
    output.push_str(",\"RepoTags\":");
    if let Some(repository_tag) = repository_tag {
        output.push('[');
        push_json_string(&mut output, repository_tag);
        output.push(']');
    } else {
        output.push_str("[]");
    }
    output.push_str(",\"Layers\":[");
    for (index, layer_path) in layer_paths.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, layer_path);
    }
    output.push_str("]}]");
    output.into_bytes()
}

fn docker_repositories_json_bytes(
    repository_tag: &str,
    image_id: &str,
) -> Result<Vec<u8>, ImageError> {
    let (repository, tag) = split_docker_repository_tag(repository_tag)?;
    let mut output = String::new();
    output.push('{');
    push_json_string(&mut output, &repository);
    output.push_str(":{");
    push_json_string(&mut output, &tag);
    output.push(':');
    push_json_string(&mut output, image_id);
    output.push_str("}}");
    Ok(output.into_bytes())
}

fn validate_docker_repository_tag(repository_tag: &str) -> Result<(), ImageError> {
    split_docker_repository_tag(repository_tag).map(|_| ())
}

fn split_docker_repository_tag(repository_tag: &str) -> Result<(String, String), ImageError> {
    if repository_tag.is_empty()
        || repository_tag.trim() != repository_tag
        || repository_tag
            .bytes()
            .any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ImageError::InvalidReference(repository_tag.to_owned()));
    }
    let (repository, tag) = split_tag(repository_tag)?;
    let Some(tag) = tag else {
        return Err(ImageError::InvalidReference(repository_tag.to_owned()));
    };
    validate_tag(&tag)?;
    Ok((repository.to_owned(), tag))
}

fn append_tar_file(archive: &mut Vec<u8>, path: &str, bytes: &[u8]) -> Result<(), ImageError> {
    let mut header = [0u8; TAR_BLOCK_SIZE];
    write_tar_path(&mut header, path)?;
    write_tar_octal(&mut header[100..108], 0o644, "mode")?;
    write_tar_octal(&mut header[108..116], 0, "uid")?;
    write_tar_octal(&mut header[116..124], 0, "gid")?;
    write_tar_octal(
        &mut header[124..136],
        u64::try_from(bytes.len()).expect("usize fits in u64"),
        "size",
    )?;
    write_tar_octal(&mut header[136..148], 0, "mtime")?;
    header[148..156].fill(b' ');
    header[156] = b'0';
    write_tar_string(&mut header[257..263], "ustar")?;
    write_tar_string(&mut header[263..265], "00")?;

    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    write_tar_checksum(&mut header[148..156], checksum)?;

    archive.extend_from_slice(&header);
    archive.extend_from_slice(bytes);
    let padding = (TAR_BLOCK_SIZE - (bytes.len() % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
    archive.extend(std::iter::repeat_n(0, padding));
    Ok(())
}

fn write_tar_path(header: &mut [u8; TAR_BLOCK_SIZE], path: &str) -> Result<(), ImageError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ImageError::InvalidTarEntryPath(path.to_owned()));
    }

    if path.len() <= 100 {
        write_tar_string(&mut header[0..100], path)?;
        return Ok(());
    }

    if let Some((prefix, name)) = split_tar_prefix_name(path)
        && name.len() <= 100
        && prefix.len() <= 155
    {
        write_tar_string(&mut header[0..100], name)?;
        write_tar_string(&mut header[345..500], prefix)?;
        return Ok(());
    }

    Err(ImageError::TarEntryPathTooLong(path.to_owned()))
}

fn split_tar_prefix_name(path: &str) -> Option<(&str, &str)> {
    let mut split_indices = path
        .match_indices('/')
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    split_indices.reverse();
    for index in split_indices {
        let prefix = &path[..index];
        let name = &path[index + 1..];
        if !name.is_empty() {
            return Some((prefix, name));
        }
    }
    None
}

fn write_tar_string(field: &mut [u8], value: &str) -> Result<(), ImageError> {
    if value.len() > field.len() {
        return Err(ImageError::TarEntryPathTooLong(value.to_owned()));
    }
    field[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

fn write_tar_octal(
    field: &mut [u8],
    value: u64,
    field_name: &'static str,
) -> Result<(), ImageError> {
    let max_digits = field.len() - 1;
    let encoded = format!("{value:o}");
    if encoded.len() > max_digits {
        return Err(ImageError::TarFieldOverflow {
            field: field_name,
            value,
        });
    }
    let padding = max_digits - encoded.len();
    field[..padding].fill(b'0');
    field[padding..padding + encoded.len()].copy_from_slice(encoded.as_bytes());
    field[field.len() - 1] = 0;
    Ok(())
}

fn write_tar_checksum(field: &mut [u8], checksum: u64) -> Result<(), ImageError> {
    let encoded = format!("{checksum:06o}");
    if encoded.len() > 6 {
        return Err(ImageError::TarFieldOverflow {
            field: "checksum",
            value: checksum,
        });
    }
    field[..encoded.len()].copy_from_slice(encoded.as_bytes());
    field[6] = 0;
    field[7] = b' ';
    Ok(())
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
    use std::{
        collections::BTreeMap,
        time::{SystemTime, UNIX_EPOCH},
    };

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
    fn image_config_serializes_deterministic_json() {
        let diff_ids = vec![
            OciDigest::parse(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            OciDigest::parse(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
        ];
        let config = OciContainerConfig::new()
            .with_env(["PATH=/usr/bin", "APP_ENV=prod"])
            .with_working_dir("/srv/app")
            .with_entrypoint(["/entrypoint"])
            .with_command(["serve", "--message=hello \"mcr\"\n"]);
        let image = OciImageConfig::new(
            OciPlatform::linux_amd64(),
            config,
            vec![
                OciHistoryEntry::new("FROM scratch").with_empty_layer(true),
                OciHistoryEntry::new("COPY app /srv/app").with_comment("build context"),
            ],
            diff_ids,
        );

        let first = image.to_json_bytes();
        let second = image.to_json_bytes();

        assert_eq!(first, second);
        assert_eq!(
            String::from_utf8(first).unwrap(),
            concat!(
                "{\"architecture\":\"amd64\",\"config\":{\"Cmd\":[\"serve\",",
                "\"--message=hello \\\"mcr\\\"\\n\"],\"Entrypoint\":[\"/entrypoint\"],",
                "\"Env\":[\"PATH=/usr/bin\",\"APP_ENV=prod\"],",
                "\"WorkingDir\":\"/srv/app\"},\"history\":[",
                "{\"created_by\":\"FROM scratch\",\"empty_layer\":true},",
                "{\"created_by\":\"COPY app /srv/app\",\"comment\":\"build context\"}],",
                "\"os\":\"linux\",\"rootfs\":{\"diff_ids\":[",
                "\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",",
                "\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"",
                "],\"type\":\"layers\"}}"
            )
        );
    }

    #[test]
    fn image_manifest_serializes_deterministic_descriptor_json() {
        let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
        let mut layer = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"layer-one");
        layer.insert_annotation("org.opencontainers.image.title", "layer");
        layer.insert_annotation("com.example.order", "first");
        let manifest = OciImageManifest::new(config.clone(), vec![layer.clone()]);

        let first = manifest.to_json_bytes();
        let second = manifest.to_json_bytes();

        assert_eq!(first, second);
        assert_eq!(
            String::from_utf8(first).unwrap(),
            format!(
                "{{\"schemaVersion\":2,\"mediaType\":\"{}\",\"config\":{{\"mediaType\":\"{}\",\"digest\":\"{}\",\"size\":{}}},\"layers\":[{{\"mediaType\":\"{}\",\"digest\":\"{}\",\"size\":{},\"annotations\":{{\"com.example.order\":\"first\",\"org.opencontainers.image.title\":\"layer\"}}}}]}}",
                MEDIA_TYPE_OCI_MANIFEST,
                config.media_type(),
                config.digest(),
                config.size(),
                layer.media_type(),
                layer.digest(),
                layer.size()
            )
        );
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
    fn registry_push_plan_uploads_missing_blobs_before_manifest() {
        let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
        let layer_one = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"layer-one");
        let layer_two = descriptor_for(MEDIA_TYPE_OCI_LAYER_GZIP, b"layer-two");
        let manifest =
            OciImageManifest::new(config.clone(), vec![layer_one.clone(), layer_two.clone()]);
        let manifest_descriptor =
            descriptor_for(MEDIA_TYPE_OCI_MANIFEST, &manifest.to_json_bytes());

        let plan = RegistryPushPlan::from_manifest(
            OciReference::parse("localhost:5000/team/app:test").unwrap(),
            manifest_descriptor.clone(),
            manifest,
            vec![layer_one.digest().clone()],
        )
        .unwrap();

        assert_eq!(plan.reference().registry(), "localhost:5000");
        assert_eq!(plan.manifest_descriptor(), &manifest_descriptor);
        assert_eq!(
            plan.uploads()
                .iter()
                .map(RegistryPushUpload::kind)
                .collect::<Vec<_>>(),
            vec![
                RegistryPushUploadKind::Blob,
                RegistryPushUploadKind::Blob,
                RegistryPushUploadKind::Manifest
            ]
        );
        assert_eq!(plan.uploads()[0].descriptor(), &config);
        assert_eq!(plan.uploads()[1].descriptor(), &layer_two);
        assert_eq!(plan.uploads()[2].descriptor(), &manifest_descriptor);
    }

    #[test]
    fn registry_push_plan_deduplicates_blob_uploads() {
        let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
        let layer = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"same-layer");
        let manifest = OciImageManifest::new(config, vec![layer.clone(), layer.clone()]);
        let manifest_descriptor =
            descriptor_for(MEDIA_TYPE_OCI_MANIFEST, &manifest.to_json_bytes());

        let plan = RegistryPushPlan::from_manifest(
            OciReference::parse("example.com/team/app:test").unwrap(),
            manifest_descriptor.clone(),
            manifest,
            Vec::new(),
        )
        .unwrap();

        assert_eq!(plan.uploads().len(), 3);
        assert_eq!(plan.uploads()[1].descriptor(), &layer);
        assert_eq!(plan.uploads()[2].kind(), RegistryPushUploadKind::Manifest);
    }

    #[test]
    fn registry_push_plan_rejects_invalid_media_types() {
        let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
        let layer = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"layer");
        let manifest = OciImageManifest::new(config.clone(), vec![layer]);
        let config_descriptor = descriptor_for(MEDIA_TYPE_OCI_CONFIG, b"not-a-manifest");

        assert!(matches!(
            RegistryPushPlan::from_manifest(
                OciReference::parse("team/app:test").unwrap(),
                config_descriptor,
                manifest,
                Vec::new(),
            ),
            Err(ImageError::UnsupportedManifestMediaType(_))
        ));

        let bad_config = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"bad-config");
        let manifest = OciImageManifest::new(bad_config, vec![config]);
        let manifest_descriptor =
            descriptor_for(MEDIA_TYPE_OCI_MANIFEST, &manifest.to_json_bytes());

        assert!(matches!(
            RegistryPushPlan::from_manifest(
                OciReference::parse("team/app:test").unwrap(),
                manifest_descriptor,
                manifest,
                Vec::new(),
            ),
            Err(ImageError::UnsupportedManifestMediaType(_))
        ));
    }

    #[test]
    fn local_content_store_pushes_to_fake_registry_and_round_trips_pull_plan() {
        let root = temp_root("registry-push");
        let store = LocalContentStore::new(&root);
        let config = OciImageConfig::new(
            OciPlatform::linux_amd64(),
            OciContainerConfig::new()
                .with_env(["PATH=/usr/bin"])
                .with_command(["/bin/app"]),
            vec![OciHistoryEntry::new("FROM scratch")],
            vec![OciDigest::sha256(b"layer")],
        );
        let config_bytes = config.to_json_bytes();
        let config_descriptor = store
            .write_blob(MEDIA_TYPE_OCI_CONFIG, &config_bytes)
            .unwrap();
        let layer_bytes = b"layer";
        let layer_descriptor = store.write_blob(MEDIA_TYPE_OCI_LAYER, layer_bytes).unwrap();
        let manifest =
            OciImageManifest::new(config_descriptor.clone(), vec![layer_descriptor.clone()]);
        let reference = OciReference::parse("localhost:5000/team/app:test").unwrap();
        let mut registry = FakeRegistry::default();
        registry.seed_blob(&layer_descriptor, layer_bytes).unwrap();

        let plan = store
            .push_to_registry(reference.clone(), &manifest, &mut registry)
            .unwrap();

        assert_eq!(
            plan.uploads()
                .iter()
                .map(RegistryPushUpload::kind)
                .collect::<Vec<_>>(),
            vec![
                RegistryPushUploadKind::Blob,
                RegistryPushUploadKind::Manifest
            ]
        );
        assert_eq!(plan.uploads()[0].descriptor(), &config_descriptor);
        assert_eq!(
            registry.uploads,
            vec![
                RegistryPushUploadKind::Blob,
                RegistryPushUploadKind::Manifest
            ]
        );

        let (pushed_manifest_descriptor, pushed_manifest_bytes) =
            registry.manifest(&reference).unwrap();
        assert_eq!(pushed_manifest_descriptor, plan.manifest_descriptor());
        assert_eq!(pushed_manifest_bytes, manifest.to_json_bytes());

        let pull_plan = RegistryPullPlan::from_manifest(
            reference,
            OciPlatform::linux_amd64(),
            pushed_manifest_descriptor.clone(),
            manifest,
        )
        .unwrap();
        assert_eq!(pull_plan.manifest_descriptor(), pushed_manifest_descriptor);
        assert_eq!(
            registry.blob_bytes(pull_plan.config()).unwrap(),
            config_bytes
        );
        assert_eq!(
            registry.blob_bytes(&pull_plan.layers()[0]).unwrap(),
            layer_bytes
        );

        fs::remove_dir_all(root).unwrap();
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
    fn local_content_store_writes_deterministic_oci_layout() {
        let root = temp_root("oci-layout");
        let store = LocalContentStore::new(&root);
        let config = OciImageConfig::new(
            OciPlatform::linux_amd64(),
            OciContainerConfig::new()
                .with_env(["PATH=/usr/bin"])
                .with_command(["/bin/app"]),
            vec![OciHistoryEntry::new("FROM scratch").with_empty_layer(true)],
            vec![OciDigest::sha256(b"layer")],
        );
        let config_descriptor = store
            .write_blob(MEDIA_TYPE_OCI_CONFIG, &config.to_json_bytes())
            .unwrap();
        let layer_descriptor = store.write_blob(MEDIA_TYPE_OCI_LAYER, b"layer").unwrap();
        let manifest = OciImageManifest::new(config_descriptor, vec![layer_descriptor]);

        let manifest_descriptor = store.write_oci_layout(&manifest, Some("mcr:test")).unwrap();
        let first_index = fs::read_to_string(root.join("index.json")).unwrap();
        let second_descriptor = store.write_oci_layout(&manifest, Some("mcr:test")).unwrap();
        let second_index = fs::read_to_string(root.join("index.json")).unwrap();

        assert_eq!(manifest_descriptor, second_descriptor);
        assert_eq!(first_index, second_index);
        assert_eq!(
            fs::read_to_string(root.join("oci-layout")).unwrap(),
            "{\"imageLayoutVersion\":\"1.0.0\"}"
        );
        assert_eq!(
            first_index,
            format!(
                "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{}\",\"digest\":\"{}\",\"size\":{},\"annotations\":{{\"{}\":\"mcr:test\"}}}}]}}",
                MEDIA_TYPE_OCI_MANIFEST,
                manifest_descriptor.digest(),
                manifest_descriptor.size(),
                ANNOTATION_REF_NAME
            )
        );
        assert_eq!(
            store.read_blob(&manifest_descriptor).unwrap(),
            manifest.to_json_bytes()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_content_store_writes_deterministic_docker_tar() {
        let root = temp_root("docker-tar");
        let store = LocalContentStore::new(&root);
        let config = OciImageConfig::new(
            OciPlatform::linux_amd64(),
            OciContainerConfig::new()
                .with_env(["PATH=/usr/bin"])
                .with_working_dir("/srv/app")
                .with_command(["/bin/app"]),
            vec![OciHistoryEntry::new("FROM scratch").with_empty_layer(true)],
            vec![OciDigest::sha256(b"layer")],
        );
        let config_bytes = config.to_json_bytes();
        let config_descriptor = store
            .write_blob(MEDIA_TYPE_OCI_CONFIG, &config_bytes)
            .unwrap();
        let layer_bytes = single_file_tar("srv/app/hello.txt", b"hello\n");
        let layer_descriptor = store
            .write_blob(MEDIA_TYPE_OCI_LAYER, &layer_bytes)
            .unwrap();
        let manifest =
            OciImageManifest::new(config_descriptor.clone(), vec![layer_descriptor.clone()]);

        let first = store
            .docker_tar_bytes(&manifest, Some("mcr/example:test"))
            .unwrap();
        let second = store
            .docker_tar_bytes(&manifest, Some("mcr/example:test"))
            .unwrap();
        let archive_path = root.join("exports").join("image.tar");
        store
            .write_docker_tar(&manifest, Some("mcr/example:test"), &archive_path)
            .unwrap();
        let entries = tar_entries(&first);
        let entry_names = entries
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>();
        let config_file = docker_config_filename(&config_descriptor);
        let layer_file = docker_layer_filename(&layer_descriptor);

        assert_eq!(first, second);
        assert_eq!(fs::read(archive_path).unwrap(), first);
        assert_eq!(
            entry_names,
            vec![
                "manifest.json",
                config_file.as_str(),
                layer_file.as_str(),
                "repositories"
            ]
        );

        let entry_map = entries.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(
            String::from_utf8(entry_map["manifest.json"].clone()).unwrap(),
            format!(
                "[{{\"Config\":\"{}\",\"RepoTags\":[\"mcr/example:test\"],\"Layers\":[\"{}\"]}}]",
                config_file, layer_file
            )
        );
        assert_eq!(entry_map[&config_file], config_bytes);
        assert_eq!(entry_map[&layer_file], layer_bytes);
        assert_eq!(
            String::from_utf8(entry_map["repositories"].clone()).unwrap(),
            format!(
                "{{\"mcr/example\":{{\"test\":\"{}\"}}}}",
                layer_descriptor.digest().encoded()
            )
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn docker_tar_rejects_compressed_layer_blob() {
        let root = temp_root("docker-tar-gzip");
        let store = LocalContentStore::new(&root);
        let config_descriptor = store
            .write_blob(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#)
            .unwrap();
        let layer_descriptor = store
            .write_blob(MEDIA_TYPE_OCI_LAYER_GZIP, b"gzip")
            .unwrap();
        let manifest = OciImageManifest::new(config_descriptor, vec![layer_descriptor]);

        assert!(matches!(
            store.docker_tar_bytes(&manifest, Some("mcr:test")),
            Err(ImageError::UnsupportedLayerMediaType(_))
        ));

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

    #[derive(Default)]
    struct FakeRegistry {
        blobs: BTreeMap<OciDigest, (OciDescriptor, Vec<u8>)>,
        manifests: BTreeMap<String, (OciDescriptor, Vec<u8>)>,
        uploads: Vec<RegistryPushUploadKind>,
    }

    impl FakeRegistry {
        fn seed_blob(
            &mut self,
            descriptor: &OciDescriptor,
            bytes: &[u8],
        ) -> Result<(), ImageError> {
            verify_descriptor_bytes(descriptor, bytes)?;
            self.blobs.insert(
                descriptor.digest().clone(),
                (descriptor.clone(), bytes.to_vec()),
            );
            Ok(())
        }

        fn blob_bytes(&self, descriptor: &OciDescriptor) -> Option<Vec<u8>> {
            let (_, bytes) = self.blobs.get(descriptor.digest())?;
            Some(bytes.clone())
        }

        fn manifest(&self, reference: &OciReference) -> Option<(&OciDescriptor, Vec<u8>)> {
            let (descriptor, bytes) = self.manifests.get(&reference.to_string())?;
            Some((descriptor, bytes.clone()))
        }
    }

    impl RegistryPushTarget for FakeRegistry {
        fn blob_exists(&self, digest: &OciDigest) -> Result<bool, ImageError> {
            Ok(self.blobs.contains_key(digest))
        }

        fn upload_blob(
            &mut self,
            descriptor: &OciDescriptor,
            bytes: &[u8],
        ) -> Result<(), ImageError> {
            verify_descriptor_bytes(descriptor, bytes)?;
            self.uploads.push(RegistryPushUploadKind::Blob);
            self.blobs.insert(
                descriptor.digest().clone(),
                (descriptor.clone(), bytes.to_vec()),
            );
            Ok(())
        }

        fn upload_manifest(
            &mut self,
            reference: &OciReference,
            descriptor: &OciDescriptor,
            bytes: &[u8],
        ) -> Result<(), ImageError> {
            verify_descriptor_bytes(descriptor, bytes)?;
            self.uploads.push(RegistryPushUploadKind::Manifest);
            self.manifests
                .insert(reference.to_string(), (descriptor.clone(), bytes.to_vec()));
            Ok(())
        }
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

    fn tar_entries(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut entries = Vec::new();
        let mut offset = 0usize;
        loop {
            assert!(offset + TAR_BLOCK_SIZE <= archive.len());
            let header = &archive[offset..offset + TAR_BLOCK_SIZE];
            if header.iter().all(|byte| *byte == 0) {
                assert!(
                    archive[offset..offset + (TAR_BLOCK_SIZE * 2)]
                        .iter()
                        .all(|byte| *byte == 0)
                );
                return entries;
            }

            let mut checksum_header = header.to_vec();
            checksum_header[148..156].fill(b' ');
            let expected_checksum = read_tar_octal(&header[148..156]);
            let actual_checksum = checksum_header
                .iter()
                .map(|byte| usize::from(*byte))
                .sum::<usize>();
            assert_eq!(expected_checksum, actual_checksum);

            let name = read_tar_string(&header[0..100]);
            let prefix = read_tar_string(&header[345..500]);
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let size = read_tar_octal(&header[124..136]);
            offset += TAR_BLOCK_SIZE;
            let data_end = offset + size;
            entries.push((path, archive[offset..data_end].to_vec()));
            offset = data_end + ((TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE);
        }
    }

    fn read_tar_string(field: &[u8]) -> String {
        let end = field
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(field.len());
        String::from_utf8(field[..end].to_vec()).unwrap()
    }

    fn read_tar_octal(field: &[u8]) -> usize {
        let end = field
            .iter()
            .position(|byte| *byte == 0 || *byte == b' ')
            .unwrap_or(field.len());
        let value = std::str::from_utf8(&field[..end]).unwrap();
        usize::from_str_radix(value, 8).unwrap()
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
