use super::*;

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
pub(crate) fn split_tag(value: &str) -> Result<(&str, Option<String>), ImageError> {
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
pub(crate) fn validate_tag(tag: &str) -> Result<(), ImageError> {
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
pub(crate) fn push_descriptor_json(output: &mut String, descriptor: &OciDescriptor) {
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
pub(crate) fn push_json_string(output: &mut String, value: &str) {
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
