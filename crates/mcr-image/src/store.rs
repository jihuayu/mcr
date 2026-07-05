use super::*;

pub(crate) const TAR_BLOCK_SIZE: usize = 512;

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
pub(crate) fn docker_config_filename(config: &OciDescriptor) -> String {
    format!("{}.json", config.digest().encoded())
}
pub(crate) fn docker_layer_filename(layer: &OciDescriptor) -> String {
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
