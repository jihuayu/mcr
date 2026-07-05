use super::*;

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
pub(crate) fn validate_layer_media_type(media_type: &str) -> Result<(), ImageError> {
    if media_type == MEDIA_TYPE_OCI_LAYER || media_type == MEDIA_TYPE_OCI_LAYER_GZIP {
        Ok(())
    } else {
        Err(ImageError::UnsupportedLayerMediaType(media_type.to_owned()))
    }
}
pub(crate) fn verify_descriptor_bytes(
    descriptor: &OciDescriptor,
    bytes: &[u8],
) -> Result<(), ImageError> {
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
