use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt::{self, Write as _},
    fs, io,
    path::{Path, PathBuf},
};

use mcr_snapshot::{BaseLayerSnapshot, LayerRef, LayerUnpackError, SnapshotError, SnapshotId};
use sha2::{Digest, Sha256};

mod error;
mod oci;
mod registry;
mod store;

#[cfg(test)]
mod tests;

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

pub use error::ImageError;
pub use oci::{
    DigestAlgorithm, OciContainerConfig, OciDescriptor, OciDigest, OciHistoryEntry, OciImageConfig,
    OciImageIndex, OciImageManifest, OciIndexManifest, OciPlatform, OciReference,
};
pub(crate) use oci::{push_descriptor_json, push_json_string, split_tag, validate_tag};
pub(crate) use registry::validate_layer_media_type;
#[cfg(test)]
pub(crate) use registry::verify_descriptor_bytes;
pub use registry::{
    RegistryPullPlan, RegistryPushPlan, RegistryPushTarget, RegistryPushUpload,
    RegistryPushUploadKind, VerifiedLayerBlob,
};
pub use store::LocalContentStore;
#[cfg(test)]
pub(crate) use store::{TAR_BLOCK_SIZE, docker_config_filename, docker_layer_filename};
