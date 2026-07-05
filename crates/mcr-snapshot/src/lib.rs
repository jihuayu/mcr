use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

mod core;
mod export;
mod unpack;

#[cfg(test)]
mod tests;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub use core::{
    LayerEntry, LayerEntryKind, LayerRef, LinuxMetadata, SnapshotEntry, SnapshotError,
    SnapshotFileKind, SnapshotId, SnapshotLayerPlan, SnapshotPath, SnapshotSpec, SnapshotView,
    WritableUpperRoot,
};
pub use export::{LayerExportError, SnapshotExportError};
pub(crate) use export::{TAR_BLOCK_SIZE, append_layer_tar_entry, read_upper_regular_contents};
pub use unpack::{BaseLayerSnapshot, LayerUnpackError};
#[cfg(test)]
pub(crate) use unpack::{padded_tar_len, tar_octal, tar_string};
