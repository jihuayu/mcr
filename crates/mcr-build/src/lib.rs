use mcr_snapshot::{LinuxMetadata, SnapshotError, SnapshotFileKind, SnapshotPath, SnapshotSpec};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

mod context;
mod dockerfile;
mod planner;

#[cfg(test)]
mod tests;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub use context::{
    BuildContext, BuildContextEntry, BuildContextEntryKind, BuildContextError,
    BuildContextErrorKind, ContextPath, DockerIgnore, load_build_context,
};
pub use dockerfile::{
    BuildPlan, DockerfileInstruction, DockerfileParseError, DockerfileParseErrorKind,
    parse_dockerfile,
};
pub use planner::{
    BuildApplicationError, BuildApplicationErrorKind, BuildApplicationPlan, SnapshotApplication,
    plan_context_application,
};
pub(crate) use planner::{ContextSource, ResolvedContextEntry};
