use mcr_snapshot::{LinuxMetadata, SnapshotError, SnapshotFileKind, SnapshotPath, SnapshotSpec};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildContext {
    root: PathBuf,
    entries: Vec<BuildContextEntry>,
    dockerignore: DockerIgnore,
}

impl BuildContext {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn entries(&self) -> &[BuildContextEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn dockerignore(&self) -> &DockerIgnore {
        &self.dockerignore
    }

    #[must_use]
    pub fn entry(&self, path: &ContextPath) -> Option<&BuildContextEntry> {
        self.entries.iter().find(|entry| entry.path() == path)
    }

    fn source_entries(
        &self,
        source: &ContextSource,
    ) -> Result<Vec<ResolvedContextEntry<'_>>, BuildApplicationError> {
        match source {
            ContextSource::Root => Ok(self
                .entries
                .iter()
                .map(|entry| ResolvedContextEntry {
                    entry,
                    relative_destination: entry.path().clone(),
                })
                .collect()),
            ContextSource::Path(path) => {
                let entry = self
                    .entry(path)
                    .ok_or_else(|| BuildApplicationError::missing_context_source(path.as_str()))?;
                match entry.kind() {
                    BuildContextEntryKind::Directory => {
                        let entries = self
                            .entries
                            .iter()
                            .filter_map(|child| {
                                child.path().strip_prefix(path).map(|relative_destination| {
                                    ResolvedContextEntry {
                                        entry: child,
                                        relative_destination,
                                    }
                                })
                            })
                            .filter(|child| !child.relative_destination.as_str().is_empty())
                            .collect::<Vec<_>>();
                        Ok(entries)
                    }
                    BuildContextEntryKind::Regular { .. }
                    | BuildContextEntryKind::Symlink { .. } => Ok(vec![ResolvedContextEntry {
                        entry,
                        relative_destination: path.basename(),
                    }]),
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildContextEntry {
    path: ContextPath,
    kind: BuildContextEntryKind,
    metadata: LinuxMetadata,
}

impl BuildContextEntry {
    #[must_use]
    pub const fn new(
        path: ContextPath,
        kind: BuildContextEntryKind,
        metadata: LinuxMetadata,
    ) -> Self {
        Self {
            path,
            kind,
            metadata,
        }
    }

    #[must_use]
    pub const fn path(&self) -> &ContextPath {
        &self.path
    }

    #[must_use]
    pub const fn kind(&self) -> &BuildContextEntryKind {
        &self.kind
    }

    #[must_use]
    pub const fn metadata(&self) -> &LinuxMetadata {
        &self.metadata
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildContextEntryKind {
    Directory,
    Regular { size: u64 },
    Symlink { target: String },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContextPath(String);

impl ContextPath {
    pub fn new(path: impl Into<String>) -> Result<Self, BuildContextError> {
        Self::normalize(path.into()).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn normalize(path: String) -> Result<String, BuildContextError> {
        let normalized = path.replace('\\', "/");
        if normalized.starts_with('/') || Path::new(&normalized).is_absolute() {
            return Err(BuildContextError::invalid_context_path(path));
        }

        let mut components = Vec::new();
        for component in normalized.split('/') {
            match component {
                "" | "." => {}
                ".." => return Err(BuildContextError::context_escape(path)),
                value => components.push(value),
            }
        }

        if components.is_empty() {
            return Err(BuildContextError::invalid_context_path(path));
        }
        Ok(components.join("/"))
    }

    fn from_relative_path(path: &Path) -> Result<Self, BuildContextError> {
        Self::new(path.to_string_lossy().replace('\\', "/"))
    }

    fn strip_prefix(&self, prefix: &Self) -> Option<Self> {
        if self == prefix {
            return Some(Self(String::new()));
        }
        let suffix = self.0.strip_prefix(prefix.as_str())?;
        let suffix = suffix.strip_prefix('/')?;
        Some(Self(suffix.to_owned()))
    }

    fn basename(&self) -> Self {
        let basename = self.0.rsplit('/').next().unwrap_or(self.as_str());
        Self(basename.to_owned())
    }
}

impl fmt::Display for ContextPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerIgnore {
    rules: Vec<DockerIgnoreRule>,
}

impl DockerIgnore {
    #[must_use]
    pub fn parse(input: &str) -> Self {
        let rules = input.lines().filter_map(DockerIgnoreRule::parse).collect();
        Self { rules }
    }

    #[must_use]
    pub fn is_ignored(&self, path: &ContextPath, is_dir: bool) -> bool {
        let mut ignored = false;
        for rule in &self.rules {
            if rule.matches(path.as_str(), is_dir) {
                ignored = !rule.negated;
            }
        }
        ignored
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DockerIgnoreRule {
    pattern: String,
    negated: bool,
    directory_only: bool,
    anchored: bool,
}

impl DockerIgnoreRule {
    fn parse(line: &str) -> Option<Self> {
        let mut pattern = line.trim();
        if pattern.is_empty() || pattern.starts_with('#') {
            return None;
        }

        let negated = pattern.starts_with('!');
        if negated {
            pattern = pattern[1..].trim_start();
        }

        let mut normalized = pattern.replace('\\', "/");
        let anchored = normalized.starts_with('/');
        normalized = normalized.trim_start_matches('/').to_owned();
        let directory_only = normalized.ends_with('/');
        normalized = normalized.trim_end_matches('/').to_owned();
        if normalized.is_empty() {
            return None;
        }

        Some(Self {
            pattern: normalized,
            negated,
            directory_only,
            anchored,
        })
    }

    fn matches(&self, path: &str, is_dir: bool) -> bool {
        if self.directory_only && !is_dir && !path.starts_with(&format!("{}/", self.pattern)) {
            return false;
        }

        if self.anchored || self.pattern.contains('/') {
            return pattern_matches_path(&self.pattern, path);
        }

        path.split('/')
            .any(|component| wildcard_matches(&self.pattern, component))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct BuildContextError {
    kind: BuildContextErrorKind,
}

impl BuildContextError {
    fn io(path: impl Into<PathBuf>, error: &std::io::Error) -> Self {
        Self {
            kind: BuildContextErrorKind::Io {
                path: path.into(),
                message: error.to_string(),
            },
        }
    }

    fn context_escape(path: impl Into<String>) -> Self {
        Self {
            kind: BuildContextErrorKind::ContextEscape(path.into()),
        }
    }

    fn invalid_context_path(path: impl Into<String>) -> Self {
        Self {
            kind: BuildContextErrorKind::InvalidContextPath(path.into()),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &BuildContextErrorKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildContextErrorKind {
    Io { path: PathBuf, message: String },
    ContextEscape(String),
    InvalidContextPath(String),
}

impl fmt::Display for BuildContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            BuildContextErrorKind::Io { path, message } => {
                write!(
                    formatter,
                    "failed to load build context `{}`: {message}",
                    path.display()
                )
            }
            BuildContextErrorKind::ContextEscape(path) => {
                write!(
                    formatter,
                    "build context path escapes the context root: {path}"
                )
            }
            BuildContextErrorKind::InvalidContextPath(path) => {
                write!(formatter, "invalid build context path: {path}")
            }
        }
    }
}

impl Error for BuildContextError {}

pub fn load_build_context(root: impl AsRef<Path>) -> Result<BuildContext, BuildContextError> {
    let root = root.as_ref();
    let canonical_root =
        fs::canonicalize(root).map_err(|error| BuildContextError::io(root, &error))?;
    let dockerignore_path = canonical_root.join(".dockerignore");
    let dockerignore = match fs::read_to_string(&dockerignore_path) {
        Ok(input) => DockerIgnore::parse(&input),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DockerIgnore { rules: Vec::new() }
        }
        Err(error) => return Err(BuildContextError::io(dockerignore_path, &error)),
    };

    let mut entries = Vec::new();
    walk_context(
        &canonical_root,
        &canonical_root,
        &dockerignore,
        &mut entries,
    )?;
    entries.sort_by(|left, right| left.path().cmp(right.path()));

    Ok(BuildContext {
        root: canonical_root,
        entries,
        dockerignore,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildApplicationPlan {
    build_args: BTreeMap<String, Option<String>>,
    env: BTreeMap<String, String>,
    workdir: SnapshotPath,
    operations: Vec<SnapshotApplication>,
}

impl BuildApplicationPlan {
    #[must_use]
    pub fn build_args(&self) -> &BTreeMap<String, Option<String>> {
        &self.build_args
    }

    #[must_use]
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    #[must_use]
    pub const fn workdir(&self) -> &SnapshotPath {
        &self.workdir
    }

    #[must_use]
    pub fn operations(&self) -> &[SnapshotApplication] {
        &self.operations
    }

    pub fn apply_metadata_to(&self, snapshot: &mut SnapshotSpec) {
        for operation in &self.operations {
            snapshot.upsert_sidecar(
                operation.destination().clone(),
                operation.metadata().clone(),
            );
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotApplication {
    EnsureDirectory {
        destination: SnapshotPath,
        metadata: LinuxMetadata,
    },
    CopyFile {
        source: ContextPath,
        destination: SnapshotPath,
        metadata: LinuxMetadata,
    },
    CopySymlink {
        source: ContextPath,
        destination: SnapshotPath,
        target: String,
        metadata: LinuxMetadata,
    },
}

impl SnapshotApplication {
    #[must_use]
    pub const fn destination(&self) -> &SnapshotPath {
        match self {
            Self::EnsureDirectory { destination, .. }
            | Self::CopyFile { destination, .. }
            | Self::CopySymlink { destination, .. } => destination,
        }
    }

    #[must_use]
    pub const fn metadata(&self) -> &LinuxMetadata {
        match self {
            Self::EnsureDirectory { metadata, .. }
            | Self::CopyFile { metadata, .. }
            | Self::CopySymlink { metadata, .. } => metadata,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct BuildApplicationError {
    kind: BuildApplicationErrorKind,
}

impl BuildApplicationError {
    fn invalid_copy_arguments(raw: impl Into<String>) -> Self {
        Self {
            kind: BuildApplicationErrorKind::InvalidCopyArguments(raw.into()),
        }
    }

    fn unsupported_copy_flag(flag: impl Into<String>) -> Self {
        Self {
            kind: BuildApplicationErrorKind::UnsupportedCopyFlag(flag.into()),
        }
    }

    fn unsupported_remote_add(source: impl Into<String>) -> Self {
        Self {
            kind: BuildApplicationErrorKind::UnsupportedRemoteAdd(source.into()),
        }
    }

    fn context_source_escape(source: impl Into<String>) -> Self {
        Self {
            kind: BuildApplicationErrorKind::ContextSourceEscape(source.into()),
        }
    }

    fn missing_context_source(source: impl Into<String>) -> Self {
        Self {
            kind: BuildApplicationErrorKind::MissingContextSource(source.into()),
        }
    }

    fn invalid_metadata_instruction(raw: impl Into<String>) -> Self {
        Self {
            kind: BuildApplicationErrorKind::InvalidMetadataInstruction(raw.into()),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &BuildApplicationErrorKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildApplicationErrorKind {
    InvalidCopyArguments(String),
    UnsupportedCopyFlag(String),
    UnsupportedRemoteAdd(String),
    ContextSourceEscape(String),
    MissingContextSource(String),
    InvalidMetadataInstruction(String),
    InvalidSnapshotPath(SnapshotError),
}

impl fmt::Display for BuildApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            BuildApplicationErrorKind::InvalidCopyArguments(raw) => {
                write!(formatter, "invalid COPY/ADD arguments: {raw}")
            }
            BuildApplicationErrorKind::UnsupportedCopyFlag(flag) => {
                write!(
                    formatter,
                    "unsupported COPY/ADD flag in local context planner: {flag}"
                )
            }
            BuildApplicationErrorKind::UnsupportedRemoteAdd(source) => {
                write!(formatter, "remote ADD is unsupported for source: {source}")
            }
            BuildApplicationErrorKind::ContextSourceEscape(source) => {
                write!(
                    formatter,
                    "COPY/ADD source escapes the build context: {source}"
                )
            }
            BuildApplicationErrorKind::MissingContextSource(source) => {
                write!(
                    formatter,
                    "COPY/ADD source is not present in the build context: {source}"
                )
            }
            BuildApplicationErrorKind::InvalidMetadataInstruction(raw) => {
                write!(formatter, "invalid ARG/ENV metadata instruction: {raw}")
            }
            BuildApplicationErrorKind::InvalidSnapshotPath(error) => error.fmt(formatter),
        }
    }
}

impl Error for BuildApplicationError {}

impl From<SnapshotError> for BuildApplicationError {
    fn from(error: SnapshotError) -> Self {
        Self {
            kind: BuildApplicationErrorKind::InvalidSnapshotPath(error),
        }
    }
}

pub fn plan_context_application(
    plan: &BuildPlan,
    context: &BuildContext,
) -> Result<BuildApplicationPlan, BuildApplicationError> {
    let mut build_args = BTreeMap::new();
    let mut env = BTreeMap::new();
    let mut workdir = SnapshotPath::new("/")?;
    let mut operations = Vec::new();

    for instruction in plan.instructions() {
        match instruction {
            DockerfileInstruction::Arg(raw) => {
                let (name, value) = parse_arg(raw)?;
                build_args.insert(name, value);
            }
            DockerfileInstruction::Env(raw) => {
                for (key, value) in parse_env(raw)? {
                    env.insert(key, value);
                }
            }
            DockerfileInstruction::Workdir(raw) => {
                workdir = resolve_guest_path(&workdir, raw)?;
                upsert_directory_operation(
                    &mut operations,
                    workdir.clone(),
                    default_directory_metadata(),
                );
            }
            DockerfileInstruction::Copy(raw) => {
                plan_copy_like_instruction(
                    raw,
                    CopyKind::Copy,
                    context,
                    &workdir,
                    &mut operations,
                )?;
            }
            DockerfileInstruction::Add(raw) => {
                plan_copy_like_instruction(raw, CopyKind::Add, context, &workdir, &mut operations)?;
            }
            DockerfileInstruction::From(_)
            | DockerfileInstruction::Run(_)
            | DockerfileInstruction::Cmd(_)
            | DockerfileInstruction::Entrypoint(_) => {}
        }
    }

    Ok(BuildApplicationPlan {
        build_args,
        env,
        workdir,
        operations,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyKind {
    Copy,
    Add,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ContextSource {
    Root,
    Path(ContextPath),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedContextEntry<'a> {
    entry: &'a BuildContextEntry,
    relative_destination: ContextPath,
}

fn walk_context(
    root: &Path,
    directory: &Path,
    dockerignore: &DockerIgnore,
    entries: &mut Vec<BuildContextEntry>,
) -> Result<(), BuildContextError> {
    let mut children = fs::read_dir(directory)
        .map_err(|error| BuildContextError::io(directory, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| BuildContextError::io(directory, &error))?;
    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| BuildContextError::context_escape(path.display().to_string()))?;
        let context_path = ContextPath::from_relative_path(relative)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| BuildContextError::io(path.clone(), &error))?;
        let file_type = metadata.file_type();
        let is_dir = file_type.is_dir();

        if dockerignore.is_ignored(&context_path, is_dir) {
            continue;
        }

        if !file_type.is_symlink() {
            let canonical = fs::canonicalize(&path)
                .map_err(|error| BuildContextError::io(path.clone(), &error))?;
            if !canonical.starts_with(root) {
                return Err(BuildContextError::context_escape(
                    path.display().to_string(),
                ));
            }
        }

        if file_type.is_symlink() {
            let target = fs::read_link(&path)
                .map_err(|error| BuildContextError::io(path.clone(), &error))?;
            let target = target.to_string_lossy().replace('\\', "/");
            let metadata = LinuxMetadata::new(
                SnapshotFileKind::Symlink {
                    target: target.clone(),
                },
                0o777,
                0,
                0,
                metadata_mtime_nanos(&metadata),
            );
            entries.push(BuildContextEntry::new(
                context_path,
                BuildContextEntryKind::Symlink { target },
                metadata,
            ));
        } else if file_type.is_dir() {
            entries.push(BuildContextEntry::new(
                context_path,
                BuildContextEntryKind::Directory,
                LinuxMetadata::new(
                    SnapshotFileKind::Directory,
                    0o755,
                    0,
                    0,
                    metadata_mtime_nanos(&metadata),
                ),
            ));
            walk_context(root, &path, dockerignore, entries)?;
        } else if file_type.is_file() {
            entries.push(BuildContextEntry::new(
                context_path,
                BuildContextEntryKind::Regular {
                    size: metadata.len(),
                },
                LinuxMetadata::new(
                    SnapshotFileKind::Regular {
                        size: metadata.len(),
                    },
                    0o644,
                    0,
                    0,
                    metadata_mtime_nanos(&metadata),
                ),
            ));
        }
    }

    Ok(())
}

fn plan_copy_like_instruction(
    raw: &str,
    kind: CopyKind,
    context: &BuildContext,
    workdir: &SnapshotPath,
    operations: &mut Vec<SnapshotApplication>,
) -> Result<(), BuildApplicationError> {
    let mut tokens = tokenize_instruction_arguments(raw);
    if tokens.len() < 2 {
        return Err(BuildApplicationError::invalid_copy_arguments(raw));
    }
    if let Some(flag) = tokens.iter().find(|token| token.starts_with("--")) {
        return Err(BuildApplicationError::unsupported_copy_flag(flag.clone()));
    }

    let destination = tokens
        .pop()
        .ok_or_else(|| BuildApplicationError::invalid_copy_arguments(raw))?;
    let source_count = tokens.len();
    let destination_is_directory = source_count > 1
        || destination == "."
        || destination.ends_with('/')
        || destination.ends_with('\\');
    let destination_base = resolve_guest_path(workdir, &destination)?;

    for source in tokens {
        if kind == CopyKind::Add && looks_like_remote_url(&source) {
            return Err(BuildApplicationError::unsupported_remote_add(source));
        }

        let source = parse_context_source(&source)?;
        let source_entries = context.source_entries(&source)?;
        let source_is_directory = matches!(source, ContextSource::Root)
            || matches!(
                &source,
                ContextSource::Path(path)
                    if matches!(
                        context.entry(path).map(BuildContextEntry::kind),
                        Some(BuildContextEntryKind::Directory)
                    )
            );
        let copy_to_directory = destination_is_directory || source_is_directory;

        if copy_to_directory {
            push_parent_directories(operations, &destination_base)?;
            upsert_directory_operation(
                operations,
                destination_base.clone(),
                default_directory_metadata(),
            );
        }

        for resolved in source_entries {
            let destination_path = if copy_to_directory {
                join_guest_context_path(&destination_base, &resolved.relative_destination)?
            } else {
                destination_base.clone()
            };
            push_parent_directories(operations, &destination_path)?;
            match resolved.entry.kind() {
                BuildContextEntryKind::Directory => {
                    upsert_directory_operation(
                        operations,
                        destination_path,
                        resolved.entry.metadata().clone(),
                    );
                }
                BuildContextEntryKind::Regular { .. } => {
                    operations.push(SnapshotApplication::CopyFile {
                        source: resolved.entry.path().clone(),
                        destination: destination_path,
                        metadata: resolved.entry.metadata().clone(),
                    })
                }
                BuildContextEntryKind::Symlink { target } => {
                    operations.push(SnapshotApplication::CopySymlink {
                        source: resolved.entry.path().clone(),
                        destination: destination_path,
                        target: target.clone(),
                        metadata: resolved.entry.metadata().clone(),
                    })
                }
            }
        }
    }

    Ok(())
}

fn parse_arg(raw: &str) -> Result<(String, Option<String>), BuildApplicationError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(BuildApplicationError::invalid_metadata_instruction(raw));
    }

    let (name, value) = raw.split_once('=').map_or((raw, None), |(name, value)| {
        (name.trim(), Some(value.to_owned()))
    });
    if name.is_empty() {
        return Err(BuildApplicationError::invalid_metadata_instruction(raw));
    }
    Ok((name.to_owned(), value))
}

fn parse_env(raw: &str) -> Result<Vec<(String, String)>, BuildApplicationError> {
    let tokens = tokenize_instruction_arguments(raw);
    if tokens.is_empty() {
        return Err(BuildApplicationError::invalid_metadata_instruction(raw));
    }

    if tokens.iter().all(|token| token.contains('=')) {
        let mut pairs = Vec::with_capacity(tokens.len());
        for token in tokens {
            let (key, value) = token
                .split_once('=')
                .ok_or_else(|| BuildApplicationError::invalid_metadata_instruction(raw))?;
            if key.is_empty() {
                return Err(BuildApplicationError::invalid_metadata_instruction(raw));
            }
            pairs.push((key.to_owned(), value.to_owned()));
        }
        return Ok(pairs);
    }

    if tokens.len() < 2 || tokens[0].is_empty() {
        return Err(BuildApplicationError::invalid_metadata_instruction(raw));
    }
    Ok(vec![(tokens[0].clone(), tokens[1..].join(" "))])
}

fn parse_context_source(raw: &str) -> Result<ContextSource, BuildApplicationError> {
    let normalized = raw.replace('\\', "/");
    if normalized.starts_with('/') || Path::new(&normalized).is_absolute() {
        return Err(BuildApplicationError::context_source_escape(raw));
    }

    let mut components = Vec::new();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(BuildApplicationError::context_source_escape(raw)),
            value => components.push(value),
        }
    }

    if components.is_empty() {
        Ok(ContextSource::Root)
    } else {
        Ok(ContextSource::Path(ContextPath(components.join("/"))))
    }
}

fn tokenize_instruction_arguments(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut escaped = false;

    for character in raw.chars() {
        if escaped {
            token.push(character);
            escaped = false;
            continue;
        }

        if character == '\\' {
            escaped = true;
            continue;
        }

        match quote {
            Some(active_quote) if character == active_quote => quote = None,
            Some(_) => token.push(character),
            None if character == '\'' || character == '"' => quote = Some(character),
            None if character.is_whitespace() => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            None => token.push(character),
        }
    }

    if escaped {
        token.push('\\');
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

fn resolve_guest_path(current: &SnapshotPath, raw: &str) -> Result<SnapshotPath, SnapshotError> {
    let normalized = raw.replace('\\', "/");
    let mut components = if normalized.starts_with('/') {
        Vec::new()
    } else {
        current
            .as_str()
            .split('/')
            .filter(|component| !component.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };

    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value => components.push(value.to_owned()),
        }
    }

    if components.is_empty() {
        SnapshotPath::new("/")
    } else {
        SnapshotPath::new(format!("/{}", components.join("/")))
    }
}

fn join_guest_context_path(
    base: &SnapshotPath,
    relative: &ContextPath,
) -> Result<SnapshotPath, SnapshotError> {
    if relative.as_str().is_empty() {
        return Ok(base.clone());
    }
    resolve_guest_path(base, relative.as_str())
}

fn push_parent_directories(
    operations: &mut Vec<SnapshotApplication>,
    path: &SnapshotPath,
) -> Result<(), SnapshotError> {
    let mut components = path
        .as_str()
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    components.pop();

    let mut current = SnapshotPath::new("/")?;
    for component in components {
        current = resolve_guest_path(&current, component)?;
        upsert_directory_operation(operations, current.clone(), default_directory_metadata());
    }
    Ok(())
}

fn upsert_directory_operation(
    operations: &mut Vec<SnapshotApplication>,
    destination: SnapshotPath,
    metadata: LinuxMetadata,
) {
    if let Some(SnapshotApplication::EnsureDirectory {
        metadata: existing, ..
    }) = operations.iter_mut().find(|operation| {
        matches!(
            operation,
            SnapshotApplication::EnsureDirectory {
                destination: existing,
                ..
            } if existing == &destination
        )
    }) {
        *existing = metadata;
        return;
    }

    operations.push(SnapshotApplication::EnsureDirectory {
        destination,
        metadata,
    });
}

fn default_directory_metadata() -> LinuxMetadata {
    LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 0)
}

fn looks_like_remote_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn pattern_matches_path(pattern: &str, path: &str) -> bool {
    wildcard_matches(pattern, path) || path.starts_with(&format!("{pattern}/"))
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == value;
    }
    if pattern == "*" {
        return true;
    }

    let mut remaining = value;
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    if !remaining.starts_with(first) {
        return false;
    }
    remaining = &remaining[first.len()..];

    let mut last_part = "";
    for part in parts {
        last_part = part;
        if part.is_empty() {
            continue;
        }
        let Some(index) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[index + part.len()..];
    }

    pattern.ends_with('*') || remaining.is_empty() || remaining.ends_with(last_part)
}

fn metadata_mtime_nanos(metadata: &fs::Metadata) -> i128 {
    metadata
        .modified()
        .map(system_time_unix_nanos)
        .unwrap_or_default()
}

fn system_time_unix_nanos(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos())
        }
        Err(error) => {
            let duration = error.duration();
            -(i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos()))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildPlan {
    instructions: Vec<DockerfileInstruction>,
}

impl BuildPlan {
    #[must_use]
    pub fn new(instructions: Vec<DockerfileInstruction>) -> Self {
        Self { instructions }
    }

    #[must_use]
    pub fn instructions(&self) -> &[DockerfileInstruction] {
        &self.instructions
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DockerfileInstruction {
    From(String),
    Arg(String),
    Env(String),
    Workdir(String),
    Copy(String),
    Add(String),
    Run(String),
    Cmd(String),
    Entrypoint(String),
}

impl DockerfileInstruction {
    #[must_use]
    pub fn keyword(&self) -> &'static str {
        match self {
            Self::From(_) => "FROM",
            Self::Arg(_) => "ARG",
            Self::Env(_) => "ENV",
            Self::Workdir(_) => "WORKDIR",
            Self::Copy(_) => "COPY",
            Self::Add(_) => "ADD",
            Self::Run(_) => "RUN",
            Self::Cmd(_) => "CMD",
            Self::Entrypoint(_) => "ENTRYPOINT",
        }
    }

    #[must_use]
    pub fn raw_args(&self) -> &str {
        match self {
            Self::From(value)
            | Self::Arg(value)
            | Self::Env(value)
            | Self::Workdir(value)
            | Self::Copy(value)
            | Self::Add(value)
            | Self::Run(value)
            | Self::Cmd(value)
            | Self::Entrypoint(value) => value,
        }
    }
}

pub fn parse_dockerfile(input: &str) -> Result<BuildPlan, DockerfileParseError> {
    let mut instructions = Vec::new();
    let mut continuation = String::new();
    let mut continuation_start = 0usize;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if !continuation.is_empty() {
            continuation.push(' ');
        } else {
            continuation_start = line_number;
        }
        continuation.push_str(line.trim_end_matches('\\').trim_end());
        if line.ends_with('\\') {
            continue;
        }

        instructions.push(parse_instruction(continuation_start, &continuation)?);
        continuation.clear();
    }

    if !continuation.is_empty() {
        instructions.push(parse_instruction(continuation_start, &continuation)?);
    }

    Ok(BuildPlan::new(instructions))
}

fn parse_instruction(
    line_number: usize,
    line: &str,
) -> Result<DockerfileInstruction, DockerfileParseError> {
    let (keyword, args) = split_instruction(line)
        .ok_or_else(|| DockerfileParseError::missing_argument(line_number, line))?;
    if args.is_empty() {
        return Err(DockerfileParseError::missing_argument(line_number, keyword));
    }

    let instruction = match keyword.to_ascii_uppercase().as_str() {
        "FROM" => DockerfileInstruction::From(args.to_owned()),
        "ARG" => DockerfileInstruction::Arg(args.to_owned()),
        "ENV" => DockerfileInstruction::Env(args.to_owned()),
        "WORKDIR" => DockerfileInstruction::Workdir(args.to_owned()),
        "COPY" => DockerfileInstruction::Copy(args.to_owned()),
        "ADD" => DockerfileInstruction::Add(args.to_owned()),
        "RUN" => DockerfileInstruction::Run(args.to_owned()),
        "CMD" => DockerfileInstruction::Cmd(args.to_owned()),
        "ENTRYPOINT" => DockerfileInstruction::Entrypoint(args.to_owned()),
        unsupported => {
            return Err(DockerfileParseError::unsupported_instruction(
                line_number,
                unsupported,
            ));
        }
    };
    Ok(instruction)
}

fn split_instruction(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let split = trimmed.find(char::is_whitespace)?;
    Some((&trimmed[..split], trimmed[split..].trim()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerfileParseError {
    line: usize,
    kind: DockerfileParseErrorKind,
}

impl DockerfileParseError {
    fn unsupported_instruction(line: usize, instruction: impl Into<String>) -> Self {
        Self {
            line,
            kind: DockerfileParseErrorKind::UnsupportedInstruction(instruction.into()),
        }
    }

    fn missing_argument(line: usize, instruction: impl Into<String>) -> Self {
        Self {
            line,
            kind: DockerfileParseErrorKind::MissingArgument(instruction.into()),
        }
    }

    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    #[must_use]
    pub const fn kind(&self) -> &DockerfileParseErrorKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DockerfileParseErrorKind {
    UnsupportedInstruction(String),
    MissingArgument(String),
}

impl fmt::Display for DockerfileParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            DockerfileParseErrorKind::UnsupportedInstruction(instruction) => write!(
                formatter,
                "unsupported Dockerfile instruction `{instruction}` at line {}",
                self.line
            ),
            DockerfileParseErrorKind::MissingArgument(instruction) => write!(
                formatter,
                "Dockerfile instruction `{instruction}` at line {} is missing an argument",
                self.line
            ),
        }
    }
}

impl Error for DockerfileParseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use mcr_snapshot::{SnapshotId, WritableUpperRoot};
    use std::path::{Path, PathBuf};

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-build");
    }

    #[test]
    fn loads_context_with_basic_dockerignore_rules() {
        let context = load_build_context(build_fixture("context-copy")).unwrap();
        let paths = context
            .entries()
            .iter()
            .map(|entry| entry.path().as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec![
                ".dockerignore",
                "Dockerfile",
                "app",
                "app/main.txt",
                "local.txt"
            ]
        );
    }

    #[test]
    fn plans_context_copy_and_local_add_against_snapshot_metadata() {
        let fixture = build_fixture("context-copy");
        let dockerfile = std::fs::read_to_string(fixture.join("Dockerfile")).unwrap();
        let plan = parse_dockerfile(&dockerfile).unwrap();
        let context = load_build_context(fixture).unwrap();

        let application = plan_context_application(&plan, &context).unwrap();

        assert_eq!(
            application.build_args().get("PROFILE"),
            Some(&Some("debug".to_owned()))
        );
        assert_eq!(application.env().get("APP_ENV"), Some(&"test".to_owned()));
        assert_eq!(
            application.env().get("PATH"),
            Some(&"/usr/bin:/bin".to_owned())
        );
        assert_eq!(application.workdir().as_str(), "/workspace");

        let destinations = application
            .operations()
            .iter()
            .map(|operation| operation.destination().as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            destinations,
            vec![
                "/workspace",
                "/opt",
                "/opt/app",
                "/opt/app/main.txt",
                "/workspace/local.txt"
            ]
        );

        let mut snapshot = SnapshotSpec::new(
            SnapshotId::new("copy-step").unwrap(),
            WritableUpperRoot::new("upper").unwrap(),
        );
        application.apply_metadata_to(&mut snapshot);
        let view = snapshot.deterministic_view();
        assert!(
            view.get(&SnapshotPath::new("/opt/app/main.txt").unwrap())
                .is_some()
        );
        assert!(
            view.get(&SnapshotPath::new("/workspace/local.txt").unwrap())
                .is_some()
        );
        assert!(
            view.get(&SnapshotPath::new("/opt/app/cache.tmp").unwrap())
                .is_none()
        );
    }

    #[test]
    fn rejects_copy_sources_that_escape_context() {
        let context = load_build_context(build_fixture("context-copy")).unwrap();
        let plan = parse_dockerfile("FROM scratch\nCOPY ../secret /secret\n").unwrap();

        let error = plan_context_application(&plan, &context).unwrap_err();

        assert_eq!(
            error.kind(),
            &BuildApplicationErrorKind::ContextSourceEscape("../secret".to_owned())
        );
    }

    #[test]
    fn rejects_ignored_copy_sources_as_missing_from_context() {
        let context = load_build_context(build_fixture("context-copy")).unwrap();
        let plan = parse_dockerfile("FROM scratch\nCOPY ignored.txt /ignored.txt\n").unwrap();

        let error = plan_context_application(&plan, &context).unwrap_err();

        assert_eq!(
            error.kind(),
            &BuildApplicationErrorKind::MissingContextSource("ignored.txt".to_owned())
        );
    }

    #[test]
    fn rejects_remote_add_without_fetching() {
        let context = load_build_context(build_fixture("context-copy")).unwrap();
        let plan = parse_dockerfile("FROM scratch\nADD https://example.test/file /file\n").unwrap();

        let error = plan_context_application(&plan, &context).unwrap_err();

        assert_eq!(
            error.kind(),
            &BuildApplicationErrorKind::UnsupportedRemoteAdd(
                "https://example.test/file".to_owned()
            )
        );
    }

    #[test]
    fn parses_supported_dockerfile_subset_into_plan() {
        let plan = parse_dockerfile(
            r#"
            # build fixture
            FROM alpine:3.21
            ARG PROFILE=release
            ENV RUST_LOG=info
            WORKDIR /src
            COPY . .
            ADD local.tar /opt/local
            RUN cargo build --release
            CMD ["/bin/app"]
            ENTRYPOINT ["/bin/sh", "-c"]
            "#,
        )
        .unwrap();

        assert_eq!(
            plan.instructions()
                .iter()
                .map(DockerfileInstruction::keyword)
                .collect::<Vec<_>>(),
            vec![
                "FROM",
                "ARG",
                "ENV",
                "WORKDIR",
                "COPY",
                "ADD",
                "RUN",
                "CMD",
                "ENTRYPOINT"
            ]
        );
        assert_eq!(plan.instructions()[0].raw_args(), "alpine:3.21");
        assert_eq!(plan.instructions()[6].raw_args(), "cargo build --release");
    }

    #[test]
    fn parses_line_continuations_without_executing_shell() {
        let plan = parse_dockerfile("FROM alpine\nRUN echo one \\\n    && echo two\n").unwrap();

        assert_eq!(
            plan.instructions(),
            &[
                DockerfileInstruction::From("alpine".to_owned()),
                DockerfileInstruction::Run("echo one && echo two".to_owned())
            ]
        );
    }

    #[test]
    fn rejects_unsupported_instruction_with_line_number() {
        let error = parse_dockerfile("FROM alpine\nHEALTHCHECK CMD true\n").unwrap_err();

        assert_eq!(error.line(), 2);
        assert_eq!(
            error.kind(),
            &DockerfileParseErrorKind::UnsupportedInstruction("HEALTHCHECK".to_owned())
        );
    }

    #[test]
    fn rejects_missing_arguments() {
        let error = parse_dockerfile("FROM\n").unwrap_err();

        assert_eq!(error.line(), 1);
        assert_eq!(
            error.kind(),
            &DockerfileParseErrorKind::MissingArgument("FROM".to_owned())
        );
    }

    fn build_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/build")
            .join(name)
    }
}
