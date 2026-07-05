use super::*;

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

    pub(crate) fn missing_context_source(source: impl Into<String>) -> Self {
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
pub(crate) enum ContextSource {
    Root,
    Path(ContextPath),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedContextEntry<'a> {
    pub(crate) entry: &'a BuildContextEntry,
    pub(crate) relative_destination: ContextPath,
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
