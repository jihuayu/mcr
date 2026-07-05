use super::*;

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

    pub(crate) fn source_entries(
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
pub struct ContextPath(pub(crate) String);

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
