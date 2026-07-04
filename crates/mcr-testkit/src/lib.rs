use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub mod perf;

const DEFAULT_FIXTURE_DIR: &str = "tests/fixtures";
const FIXTURE_ENV_VAR: &str = "MCR_FIXTURES_DIR";
const GUEST_BINARY_MANIFEST: &str = "guest-binaries/manifest.mcr";
const ROOTFS_MANIFEST: &str = "rootfs/manifest.mcr";

pub type Result<T> = std::result::Result<T, TestkitError>;

#[derive(Debug)]
pub enum TestkitError {
    Io {
        context: String,
        source: io::Error,
    },
    Manifest {
        path: PathBuf,
        line: usize,
        message: String,
    },
    FixtureRootNotFound {
        searched_from: PathBuf,
    },
    UnknownFixture {
        kind: &'static str,
        name: String,
    },
    MissingFixturePayload {
        kind: &'static str,
        name: String,
        path: PathBuf,
    },
    GoldenMismatch(GoldenMismatch),
    MissingExpectedGolden,
}

impl fmt::Display for TestkitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Manifest {
                path,
                line,
                message,
            } => write!(f, "{}:{line}: {message}", path.display()),
            Self::FixtureRootNotFound { searched_from } => write!(
                f,
                "could not find {DEFAULT_FIXTURE_DIR} while searching from {}",
                searched_from.display()
            ),
            Self::UnknownFixture { kind, name } => {
                write!(f, "unknown {kind} fixture `{name}`")
            }
            Self::MissingFixturePayload { kind, name, path } => write!(
                f,
                "{kind} fixture `{name}` is marked required but {} does not exist",
                path.display()
            ),
            Self::GoldenMismatch(mismatch) => mismatch.fmt(f),
            Self::MissingExpectedGolden => {
                write!(f, "smoke command has no expected golden output")
            }
        }
    }
}

impl Error for TestkitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoldenMismatch {
    Status { expected: i32, actual: Option<i32> },
    Stdout { expected: Vec<u8>, actual: Vec<u8> },
    Stderr { expected: Vec<u8>, actual: Vec<u8> },
}

impl fmt::Display for GoldenMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status { expected, actual } => {
                write!(f, "expected exit status {expected}, got {actual:?}")
            }
            Self::Stdout { expected, actual } => write!(
                f,
                "stdout mismatch\nexpected:\n{}\nactual:\n{}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(actual)
            ),
            Self::Stderr { expected, actual } => write!(
                f,
                "stderr mismatch\nexpected:\n{}\nactual:\n{}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(actual)
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureRoot {
    root: PathBuf,
}

impl FixtureRoot {
    pub fn discover() -> Result<Self> {
        if let Some(root) = env::var_os(FIXTURE_ENV_VAR) {
            return Ok(Self {
                root: PathBuf::from(root),
            });
        }

        let searched_from = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for ancestor in searched_from.ancestors() {
            let candidate = ancestor.join(DEFAULT_FIXTURE_DIR);
            if candidate.is_dir() {
                return Ok(Self { root: candidate });
            }
        }

        Err(TestkitError::FixtureRootNotFound { searched_from })
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self { root: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn resolve(&self, relative_path: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative_path)
    }

    pub fn read_bytes(&self, relative_path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let path = self.resolve(relative_path);
        fs::read(&path).map_err(|source| TestkitError::Io {
            context: format!("read fixture {}", path.display()),
            source,
        })
    }

    pub fn read_text(&self, relative_path: impl AsRef<Path>) -> Result<String> {
        let path = self.resolve(relative_path);
        fs::read_to_string(&path).map_err(|source| TestkitError::Io {
            context: format!("read fixture {}", path.display()),
            source,
        })
    }

    pub fn guest_binaries(&self) -> Result<Vec<GuestBinaryFixture>> {
        let manifest = self.resolve(GUEST_BINARY_MANIFEST);
        let contents = self.read_text(GUEST_BINARY_MANIFEST)?;
        parse_manifest(&manifest, &contents, "guest_binary")?
            .into_iter()
            .map(GuestBinaryFixture::from_record)
            .collect()
    }

    pub fn guest_binary(&self, name: &str) -> Result<GuestBinaryFixture> {
        self.guest_binaries()?
            .into_iter()
            .find(|fixture| fixture.name == name)
            .ok_or_else(|| TestkitError::UnknownFixture {
                kind: "guest binary",
                name: name.to_owned(),
            })
    }

    pub fn rootfs_fixtures(&self) -> Result<Vec<RootfsFixture>> {
        let manifest = self.resolve(ROOTFS_MANIFEST);
        let contents = self.read_text(ROOTFS_MANIFEST)?;
        parse_manifest(&manifest, &contents, "rootfs")?
            .into_iter()
            .map(RootfsFixture::from_record)
            .collect()
    }

    pub fn rootfs_fixture(&self, name: &str) -> Result<RootfsFixture> {
        self.rootfs_fixtures()?
            .into_iter()
            .find(|fixture| fixture.name == name)
            .ok_or_else(|| TestkitError::UnknownFixture {
                kind: "rootfs",
                name: name.to_owned(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBinaryFixture {
    name: String,
    relative_path: PathBuf,
    architecture: String,
    abi: String,
    format: String,
    linkage: String,
    stage: String,
    source: Option<String>,
    sha256: Option<String>,
    required: bool,
}

impl GuestBinaryFixture {
    fn from_record(record: ManifestRecord) -> Result<Self> {
        Ok(Self {
            name: record.required("name")?,
            relative_path: record.required_relative_path("path")?,
            architecture: record.required("architecture")?,
            abi: record.required("abi")?,
            format: record.required("format")?,
            linkage: record.required("linkage")?,
            stage: record.required("stage")?,
            source: record.optional("source"),
            sha256: record.optional("sha256"),
            required: record.optional_bool("required")?.unwrap_or(false),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    pub fn abi(&self) -> &str {
        &self.abi
    }

    pub fn format(&self) -> &str {
        &self.format
    }

    pub fn linkage(&self) -> &str {
        &self.linkage
    }

    pub fn stage(&self) -> &str {
        &self.stage
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }

    pub fn required(&self) -> bool {
        self.required
    }

    pub fn absolute_path(&self, fixtures: &FixtureRoot) -> PathBuf {
        fixtures.resolve(&self.relative_path)
    }

    pub fn available(&self, fixtures: &FixtureRoot) -> bool {
        self.absolute_path(fixtures).is_file()
    }

    pub fn assert_available(&self, fixtures: &FixtureRoot) -> Result<()> {
        if !self.required || self.available(fixtures) {
            return Ok(());
        }

        Err(TestkitError::MissingFixturePayload {
            kind: "guest binary",
            name: self.name.clone(),
            path: self.absolute_path(fixtures),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsFixture {
    name: String,
    relative_path: PathBuf,
    archive_path: Option<PathBuf>,
    architecture: String,
    distro: String,
    version: String,
    stage: String,
    source_url: Option<String>,
    sha256: Option<String>,
    required: bool,
}

impl RootfsFixture {
    fn from_record(record: ManifestRecord) -> Result<Self> {
        Ok(Self {
            name: record.required("name")?,
            relative_path: record.required_relative_path("path")?,
            archive_path: record.optional_relative_path("archive_path")?,
            architecture: record.required("architecture")?,
            distro: record.required("distro")?,
            version: record.required("version")?,
            stage: record.required("stage")?,
            source_url: record.optional("source_url"),
            sha256: record.optional("sha256"),
            required: record.optional_bool("required")?.unwrap_or(false),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn archive_relative_path(&self) -> Option<&Path> {
        self.archive_path.as_deref()
    }

    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    pub fn distro(&self) -> &str {
        &self.distro
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn stage(&self) -> &str {
        &self.stage
    }

    pub fn source_url(&self) -> Option<&str> {
        self.source_url.as_deref()
    }

    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }

    pub fn required(&self) -> bool {
        self.required
    }

    pub fn absolute_path(&self, fixtures: &FixtureRoot) -> PathBuf {
        fixtures.resolve(&self.relative_path)
    }

    pub fn archive_path(&self, fixtures: &FixtureRoot) -> Option<PathBuf> {
        self.archive_path
            .as_ref()
            .map(|archive_path| fixtures.resolve(archive_path))
    }

    pub fn materialized(&self, fixtures: &FixtureRoot) -> bool {
        self.absolute_path(fixtures).is_dir()
    }

    pub fn archive_available(&self, fixtures: &FixtureRoot) -> bool {
        self.archive_path(fixtures)
            .is_some_and(|path| path.is_file())
    }

    pub fn assert_available(&self, fixtures: &FixtureRoot) -> Result<()> {
        if !self.required || self.materialized(fixtures) || self.archive_available(fixtures) {
            return Ok(());
        }

        Err(TestkitError::MissingFixturePayload {
            kind: "rootfs",
            name: self.name.clone(),
            path: self.absolute_path(fixtures),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenOutput {
    expected_status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl GoldenOutput {
    pub fn new(
        expected_status: i32,
        stdout: impl Into<Vec<u8>>,
        stderr: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            expected_status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    pub fn from_fixture_files(
        fixtures: &FixtureRoot,
        stdout_path: impl AsRef<Path>,
        stderr_path: impl AsRef<Path>,
        expected_status: i32,
    ) -> Result<Self> {
        Ok(Self {
            expected_status,
            stdout: fixtures.read_bytes(stdout_path)?,
            stderr: fixtures.read_bytes(stderr_path)?,
        })
    }

    pub fn expected_status(&self) -> i32 {
        self.expected_status
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn assert_streams(
        &self,
        actual_status: Option<i32>,
        actual_stdout: &[u8],
        actual_stderr: &[u8],
    ) -> Result<()> {
        if actual_status != Some(self.expected_status) {
            return Err(TestkitError::GoldenMismatch(GoldenMismatch::Status {
                expected: self.expected_status,
                actual: actual_status,
            }));
        }

        if actual_stdout != self.stdout {
            return Err(TestkitError::GoldenMismatch(GoldenMismatch::Stdout {
                expected: self.stdout.clone(),
                actual: actual_stdout.to_vec(),
            }));
        }

        if actual_stderr != self.stderr {
            return Err(TestkitError::GoldenMismatch(GoldenMismatch::Stderr {
                expected: self.stderr.clone(),
                actual: actual_stderr.to_vec(),
            }));
        }

        Ok(())
    }

    pub fn assert_matches(&self, output: &CapturedOutput) -> Result<()> {
        self.assert_streams(output.status_code(), output.stdout(), output.stderr())
    }
}

#[derive(Debug)]
pub struct CapturedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CapturedOutput {
    pub fn status(&self) -> ExitStatus {
        self.status
    }

    pub fn status_code(&self) -> Option<i32> {
        self.status.code()
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

impl From<std::process::Output> for CapturedOutput {
    fn from(output: std::process::Output) -> Self {
        Self {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmokeCommand {
    program: OsString,
    args: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
    current_dir: Option<PathBuf>,
    stdin: Option<Vec<u8>>,
    expected: Option<GoldenOutput>,
}

impl SmokeCommand {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
            current_dir: None,
            stdin: None,
            expected: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, A>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    pub fn current_dir(mut self, current_dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(current_dir.into());
        self
    }

    pub fn stdin(mut self, stdin: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(stdin.into());
        self
    }

    pub fn expected(mut self, expected: GoldenOutput) -> Self {
        self.expected = Some(expected);
        self
    }

    pub fn program(&self) -> &OsStr {
        &self.program
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        command.envs(self.envs.iter().map(|(key, value)| (key, value)));
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdin(if self.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });

        if let Some(current_dir) = &self.current_dir {
            command.current_dir(current_dir);
        }

        command
    }

    pub fn run(&self) -> Result<CapturedOutput> {
        let mut command = self.command();
        let mut child = command.spawn().map_err(|source| TestkitError::Io {
            context: format!("spawn smoke command {}", Path::new(&self.program).display()),
            source,
        })?;

        if let Some(stdin) = &self.stdin {
            let mut child_stdin = child.stdin.take().ok_or_else(|| TestkitError::Io {
                context: "open smoke command stdin".to_owned(),
                source: io::Error::new(io::ErrorKind::BrokenPipe, "stdin pipe was not available"),
            })?;
            child_stdin
                .write_all(stdin)
                .map_err(|source| TestkitError::Io {
                    context: "write smoke command stdin".to_owned(),
                    source,
                })?;
        }

        child
            .wait_with_output()
            .map(CapturedOutput::from)
            .map_err(|source| TestkitError::Io {
                context: format!(
                    "wait for smoke command {}",
                    Path::new(&self.program).display()
                ),
                source,
            })
    }

    pub fn run_and_assert(&self) -> Result<CapturedOutput> {
        let expected = self
            .expected
            .as_ref()
            .ok_or(TestkitError::MissingExpectedGolden)?;
        let output = self.run()?;
        expected.assert_matches(&output)?;
        Ok(output)
    }
}

#[derive(Debug)]
struct ManifestRecord {
    path: PathBuf,
    start_line: usize,
    fields: BTreeMap<String, String>,
}

impl ManifestRecord {
    fn required(&self, key: &str) -> Result<String> {
        self.fields
            .get(key)
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| TestkitError::Manifest {
                path: self.path.clone(),
                line: self.start_line,
                message: format!("missing required field `{key}`"),
            })
    }

    fn optional(&self, key: &str) -> Option<String> {
        self.fields
            .get(key)
            .filter(|value| !value.is_empty())
            .cloned()
    }

    fn required_relative_path(&self, key: &str) -> Result<PathBuf> {
        let value = self.required(key)?;
        self.validate_relative_path(key, value)
    }

    fn optional_relative_path(&self, key: &str) -> Result<Option<PathBuf>> {
        self.optional(key)
            .map(|value| self.validate_relative_path(key, value))
            .transpose()
    }

    fn optional_bool(&self, key: &str) -> Result<Option<bool>> {
        let Some(value) = self.optional(key) else {
            return Ok(None);
        };

        match value.as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(TestkitError::Manifest {
                path: self.path.clone(),
                line: self.start_line,
                message: format!("field `{key}` must be true or false"),
            }),
        }
    }

    fn validate_relative_path(&self, key: &str, value: String) -> Result<PathBuf> {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            return Err(TestkitError::Manifest {
                path: self.path.clone(),
                line: self.start_line,
                message: format!("field `{key}` must be relative to {DEFAULT_FIXTURE_DIR}"),
            });
        }

        Ok(path)
    }
}

fn parse_manifest(
    path: &Path,
    contents: &str,
    section: &'static str,
) -> Result<Vec<ManifestRecord>> {
    let mut records = Vec::new();
    let mut current: Option<ManifestRecord> = None;
    let expected_header = format!("[[{section}]]");

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed == expected_header {
            if let Some(record) = current.replace(ManifestRecord {
                path: path.to_path_buf(),
                start_line: line_number,
                fields: BTreeMap::new(),
            }) {
                records.push(record);
            }
            continue;
        }

        if trimmed.starts_with("[[") {
            return Err(TestkitError::Manifest {
                path: path.to_path_buf(),
                line: line_number,
                message: format!("expected section header {expected_header}"),
            });
        }

        let Some(record) = current.as_mut() else {
            return Err(TestkitError::Manifest {
                path: path.to_path_buf(),
                line: line_number,
                message: format!("field appears before {expected_header}"),
            });
        };

        let (key, value) = trimmed
            .split_once('=')
            .ok_or_else(|| TestkitError::Manifest {
                path: path.to_path_buf(),
                line: line_number,
                message: "expected key=value field".to_owned(),
            })?;
        let key = key.trim();
        if key.is_empty() {
            return Err(TestkitError::Manifest {
                path: path.to_path_buf(),
                line: line_number,
                message: "field key cannot be empty".to_owned(),
            });
        }

        let value = unquote(value.trim());
        if record.fields.insert(key.to_owned(), value).is_some() {
            return Err(TestkitError::Manifest {
                path: path.to_path_buf(),
                line: line_number,
                message: format!("duplicate field `{key}`"),
            });
        }
    }

    if let Some(record) = current {
        records.push(record);
    }

    if records.is_empty() {
        return Err(TestkitError::Manifest {
            path: path.to_path_buf(),
            line: 1,
            message: format!("manifest must contain at least one {expected_header} record"),
        });
    }

    Ok(records)
}

fn unquote(value: &str) -> String {
    if let Some(unquoted) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        unquoted.to_owned()
    } else {
        value.to_owned()
    }
}

pub mod elf {
    pub const ELF64_HEADER_SIZE: u16 = 64;
    pub const ELF64_PROGRAM_HEADER_SIZE: u16 = 56;

    pub const ET_EXEC: u16 = 2;
    pub const ET_DYN: u16 = 3;
    pub const EM_X86_64: u16 = 62;

    pub const PT_LOAD: u32 = 1;
    pub const PT_INTERP: u32 = 3;

    pub const PF_X: u32 = 1;
    pub const PF_W: u32 = 2;
    pub const PF_R: u32 = 4;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Elf64Builder {
        object_type: u16,
        machine: u16,
        entrypoint: u64,
        program_headers: Vec<Elf64ProgramHeader>,
        data: Vec<(u64, Vec<u8>)>,
    }

    impl Default for Elf64Builder {
        fn default() -> Self {
            Self {
                object_type: ET_EXEC,
                machine: EM_X86_64,
                entrypoint: 0,
                program_headers: Vec::new(),
                data: Vec::new(),
            }
        }
    }

    impl Elf64Builder {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        #[must_use]
        pub fn object_type(mut self, object_type: u16) -> Self {
            self.object_type = object_type;
            self
        }

        #[must_use]
        pub fn machine(mut self, machine: u16) -> Self {
            self.machine = machine;
            self
        }

        #[must_use]
        pub fn entrypoint(mut self, entrypoint: u64) -> Self {
            self.entrypoint = entrypoint;
            self
        }

        #[must_use]
        pub fn program_header(mut self, header: Elf64ProgramHeader) -> Self {
            self.program_headers.push(header);
            self
        }

        #[must_use]
        pub fn data_at(mut self, file_offset: u64, data: Vec<u8>) -> Self {
            self.data.push((file_offset, data));
            self
        }

        #[must_use]
        pub fn build(self) -> Vec<u8> {
            let phoff = u64::from(ELF64_HEADER_SIZE);
            let ph_table_len = usize::from(ELF64_PROGRAM_HEADER_SIZE) * self.program_headers.len();
            let mut len = usize::from(ELF64_HEADER_SIZE) + ph_table_len;

            for header in &self.program_headers {
                len = len.max(
                    header
                        .file_offset
                        .checked_add(header.file_size)
                        .expect("test ELF segment range should not overflow")
                        as usize,
                );
            }

            for (offset, data) in &self.data {
                len = len.max(
                    offset
                        .checked_add(data.len() as u64)
                        .expect("test ELF data range should not overflow")
                        as usize,
                );
            }

            let mut bytes = vec![0; len];
            bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
            bytes[4] = 2;
            bytes[5] = 1;
            bytes[6] = 1;
            write_u16(&mut bytes, 16, self.object_type);
            write_u16(&mut bytes, 18, self.machine);
            write_u32(&mut bytes, 20, 1);
            write_u64(&mut bytes, 24, self.entrypoint);
            write_u64(&mut bytes, 32, phoff);
            write_u16(&mut bytes, 52, ELF64_HEADER_SIZE);
            write_u16(&mut bytes, 54, ELF64_PROGRAM_HEADER_SIZE);
            write_u16(
                &mut bytes,
                56,
                self.program_headers
                    .len()
                    .try_into()
                    .expect("test ELF should fit u16 phnum"),
            );

            for (index, header) in self.program_headers.iter().enumerate() {
                let offset =
                    usize::from(ELF64_HEADER_SIZE) + index * usize::from(ELF64_PROGRAM_HEADER_SIZE);
                header
                    .write_to(&mut bytes[offset..offset + usize::from(ELF64_PROGRAM_HEADER_SIZE)]);
            }

            for (offset, data) in self.data {
                let offset = offset as usize;
                bytes[offset..offset + data.len()].copy_from_slice(&data);
            }

            bytes
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Elf64ProgramHeader {
        header_type: u32,
        flags: u32,
        file_offset: u64,
        virtual_address: u64,
        physical_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    }

    impl Elf64ProgramHeader {
        #[must_use]
        pub fn new(
            header_type: u32,
            flags: u32,
            file_offset: u64,
            virtual_address: u64,
            file_size: u64,
            memory_size: u64,
            alignment: u64,
        ) -> Self {
            Self {
                header_type,
                flags,
                file_offset,
                virtual_address,
                physical_address: virtual_address,
                file_size,
                memory_size,
                alignment,
            }
        }

        #[must_use]
        pub fn load(
            flags: u32,
            file_offset: u64,
            virtual_address: u64,
            file_size: u64,
            memory_size: u64,
        ) -> Self {
            Self::new(
                PT_LOAD,
                flags,
                file_offset,
                virtual_address,
                file_size,
                memory_size,
                0x1000,
            )
        }

        fn write_to(&self, bytes: &mut [u8]) {
            write_u32(bytes, 0, self.header_type);
            write_u32(bytes, 4, self.flags);
            write_u64(bytes, 8, self.file_offset);
            write_u64(bytes, 16, self.virtual_address);
            write_u64(bytes, 24, self.physical_address);
            write_u64(bytes, 32, self.file_size);
            write_u64(bytes, 40, self.memory_size);
            write_u64(bytes, 48, self.alignment);
        }
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CRATE_NAME, FixtureRoot, GoldenMismatch, GoldenOutput, Result, SmokeCommand, TestkitError,
    };
    use std::env;
    use std::ffi::OsString;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-testkit");
    }

    #[test]
    fn discovers_workspace_fixture_root() -> Result<()> {
        let fixtures = FixtureRoot::discover()?;

        assert!(fixtures.path().ends_with("tests/fixtures"));
        assert!(
            fixtures
                .path()
                .join("guest-binaries/manifest.mcr")
                .is_file()
        );

        Ok(())
    }

    #[test]
    fn loads_guest_binary_fixture_contracts() -> Result<()> {
        let fixtures = FixtureRoot::discover()?;
        let busybox = fixtures.guest_binary("busybox-static")?;

        assert_eq!(busybox.architecture(), "x86_64");
        assert_eq!(busybox.abi(), "linux");
        assert_eq!(busybox.format(), "elf");
        assert_eq!(busybox.linkage(), "static");
        assert_eq!(busybox.stage(), "mvp");
        assert!(!busybox.required());
        assert!(!busybox.available(&fixtures));

        Ok(())
    }

    #[test]
    fn loads_rootfs_fixture_contracts() -> Result<()> {
        let fixtures = FixtureRoot::discover()?;
        let alpine = fixtures.rootfs_fixture("alpine-rootfs")?;

        assert_eq!(alpine.architecture(), "x86_64");
        assert_eq!(alpine.distro(), "alpine");
        assert_eq!(alpine.stage(), "mvp");
        assert!(alpine.archive_relative_path().is_some());
        assert!(!alpine.required());
        assert_eq!(
            alpine.materialized(&fixtures),
            alpine.absolute_path(&fixtures).is_dir()
        );

        Ok(())
    }

    #[test]
    fn golden_output_reports_stdout_mismatch() {
        let golden = GoldenOutput::new(0, b"expected".to_vec(), Vec::new());
        let error = golden
            .assert_streams(Some(0), b"actual", &[])
            .expect_err("stdout should not match");

        assert!(matches!(
            error,
            TestkitError::GoldenMismatch(GoldenMismatch::Stdout { .. })
        ));
    }

    #[test]
    #[ignore = "enabled by the MVP runtime integration task when mcr run-rootfs works"]
    fn ignored_mvp_busybox_echo_smoke_contract() -> Result<()> {
        let fixtures = FixtureRoot::discover()?;
        let rootfs = fixtures.rootfs_fixture("alpine-rootfs")?;
        let golden = GoldenOutput::from_fixture_files(
            &fixtures,
            "golden/busybox-echo.stdout",
            "golden/empty.stderr",
            0,
        )?;
        let mcr = env::var_os("MCR_BIN").unwrap_or_else(|| OsString::from("mcr"));

        SmokeCommand::new(mcr)
            .arg("run-rootfs")
            .arg(rootfs.absolute_path(&fixtures))
            .arg("/bin/busybox")
            .arg("echo")
            .arg("hello")
            .expected(golden)
            .run_and_assert()?;

        Ok(())
    }
}
