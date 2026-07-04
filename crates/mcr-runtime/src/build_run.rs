use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use mcr_snapshot::{SnapshotId, SnapshotPath};

use crate::{RunRootfsConfig, RunRootfsError, run_rootfs};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildRunSpec {
    snapshot_id: SnapshotId,
    rootfs: PathBuf,
    working_dir: SnapshotPath,
    command: BuildRunCommand,
    env: BTreeMap<String, String>,
    trace_id: Option<String>,
    guest_step_limit: Option<u64>,
}

impl BuildRunSpec {
    #[must_use]
    pub fn new(
        snapshot_id: SnapshotId,
        rootfs: impl Into<PathBuf>,
        command: BuildRunCommand,
    ) -> Self {
        Self {
            snapshot_id,
            rootfs: rootfs.into(),
            working_dir: SnapshotPath::new("/").expect("root snapshot path is valid"),
            command,
            env: BTreeMap::new(),
            trace_id: None,
            guest_step_limit: None,
        }
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> &SnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    #[must_use]
    pub const fn working_dir(&self) -> &SnapshotPath {
        &self.working_dir
    }

    #[must_use]
    pub const fn command(&self) -> &BuildRunCommand {
        &self.command
    }

    #[must_use]
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }

    #[must_use]
    pub const fn guest_step_limit(&self) -> Option<u64> {
        self.guest_step_limit
    }

    #[must_use]
    pub fn with_working_dir(mut self, working_dir: SnapshotPath) -> Self {
        self.working_dir = working_dir;
        self
    }

    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    #[must_use]
    pub const fn with_guest_step_limit(mut self, max_guest_steps: u64) -> Self {
        self.guest_step_limit = Some(max_guest_steps);
        self
    }

    pub fn to_run_rootfs_config(&self) -> Result<RunRootfsConfig, BuildRunError> {
        let argv = self.command.argv()?;
        let mut config = RunRootfsConfig::new(&self.rootfs, argv[0].clone())
            .with_args(argv)
            .with_env(
                self.env
                    .iter()
                    .map(|(key, value)| format!("{key}={value}").into_bytes()),
            );
        if let Some(max_guest_steps) = self.guest_step_limit {
            config = config.with_guest_step_limit(max_guest_steps);
        }
        Ok(config)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildRunCommand {
    Shell(String),
    Exec {
        program: Vec<u8>,
        args: Vec<Vec<u8>>,
    },
}

impl BuildRunCommand {
    #[must_use]
    pub fn shell(script: impl Into<String>) -> Self {
        Self::Shell(script.into())
    }

    #[must_use]
    pub fn exec<P, I, A>(program: P, args: I) -> Self
    where
        P: Into<Vec<u8>>,
        I: IntoIterator<Item = A>,
        A: Into<Vec<u8>>,
    {
        Self::Exec {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    fn argv(&self) -> Result<Vec<Vec<u8>>, BuildRunError> {
        match self {
            Self::Shell(script) => Ok(vec![
                b"/bin/sh".to_vec(),
                b"-c".to_vec(),
                script.as_bytes().to_vec(),
            ]),
            Self::Exec { program, args } => {
                if program.is_empty() {
                    return Err(BuildRunError::EmptyExecProgram);
                }
                let mut argv = Vec::with_capacity(args.len() + 1);
                argv.push(program.clone());
                argv.extend(args.iter().cloned());
                Ok(argv)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildRunResult {
    snapshot_id: SnapshotId,
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    trace_id: Option<String>,
}

impl BuildRunResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &SnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn status(&self) -> i32 {
        self.status
    }

    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }
}

#[derive(Debug)]
pub enum BuildRunError {
    EmptyExecProgram,
    RunRootfs(RunRootfsError),
}

impl fmt::Display for BuildRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExecProgram => {
                formatter.write_str("build RUN exec form has an empty program")
            }
            Self::RunRootfs(error) => error.fmt(formatter),
        }
    }
}

impl Error for BuildRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RunRootfs(error) => Some(error),
            Self::EmptyExecProgram => None,
        }
    }
}

impl From<RunRootfsError> for BuildRunError {
    fn from(error: RunRootfsError) -> Self {
        Self::RunRootfs(error)
    }
}

pub fn execute_build_run(spec: BuildRunSpec) -> Result<BuildRunResult, BuildRunError> {
    let config = spec.to_run_rootfs_config()?;
    let output = run_rootfs(config)?;
    let (status, stdout, stderr) = output.into_parts();
    Ok(BuildRunResult {
        snapshot_id: spec.snapshot_id,
        status,
        stdout,
        stderr,
        trace_id: spec.trace_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_form_maps_to_guest_shell_without_host_execution() {
        let spec = BuildRunSpec::new(
            SnapshotId::new("step-1").unwrap(),
            "rootfs",
            BuildRunCommand::shell("echo hello"),
        )
        .with_env("PATH", "/usr/bin:/bin")
        .with_env("APP_ENV", "test")
        .with_guest_step_limit(32)
        .with_trace_id("trace-build-1");

        let config = spec.to_run_rootfs_config().unwrap();

        assert_eq!(config.rootfs(), Path::new("rootfs"));
        assert_eq!(config.program(), b"/bin/sh");
        assert_eq!(
            config.args(),
            &[b"/bin/sh".to_vec(), b"-c".to_vec(), b"echo hello".to_vec()]
        );
        assert_eq!(
            config.env(),
            &[b"APP_ENV=test".to_vec(), b"PATH=/usr/bin:/bin".to_vec()]
        );
        assert_eq!(config.guest_step_limit(), Some(32));
    }

    #[test]
    fn exec_form_rejects_empty_program() {
        let spec = BuildRunSpec::new(
            SnapshotId::new("step-2").unwrap(),
            "rootfs",
            BuildRunCommand::exec(Vec::<u8>::new(), [b"--version".to_vec()]),
        );

        assert!(matches!(
            spec.to_run_rootfs_config(),
            Err(BuildRunError::EmptyExecProgram)
        ));
    }
}
