#![allow(clippy::result_large_err)]

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use mcr_build::parse_dockerfile;
use mcr_runtime::{RunRootfsConfig, run_rootfs};

fn main() {
    match run(std::env::args_os().skip(1)) {
        Ok(status) => process::exit(status),
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}

fn run(args: impl IntoIterator<Item = OsString>) -> Result<i32, CliError> {
    let command = parse_command(args)?;
    match command {
        Command::RunRootfs(config) => {
            let output = run_rootfs(config)?;
            io::stdout().write_all(output.stdout())?;
            io::stderr().write_all(output.stderr())?;
            Ok(output.status())
        }
        Command::Build(config) => {
            let dockerfile = std::fs::read_to_string(config.dockerfile())?;
            let plan = parse_dockerfile(&dockerfile)?;
            writeln!(
                io::stdout(),
                "parsed Dockerfile at {}: {} instruction(s)",
                config.dockerfile().display(),
                plan.instructions().len()
            )?;
            Ok(0)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum Command {
    RunRootfs(RunRootfsConfig),
    Build(BuildCliConfig),
}

fn parse_command(args: impl IntoIterator<Item = OsString>) -> Result<Command, CliError> {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return Err(CliError::Usage);
    };
    if command == "run-rootfs" {
        return parse_run_rootfs(args);
    }
    if command == "build" {
        return parse_build(args);
    }

    Err(CliError::UnknownCommand(
        command.to_string_lossy().into_owned(),
    ))
}

fn parse_run_rootfs(mut args: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let mut mvp_emulator = false;
    let mut guest_step_limit = None;
    let mut rootfs = args.next().ok_or(CliError::Usage)?;
    loop {
        if rootfs == "--mvp-emulator" {
            mvp_emulator = true;
            rootfs = args.next().ok_or(CliError::Usage)?;
        } else if rootfs == "--guest-step-limit" {
            let value = args.next().ok_or(CliError::Usage)?;
            guest_step_limit = Some(parse_guest_step_limit(value)?);
            rootfs = args.next().ok_or(CliError::Usage)?;
        } else {
            break;
        }
    }
    let program = args.next().ok_or(CliError::Usage)?;
    let mut guest_args = vec![os_bytes(&program)];
    guest_args.extend(args.map(|arg| os_bytes(&arg)));

    let mut config = RunRootfsConfig::new(rootfs, os_bytes(&program))
        .with_args(guest_args)
        .with_mvp_emulator(mvp_emulator);
    if let Some(guest_step_limit) = guest_step_limit {
        config = config.with_guest_step_limit(guest_step_limit);
    }

    Ok(Command::RunRootfs(config))
}

fn parse_build(mut args: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let mut dockerfile = None;
    let mut context = None;
    while let Some(arg) = args.next() {
        if arg == "--file" || arg == "-f" {
            dockerfile = Some(PathBuf::from(args.next().ok_or(CliError::Usage)?));
            continue;
        }
        if context.is_some() {
            return Err(CliError::Usage);
        }
        context = Some(PathBuf::from(arg));
    }
    let context = context.ok_or(CliError::Usage)?;
    let dockerfile = dockerfile.unwrap_or_else(|| context.join("Dockerfile"));
    Ok(Command::Build(BuildCliConfig {
        context,
        dockerfile,
    }))
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct BuildCliConfig {
    context: PathBuf,
    dockerfile: PathBuf,
}

impl BuildCliConfig {
    #[cfg(test)]
    fn context(&self) -> &std::path::Path {
        &self.context
    }

    fn dockerfile(&self) -> &std::path::Path {
        &self.dockerfile
    }
}

fn os_bytes(value: &OsString) -> Vec<u8> {
    value.to_string_lossy().into_owned().into_bytes()
}

fn parse_guest_step_limit(value: OsString) -> Result<u64, CliError> {
    value
        .to_string_lossy()
        .parse::<u64>()
        .map_err(|_| CliError::InvalidGuestStepLimit(value.to_string_lossy().into_owned()))
}

#[derive(Debug)]
enum CliError {
    Usage,
    UnknownCommand(String),
    InvalidGuestStepLimit(String),
    Build(mcr_build::DockerfileParseError),
    Runtime(mcr_runtime::RunRootfsError),
    Io(io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => write!(
                formatter,
                "usage: mcr run-rootfs [--mvp-emulator] [--guest-step-limit <steps>] <rootfs> <program> [args...]\n       mcr build [--file <Dockerfile>] <context>"
            ),
            Self::UnknownCommand(command) => write!(formatter, "unknown command `{command}`"),
            Self::InvalidGuestStepLimit(value) => {
                write!(formatter, "invalid guest step limit `{value}`")
            }
            Self::Build(error) => write!(formatter, "{error}"),
            Self::Runtime(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Usage | Self::UnknownCommand(_) | Self::InvalidGuestStepLimit(_) => None,
        }
    }
}

impl From<mcr_build::DockerfileParseError> for CliError {
    fn from(value: mcr_build::DockerfileParseError) -> Self {
        Self::Build(value)
    }
}

impl From<mcr_runtime::RunRootfsError> for CliError {
    fn from(value: mcr_runtime::RunRootfsError) -> Self {
        Self::Runtime(value)
    }
}

impl From<io::Error> for CliError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{Command, parse_command};

    #[test]
    fn package_name_is_stable() {
        assert_eq!(env!("CARGO_PKG_NAME"), "mcr-cli");
    }

    #[test]
    fn parses_run_rootfs_command() {
        let command = parse_command([
            OsString::from("run-rootfs"),
            OsString::from("rootfs"),
            OsString::from("/bin/busybox"),
            OsString::from("echo"),
            OsString::from("hello"),
        ])
        .unwrap();

        let Command::RunRootfs(config) = command else {
            panic!("expected run-rootfs command");
        };
        assert_eq!(config.rootfs(), std::path::Path::new("rootfs"));
        assert_eq!(config.program(), b"/bin/busybox");
        assert!(!config.mvp_emulator());
        assert_eq!(
            config.args(),
            &[
                b"/bin/busybox".to_vec(),
                b"echo".to_vec(),
                b"hello".to_vec()
            ]
        );
    }

    #[test]
    fn parses_run_rootfs_mvp_emulator_flag() {
        let command = parse_command([
            OsString::from("run-rootfs"),
            OsString::from("--mvp-emulator"),
            OsString::from("rootfs"),
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("echo hi"),
        ])
        .unwrap();

        let Command::RunRootfs(config) = command else {
            panic!("expected run-rootfs command");
        };
        assert!(config.mvp_emulator());
        assert_eq!(config.rootfs(), std::path::Path::new("rootfs"));
        assert_eq!(config.program(), b"/bin/sh");
    }

    #[test]
    fn parses_run_rootfs_guest_step_limit_flag() {
        let command = parse_command([
            OsString::from("run-rootfs"),
            OsString::from("--guest-step-limit"),
            OsString::from("1234"),
            OsString::from("rootfs"),
            OsString::from("/bin/sh"),
        ])
        .unwrap();

        let Command::RunRootfs(config) = command else {
            panic!("expected run-rootfs command");
        };
        assert_eq!(config.guest_step_limit(), Some(1234));
        assert_eq!(config.rootfs(), std::path::Path::new("rootfs"));
        assert_eq!(config.program(), b"/bin/sh");
    }

    #[test]
    fn parses_build_command_with_default_dockerfile() {
        let command = parse_command([OsString::from("build"), OsString::from("context")]).unwrap();

        let Command::Build(config) = command else {
            panic!("expected build command");
        };
        assert_eq!(config.context(), std::path::Path::new("context"));
        assert_eq!(
            config.dockerfile(),
            std::path::Path::new("context/Dockerfile")
        );
    }

    #[test]
    fn parses_build_command_with_file_flag() {
        let command = parse_command([
            OsString::from("build"),
            OsString::from("--file"),
            OsString::from("Dockerfile.dev"),
            OsString::from("."),
        ])
        .unwrap();

        let Command::Build(config) = command else {
            panic!("expected build command");
        };
        assert_eq!(config.context(), std::path::Path::new("."));
        assert_eq!(config.dockerfile(), std::path::Path::new("Dockerfile.dev"));
    }
}
