use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::process;

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
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum Command {
    RunRootfs(RunRootfsConfig),
}

fn parse_command(args: impl IntoIterator<Item = OsString>) -> Result<Command, CliError> {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return Err(CliError::Usage);
    };
    if command != "run-rootfs" {
        return Err(CliError::UnknownCommand(
            command.to_string_lossy().into_owned(),
        ));
    }

    let mut mvp_emulator = false;
    let mut rootfs = args.next().ok_or(CliError::Usage)?;
    if rootfs == "--mvp-emulator" {
        mvp_emulator = true;
        rootfs = args.next().ok_or(CliError::Usage)?;
    }
    let program = args.next().ok_or(CliError::Usage)?;
    let mut guest_args = vec![os_bytes(&program)];
    guest_args.extend(args.map(|arg| os_bytes(&arg)));

    Ok(Command::RunRootfs(
        RunRootfsConfig::new(rootfs, os_bytes(&program))
            .with_args(guest_args)
            .with_mvp_emulator(mvp_emulator),
    ))
}

fn os_bytes(value: &OsString) -> Vec<u8> {
    value.to_string_lossy().into_owned().into_bytes()
}

#[derive(Debug)]
enum CliError {
    Usage,
    UnknownCommand(String),
    Runtime(mcr_runtime::RunRootfsError),
    Io(io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => write!(
                formatter,
                "usage: mcr run-rootfs [--mvp-emulator] <rootfs> <program> [args...]"
            ),
            Self::UnknownCommand(command) => write!(formatter, "unknown command `{command}`"),
            Self::Runtime(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Usage | Self::UnknownCommand(_) => None,
        }
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

        let Command::RunRootfs(config) = command;
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

        let Command::RunRootfs(config) = command;
        assert!(config.mvp_emulator());
        assert_eq!(config.rootfs(), std::path::Path::new("rootfs"));
        assert_eq!(config.program(), b"/bin/sh");
    }
}
