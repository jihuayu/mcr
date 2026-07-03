use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use mcr_testkit::{FixtureRoot, GoldenOutput, Result, SmokeCommand};

const ALPINE_ROOTFS: &str = "alpine-rootfs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShellSmokeContract {
    name: &'static str,
    script: &'static str,
    stdout: &'static [u8],
}

const SHELL_ECHO: ShellSmokeContract = ShellSmokeContract {
    name: "shell echo",
    script: "echo hi",
    stdout: b"hi\n",
};
const SHELL_PIPE: ShellSmokeContract = ShellSmokeContract {
    name: "shell pipe",
    script: "echo hi | cat",
    stdout: b"hi\n",
};
const SHELL_PROCFS_DEVFS: ShellSmokeContract = ShellSmokeContract {
    name: "shell procfs/devfs",
    script: "cat /proc/self/cmdline >/dev/null && head -c 4 /dev/zero >/dev/null",
    stdout: b"",
};

const SHELL_SMOKE_CONTRACTS: &[ShellSmokeContract] = &[SHELL_ECHO, SHELL_PIPE, SHELL_PROCFS_DEVFS];

#[derive(Debug)]
struct ShellSmokeContext {
    mcr: OsString,
    rootfs: PathBuf,
}

impl ShellSmokeContext {
    fn discover() -> Result<Option<Self>> {
        let Some(mcr) = env::var_os("MCR_BIN") else {
            eprintln!("skipping shell smoke contract: set MCR_BIN to the mcr executable");
            return Ok(None);
        };

        if mcr.as_os_str().is_empty() {
            eprintln!("skipping shell smoke contract: MCR_BIN is empty");
            return Ok(None);
        }

        let fixtures = FixtureRoot::discover()?;
        let rootfs = fixtures.rootfs_fixture(ALPINE_ROOTFS)?;
        let rootfs_path = rootfs.absolute_path(&fixtures);
        if !rootfs.materialized(&fixtures) {
            eprintln!(
                "skipping shell smoke contract: materialize {} at {}",
                rootfs.name(),
                rootfs_path.display()
            );
            return Ok(None);
        }

        Ok(Some(Self {
            mcr,
            rootfs: rootfs_path,
        }))
    }

    fn command(&self, contract: ShellSmokeContract) -> SmokeCommand {
        SmokeCommand::new(self.mcr.clone())
            .arg("run-rootfs")
            .arg(self.rootfs.clone())
            .arg("/bin/sh")
            .arg("-c")
            .arg(contract.script)
    }
}

#[test]
fn shell_procfs_smoke_contracts_model_guest_runtime_commands() {
    let context = ShellSmokeContext {
        mcr: OsString::from("mcr"),
        rootfs: PathBuf::from(ALPINE_ROOTFS),
    };

    for contract in SHELL_SMOKE_CONTRACTS {
        let command = context.command(*contract).command();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(command.get_program(), "mcr");
        assert_eq!(
            args,
            vec![
                "run-rootfs".to_owned(),
                ALPINE_ROOTFS.to_owned(),
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                contract.script.to_owned(),
            ],
            "shell smoke contract `{}` must run through mcr run-rootfs",
            contract.name
        );
    }
}

#[test]
#[ignore = "requires MCR_BIN and a materialized alpine-rootfs"]
fn shell_smoke_contract_echo() -> Result<()> {
    run_shell_smoke(SHELL_ECHO)
}

#[test]
#[ignore = "requires MCR_BIN and a materialized alpine-rootfs"]
fn shell_smoke_contract_pipeline() -> Result<()> {
    run_shell_smoke(SHELL_PIPE)
}

#[test]
#[ignore = "requires MCR_BIN and a materialized alpine-rootfs"]
fn shell_smoke_contract_procfs_devfs() -> Result<()> {
    run_shell_smoke(SHELL_PROCFS_DEVFS)
}

fn run_shell_smoke(contract: ShellSmokeContract) -> Result<()> {
    let Some(context) = ShellSmokeContext::discover()? else {
        return Ok(());
    };

    context
        .command(contract)
        .expected(GoldenOutput::new(0, contract.stdout, b""))
        .run_and_assert()?;

    Ok(())
}
