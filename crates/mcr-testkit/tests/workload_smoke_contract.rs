use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use mcr_testkit::{FixtureRoot, Result, SmokeCommand};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkloadSmokeContract {
    name: &'static str,
    rootfs: &'static str,
    script: &'static str,
    stdout_prefix: &'static [u8],
}

const NODE_VERSION: WorkloadSmokeContract = WorkloadSmokeContract {
    name: "node -v",
    rootfs: "node-rootfs",
    script: "node -v",
    stdout_prefix: b"v",
};
const PYTHON_VERSION: WorkloadSmokeContract = WorkloadSmokeContract {
    name: "python -V",
    rootfs: "python-rootfs",
    script: "python -V",
    stdout_prefix: b"Python ",
};
const GO_VERSION: WorkloadSmokeContract = WorkloadSmokeContract {
    name: "go version",
    rootfs: "go-rootfs",
    script: "go version",
    stdout_prefix: b"go version ",
};
const CARGO_VERSION: WorkloadSmokeContract = WorkloadSmokeContract {
    name: "cargo --version",
    rootfs: "rust-rootfs",
    script: "cargo --version",
    stdout_prefix: b"cargo ",
};

const WORKLOAD_SMOKE_CONTRACTS: &[WorkloadSmokeContract] =
    &[NODE_VERSION, PYTHON_VERSION, GO_VERSION, CARGO_VERSION];

#[derive(Debug)]
struct WorkloadSmokeContext {
    mcr: OsString,
    rootfs: PathBuf,
}

impl WorkloadSmokeContext {
    fn discover(rootfs_name: &str) -> Result<Option<Self>> {
        let Some(mcr) = env::var_os("MCR_BIN") else {
            eprintln!("skipping workload smoke contract: set MCR_BIN to the mcr executable");
            return Ok(None);
        };

        if mcr.as_os_str().is_empty() {
            eprintln!("skipping workload smoke contract: MCR_BIN is empty");
            return Ok(None);
        }

        let fixtures = FixtureRoot::discover()?;
        let rootfs = fixtures.rootfs_fixture(rootfs_name)?;
        let rootfs_path = rootfs.absolute_path(&fixtures);
        if !rootfs.materialized(&fixtures) {
            eprintln!(
                "skipping workload smoke contract: materialize {} at {}",
                rootfs.name(),
                rootfs_path.display()
            );
            return Ok(None);
        }

        Ok(Some(Self {
            mcr: resolve_mcr_bin(mcr, &fixtures),
            rootfs: rootfs_path,
        }))
    }

    fn command(&self, contract: WorkloadSmokeContract) -> SmokeCommand {
        SmokeCommand::new(self.mcr.clone())
            .arg("run-rootfs")
            .arg(self.rootfs.clone())
            .arg("/bin/sh")
            .arg("-c")
            .arg(contract.script)
    }
}

fn resolve_mcr_bin(mcr: OsString, fixtures: &FixtureRoot) -> OsString {
    let path = PathBuf::from(&mcr);
    if path.is_absolute() {
        return mcr;
    }

    let Some(workspace) = fixtures.path().parent().and_then(std::path::Path::parent) else {
        return mcr;
    };
    let candidate = workspace.join(&path);
    if candidate.exists() {
        return candidate.into_os_string();
    }

    mcr
}

#[test]
fn workload_smoke_contracts_model_guest_shell_commands() {
    for contract in WORKLOAD_SMOKE_CONTRACTS {
        let context = WorkloadSmokeContext {
            mcr: OsString::from("mcr"),
            rootfs: PathBuf::from(contract.rootfs),
        };
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
                contract.rootfs.to_owned(),
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                contract.script.to_owned(),
            ],
            "workload smoke contract `{}` must run through mcr run-rootfs",
            contract.name
        );
    }
}

macro_rules! workload_smoke_contract {
    ($test_name:ident, $contract:expr) => {
        #[test]
        #[ignore = "requires MCR_BIN and the matching materialized language rootfs"]
        fn $test_name() -> Result<()> {
            run_workload_smoke_contract($contract)
        }
    };
}

workload_smoke_contract!(workload_smoke_contract_node_version, NODE_VERSION);
workload_smoke_contract!(workload_smoke_contract_python_version, PYTHON_VERSION);
workload_smoke_contract!(workload_smoke_contract_go_version, GO_VERSION);
workload_smoke_contract!(workload_smoke_contract_cargo_version, CARGO_VERSION);

fn run_workload_smoke_contract(contract: WorkloadSmokeContract) -> Result<()> {
    let Some(context) = WorkloadSmokeContext::discover(contract.rootfs)? else {
        return Ok(());
    };

    let output = context.command(contract).run()?;
    assert_eq!(
        output.status_code(),
        Some(0),
        "workload smoke contract `{}` failed\nstdout:\n{}\nstderr:\n{}",
        contract.name,
        String::from_utf8_lossy(output.stdout()),
        String::from_utf8_lossy(output.stderr())
    );
    assert!(
        output.stdout().starts_with(contract.stdout_prefix),
        "workload smoke contract `{}` stdout should start with `{}`\nactual:\n{}",
        contract.name,
        String::from_utf8_lossy(contract.stdout_prefix),
        String::from_utf8_lossy(output.stdout())
    );

    Ok(())
}
