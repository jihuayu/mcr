use std::ffi::OsString;
use std::path::PathBuf;
use std::{env, fs};

use mcr_testkit::{FixtureRoot, Result, SmokeCommand};

const ALPINE_ROOTFS: &str = "alpine-rootfs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkSmokeContract {
    name: &'static str,
    script: &'static str,
    cleanup_guest_path: Option<&'static str>,
}

const CURL_VERSION: NetworkSmokeContract = NetworkSmokeContract {
    name: "curl --version",
    script: "curl --version",
    cleanup_guest_path: None,
};
const CURL_EXAMPLE: NetworkSmokeContract = NetworkSmokeContract {
    name: "curl example.com",
    script: "curl -fsSL https://example.com >/dev/null",
    cleanup_guest_path: None,
};
const GIT_VERSION: NetworkSmokeContract = NetworkSmokeContract {
    name: "git --version",
    script: "git --version",
    cleanup_guest_path: None,
};
const GIT_CLONE_HELLO_WORLD: NetworkSmokeContract = NetworkSmokeContract {
    name: "git clone Hello-World",
    script: "git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hello-world",
    cleanup_guest_path: Some("/tmp/hello-world"),
};

const NETWORK_SMOKE_CONTRACTS: &[NetworkSmokeContract] = &[
    CURL_VERSION,
    CURL_EXAMPLE,
    GIT_VERSION,
    GIT_CLONE_HELLO_WORLD,
];

#[derive(Debug)]
struct NetworkSmokeContext {
    mcr: OsString,
    rootfs: PathBuf,
}

impl NetworkSmokeContext {
    fn discover() -> Result<Option<Self>> {
        let Some(mcr) = env::var_os("MCR_BIN") else {
            eprintln!("skipping network smoke contract: set MCR_BIN to the mcr executable");
            return Ok(None);
        };

        if mcr.as_os_str().is_empty() {
            eprintln!("skipping network smoke contract: MCR_BIN is empty");
            return Ok(None);
        }

        let fixtures = FixtureRoot::discover()?;
        let rootfs = fixtures.rootfs_fixture(ALPINE_ROOTFS)?;
        let rootfs_path = rootfs.absolute_path(&fixtures);
        if !rootfs.materialized(&fixtures) {
            eprintln!(
                "skipping network smoke contract: materialize {} at {}",
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

    fn command(&self, contract: NetworkSmokeContract) -> SmokeCommand {
        SmokeCommand::new(self.mcr.clone())
            .arg("run-rootfs")
            .arg(self.rootfs.clone())
            .arg("/bin/sh")
            .arg("-c")
            .arg(contract.script)
    }
}

#[test]
fn network_smoke_contracts_model_guest_shell_commands() {
    let context = NetworkSmokeContext {
        mcr: OsString::from("mcr"),
        rootfs: PathBuf::from(ALPINE_ROOTFS),
    };

    for contract in NETWORK_SMOKE_CONTRACTS {
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
            "network smoke contract `{}` must run through mcr run-rootfs",
            contract.name
        );
    }
}

#[test]
#[ignore = "requires MCR_BIN, materialized alpine-rootfs with curl/git/CA, and public network"]
fn network_smoke_contract_curl_version() -> Result<()> {
    run_network_smoke(CURL_VERSION)
}

#[test]
#[ignore = "requires MCR_BIN, materialized alpine-rootfs with curl/git/CA, and public network"]
fn network_smoke_contract_curl_example_dot_com() -> Result<()> {
    run_network_smoke(CURL_EXAMPLE)
}

#[test]
#[ignore = "requires MCR_BIN, materialized alpine-rootfs with curl/git/CA, and public network"]
fn network_smoke_contract_git_version() -> Result<()> {
    run_network_smoke(GIT_VERSION)
}

#[test]
#[ignore = "requires MCR_BIN, materialized alpine-rootfs with curl/git/CA, and public network"]
fn network_smoke_contract_git_clone_hello_world() -> Result<()> {
    run_network_smoke(GIT_CLONE_HELLO_WORLD)
}

fn run_network_smoke(contract: NetworkSmokeContract) -> Result<()> {
    let Some(context) = NetworkSmokeContext::discover()? else {
        return Ok(());
    };

    let cleanup_path = contract
        .cleanup_guest_path
        .map(|guest_path| context.rootfs.join(guest_path.trim_start_matches('/')));
    if let Some(path) = &cleanup_path {
        let _ = fs::remove_dir_all(path);
    }

    let output = context.command(contract).run()?;
    if let Some(path) = &cleanup_path {
        let _ = fs::remove_dir_all(path);
    }

    assert_eq!(
        output.status_code(),
        Some(0),
        "network smoke contract `{}` failed\nstdout:\n{}\nstderr:\n{}",
        contract.name,
        String::from_utf8_lossy(output.stdout()),
        String::from_utf8_lossy(output.stderr())
    );

    Ok(())
}
