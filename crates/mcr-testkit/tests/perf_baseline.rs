use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use mcr_testkit::perf::{PerfBaselineReport, PerfMeasurement, measure_wall_time};
use mcr_testkit::{FixtureRoot, Result, SmokeCommand};

const ALPINE_ROOTFS: &str = "alpine-rootfs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestPerfWorkload {
    name: &'static str,
    script: &'static str,
    operations: u64,
    category: &'static str,
    requires_public_network: bool,
}

const SHELL_STARTUP: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_shell_startup_true",
    script: "true",
    operations: 1,
    category: "shell_fork_exec_wait4",
    requires_public_network: false,
};
const SMALL_FILE_IO: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_small_file_io",
    script: "i=0; while [ $i -lt 16 ]; do p=/tmp/mcr-perf-small-$$-$i; printf 'payload\n' > \"$p\" && cat \"$p\" >/dev/null && rm \"$p\"; i=$((i+1)); done",
    operations: 16,
    category: "small_file_io",
    requires_public_network: false,
};
const DIRECTORY_METADATA_WALK: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_directory_metadata_walk",
    script: "d=/tmp/mcr-perf-dir-$$; i=0; while [ $i -lt 32 ]; do rm -f \"$d/f$i\"; i=$((i+1)); done; rmdir \"$d\" 2>/dev/null || true; mkdir -p \"$d\"; i=0; while [ $i -lt 32 ]; do touch \"$d/f$i\"; i=$((i+1)); done; ls -l \"$d\" >/dev/null; i=0; while [ $i -lt 32 ]; do rm \"$d/f$i\"; i=$((i+1)); done; rmdir \"$d\"",
    operations: 32,
    category: "directory_metadata_walk",
    requires_public_network: false,
};
const CURL_EXAMPLE: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_curl_example",
    script: "curl -fsSL https://example.com >/dev/null",
    operations: 1,
    category: "network_smoke_curl",
    requires_public_network: true,
};
const GIT_LS_REMOTE: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_git_ls_remote",
    script: "git ls-remote https://github.com/octocat/Hello-World.git HEAD >/dev/null",
    operations: 1,
    category: "network_smoke_git",
    requires_public_network: true,
};

const GUEST_PERF_WORKLOADS: &[GuestPerfWorkload] = &[
    SHELL_STARTUP,
    SMALL_FILE_IO,
    DIRECTORY_METADATA_WALK,
    CURL_EXAMPLE,
    GIT_LS_REMOTE,
];

#[derive(Debug)]
struct GuestPerfContext {
    mcr: OsString,
    rootfs: PathBuf,
}

impl GuestPerfContext {
    fn discover() -> Result<Option<Self>> {
        let Some(mcr) = env::var_os("MCR_BIN") else {
            eprintln!("skipping guest perf baseline: set MCR_BIN to the mcr executable");
            return Ok(None);
        };

        if mcr.as_os_str().is_empty() {
            eprintln!("skipping guest perf baseline: MCR_BIN is empty");
            return Ok(None);
        }

        let fixtures = FixtureRoot::discover()?;
        let rootfs = fixtures.rootfs_fixture(ALPINE_ROOTFS)?;
        let rootfs_path = rootfs.absolute_path(&fixtures);
        if !rootfs.materialized(&fixtures) {
            eprintln!(
                "skipping guest perf baseline: materialize {} at {}",
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

    fn command(&self, workload: GuestPerfWorkload) -> SmokeCommand {
        SmokeCommand::new(self.mcr.clone())
            .arg("run-rootfs")
            .arg(self.rootfs.clone())
            .arg("/bin/sh")
            .arg("-c")
            .arg(workload.script)
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
fn perf_baseline_guest_workloads_model_expected_commands() {
    let context = GuestPerfContext {
        mcr: OsString::from("mcr"),
        rootfs: PathBuf::from(ALPINE_ROOTFS),
    };

    for workload in GUEST_PERF_WORKLOADS {
        let command = context.command(*workload).command();
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
                workload.script.to_owned(),
            ],
            "guest perf workload `{}` must run through mcr run-rootfs",
            workload.name
        );
        assert!(workload.operations > 0);
    }
}

#[test]
#[ignore = "requires MCR_BIN, materialized alpine-rootfs, and public network for curl/git workloads"]
fn perf_baseline_guest_smoke_workloads() -> Result<()> {
    let Some(context) = GuestPerfContext::discover()? else {
        return Ok(());
    };
    let mut report = PerfBaselineReport::new("mcr-testkit guest workload performance baseline");
    let run_public_network = env::var_os("MCR_PERF_PUBLIC_NETWORK").is_some();

    for workload in GUEST_PERF_WORKLOADS {
        if workload.requires_public_network && !run_public_network {
            eprintln!(
                "skipping guest perf workload `{}`: set MCR_PERF_PUBLIC_NETWORK=1",
                workload.name
            );
            continue;
        }

        let command = context.command(*workload);
        let (output_result, wall_time) = measure_wall_time(|| command.run());
        let output = output_result?;
        report.push(
            PerfMeasurement::new(workload.name, workload.operations, wall_time)
                .with_field("category", workload.category)
                .with_field("script", workload.script)
                .with_field("requires_public_network", workload.requires_public_network)
                .with_field("status", output.status_code().unwrap_or_default()),
        );

        assert_eq!(
            output.status_code(),
            Some(0),
            "guest perf workload `{}` failed\nstdout:\n{}\nstderr:\n{}",
            workload.name,
            String::from_utf8_lossy(output.stdout()),
            String::from_utf8_lossy(output.stderr())
        );
    }

    println!("{report}");
    Ok(())
}
