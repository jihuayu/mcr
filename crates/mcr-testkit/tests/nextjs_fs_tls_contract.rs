use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use mcr_testkit::{FixtureRoot, Result, SmokeCommand};

const NEXT_APP_ROOT: &str = "tmp/mcr-next-smoke";
const NEXT_CONFIG_SCRIPT: &str = r#"set -eu
cd /tmp/mcr-next-smoke
cat > probe-config-require.js <<'EOF'
const fs = require("fs");
fs.writeSync(1, "before\n");
require("next/dist/server/config");
fs.writeSync(1, "after\n");
EOF
/usr/bin/node --jitless probe-config-require.js
"#;

#[test]
fn nextjs_fs_tls_contract_models_guest_shell_command() {
    let context = NextJsFsTlsContext {
        mcr: OsString::from("mcr"),
        rootfs: PathBuf::from("node-rootfs"),
    };
    let command = context.command().command();
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(command.get_program(), "mcr");
    assert_eq!(
        args,
        vec![
            "run-rootfs".to_owned(),
            "node-rootfs".to_owned(),
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            NEXT_CONFIG_SCRIPT.to_owned(),
        ]
    );
}

#[test]
#[ignore = "requires MCR_BIN, node-rootfs, and a prepared /tmp/mcr-next-smoke app"]
fn nextjs_config_loader_fs_tls_contract() -> Result<()> {
    let Some(context) = NextJsFsTlsContext::discover()? else {
        return Ok(());
    };

    let output = context.command().run()?;
    assert_eq!(
        output.status_code(),
        Some(0),
        "nextjs FS/TLS contract failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(output.stdout()),
        String::from_utf8_lossy(output.stderr())
    );
    assert_eq!(output.stdout(), b"before\nafter\n");

    Ok(())
}

#[derive(Debug)]
struct NextJsFsTlsContext {
    mcr: OsString,
    rootfs: PathBuf,
}

impl NextJsFsTlsContext {
    fn discover() -> Result<Option<Self>> {
        let Some(mcr) = env::var_os("MCR_BIN") else {
            eprintln!("skipping nextjs FS/TLS contract: set MCR_BIN to the mcr executable");
            return Ok(None);
        };
        if mcr.as_os_str().is_empty() {
            eprintln!("skipping nextjs FS/TLS contract: MCR_BIN is empty");
            return Ok(None);
        }

        let fixtures = FixtureRoot::discover()?;
        let rootfs = fixtures.rootfs_fixture("node-rootfs")?;
        let rootfs_path = rootfs.absolute_path(&fixtures);
        if !rootfs.materialized(&fixtures) {
            eprintln!(
                "skipping nextjs FS/TLS contract: materialize node-rootfs at {}",
                rootfs_path.display()
            );
            return Ok(None);
        }

        let app_root = rootfs_path.join(NEXT_APP_ROOT);
        if !app_root
            .join("node_modules/next/dist/server/config.js")
            .exists()
        {
            eprintln!(
                "skipping nextjs FS/TLS contract: prepare Next.js app at {}",
                app_root.display()
            );
            return Ok(None);
        }

        Ok(Some(Self {
            mcr: resolve_mcr_bin(mcr, &fixtures),
            rootfs: command_rootfs_path(&rootfs_path),
        }))
    }

    fn command(&self) -> SmokeCommand {
        SmokeCommand::new(self.mcr.clone())
            .arg("run-rootfs")
            .arg(self.rootfs.clone())
            .arg("/bin/sh")
            .arg("-c")
            .arg(NEXT_CONFIG_SCRIPT)
    }
}

fn command_rootfs_path(rootfs_path: &Path) -> PathBuf {
    let Ok(cwd) = env::current_dir() else {
        return rootfs_path.to_path_buf();
    };
    rootfs_path
        .strip_prefix(cwd)
        .map_or_else(|_| rootfs_path.to_path_buf(), Path::to_path_buf)
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
