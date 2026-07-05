use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Mutex;

use mcr_testkit::{FixtureRoot, Result, SmokeCommand};

static EXTENDED_SUPPORT_SMOKE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExtendedSupportSmokeContract {
    name: &'static str,
    rootfs: &'static str,
    script: &'static str,
    stdout: &'static [u8],
}

const GCC_COMPILE_SCRIPT: &str = r#"set -eu
base=/tmp/mcr-gcc-smoke-$$
mkdir -p "$base"
trap 'rm -rf "$base"' EXIT
cat > "$base/main.c" <<'EOF'
#include <stdio.h>

int main(void) {
    puts("gcc-ok");
    return 0;
}
EOF
/usr/bin/gcc "$base/main.c" -o "$base/main"
"$base/main"
"#;

const NODEJS_RUN_SCRIPT: &str = r#"node -e "console.log('node-ok')""#;

const JDK_RUN_SCRIPT: &str = r#"set -eu
export PATH=/usr/lib/jvm/java-21-openjdk/bin:/usr/bin:/bin
base=/tmp/mcr-jdk-smoke-$$
mkdir -p "$base"
trap 'rm -rf "$base"' EXIT
cat > "$base/McrSmoke.java" <<'EOF'
public final class McrSmoke {
    public static void main(String[] args) {
        System.out.println("jdk-ok");
    }
}
EOF
javac "$base/McrSmoke.java"
java -cp "$base" McrSmoke
"#;

const MYSQL_RUN_SCRIPT: &str = r#"set -eu
require_command() {
    if command -v "$1" >/dev/null 2>&1; then
        command -v "$1"
        return 0
    fi
    if command -v "$2" >/dev/null 2>&1; then
        command -v "$2"
        return 0
    fi
    echo "missing $1/$2" >&2
    exit 127
}

base=/tmp/mcr-mysql-smoke-$$
data="$base/data"
socket="$base/mysql.sock"
log="$base/mysql.log"
mkdir -p "$data"

install_db=$(require_command mariadb-install-db mysql_install_db)
server=$(require_command mariadbd mysqld)
admin=$(require_command mariadb-admin mysqladmin)
client=$(require_command mariadb mysql)

"$install_db" --datadir="$data" --auth-root-authentication-method=normal --skip-test-db >/dev/null
"$server" --datadir="$data" --socket="$socket" --pid-file="$base/mysql.pid" --skip-networking --skip-grant-tables --user=root >"$log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -rf "$base"' EXIT

i=0
until "$admin" --socket="$socket" ping >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        cat "$log" >&2
        exit 1
    fi
    sleep 1
done

"$client" --socket="$socket" -N -B -e "SELECT 'mysql-ok';"
"#;

const REDIS_RUN_SCRIPT: &str = r#"set -eu
redis-server --test-memory 1 >/dev/null
echo redis-ok
"#;

const GCC_COMPILE: ExtendedSupportSmokeContract = ExtendedSupportSmokeContract {
    name: "gcc compile and run",
    rootfs: "gcc-rootfs",
    script: GCC_COMPILE_SCRIPT,
    stdout: b"gcc-ok\n",
};
const NODEJS_RUN: ExtendedSupportSmokeContract = ExtendedSupportSmokeContract {
    name: "nodejs run",
    rootfs: "node-rootfs",
    script: NODEJS_RUN_SCRIPT,
    stdout: b"node-ok\n",
};
const JDK_RUN: ExtendedSupportSmokeContract = ExtendedSupportSmokeContract {
    name: "jdk compile and run",
    rootfs: "jdk-rootfs",
    script: JDK_RUN_SCRIPT,
    stdout: b"jdk-ok\n",
};
const MYSQL_RUN: ExtendedSupportSmokeContract = ExtendedSupportSmokeContract {
    name: "mysql server run",
    rootfs: "mysql-rootfs",
    script: MYSQL_RUN_SCRIPT,
    stdout: b"mysql-ok\n",
};
const REDIS_RUN: ExtendedSupportSmokeContract = ExtendedSupportSmokeContract {
    name: "redis server memory test",
    rootfs: "redis-rootfs",
    script: REDIS_RUN_SCRIPT,
    stdout: b"redis-ok\n",
};

const EXTENDED_SUPPORT_SMOKE_CONTRACTS: &[ExtendedSupportSmokeContract] =
    &[GCC_COMPILE, NODEJS_RUN, JDK_RUN, MYSQL_RUN, REDIS_RUN];

#[derive(Debug)]
struct ExtendedSupportSmokeContext {
    mcr: OsString,
    rootfs: PathBuf,
}

impl ExtendedSupportSmokeContext {
    fn discover(rootfs_name: &str) -> Result<Option<Self>> {
        let Some(mcr) = env::var_os("MCR_BIN") else {
            eprintln!(
                "skipping extended support smoke contract: set MCR_BIN to the mcr executable"
            );
            return Ok(None);
        };

        if mcr.as_os_str().is_empty() {
            eprintln!("skipping extended support smoke contract: MCR_BIN is empty");
            return Ok(None);
        }

        let fixtures = FixtureRoot::discover()?;
        let rootfs = fixtures.rootfs_fixture(rootfs_name)?;
        let rootfs_path = rootfs.absolute_path(&fixtures);
        if !rootfs.materialized(&fixtures) {
            eprintln!(
                "skipping extended support smoke contract: materialize {} at {}",
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

    fn command(&self, contract: ExtendedSupportSmokeContract) -> SmokeCommand {
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
fn extended_support_smoke_contracts_model_guest_shell_commands() {
    for contract in EXTENDED_SUPPORT_SMOKE_CONTRACTS {
        let context = ExtendedSupportSmokeContext {
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
            "extended support smoke contract `{}` must run through mcr run-rootfs",
            contract.name
        );
    }
}

macro_rules! extended_support_smoke_contract {
    ($test_name:ident, $contract:expr) => {
        #[test]
        #[ignore = "requires MCR_BIN and the matching materialized extended-support rootfs"]
        fn $test_name() -> Result<()> {
            run_extended_support_smoke_contract($contract)
        }
    };
}

extended_support_smoke_contract!(extended_support_smoke_contract_gcc_compile, GCC_COMPILE);
extended_support_smoke_contract!(extended_support_smoke_contract_nodejs_run, NODEJS_RUN);
extended_support_smoke_contract!(extended_support_smoke_contract_jdk_run, JDK_RUN);
extended_support_smoke_contract!(extended_support_smoke_contract_mysql_run, MYSQL_RUN);
extended_support_smoke_contract!(extended_support_smoke_contract_redis_run, REDIS_RUN);

fn run_extended_support_smoke_contract(contract: ExtendedSupportSmokeContract) -> Result<()> {
    let _guard = EXTENDED_SUPPORT_SMOKE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(context) = ExtendedSupportSmokeContext::discover(contract.rootfs)? else {
        return Ok(());
    };

    let output = context.command(contract).run()?;
    assert_eq!(
        output.status_code(),
        Some(0),
        "extended support smoke contract `{}` failed\nstdout:\n{}\nstderr:\n{}",
        contract.name,
        String::from_utf8_lossy(output.stdout()),
        String::from_utf8_lossy(output.stderr())
    );
    assert_eq!(
        output.stdout(),
        contract.stdout,
        "extended support smoke contract `{}` stdout mismatch\nexpected:\n{}\nactual:\n{}",
        contract.name,
        String::from_utf8_lossy(contract.stdout),
        String::from_utf8_lossy(output.stdout())
    );

    Ok(())
}
