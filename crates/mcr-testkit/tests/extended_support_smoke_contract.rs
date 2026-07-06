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

const NODEJS_RUN_SCRIPT: &str = r#"set -eu
/usr/bin/node -e "require('fs').writeSync(1, 'node-ok\n')"
"#;

const JDK_RUN_SCRIPT: &str = r#"set -eu
base=/tmp/mcr-jdk-smoke-$$
mkdir -p "$base"
trap 'rm -rf "$base"' EXIT
cat > "$base/Hello.java" <<'EOF'
public class Hello {
    public static void main(String[] args) {
        System.out.println("jdk-ok");
    }
}
EOF
/usr/lib/jvm/java-21-openjdk/bin/javac -version >/dev/null
/usr/lib/jvm/java-21-openjdk/bin/javac -J-Xint "$base/Hello.java"
/usr/lib/jvm/java-21-openjdk/bin/java -Xint -cp "$base" Hello
"#;

const MYSQL_RUN_SCRIPT: &str = r#"set -eu
base=/tmp/mcr-mysql-smoke
rm -rf "$base"
mkdir -p "$base"
trap 'rm -rf "$base"' EXIT
sql="$base/bootstrap.sql"
cat > "$sql" <<SQL
CREATE DATABASE mcr_smoke;
USE mcr_smoke;
CREATE TABLE smoke_customers (id INT PRIMARY KEY, name VARCHAR(16));
CREATE TABLE smoke_items (id INT PRIMARY KEY, bucket INT, n INT, INDEX idx_bucket (bucket));
CREATE TABLE smoke_orders (id INT PRIMARY KEY, customer_id INT, item_id INT, amount INT, INDEX idx_customer (customer_id));
INSERT INTO smoke_customers VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma'), (4, 'delta');
SQL
item=1
printf 'INSERT INTO smoke_items VALUES ' >> "$sql"
while [ "$item" -le 128 ]; do
    bucket=$((item % 16))
    amount=$((item * 3))
    if [ "$item" -gt 1 ]; then
        printf ', ' >> "$sql"
    fi
    printf '(%s, %s, %s)' "$item" "$bucket" "$amount" >> "$sql"
    item=$((item + 1))
done
printf ';\n' >> "$sql"
item=1
printf 'INSERT INTO smoke_orders VALUES ' >> "$sql"
while [ "$item" -le 128 ]; do
    customer=$(((item % 4) + 1))
    amount=$((item * 3))
    if [ "$item" -gt 1 ]; then
        printf ', ' >> "$sql"
    fi
    printf '(%s, %s, %s, %s)' "$item" "$customer" "$item" "$amount" >> "$sql"
    item=$((item + 1))
done
printf ';\n' >> "$sql"
cat >> "$sql" <<SQL
SELECT CONCAT('plain=', n) INTO OUTFILE '$base/plain.out' FROM smoke_items WHERE id = 42;
SELECT CONCAT('index=', COUNT(*), ',', SUM(n)) INTO OUTFILE '$base/index.out' FROM smoke_items FORCE INDEX(idx_bucket) WHERE bucket = 7;
SELECT CONCAT('join=', c.name, ',', SUM(o.amount)) INTO OUTFILE '$base/join.out' FROM smoke_customers c JOIN smoke_orders o ON o.customer_id = c.id WHERE c.id = 3 GROUP BY c.name;
SELECT CONCAT('range=', COUNT(*), ',', SUM(n)) INTO OUTFILE '$base/range.out' FROM smoke_items WHERE id BETWEEN 1 AND 128;
SQL
/usr/bin/mariadbd --no-defaults --user=root --datadir="$base" --bootstrap --skip-grant-tables --innodb-use-native-aio=0 >/dev/null < "$sql"
test "$(cat "$base/plain.out")" = "plain=126"
test "$(cat "$base/index.out")" = "index=8,1512"
test "$(cat "$base/join.out")" = "join=gamma,6144"
test "$(cat "$base/range.out")" = "range=128,24768"
test -f "$base/mcr_smoke/smoke_items.frm"
test -f "$base/mcr_smoke/smoke_items.ibd"
echo mysql-ok
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
    name: "nodejs javascript run",
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
    name: "mysql bootstrap query matrix",
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
