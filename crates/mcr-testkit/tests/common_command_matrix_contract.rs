use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use mcr_testkit::{FixtureRoot, GoldenOutput, Result, SmokeCommand};

const ALPINE_ROOTFS: &str = "alpine-rootfs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommonCommandContract {
    name: &'static str,
    script: &'static str,
    stdout: &'static [u8],
}

const CAT: CommonCommandContract = CommonCommandContract {
    name: "cat",
    script: r#"p=/tmp/mcr-cat-$$; printf 'cat-ok\n' > "$p" && cat "$p""#,
    stdout: b"cat-ok\n",
};
const MKDIR: CommonCommandContract = CommonCommandContract {
    name: "mkdir",
    script: r#"d=/tmp/mcr-mkdir-$$; mkdir "$d" && test -d "$d" && echo mkdir-ok"#,
    stdout: b"mkdir-ok\n",
};
const LS: CommonCommandContract = CommonCommandContract {
    name: "ls",
    script: r#"d=/tmp/mcr-ls-$$; mkdir "$d" && touch "$d/a" "$d/b" && ls "$d""#,
    stdout: b"a\nb\n",
};
const RMDIR: CommonCommandContract = CommonCommandContract {
    name: "rmdir",
    script: r#"d=/tmp/mcr-rmdir-$$; mkdir "$d" && rmdir "$d" && test ! -e "$d" && echo rmdir-ok"#,
    stdout: b"rmdir-ok\n",
};
const RM: CommonCommandContract = CommonCommandContract {
    name: "rm",
    script: r#"p=/tmp/mcr-rm-$$; printf x > "$p" && rm "$p" && test ! -e "$p" && echo rm-ok"#,
    stdout: b"rm-ok\n",
};
const CP: CommonCommandContract = CommonCommandContract {
    name: "cp",
    script: r#"src=/tmp/mcr-cp-src-$$; dst=/tmp/mcr-cp-dst-$$; printf 'cp-ok\n' > "$src" && cp "$src" "$dst" && cat "$dst""#,
    stdout: b"cp-ok\n",
};
const MV: CommonCommandContract = CommonCommandContract {
    name: "mv",
    script: r#"src=/tmp/mcr-mv-src-$$; dst=/tmp/mcr-mv-dst-$$; printf 'mv-ok\n' > "$src" && mv "$src" "$dst" && test ! -e "$src" && cat "$dst""#,
    stdout: b"mv-ok\n",
};
const LN: CommonCommandContract = CommonCommandContract {
    name: "ln",
    script: r#"src=/tmp/mcr-ln-src-$$; dst=/tmp/mcr-ln-dst-$$; printf 'ln-ok\n' > "$src" && ln "$src" "$dst" && cat "$dst""#,
    stdout: b"ln-ok\n",
};
const READLINK: CommonCommandContract = CommonCommandContract {
    name: "readlink",
    script: r#"src=/tmp/mcr-readlink-src-$$; link=/tmp/mcr-readlink-link-$$; ln -s "$src" "$link" && test "$(readlink "$link")" = "$src" && echo readlink-ok"#,
    stdout: b"readlink-ok\n",
};
const TOUCH: CommonCommandContract = CommonCommandContract {
    name: "touch",
    script: r#"p=/tmp/mcr-touch-$$; touch "$p" && test -f "$p" && echo touch-ok"#,
    stdout: b"touch-ok\n",
};
const ECHO: CommonCommandContract = CommonCommandContract {
    name: "echo",
    script: "echo echo-ok",
    stdout: b"echo-ok\n",
};
const GREP: CommonCommandContract = CommonCommandContract {
    name: "grep",
    script: r#"p=/tmp/mcr-grep-$$; printf 'alpha\nbeta\n' > "$p" && grep beta "$p""#,
    stdout: b"beta\n",
};
const HEAD: CommonCommandContract = CommonCommandContract {
    name: "head",
    script: r#"p=/tmp/mcr-head-$$; printf 'one\ntwo\nthree\n' > "$p" && head -n 2 "$p""#,
    stdout: b"one\ntwo\n",
};
const TAIL: CommonCommandContract = CommonCommandContract {
    name: "tail",
    script: r#"p=/tmp/mcr-tail-$$; printf 'one\ntwo\nthree\n' > "$p" && tail -n 2 "$p""#,
    stdout: b"two\nthree\n",
};
const SED: CommonCommandContract = CommonCommandContract {
    name: "sed",
    script: r#"p=/tmp/mcr-sed-$$; printf 'alpha\n' > "$p" && sed 's/alpha/sed-ok/' "$p""#,
    stdout: b"sed-ok\n",
};
const CHMOD: CommonCommandContract = CommonCommandContract {
    name: "chmod",
    script: r#"p=/tmp/mcr-chmod-$$; touch "$p" && chmod 700 "$p" && test -x "$p" && echo chmod-ok"#,
    stdout: b"chmod-ok\n",
};
const CHOWN: CommonCommandContract = CommonCommandContract {
    name: "chown",
    script: r#"p=/tmp/mcr-chown-$$; touch "$p" && chown 0:0 "$p" && echo chown-ok"#,
    stdout: b"chown-ok\n",
};
const PS: CommonCommandContract = CommonCommandContract {
    name: "ps",
    script: r#"p=/tmp/mcr-ps-$$; ps > "$p" && grep PID "$p" >/dev/null && echo ps-ok"#,
    stdout: b"ps-ok\n",
};

const COMMON_COMMAND_MATRIX_CONTRACTS: &[CommonCommandContract] = &[
    CAT, MKDIR, LS, RMDIR, RM, CP, MV, LN, READLINK, TOUCH, ECHO, GREP, HEAD, TAIL, SED, CHMOD,
    CHOWN, PS,
];

#[derive(Debug)]
struct CommonCommandMatrixContext {
    mcr: OsString,
    rootfs: PathBuf,
}

impl CommonCommandMatrixContext {
    fn discover() -> Result<Option<Self>> {
        let Some(mcr) = env::var_os("MCR_BIN") else {
            eprintln!("skipping common command matrix contract: set MCR_BIN to the mcr executable");
            return Ok(None);
        };

        if mcr.as_os_str().is_empty() {
            eprintln!("skipping common command matrix contract: MCR_BIN is empty");
            return Ok(None);
        }

        let fixtures = FixtureRoot::discover()?;
        let rootfs = fixtures.rootfs_fixture(ALPINE_ROOTFS)?;
        let rootfs_path = rootfs.absolute_path(&fixtures);
        if !rootfs.materialized(&fixtures) {
            eprintln!(
                "skipping common command matrix contract: materialize {} at {}",
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

    fn command(&self, contract: CommonCommandContract) -> SmokeCommand {
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
fn common_command_matrix_contracts_model_guest_shell_commands() {
    let context = CommonCommandMatrixContext {
        mcr: OsString::from("mcr"),
        rootfs: PathBuf::from(ALPINE_ROOTFS),
    };

    for contract in COMMON_COMMAND_MATRIX_CONTRACTS {
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
            "common command matrix contract `{}` must run through mcr run-rootfs",
            contract.name
        );
    }
}

macro_rules! common_command_matrix_contract {
    ($test_name:ident, $contract:expr) => {
        #[test]
        #[ignore = "requires MCR_BIN and a materialized alpine-rootfs"]
        fn $test_name() -> Result<()> {
            run_common_command_matrix_contract($contract)
        }
    };
}

common_command_matrix_contract!(common_command_matrix_contract_cat, CAT);
common_command_matrix_contract!(common_command_matrix_contract_mkdir, MKDIR);
common_command_matrix_contract!(common_command_matrix_contract_ls, LS);
common_command_matrix_contract!(common_command_matrix_contract_rmdir, RMDIR);
common_command_matrix_contract!(common_command_matrix_contract_rm, RM);
common_command_matrix_contract!(common_command_matrix_contract_cp, CP);
common_command_matrix_contract!(common_command_matrix_contract_mv, MV);
common_command_matrix_contract!(common_command_matrix_contract_ln, LN);
common_command_matrix_contract!(common_command_matrix_contract_readlink, READLINK);
common_command_matrix_contract!(common_command_matrix_contract_touch, TOUCH);
common_command_matrix_contract!(common_command_matrix_contract_echo, ECHO);
common_command_matrix_contract!(common_command_matrix_contract_grep, GREP);
common_command_matrix_contract!(common_command_matrix_contract_head, HEAD);
common_command_matrix_contract!(common_command_matrix_contract_tail, TAIL);
common_command_matrix_contract!(common_command_matrix_contract_sed, SED);
common_command_matrix_contract!(common_command_matrix_contract_chmod, CHMOD);
common_command_matrix_contract!(common_command_matrix_contract_chown, CHOWN);
common_command_matrix_contract!(common_command_matrix_contract_ps, PS);

fn run_common_command_matrix_contract(contract: CommonCommandContract) -> Result<()> {
    let Some(context) = CommonCommandMatrixContext::discover()? else {
        return Ok(());
    };

    context
        .command(contract)
        .expected(GoldenOutput::new(0, contract.stdout, b""))
        .run_and_assert()?;

    Ok(())
}
