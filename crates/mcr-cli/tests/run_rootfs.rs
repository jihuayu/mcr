use std::fs;
use std::path::{Path, PathBuf};

use mcr_testkit::SmokeCommand;
use mcr_testkit::elf::{Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X};

#[test]
fn cli_runs_mvp_busybox_smokes() {
    let rootfs = TestRootfs::new("cli-smoke");
    rootfs.write_static_elf("/bin/busybox");
    rootfs.write_file("/etc/os-release", b"NAME=Alpine\n");
    rootfs.write_file("/hello.txt", b"hello\n");
    let mcr = env!("CARGO_BIN_EXE_mcr");

    let echo = SmokeCommand::new(mcr)
        .args([
            "run-rootfs",
            rootfs.path().to_str().unwrap(),
            "/bin/busybox",
            "echo",
            "hello",
        ])
        .run()
        .unwrap();
    assert_eq!(echo.status().code(), Some(0));
    assert_eq!(echo.stdout(), b"hello\n");
    assert_eq!(echo.stderr(), b"");

    let ls = SmokeCommand::new(mcr)
        .args([
            "run-rootfs",
            rootfs.path().to_str().unwrap(),
            "/bin/busybox",
            "ls",
            "/",
        ])
        .run()
        .unwrap();
    assert_eq!(ls.status().code(), Some(0));
    assert_eq!(ls.stdout(), b"bin\ndev\netc\nhello.txt\nproc\n");
    assert_eq!(ls.stderr(), b"");

    let cat = SmokeCommand::new(mcr)
        .args([
            "run-rootfs",
            rootfs.path().to_str().unwrap(),
            "/bin/busybox",
            "cat",
            "/etc/os-release",
        ])
        .run()
        .unwrap();
    assert_eq!(cat.status().code(), Some(0));
    assert_eq!(cat.stdout(), b"NAME=Alpine\n");
    assert_eq!(cat.stderr(), b"");
}

struct TestRootfs {
    path: PathBuf,
}

impl TestRootfs {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("mcr-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write_file(&self, guest_path: &str, bytes: &[u8]) {
        let path = self.host_path(guest_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn write_static_elf(&self, guest_path: &str) {
        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_X,
                0,
                0x401000,
                0x1000,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000,
                0x402000,
                0x08,
                0x100,
            ))
            .data_at(0x200, vec![0x90; 0x20])
            .data_at(0x2000, vec![0; 0x08])
            .build();
        self.write_file(guest_path, &elf);
    }

    fn host_path(&self, guest_path: &str) -> PathBuf {
        let mut path = self.path.clone();
        for component in guest_path
            .split('/')
            .filter(|component| !component.is_empty())
        {
            path.push(component);
        }
        path
    }
}

impl Drop for TestRootfs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
