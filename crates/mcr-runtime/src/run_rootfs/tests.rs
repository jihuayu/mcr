use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use mcr_sys::{LINUX_CLONE_VFORK, LINUX_CLONE_VM, LINUX_SIGCHLD, LinuxErrno, Syscall};
use mcr_testkit::elf::{ET_DYN, Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X, PT_INTERP};
use mcr_vfs::{AT_FDCWD, O_RDONLY, OpenFlags};

use super::{RunRootfsConfig, RunRootfsError, load_rootfs, run_rootfs};

static RUN_ROOTFS_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn run_rootfs_executes_busybox_echo_smoke() {
    let rootfs = TestRootfs::new("echo");
    rootfs.write_static_elf("/bin/busybox");

    let output = run_rootfs(emulated_config(&rootfs, b"/bin/busybox").with_args([
        b"/bin/busybox".to_vec(),
        b"echo".to_vec(),
        b"hello".to_vec(),
    ]))
    .unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"hello\n");
    assert_eq!(output.stderr(), b"");
}

#[test]
fn run_rootfs_executes_busybox_ls_and_cat_smokes() {
    let rootfs = TestRootfs::new("ls-cat");
    rootfs.write_static_elf("/bin/busybox");
    rootfs.write_file("/etc/os-release", b"NAME=Alpine\n");
    rootfs.write_file("/hello.txt", b"hello\n");

    let ls = run_rootfs(emulated_config(&rootfs, b"/bin/busybox").with_args([
        b"/bin/busybox".to_vec(),
        b"ls".to_vec(),
        b"/".to_vec(),
    ]))
    .unwrap();
    assert_eq!(ls.status(), 0);
    assert_eq!(ls.stdout(), b"bin\ndev\netc\nhello.txt\nproc\n");

    let cat = run_rootfs(emulated_config(&rootfs, b"/bin/busybox").with_args([
        b"/bin/busybox".to_vec(),
        b"cat".to_vec(),
        b"/etc/os-release".to_vec(),
    ]))
    .unwrap();
    assert_eq!(cat.status(), 0);
    assert_eq!(cat.stdout(), b"NAME=Alpine\n");
}

#[test]
fn load_rootfs_defers_regular_file_content_until_host_read() {
    let rootfs = TestRootfs::new("lazy-open");
    rootfs.write_file("/payload.txt", b"first");

    let mut vfs = load_rootfs(rootfs.path()).unwrap();
    fs::write(rootfs.host_path("/payload.txt"), b"late!").unwrap();
    let fd = vfs
        .openat(AT_FDCWD, "/payload.txt", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    fs::write(rootfs.host_path("/payload.txt"), b"after").unwrap();

    let mut buffer = [0; 8];
    let count = vfs.read(fd, &mut buffer).unwrap();
    vfs.close(fd).unwrap();

    assert_eq!(&buffer[..count], b"after");
}

#[test]
fn run_rootfs_mounts_minimal_procfs_and_devfs() {
    let rootfs = TestRootfs::new("proc-dev");
    rootfs.write_static_elf("/bin/busybox");
    rootfs.create_dir("/dev");
    rootfs.create_dir("/proc/self/fd");

    let dev = run_rootfs(emulated_config(&rootfs, b"/bin/busybox").with_args([
        b"/bin/busybox".to_vec(),
        b"ls".to_vec(),
        b"/dev".to_vec(),
    ]))
    .unwrap();
    assert_eq!(dev.status(), 0);
    assert_eq!(dev.stdout(), b"null\nurandom\nzero\n");

    let proc_self = run_rootfs(emulated_config(&rootfs, b"/bin/busybox").with_args([
        b"/bin/busybox".to_vec(),
        b"ls".to_vec(),
        b"/proc/self".to_vec(),
    ]))
    .unwrap();
    assert_eq!(proc_self.status(), 0);
    assert_eq!(proc_self.stdout(), b"cmdline\nenviron\nexe\nfd\n");
}

#[test]
fn run_rootfs_materializes_minimal_dns_config() {
    let rootfs = TestRootfs::new("dns-config");
    rootfs.write_static_elf("/bin/busybox");

    let output = run_rootfs(emulated_config(&rootfs, b"/bin/busybox").with_args([
        b"/bin/busybox".to_vec(),
        b"cat".to_vec(),
        b"/etc/hosts".to_vec(),
        b"/etc/resolv.conf".to_vec(),
        b"/etc/nsswitch.conf".to_vec(),
    ]))
    .unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(
            output.stdout(),
            b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\nnameserver 1.1.1.1\nhosts: files dns\npasswd: files\ngroup: files\n"
        );
}

#[test]
fn run_rootfs_keeps_existing_dns_config() {
    let rootfs = TestRootfs::new("dns-config-existing");
    rootfs.write_static_elf("/bin/busybox");
    rootfs.write_file("/etc/resolv.conf", b"nameserver 9.9.9.9\n");

    let output = run_rootfs(emulated_config(&rootfs, b"/bin/busybox").with_args([
        b"/bin/busybox".to_vec(),
        b"cat".to_vec(),
        b"/etc/resolv.conf".to_vec(),
    ]))
    .unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"nameserver 9.9.9.9\n");
}

#[test]
fn run_rootfs_exposes_proc_self_cmdline_and_environ_content() {
    let rootfs = TestRootfs::new("proc-content");
    rootfs.write_static_elf("/bin/busybox");

    let cmdline = run_rootfs(emulated_config(&rootfs, b"/bin/busybox").with_args([
        b"/bin/busybox".to_vec(),
        b"cat".to_vec(),
        b"/proc/self/cmdline".to_vec(),
    ]))
    .unwrap();
    assert_eq!(cmdline.status(), 0);
    assert_eq!(cmdline.stdout(), b"/bin/busybox\0cat\0/proc/self/cmdline\0");

    let environ = run_rootfs(
        emulated_config(&rootfs, b"/bin/busybox")
            .with_args([
                b"/bin/busybox".to_vec(),
                b"cat".to_vec(),
                b"/proc/self/environ".to_vec(),
            ])
            .with_env([b"PATH=/bin".to_vec(), b"LANG=C".to_vec()]),
    )
    .unwrap();
    assert_eq!(environ.status(), 0);
    assert_eq!(environ.stdout(), b"PATH=/bin\0LANG=C\0");
}

#[test]
fn run_rootfs_loads_dynamic_interpreter_from_rootfs() {
    let rootfs = TestRootfs::new("dynamic");
    rootfs.write_dynamic_elf("/bin/busybox", "/lib/ld-musl-x86_64.so.1");
    rootfs.write_interpreter_elf("/lib/ld-musl-x86_64.so.1");

    let output = run_rootfs(emulated_config(&rootfs, b"/bin/busybox").with_args([
        b"/bin/busybox".to_vec(),
        b"echo".to_vec(),
        b"dynamic".to_vec(),
    ]))
    .unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"dynamic\n");
    assert_eq!(output.stderr(), b"");
}

#[test]
fn run_rootfs_executes_guest_syscalls_and_captures_stdio() {
    let rootfs = TestRootfs::new("guest-syscalls");
    rootfs.write_guest_syscall_elf("/bin/guest", b"hello from guest\n", 7);

    let output = run_rootfs(RunRootfsConfig::new(rootfs.path(), b"/bin/guest".to_vec())).unwrap();

    assert_eq!(output.status(), 7);
    assert_eq!(output.stdout(), b"hello from guest\n");
    assert_eq!(output.stderr(), b"");
}

#[test]
fn run_rootfs_guest_fork_exec_wait4_without_mvp_emulator() {
    let rootfs = TestRootfs::new("guest-fork-exec-wait4");
    rootfs.write_guest_fork_exec_parent_elf("/bin/parent", "/bin/child");
    rootfs.write_guest_syscall_elf("/bin/child", b"child exec\n", 23);

    let output = run_rootfs(RunRootfsConfig::new(rootfs.path(), b"/bin/parent".to_vec())).unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"child exec\n");
    assert_eq!(output.stderr(), b"");
}

#[test]
fn run_rootfs_guest_clone_vfork_exec_wait4_without_mvp_emulator() {
    let rootfs = TestRootfs::new("guest-clone-vfork-exec-wait4");
    rootfs.write_guest_clone_vfork_exec_parent_elf("/bin/parent", "/bin/child");
    rootfs.write_guest_syscall_elf("/bin/child", b"child clone exec\n", 23);

    let output = run_rootfs(RunRootfsConfig::new(rootfs.path(), b"/bin/parent".to_vec())).unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"child clone exec\n");
    assert_eq!(output.stderr(), b"");
}

#[test]
fn run_rootfs_child_exec_proc_self_cmdline_reports_child_image() {
    let rootfs = TestRootfs::new("guest-child-exec-proc-self");
    rootfs.write_guest_fork_exec_parent_with_argv_elf("/bin/parent", "/bin/proc-reader");
    rootfs.write_guest_proc_self_cmdline_reader_elf("/bin/proc-reader");

    let output = run_rootfs(RunRootfsConfig::new(rootfs.path(), b"/bin/parent".to_vec())).unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"/bin/proc-reader\0--child\0");
    assert_eq!(output.stderr(), b"");
}

#[test]
fn run_rootfs_executes_shell_echo_pipeline_smoke() {
    let rootfs = TestRootfs::new("shell-pipe");
    rootfs.write_static_elf("/bin/sh");

    let output = run_rootfs(emulated_config(&rootfs, b"/bin/sh").with_args([
        b"/bin/sh".to_vec(),
        b"-c".to_vec(),
        b"echo hi | cat".to_vec(),
    ]))
    .unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"hi\n");
    assert_eq!(output.stderr(), b"");
}

#[test]
fn run_rootfs_executes_shell_procfs_devfs_smoke() {
    let rootfs = TestRootfs::new("shell-proc-dev");
    rootfs.write_static_elf("/bin/sh");

    let output = run_rootfs(emulated_config(&rootfs, b"/bin/sh").with_args([
        b"/bin/sh".to_vec(),
        b"-c".to_vec(),
        b"cat /proc/self/cmdline >/dev/null && head -c 4 /dev/zero >/dev/null".to_vec(),
    ]))
    .unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"");
    assert_eq!(output.stderr(), b"");
}

#[test]
fn run_rootfs_applies_initial_working_dir_to_relative_paths() {
    let rootfs = TestRootfs::new("working-dir");
    rootfs.write_static_elf("/bin/sh");
    rootfs.create_dir("/work");
    rootfs.write_file("/work/message.txt", b"from cwd\n");

    let output = run_rootfs(
        emulated_config(&rootfs, b"/bin/sh")
            .with_args([
                b"/bin/sh".to_vec(),
                b"-c".to_vec(),
                b"cat message.txt".to_vec(),
            ])
            .with_working_dir("/work"),
    )
    .unwrap();

    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"from cwd\n");
    assert_eq!(output.stderr(), b"");
}

#[test]
fn run_rootfs_does_not_use_mvp_emulator_by_default() {
    let rootfs = TestRootfs::new("mvp-disabled");
    rootfs.write_static_elf("/bin/busybox");

    let error = run_rootfs(
        RunRootfsConfig::new(rootfs.path(), b"/bin/busybox".to_vec()).with_args([
            b"/bin/busybox".to_vec(),
            b"echo".to_vec(),
            b"hello".to_vec(),
        ]),
    )
    .expect_err("synthetic busybox should not fall back to the MVP emulator by default");

    match &error {
        RunRootfsError::GuestRun(error) => {
            assert_ne!(error.linux_errno(), LinuxErrno::ENOSYS);
        }
        other => panic!("expected detailed guest runtime error, got {other:?}"),
    }
}

#[test]
fn guest_run_error_reports_native_fault_registers() {
    let error = RunRootfsError::GuestRun(Box::new(crate::GuestRunError::GuestExecution(
            crate::GuestExecutionError::Execution(mcr_jit::ExecutionError::NativeFault {
                signal: -1073741819,
                rip: 0x7000_004d_5305,
                address: 0x9139b,
                fs_base: 0x7000_0000,
                registers: mcr_jit::GuestRegisters {
                    rax: u64::MAX,
                    rcx: 1,
                    rdx: 0x7000_007b_3280,
                    rdi: 0x9139b,
                    rsp: 0x1001_ffb58,
                    ..mcr_jit::GuestRegisters::default()
                },
                instruction: Some(Box::new(mcr_jit::NativeFaultInstruction {
                    rip: 0x7000_004d_5305,
                    bytes: vec![0x48, 0x8b, 0x40, 0x28],
                    decoded: "code=Mov_r64_rm64 mnemonic=Mov len=4 operands=[reg=RAX,mem(seg=DS,base=RAX,index=None,scale=1,disp=0x28)]"
                        .to_string(),
                })),
                stack_words: vec![mcr_jit::NativeFaultStackWord {
                    address: 0x1001_ffb58,
                    value: 0x7000_004d_1234,
                }],
            }),
        )));
    let rendered = error.to_string();

    assert!(rendered.contains("fault registers:"));
    assert!(rendered.contains("fault instruction:"));
    assert!(rendered.contains("fault tls: fs_base=0x0000000070000000"));
    assert!(rendered.contains("bytes=48 8b 40 28"));
    assert!(rendered.contains("code=Mov_r64_rm64"));
    assert!(rendered.contains("rax=0xffffffffffffffff"));
    assert!(rendered.contains("rdi=0x000000000009139b"));
    assert!(rendered.contains("rsp=0x00000001001ffb58"));
    assert!(rendered.contains("fault registers ext:"));
    assert!(rendered.contains("fault stack words:"));
    assert!(
        rendered.contains("[0x00000001001ffb58]=0x00007000004d1234"),
        "{rendered}"
    );
}

fn emulated_config(rootfs: &TestRootfs, program: &[u8]) -> RunRootfsConfig {
    RunRootfsConfig::new(rootfs.path(), program.to_vec()).with_mvp_emulator(true)
}

struct TestRootfs {
    path: PathBuf,
    _native_guard: MutexGuard<'static, ()>,
    _guard: MutexGuard<'static, ()>,
}

impl TestRootfs {
    fn new(name: &str) -> Self {
        let native_guard = crate::test_support::native_execution_test_guard();
        let guard = RUN_ROOTFS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = std::env::temp_dir().join(format!(
            "mcr-runtime-run-rootfs-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self {
            path,
            _native_guard: native_guard,
            _guard: guard,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write_file(&self, guest_path: &str, bytes: &[u8]) {
        let path = self.host_path(guest_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn create_dir(&self, guest_path: &str) {
        fs::create_dir_all(self.host_path(guest_path)).unwrap();
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

    fn write_guest_syscall_elf(&self, guest_path: &str, stdout: &[u8], status: u32) {
        let mut code = Vec::new();
        push_mov_r32_imm32(&mut code, 0, Syscall::Write.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, 1);
        push_mov_r32_imm32(&mut code, 6, 0x402000);
        push_mov_r32_imm32(&mut code, 2, stdout.len() as u32);
        code.extend_from_slice(&[0x0f, 0x05]);
        push_mov_r32_imm32(&mut code, 0, Syscall::ExitGroup.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, status);
        code.extend_from_slice(&[0x0f, 0x05]);

        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_X,
                0x1000,
                0x401000,
                0x1000,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000,
                0x402000,
                stdout.len() as u64,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(PF_R, 0, 0x403000, 0x100, 0x100))
            .data_at(0x1000, code)
            .data_at(0x2000, stdout.to_vec())
            .build();
        self.write_file(guest_path, &elf);
    }

    fn write_guest_fork_exec_parent_elf(&self, guest_path: &str, child_path: &str) {
        let mut child_path_bytes = child_path.as_bytes().to_vec();
        child_path_bytes.push(0);

        let mut data = vec![0; 0x200];
        data[..child_path_bytes.len()].copy_from_slice(&child_path_bytes);

        let mut code = Vec::new();
        push_mov_r32_imm32(&mut code, 0, Syscall::Fork.number().raw() as u32);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall
        code.extend_from_slice(&[0x85, 0xc0]); // test eax,eax
        code.extend_from_slice(&[0x74, 0x22]); // je child_exec

        push_mov_r32_imm32(&mut code, 0, Syscall::Wait4.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, u32::MAX);
        push_mov_r32_imm32(&mut code, 6, 0x402100);
        push_mov_r32_imm32(&mut code, 2, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall
        push_mov_r32_imm32(&mut code, 0, Syscall::ExitGroup.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall

        push_mov_r32_imm32(&mut code, 0, Syscall::Execve.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, 0x402000);
        push_mov_r32_imm32(&mut code, 6, 0);
        push_mov_r32_imm32(&mut code, 2, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall

        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_X,
                0x1000,
                0x401000,
                0x1000,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000,
                0x402000,
                data.len() as u64,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(PF_R, 0, 0x403000, 0x100, 0x100))
            .data_at(0x1000, code)
            .data_at(0x2000, data)
            .build();
        self.write_file(guest_path, &elf);
    }

    fn write_guest_clone_vfork_exec_parent_elf(&self, guest_path: &str, child_path: &str) {
        let mut child_path_bytes = child_path.as_bytes().to_vec();
        child_path_bytes.push(0);

        let mut data = vec![0; 0x200];
        data[..child_path_bytes.len()].copy_from_slice(&child_path_bytes);

        let clone_flags = (LINUX_SIGCHLD | LINUX_CLONE_VM | LINUX_CLONE_VFORK) as u32;
        let mut code = Vec::new();
        push_mov_r32_imm32(&mut code, 0, Syscall::Clone.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, clone_flags);
        push_mov_r32_imm32(&mut code, 6, 0);
        push_mov_r32_imm32(&mut code, 2, 0);
        push_mov_r32_imm32(&mut code, 10, 0);
        push_mov_r32_imm32(&mut code, 8, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall
        code.extend_from_slice(&[0x85, 0xc0]); // test eax,eax
        let child_exec_jump_byte = code.len() + 1;
        code.extend_from_slice(&[0x74, 0x00]); // je child_exec

        push_mov_r32_imm32(&mut code, 0, Syscall::Wait4.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, u32::MAX);
        push_mov_r32_imm32(&mut code, 6, 0x402100);
        push_mov_r32_imm32(&mut code, 2, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall
        push_mov_r32_imm32(&mut code, 0, Syscall::ExitGroup.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall

        let child_exec_offset = code.len();
        let jump_offset = child_exec_offset
            .checked_sub(child_exec_jump_byte + 1)
            .and_then(|offset| i8::try_from(offset).ok())
            .unwrap();
        code[child_exec_jump_byte] = jump_offset as u8;

        push_mov_r32_imm32(&mut code, 0, Syscall::Execve.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, 0x402000);
        push_mov_r32_imm32(&mut code, 6, 0);
        push_mov_r32_imm32(&mut code, 2, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall

        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_X,
                0x1000,
                0x401000,
                0x1000,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000,
                0x402000,
                data.len() as u64,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(PF_R, 0, 0x403000, 0x100, 0x100))
            .data_at(0x1000, code)
            .data_at(0x2000, data)
            .build();
        self.write_file(guest_path, &elf);
    }

    fn write_guest_fork_exec_parent_with_argv_elf(&self, guest_path: &str, child_path: &str) {
        let mut child_path_bytes = child_path.as_bytes().to_vec();
        child_path_bytes.push(0);
        let child_arg = b"--child\0";

        let mut data = vec![0; 0x200];
        data[..child_path_bytes.len()].copy_from_slice(&child_path_bytes);
        data[0x40..0x40 + child_path_bytes.len()].copy_from_slice(&child_path_bytes);
        data[0x80..0x80 + child_arg.len()].copy_from_slice(child_arg);
        data[0x100..0x108].copy_from_slice(&0x402040u64.to_le_bytes());
        data[0x108..0x110].copy_from_slice(&0x402080u64.to_le_bytes());
        data[0x110..0x118].copy_from_slice(&0u64.to_le_bytes());

        let mut code = Vec::new();
        push_mov_r32_imm32(&mut code, 0, Syscall::Fork.number().raw() as u32);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall
        code.extend_from_slice(&[0x85, 0xc0]); // test eax,eax
        let child_exec_jump_byte = code.len() + 1;
        code.extend_from_slice(&[0x74, 0x00]); // je child_exec

        push_mov_r32_imm32(&mut code, 0, Syscall::Wait4.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, u32::MAX);
        push_mov_r32_imm32(&mut code, 6, 0x402180);
        push_mov_r32_imm32(&mut code, 2, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall
        push_mov_r32_imm32(&mut code, 0, Syscall::ExitGroup.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall

        let child_exec_offset = code.len();
        let jump_offset = child_exec_offset
            .checked_sub(child_exec_jump_byte + 1)
            .and_then(|offset| i8::try_from(offset).ok())
            .unwrap();
        code[child_exec_jump_byte] = jump_offset as u8;

        push_mov_r32_imm32(&mut code, 0, Syscall::Execve.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, 0x402000);
        push_mov_r32_imm32(&mut code, 6, 0x402100);
        push_mov_r32_imm32(&mut code, 2, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall

        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_X,
                0x1000,
                0x401000,
                0x1000,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000,
                0x402000,
                data.len() as u64,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(PF_R, 0, 0x403000, 0x100, 0x100))
            .data_at(0x1000, code)
            .data_at(0x2000, data)
            .build();
        self.write_file(guest_path, &elf);
    }

    fn write_guest_proc_self_cmdline_reader_elf(&self, guest_path: &str) {
        let proc_cmdline = b"/proc/self/cmdline\0";
        let mut data = vec![0; 0x200];
        data[..proc_cmdline.len()].copy_from_slice(proc_cmdline);

        let mut code = Vec::new();
        push_mov_r32_imm32(&mut code, 0, Syscall::Openat.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, AT_FDCWD as u32);
        push_mov_r32_imm32(&mut code, 6, 0x402000);
        push_mov_r32_imm32(&mut code, 2, O_RDONLY);
        push_mov_r32_imm32(&mut code, 10, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall
        code.extend_from_slice(&[0x89, 0xc7]); // mov edi,eax

        push_mov_r32_imm32(&mut code, 0, Syscall::Read.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 6, 0x402100);
        push_mov_r32_imm32(&mut code, 2, 0x40);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall
        code.extend_from_slice(&[0x89, 0xc2]); // mov edx,eax

        push_mov_r32_imm32(&mut code, 0, Syscall::Write.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, 1);
        push_mov_r32_imm32(&mut code, 6, 0x402100);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall

        push_mov_r32_imm32(&mut code, 0, Syscall::ExitGroup.number().raw() as u32);
        push_mov_r32_imm32(&mut code, 7, 0);
        code.extend_from_slice(&[0x0f, 0x05]); // syscall

        let elf = Elf64Builder::new()
            .entrypoint(0x401000)
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_X,
                0x1000,
                0x401000,
                0x1000,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000,
                0x402000,
                data.len() as u64,
                0x1000,
            ))
            .program_header(Elf64ProgramHeader::load(PF_R, 0, 0x403000, 0x100, 0x100))
            .data_at(0x1000, code)
            .data_at(0x2000, data)
            .build();
        self.write_file(guest_path, &elf);
    }

    fn write_dynamic_elf(&self, guest_path: &str, interpreter: &str) {
        let mut interpreter_path = interpreter.as_bytes().to_vec();
        interpreter_path.push(0);
        let elf = Elf64Builder::new()
            .object_type(ET_DYN)
            .entrypoint(0x1010)
            .program_header(Elf64ProgramHeader::new(
                PT_INTERP,
                PF_R,
                0x300,
                0,
                interpreter_path.len() as u64,
                interpreter_path.len() as u64,
                1,
            ))
            .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x2000))
            .data_at(0x300, interpreter_path)
            .data_at(0x400, vec![0x90; 4])
            .build();
        self.write_file(guest_path, &elf);
    }

    fn write_interpreter_elf(&self, guest_path: &str) {
        let elf = Elf64Builder::new()
            .object_type(ET_DYN)
            .entrypoint(0x400)
            .program_header(Elf64ProgramHeader::load(PF_R | PF_X, 0, 0, 0x1000, 0x1000))
            .data_at(0x400, vec![0x90; 4])
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

fn push_mov_r32_imm32(code: &mut Vec<u8>, register: u8, value: u32) {
    assert!(register < 16);
    if register >= 8 {
        code.push(0x41);
    }
    code.push(0xb8 + (register & 0x07));
    code.extend_from_slice(&value.to_le_bytes());
}
