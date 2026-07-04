use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use mcr_runtime::{RunRootfsConfig, Runtime, run_rootfs};
use mcr_task::{GuestExecutable, GuestProgram};
use mcr_testkit::elf::{Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X};
use mcr_testkit::perf::{PerfBaselineReport, PerfMeasurement, measure_wall_time};

const ENTRYPOINT: u64 = 0x401000;
const DATA_ADDR: u64 = 0x402000;
const SYS_GETPID: u32 = 39;
const SYS_FORK: u32 = 57;
const SYS_EXECVE: u32 = 59;
const SYS_WAIT4: u32 = 61;
const SYS_EXIT_GROUP: u32 = 231;
static PERF_BASELINE_LOCK: Mutex<()> = Mutex::new(());

#[test]
#[ignore = "captures runtime performance baseline output"]
fn perf_baseline_runtime_syscall_and_process_paths() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = PERF_BASELINE_LOCK
        .lock()
        .expect("perf baseline mutex poisoned");
    let rootfs = TestRootfs::new("perf-baseline-runtime");
    rootfs.write_guest_syscall_loop_elf("/bin/getpid-loop", 512);
    rootfs.write_guest_exit_elf("/bin/child-exit");
    rootfs.write_guest_fork_exec_parent_elf("/bin/fork-exec-parent", "/bin/child-exit");

    let mut report = PerfBaselineReport::new("mcr-runtime synthetic performance baseline");

    let (syscall_result, syscall_wall_time) = measure_wall_time(|| {
        run_rootfs(RunRootfsConfig::new(
            rootfs.path(),
            b"/bin/getpid-loop".to_vec(),
        ))
    });
    let syscall_output = syscall_result?;
    assert_eq!(syscall_output.status(), 0);
    report.push(
        PerfMeasurement::new("runtime_syscall_dispatch_getpid", 512, syscall_wall_time)
            .with_field("syscall", "getpid")
            .with_field("program", "/bin/getpid-loop")
            .with_field("status", syscall_output.status()),
    );
    enforce_wall_time_gate("runtime_syscall_dispatch_getpid", syscall_wall_time, 500);

    let (process_result, process_wall_time) = measure_wall_time(|| {
        run_rootfs(RunRootfsConfig::new(
            rootfs.path(),
            b"/bin/fork-exec-parent".to_vec(),
        ))
    });
    let process_output = process_result?;
    assert_eq!(process_output.status(), 0);
    report.push(
        PerfMeasurement::new("runtime_fork_exec_wait4", 1, process_wall_time)
            .with_field("syscalls", "fork,execve,wait4")
            .with_field("program", "/bin/fork-exec-parent")
            .with_field("status", process_output.status()),
    );
    enforce_wall_time_gate("runtime_fork_exec_wait4", process_wall_time, 500);

    println!("{report}");
    Ok(())
}

#[test]
#[ignore = "captures native patch scanner performance baseline output"]
fn perf_baseline_native_patch_scanner() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = PERF_BASELINE_LOCK
        .lock()
        .expect("perf baseline mutex poisoned");
    let iterations = std::env::var("MCR_PERF_NATIVE_PATCH_SYSCALLS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(512);
    let mut code = Vec::with_capacity(iterations * 7 + 16);
    for _ in 0..iterations {
        push_mov_r32_imm32(&mut code, 0, SYS_GETPID);
        code.extend_from_slice(&[0x0f, 0x05]);
    }
    push_exit_group(&mut code, 0);
    let program = GuestProgram::new(GuestExecutable::new(
        b"/bin/native-patch".to_vec(),
        executable_elf(code, Vec::new()),
    ));
    let mut runtime = Runtime::new(program)?;
    runtime.enable_native_execution();

    let (step, wall_time) = measure_wall_time(|| runtime.dispatch_guest_execution());
    step?;

    let mut report = PerfBaselineReport::new("mcr-runtime native patch performance baseline");
    report.push(
        PerfMeasurement::new("runtime_native_patch_scan", iterations as u64, wall_time)
            .with_field("syscall_sites", iterations)
            .with_field("program", "/bin/native-patch"),
    );
    enforce_wall_time_gate("runtime_native_patch_scan", wall_time, 1_000);

    println!("{report}");
    Ok(())
}

struct TestRootfs {
    path: PathBuf,
}

impl TestRootfs {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mcr-runtime-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write_guest_syscall_loop_elf(&self, guest_path: &str, iterations: usize) {
        let mut code = Vec::with_capacity(iterations * 7 + 16);
        for _ in 0..iterations {
            push_mov_r32_imm32(&mut code, 0, SYS_GETPID);
            code.extend_from_slice(&[0x0f, 0x05]);
        }
        push_exit_group(&mut code, 0);
        self.write_elf(guest_path, executable_elf(code, Vec::new()));
    }

    fn write_guest_exit_elf(&self, guest_path: &str) {
        let mut code = Vec::new();
        push_exit_group(&mut code, 0);
        self.write_elf(guest_path, executable_elf(code, Vec::new()));
    }

    fn write_guest_fork_exec_parent_elf(&self, guest_path: &str, child_path: &str) {
        let mut child_path_bytes = child_path.as_bytes().to_vec();
        child_path_bytes.push(0);

        let mut data = vec![0; 0x200];
        data[..child_path_bytes.len()].copy_from_slice(&child_path_bytes);

        let mut code = Vec::new();
        push_mov_r32_imm32(&mut code, 0, SYS_FORK);
        code.extend_from_slice(&[0x0f, 0x05]);
        code.extend_from_slice(&[0x85, 0xc0]);
        let child_exec_jump_byte = code.len() + 1;
        code.extend_from_slice(&[0x74, 0x00]);

        push_mov_r32_imm32(&mut code, 0, SYS_WAIT4);
        push_mov_r32_imm32(&mut code, 7, u32::MAX);
        push_mov_r32_imm32(&mut code, 6, (DATA_ADDR + 0x100) as u32);
        push_mov_r32_imm32(&mut code, 2, 0);
        code.extend_from_slice(&[0x0f, 0x05]);
        push_exit_group(&mut code, 0);

        let child_exec_offset = code.len();
        let jump_offset = child_exec_offset
            .checked_sub(child_exec_jump_byte + 1)
            .and_then(|offset| i8::try_from(offset).ok())
            .expect("child exec jump should fit i8");
        code[child_exec_jump_byte] = jump_offset as u8;

        push_mov_r32_imm32(&mut code, 0, SYS_EXECVE);
        push_mov_r32_imm32(&mut code, 7, DATA_ADDR as u32);
        push_mov_r32_imm32(&mut code, 6, 0);
        push_mov_r32_imm32(&mut code, 2, 0);
        code.extend_from_slice(&[0x0f, 0x05]);

        self.write_elf(guest_path, executable_elf(code, data));
    }

    fn write_elf(&self, guest_path: &str, bytes: Vec<u8>) {
        let path = self.host_path(guest_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
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

fn executable_elf(code: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    let code_size = align_to_page(code.len() as u64);
    let mut builder = Elf64Builder::new()
        .entrypoint(ENTRYPOINT)
        .program_header(Elf64ProgramHeader::load(
            PF_R | PF_X,
            0x1000,
            ENTRYPOINT,
            code_size,
            code_size,
        ))
        .program_header(Elf64ProgramHeader::load(PF_R, 0, 0x403000, 0x100, 0x100))
        .data_at(0x1000, code);

    if !data.is_empty() {
        builder = builder
            .program_header(Elf64ProgramHeader::load(
                PF_R | PF_W,
                0x2000,
                DATA_ADDR,
                data.len() as u64,
                0x1000,
            ))
            .data_at(0x2000, data);
    }

    builder.build()
}

fn align_to_page(value: u64) -> u64 {
    (value + 0xfff) & !0xfff
}

fn enforce_wall_time_gate(name: &str, wall_time: std::time::Duration, default_max_wall_ms: u64) {
    if std::env::var_os("MCR_PERF_ENFORCE_GATES").is_none() {
        return;
    }

    let threshold_key = perf_threshold_env_key(name);
    let max_wall_ms = std::env::var(&threshold_key)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| *value > 0.0)
        .unwrap_or(default_max_wall_ms as f64);
    let actual_wall_ms = wall_time.as_secs_f64() * 1_000.0;
    assert!(
        actual_wall_ms <= max_wall_ms,
        "perf workload `{name}` exceeded wall-time gate: actual {actual_wall_ms:.3}ms > max {max_wall_ms:.3}ms; override with {threshold_key}",
    );
}

fn perf_threshold_env_key(name: &str) -> String {
    let normalized = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("MCR_PERF_MAX_WALL_MS_{normalized}")
}

fn push_exit_group(code: &mut Vec<u8>, status: u32) {
    push_mov_r32_imm32(code, 0, SYS_EXIT_GROUP);
    push_mov_r32_imm32(code, 7, status);
    code.extend_from_slice(&[0x0f, 0x05]);
}

fn push_mov_r32_imm32(code: &mut Vec<u8>, register: u8, value: u32) {
    assert!(register < 16);
    if register >= 8 {
        code.push(0x41);
    }
    code.push(0xb8 + (register & 0x07));
    code.extend_from_slice(&value.to_le_bytes());
}
