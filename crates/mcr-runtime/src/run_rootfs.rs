use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use mcr_jit::ExecutionError;
use mcr_net::WinHostSocketTransport;
use mcr_sys::LinuxErrno;
use mcr_vfs::ProcSelfData;

use crate::RuntimeFileSystem;

mod mvp;
mod rootfs;
#[cfg(test)]
mod tests;

use mvp::dispatch_mvp_program;
use rootfs::load_rootfs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRootfsConfig {
    rootfs: PathBuf,
    program: Vec<u8>,
    args: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    working_dir: Option<String>,
    mvp_emulator: bool,
    guest_step_limit: Option<u64>,
}

impl RunRootfsConfig {
    #[must_use]
    pub fn new(rootfs: impl Into<PathBuf>, program: impl Into<Vec<u8>>) -> Self {
        let program = program.into();
        Self {
            rootfs: rootfs.into(),
            args: vec![program.clone()],
            program,
            env: Vec::new(),
            working_dir: None,
            mvp_emulator: false,
            guest_step_limit: None,
        }
    }

    #[must_use]
    pub fn with_args<I, A>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<Vec<u8>>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_env<I, E>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = E>,
        E: Into<Vec<u8>>,
    {
        self.env = env.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_working_dir(mut self, working_dir: impl Into<String>) -> Self {
        self.working_dir = Some(working_dir.into());
        self
    }

    #[must_use]
    pub const fn with_mvp_emulator(mut self, enabled: bool) -> Self {
        self.mvp_emulator = enabled;
        self
    }

    #[must_use]
    pub const fn with_guest_step_limit(mut self, max_guest_steps: u64) -> Self {
        self.guest_step_limit = Some(max_guest_steps);
        self
    }

    #[must_use]
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    #[must_use]
    pub fn program(&self) -> &[u8] {
        &self.program
    }

    #[must_use]
    pub fn args(&self) -> &[Vec<u8>] {
        &self.args
    }

    #[must_use]
    pub fn env(&self) -> &[Vec<u8>] {
        &self.env
    }

    #[must_use]
    pub fn working_dir(&self) -> Option<&str> {
        self.working_dir.as_deref()
    }

    #[must_use]
    pub const fn mvp_emulator(&self) -> bool {
        self.mvp_emulator
    }

    #[must_use]
    pub const fn guest_step_limit(&self) -> Option<u64> {
        self.guest_step_limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRootfsOutput {
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl RunRootfsOutput {
    #[must_use]
    pub const fn new(status: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            status,
            stdout,
            stderr,
        }
    }

    #[must_use]
    pub const fn status(&self) -> i32 {
        self.status
    }

    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    #[must_use]
    pub fn into_parts(self) -> (i32, Vec<u8>, Vec<u8>) {
        (self.status, self.stdout, self.stderr)
    }
}

#[derive(Debug)]
pub enum RunRootfsError {
    InvalidGuestPath(Vec<u8>),
    InvalidUtf8(Vec<u8>),
    MissingRootfs(PathBuf),
    MissingExecutable(PathBuf),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Vfs(mcr_vfs::VfsError),
    Linux(LinuxErrno),
    GuestRun(Box<crate::GuestRunError>),
    UnsupportedProgram(String),
    UnsupportedApplet(String),
    UnsupportedShell(String),
}

impl fmt::Display for RunRootfsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGuestPath(path) => {
                write!(formatter, "invalid guest path `{}`", bytes_lossy(path))
            }
            Self::InvalidUtf8(bytes) => {
                write!(
                    formatter,
                    "argument is not valid UTF-8: `{}`",
                    bytes_lossy(bytes)
                )
            }
            Self::MissingRootfs(path) => {
                write!(formatter, "rootfs does not exist: {}", path.display())
            }
            Self::MissingExecutable(path) => {
                write!(
                    formatter,
                    "guest executable does not exist: {}",
                    path.display()
                )
            }
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Vfs(error) => write!(formatter, "{error}"),
            Self::Linux(errno) => write!(formatter, "guest runtime error: {errno}"),
            Self::GuestRun(error) => {
                write!(formatter, "guest runtime error: {error}")?;
                write_native_fault_details(formatter, error)
            }
            Self::UnsupportedProgram(program) => {
                write!(formatter, "unsupported MVP program `{program}`")
            }
            Self::UnsupportedApplet(applet) => {
                write!(formatter, "unsupported MVP busybox applet `{applet}`")
            }
            Self::UnsupportedShell(script) => {
                write!(formatter, "unsupported MVP shell fragment `{script}`")
            }
        }
    }
}

impl std::error::Error for RunRootfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Vfs(error) => Some(error),
            Self::GuestRun(error) => Some(error),
            Self::Linux(_) => None,
            Self::InvalidGuestPath(_)
            | Self::InvalidUtf8(_)
            | Self::MissingRootfs(_)
            | Self::MissingExecutable(_)
            | Self::UnsupportedProgram(_)
            | Self::UnsupportedApplet(_)
            | Self::UnsupportedShell(_) => None,
        }
    }
}

fn write_native_fault_details(
    formatter: &mut fmt::Formatter<'_>,
    error: &crate::GuestRunError,
) -> fmt::Result {
    let Some((registers, fs_base, instruction, stack_words)) = native_fault_details(error) else {
        return Ok(());
    };
    if let Some(instruction) = instruction {
        write!(formatter, "\nfault instruction: {instruction}")?;
    }
    write!(formatter, "\nfault tls: fs_base=0x{fs_base:016x}")?;
    write!(
        formatter,
        "\nfault registers: rax=0x{:016x} rbx=0x{:016x} rcx=0x{:016x} rdx=0x{:016x} rsi=0x{:016x} rdi=0x{:016x} rbp=0x{:016x} rsp=0x{:016x}",
        registers.rax,
        registers.rbx,
        registers.rcx,
        registers.rdx,
        registers.rsi,
        registers.rdi,
        registers.rbp,
        registers.rsp
    )?;
    write!(
        formatter,
        "\nfault registers ext: r8=0x{:016x} r9=0x{:016x} r10=0x{:016x} r11=0x{:016x} r12=0x{:016x} r13=0x{:016x} r14=0x{:016x} r15=0x{:016x} rflags=0x{:016x}",
        registers.r8,
        registers.r9,
        registers.r10,
        registers.r11,
        registers.r12,
        registers.r13,
        registers.r14,
        registers.r15,
        registers.rflags
    )?;
    if stack_words.is_empty() {
        return Ok(());
    }
    write!(formatter, "\nfault stack words:")?;
    for word in stack_words {
        write!(
            formatter,
            " [0x{:016x}]=0x{:016x}",
            word.address, word.value
        )?;
    }
    Ok(())
}

fn native_fault_details(
    error: &crate::GuestRunError,
) -> Option<(
    mcr_jit::GuestRegisters,
    u64,
    Option<&mcr_jit::NativeFaultInstruction>,
    &[mcr_jit::NativeFaultStackWord],
)> {
    match error {
        crate::GuestRunError::GuestExecution(crate::GuestExecutionError::Execution(
            ExecutionError::NativeFault {
                registers,
                fs_base,
                instruction,
                stack_words,
                ..
            },
        )) => Some((*registers, *fs_base, instruction.as_deref(), stack_words)),
        _ => None,
    }
}

impl From<mcr_vfs::VfsError> for RunRootfsError {
    fn from(value: mcr_vfs::VfsError) -> Self {
        Self::Vfs(value)
    }
}

fn run_rootfs_linux_errno(errno: LinuxErrno) -> RunRootfsError {
    RunRootfsError::Linux(errno)
}

pub fn run_rootfs(config: RunRootfsConfig) -> Result<RunRootfsOutput, RunRootfsError> {
    let run_start = Instant::now();
    crate::host_step_trace(format_args!(
        "run-rootfs start rootfs={} program={} args={} guest_step_limit={:?}",
        config.rootfs.display(),
        bytes_lossy(&config.program),
        config.args.len(),
        config.guest_step_limit()
    ));
    if !config.rootfs.is_dir() {
        return Err(RunRootfsError::MissingRootfs(config.rootfs));
    }

    let load_start = Instant::now();
    let mut vfs = load_rootfs(&config.rootfs)?;
    if let Some(working_dir) = config.working_dir() {
        vfs.chdir(working_dir)?;
    }
    crate::host_step_trace(format_args!(
        "run-rootfs rootfs-loaded elapsed_ms={}",
        crate::host_step_elapsed_ms(load_start)
    ));
    let mut program_loader = RuntimeFileSystem::new(vfs.clone(), ());
    let program_load_start = Instant::now();
    let program = program_loader
        .load_guest_program(
            config.program.clone(),
            config.args.clone(),
            config.env.clone(),
        )
        .map_err(run_rootfs_linux_errno)?;
    crate::host_step_trace(format_args!(
        "run-rootfs program-loaded elapsed_ms={} executable_bytes={} interpreter={}",
        crate::host_step_elapsed_ms(program_load_start),
        program.executable().bytes().len(),
        program.interpreter().is_some()
    ));
    vfs.set_proc_self(ProcSelfData::new(
        program.executable().path().to_vec(),
        program.argv().to_vec(),
        program.envp().to_vec(),
    ));
    let runtime_start = Instant::now();
    let transport = WinHostSocketTransport::new().map_err(crate::RuntimeError::from)?;
    let mut runtime = crate::Runtime::with_tracer_vfs_and_socket_transport(
        program,
        vfs.clone(),
        crate::RuntimeDiagnosticsTracer::new(),
        transport,
    )?;
    runtime.enable_native_execution();
    crate::host_step_trace(format_args!(
        "run-rootfs runtime-ready elapsed_ms={}",
        crate::host_step_elapsed_ms(runtime_start)
    ));

    let guest_start = Instant::now();
    let run_result = match config.guest_step_limit() {
        Some(max_guest_steps) => runtime.run_guest_until_exit_with_step_limit(max_guest_steps),
        None => runtime.run_guest_until_exit(),
    };
    crate::host_step_trace(format_args!(
        "run-rootfs guest-run-returned elapsed_ms={} total_elapsed_ms={}",
        crate::host_step_elapsed_ms(guest_start),
        crate::host_step_elapsed_ms(run_start)
    ));

    match run_result {
        Ok(status) => Ok(RunRootfsOutput::new(
            status,
            runtime.vfs().stdout_snapshot(),
            runtime.vfs().stderr_snapshot(),
        )),
        Err(error) if config.mvp_emulator() && error.linux_errno() == LinuxErrno::ENOEXEC => {
            dispatch_mvp_program(&mut vfs, &config.program, &config.args)
        }
        Err(error) => Err(RunRootfsError::GuestRun(Box::new(error))),
    }
}

fn guest_arg_to_string(bytes: &[u8]) -> Result<String, RunRootfsError> {
    String::from_utf8(bytes.to_vec())
        .map_err(|error| RunRootfsError::InvalidUtf8(error.into_bytes()))
}

fn bytes_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

impl From<crate::RuntimeError> for RunRootfsError {
    fn from(value: crate::RuntimeError) -> Self {
        match value {
            crate::RuntimeError::Task(error) => Self::UnsupportedProgram(error.to_string()),
            crate::RuntimeError::Memory(error) => Self::UnsupportedProgram(format!("{error:?}")),
            crate::RuntimeError::Network(error) => Self::UnsupportedProgram(error.to_string()),
        }
    }
}
