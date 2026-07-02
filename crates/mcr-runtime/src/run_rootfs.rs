use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use mcr_elf::ElfValidationError;
use mcr_sys::{GuestContext, Syscall, SyscallRegisters};
use mcr_task::{GuestExecutable, GuestProgram, INITIAL_GUEST_PID, INITIAL_GUEST_TID};
use mcr_vfs::{AT_FDCWD, Fd, FdTable, O_DIRECTORY, O_RDONLY, PathTree, Rootfs, VirtualFileSystem};

use crate::RuntimeWithTracer;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRootfsConfig {
    rootfs: PathBuf,
    program: Vec<u8>,
    args: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
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
    Elf(ElfValidationError),
    UnsupportedProgram(String),
    UnsupportedApplet(String),
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
            Self::Elf(error) => write!(formatter, "{error}"),
            Self::UnsupportedProgram(program) => {
                write!(formatter, "unsupported MVP program `{program}`")
            }
            Self::UnsupportedApplet(applet) => {
                write!(formatter, "unsupported MVP busybox applet `{applet}`")
            }
        }
    }
}

impl std::error::Error for RunRootfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Vfs(error) => Some(error),
            Self::Elf(error) => Some(error),
            Self::InvalidGuestPath(_)
            | Self::InvalidUtf8(_)
            | Self::MissingRootfs(_)
            | Self::MissingExecutable(_)
            | Self::UnsupportedProgram(_)
            | Self::UnsupportedApplet(_) => None,
        }
    }
}

impl From<mcr_vfs::VfsError> for RunRootfsError {
    fn from(value: mcr_vfs::VfsError) -> Self {
        Self::Vfs(value)
    }
}

impl From<ElfValidationError> for RunRootfsError {
    fn from(value: ElfValidationError) -> Self {
        Self::Elf(value)
    }
}

pub fn run_rootfs(config: RunRootfsConfig) -> Result<RunRootfsOutput, RunRootfsError> {
    if !config.rootfs.is_dir() {
        return Err(RunRootfsError::MissingRootfs(config.rootfs));
    }

    let executable = read_guest_executable(&config)?;
    let mut program = GuestProgram::new(GuestExecutable::new(
        config.program.clone(),
        executable.bytes,
    ))
    .with_args(config.args.clone())
    .with_env(config.env.clone());
    if let Some(interpreter) = executable.interpreter {
        program = program.with_interpreter(interpreter);
    }
    let mut runtime = RuntimeWithTracer::with_diagnostics(program)?;
    runtime.dispatch_syscall(GuestContext::new(
        INITIAL_GUEST_PID,
        INITIAL_GUEST_TID,
        SyscallRegisters {
            rax: Syscall::Getpid.number().raw(),
            rip: runtime
                .kernel()
                .task(INITIAL_GUEST_TID)
                .expect("initial task exists")
                .regs()
                .rip(),
            ..SyscallRegisters::default()
        },
    ));

    let mut vfs = load_rootfs(&config.rootfs)?;
    let output = dispatch_mvp_program(&mut vfs, &config.program, &config.args)?;
    let status = output.status();
    runtime.dispatch_syscall(GuestContext::new(
        INITIAL_GUEST_PID,
        INITIAL_GUEST_TID,
        SyscallRegisters {
            rax: Syscall::ExitGroup.number().raw(),
            rdi: status as u64,
            rip: runtime
                .kernel()
                .task(INITIAL_GUEST_TID)
                .expect("initial task exists")
                .regs()
                .rip(),
            ..SyscallRegisters::default()
        },
    ));

    Ok(output)
}

#[derive(Debug)]
struct LoadedGuestExecutable {
    bytes: Vec<u8>,
    interpreter: Option<GuestExecutable>,
}

fn read_guest_executable(
    config: &RunRootfsConfig,
) -> Result<LoadedGuestExecutable, RunRootfsError> {
    let path = host_path_for_guest(&config.rootfs, &config.program)?;
    if !path.is_file() {
        return Err(RunRootfsError::MissingExecutable(path));
    }
    let bytes = fs::read(&path).map_err(|source| RunRootfsError::Io {
        path: path.clone(),
        source,
    })?;
    let load_plan = mcr_elf::parse_load_plan(&bytes)?;
    let interpreter = load_plan
        .interpreter()
        .map(|interpreter| read_guest_interpreter(config, interpreter.as_bytes()))
        .transpose()?;
    Ok(LoadedGuestExecutable { bytes, interpreter })
}

fn read_guest_interpreter(
    config: &RunRootfsConfig,
    interpreter_path: &[u8],
) -> Result<GuestExecutable, RunRootfsError> {
    let path = host_path_for_guest(&config.rootfs, interpreter_path)?;
    if !path.is_file() {
        return Err(RunRootfsError::MissingExecutable(path));
    }
    let bytes = fs::read(&path).map_err(|source| RunRootfsError::Io {
        path: path.clone(),
        source,
    })?;
    mcr_elf::parse_load_plan(&bytes)?;
    Ok(GuestExecutable::new(interpreter_path.to_vec(), bytes))
}

fn dispatch_mvp_program(
    vfs: &mut VirtualFileSystem,
    program: &[u8],
    args: &[Vec<u8>],
) -> Result<RunRootfsOutput, RunRootfsError> {
    let program = guest_arg_to_string(program)?;
    let Some(program_name) = program.rsplit('/').next() else {
        return Err(RunRootfsError::UnsupportedProgram(program));
    };

    if program_name == "busybox" {
        let applet = args
            .get(1)
            .ok_or_else(|| RunRootfsError::UnsupportedApplet(String::new()))?;
        return dispatch_busybox_applet(vfs, applet, &args[2..]);
    }

    dispatch_busybox_applet(vfs, program_name.as_bytes(), &args[1..])
}

fn dispatch_busybox_applet(
    vfs: &mut VirtualFileSystem,
    applet: &[u8],
    args: &[Vec<u8>],
) -> Result<RunRootfsOutput, RunRootfsError> {
    let applet = guest_arg_to_string(applet)?;
    match applet.as_str() {
        "echo" => busybox_echo(args),
        "ls" => busybox_ls(vfs, args),
        "cat" => busybox_cat(vfs, args),
        _ => Err(RunRootfsError::UnsupportedApplet(applet)),
    }
}

fn busybox_echo(args: &[Vec<u8>]) -> Result<RunRootfsOutput, RunRootfsError> {
    let mut stdout = Vec::new();
    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            stdout.push(b' ');
        }
        stdout.extend_from_slice(arg);
    }
    stdout.push(b'\n');
    Ok(RunRootfsOutput::new(0, stdout, Vec::new()))
}

fn busybox_ls(
    vfs: &mut VirtualFileSystem,
    args: &[Vec<u8>],
) -> Result<RunRootfsOutput, RunRootfsError> {
    let path = match args {
        [] => "/".to_owned(),
        [path] => guest_arg_to_string(path)?,
        _ => return Err(RunRootfsError::UnsupportedApplet("ls".to_owned())),
    };
    let mut stdout = Vec::new();
    let fd = vfs.openat(
        AT_FDCWD,
        &path,
        mcr_vfs::OpenFlags::new(O_RDONLY | O_DIRECTORY),
        0,
    )?;
    let entries = vfs.getdents64(fd, 64 * 1024)?;
    vfs.close(fd)?;
    for entry in entries
        .into_iter()
        .filter(|entry| entry.name != "." && entry.name != "..")
    {
        stdout.extend_from_slice(entry.name.as_bytes());
        stdout.push(b'\n');
    }
    Ok(RunRootfsOutput::new(0, stdout, Vec::new()))
}

fn busybox_cat(
    vfs: &mut VirtualFileSystem,
    args: &[Vec<u8>],
) -> Result<RunRootfsOutput, RunRootfsError> {
    if args.is_empty() {
        return Err(RunRootfsError::UnsupportedApplet("cat".to_owned()));
    }

    let mut stdout = Vec::new();
    for path in args {
        let path = guest_arg_to_string(path)?;
        let fd = vfs.openat(AT_FDCWD, &path, mcr_vfs::OpenFlags::new(O_RDONLY), 0)?;
        read_all(vfs, fd, &mut stdout)?;
        vfs.close(fd)?;
    }
    Ok(RunRootfsOutput::new(0, stdout, Vec::new()))
}

fn read_all(
    vfs: &mut VirtualFileSystem,
    fd: Fd,
    output: &mut Vec<u8>,
) -> Result<(), RunRootfsError> {
    let mut buffer = [0; 8192];
    loop {
        let count = vfs.read(fd, &mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

fn load_rootfs(rootfs: &Path) -> Result<VirtualFileSystem, RunRootfsError> {
    let mut tree = PathTree::new();
    let mut entries = Vec::new();
    collect_rootfs_entries(rootfs, rootfs, &mut entries)?;
    entries.sort_by_key(|entry| (entry.depth, entry.relative.clone()));

    for entry in entries {
        let guest_path = format!("/{}", entry.relative.to_string_lossy().replace('\\', "/"));
        if entry.kind.is_dir() {
            tree.create_dir(&guest_path)?;
        } else if entry.kind.is_symlink() {
            let host_path = rootfs.join(&entry.relative);
            let target = fs::read_link(&host_path).map_err(|source| RunRootfsError::Io {
                path: host_path,
                source,
            })?;
            tree.create_symlink(&guest_path, target.to_string_lossy().into_owned())?;
        } else if entry.kind.is_file() {
            let host_path = rootfs.join(&entry.relative);
            let content = fs::read(&host_path).map_err(|source| RunRootfsError::Io {
                path: host_path,
                source,
            })?;
            tree.create_file_with_content(&guest_path, content, 0o755)?;
        }
    }

    Ok(VirtualFileSystem::from_parts(
        Rootfs::new(rootfs),
        tree,
        FdTable::with_stdio(),
    ))
}

#[derive(Debug)]
struct RootfsEntry {
    relative: PathBuf,
    depth: usize,
    kind: fs::FileType,
}

fn collect_rootfs_entries(
    rootfs: &Path,
    current: &Path,
    entries: &mut Vec<RootfsEntry>,
) -> Result<(), RunRootfsError> {
    for item in fs::read_dir(current).map_err(|source| RunRootfsError::Io {
        path: current.to_path_buf(),
        source,
    })? {
        let item = item.map_err(|source| RunRootfsError::Io {
            path: current.to_path_buf(),
            source,
        })?;
        let path = item.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| RunRootfsError::Io {
            path: path.clone(),
            source,
        })?;
        let relative = path
            .strip_prefix(rootfs)
            .expect("walked path is under rootfs")
            .to_path_buf();
        let depth = relative.components().count();
        let kind = metadata.file_type();
        entries.push(RootfsEntry {
            relative: relative.clone(),
            depth,
            kind,
        });
        if kind.is_dir() {
            collect_rootfs_entries(rootfs, &path, entries)?;
        }
    }
    Ok(())
}

fn host_path_for_guest(rootfs: &Path, guest_path: &[u8]) -> Result<PathBuf, RunRootfsError> {
    let guest_path = guest_arg_to_string(guest_path)?;
    if !guest_path.starts_with('/') || guest_path.as_bytes().contains(&0) {
        return Err(RunRootfsError::InvalidGuestPath(guest_path.into_bytes()));
    }

    let mut host = rootfs.to_path_buf();
    for component in guest_path.split('/').filter(|part| !part.is_empty()) {
        if matches!(component, "." | "..") {
            return Err(RunRootfsError::InvalidGuestPath(guest_path.into_bytes()));
        }
        host.push(component);
    }
    Ok(host)
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
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use mcr_testkit::elf::{ET_DYN, Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X, PT_INTERP};

    use super::{RunRootfsConfig, run_rootfs};

    #[test]
    fn run_rootfs_executes_busybox_echo_smoke() {
        let rootfs = TestRootfs::new("echo");
        rootfs.write_static_elf("/bin/busybox");

        let output = run_rootfs(
            RunRootfsConfig::new(rootfs.path(), b"/bin/busybox".to_vec()).with_args([
                b"/bin/busybox".to_vec(),
                b"echo".to_vec(),
                b"hello".to_vec(),
            ]),
        )
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

        let ls = run_rootfs(
            RunRootfsConfig::new(rootfs.path(), b"/bin/busybox".to_vec()).with_args([
                b"/bin/busybox".to_vec(),
                b"ls".to_vec(),
                b"/".to_vec(),
            ]),
        )
        .unwrap();
        assert_eq!(ls.status(), 0);
        assert_eq!(ls.stdout(), b"bin\netc\nhello.txt\n");

        let cat = run_rootfs(
            RunRootfsConfig::new(rootfs.path(), b"/bin/busybox".to_vec()).with_args([
                b"/bin/busybox".to_vec(),
                b"cat".to_vec(),
                b"/etc/os-release".to_vec(),
            ]),
        )
        .unwrap();
        assert_eq!(cat.status(), 0);
        assert_eq!(cat.stdout(), b"NAME=Alpine\n");
    }

    #[test]
    fn run_rootfs_loads_dynamic_interpreter_from_rootfs() {
        let rootfs = TestRootfs::new("dynamic");
        rootfs.write_dynamic_elf("/bin/busybox", "/lib/ld-musl-x86_64.so.1");
        rootfs.write_interpreter_elf("/lib/ld-musl-x86_64.so.1");

        let output = run_rootfs(
            RunRootfsConfig::new(rootfs.path(), b"/bin/busybox".to_vec()).with_args([
                b"/bin/busybox".to_vec(),
                b"echo".to_vec(),
                b"dynamic".to_vec(),
            ]),
        )
        .unwrap();

        assert_eq!(output.status(), 0);
        assert_eq!(output.stdout(), b"dynamic\n");
        assert_eq!(output.stderr(), b"");
    }

    struct TestRootfs {
        path: PathBuf,
    }

    impl TestRootfs {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mcr-runtime-run-rootfs-{name}-{}",
                std::process::id()
            ));
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
}
