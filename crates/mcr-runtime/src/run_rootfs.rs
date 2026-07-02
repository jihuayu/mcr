use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use mcr_net::WinHostSocketTransport;
use mcr_sys::LinuxErrno;
use mcr_vfs::{
    AT_FDCWD, Fd, FdTable, O_DIRECTORY, O_RDONLY, PathTree, ProcSelfData, Rootfs, VfsError,
    VirtualFileSystem,
};

use crate::RuntimeFileSystem;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRootfsConfig {
    rootfs: PathBuf,
    program: Vec<u8>,
    args: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    mvp_emulator: bool,
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
            mvp_emulator: false,
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
    pub const fn with_mvp_emulator(mut self, enabled: bool) -> Self {
        self.mvp_emulator = enabled;
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
    pub const fn mvp_emulator(&self) -> bool {
        self.mvp_emulator
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

impl From<mcr_vfs::VfsError> for RunRootfsError {
    fn from(value: mcr_vfs::VfsError) -> Self {
        Self::Vfs(value)
    }
}

fn run_rootfs_linux_errno(errno: LinuxErrno) -> RunRootfsError {
    RunRootfsError::Linux(errno)
}

pub fn run_rootfs(config: RunRootfsConfig) -> Result<RunRootfsOutput, RunRootfsError> {
    if !config.rootfs.is_dir() {
        return Err(RunRootfsError::MissingRootfs(config.rootfs));
    }

    let mut vfs = load_rootfs(&config.rootfs)?;
    let mut program_loader = RuntimeFileSystem::new(vfs.clone(), ());
    let program = program_loader
        .load_guest_program(
            config.program.clone(),
            config.args.clone(),
            config.env.clone(),
        )
        .map_err(run_rootfs_linux_errno)?;
    vfs.set_proc_self(ProcSelfData::new(
        program.executable().path().to_vec(),
        program.argv().to_vec(),
        program.envp().to_vec(),
    ));
    let transport = WinHostSocketTransport::new().map_err(crate::RuntimeError::from)?;
    let mut runtime = crate::Runtime::with_tracer_vfs_and_socket_transport(
        program,
        vfs.clone(),
        crate::RuntimeDiagnosticsTracer::new(),
        transport,
    )?;

    match runtime.run_guest_until_exit() {
        Ok(status) => Ok(RunRootfsOutput::new(
            status,
            runtime.vfs().stdout_snapshot(),
            runtime.vfs().stderr_snapshot(),
        )),
        Err(error) if config.mvp_emulator() && error.linux_errno() == LinuxErrno::ENOEXEC => {
            dispatch_mvp_program(&mut vfs, &config.program, &config.args)
        }
        Err(error) => Err(run_rootfs_linux_errno(error.linux_errno())),
    }
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

    if program_name == "sh" {
        return dispatch_shell(vfs, &args[1..]);
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
        "head" => command_head(vfs, args, &[]),
        "sh" => dispatch_shell(vfs, args),
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

    command_cat(vfs, args, &[])
}

fn command_cat(
    vfs: &mut VirtualFileSystem,
    args: &[Vec<u8>],
    stdin: &[u8],
) -> Result<RunRootfsOutput, RunRootfsError> {
    if args.is_empty() {
        return Ok(RunRootfsOutput::new(0, stdin.to_vec(), Vec::new()));
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

fn command_head(
    vfs: &mut VirtualFileSystem,
    args: &[Vec<u8>],
    stdin: &[u8],
) -> Result<RunRootfsOutput, RunRootfsError> {
    let (count, path) = parse_head_args(args)?;
    let mut stdout = vec![0; count];
    let read = if let Some(path) = path {
        let fd = vfs.openat(AT_FDCWD, &path, mcr_vfs::OpenFlags::new(O_RDONLY), 0)?;
        let read = vfs.read(fd, &mut stdout)?;
        vfs.close(fd)?;
        read
    } else {
        let read = count.min(stdin.len());
        stdout[..read].copy_from_slice(&stdin[..read]);
        read
    };
    stdout.truncate(read);
    Ok(RunRootfsOutput::new(0, stdout, Vec::new()))
}

fn parse_head_args(args: &[Vec<u8>]) -> Result<(usize, Option<String>), RunRootfsError> {
    match args {
        [flag, count] if flag == b"-c" => Ok((parse_usize_arg(count)?, None)),
        [flag, count, path] if flag == b"-c" => {
            Ok((parse_usize_arg(count)?, Some(guest_arg_to_string(path)?)))
        }
        _ => Err(RunRootfsError::UnsupportedApplet("head".to_owned())),
    }
}

fn parse_usize_arg(arg: &[u8]) -> Result<usize, RunRootfsError> {
    guest_arg_to_string(arg)?
        .parse()
        .map_err(|_| RunRootfsError::UnsupportedApplet("head".to_owned()))
}

fn dispatch_shell(
    vfs: &mut VirtualFileSystem,
    args: &[Vec<u8>],
) -> Result<RunRootfsOutput, RunRootfsError> {
    match args {
        [flag, script] if flag == b"-c" => execute_shell_script(vfs, &guest_arg_to_string(script)?),
        _ => Err(RunRootfsError::UnsupportedApplet("sh".to_owned())),
    }
}

fn execute_shell_script(
    vfs: &mut VirtualFileSystem,
    script: &str,
) -> Result<RunRootfsOutput, RunRootfsError> {
    let tokens = lex_shell(script)?;
    let mut last = RunRootfsOutput::new(0, Vec::new(), Vec::new());
    for segment in split_tokens(&tokens, ShellToken::AndIf) {
        last = execute_shell_pipeline(vfs, segment)?;
        if last.status() != 0 {
            return Ok(last);
        }
    }
    Ok(last)
}

fn execute_shell_pipeline(
    vfs: &mut VirtualFileSystem,
    tokens: &[ShellToken],
) -> Result<RunRootfsOutput, RunRootfsError> {
    let mut stdin = Vec::new();
    let mut stderr = Vec::new();
    let mut last = RunRootfsOutput::new(0, Vec::new(), Vec::new());
    for command in split_tokens(tokens, ShellToken::Pipe) {
        last = execute_shell_command(vfs, command, &stdin)?;
        stderr.extend_from_slice(last.stderr());
        if last.status() != 0 {
            return Ok(RunRootfsOutput::new(last.status(), Vec::new(), stderr));
        }
        stdin = last.stdout().to_vec();
    }
    Ok(RunRootfsOutput::new(last.status(), stdin, stderr))
}

fn execute_shell_command(
    vfs: &mut VirtualFileSystem,
    tokens: &[ShellToken],
    stdin: &[u8],
) -> Result<RunRootfsOutput, RunRootfsError> {
    let (argv, redirect_stdout) = parse_shell_command(tokens)?;
    let Some((program, args)) = argv.split_first() else {
        return Err(RunRootfsError::UnsupportedShell(String::new()));
    };

    let mut output = match program.as_str() {
        "busybox" => execute_shell_busybox(vfs, args, stdin),
        "echo" => busybox_echo(&string_args_to_guest(args)),
        "cat" => command_cat(vfs, &string_args_to_guest(args), stdin),
        "head" => command_head(vfs, &string_args_to_guest(args), stdin),
        "true" => Ok(RunRootfsOutput::new(0, Vec::new(), Vec::new())),
        "false" => Ok(RunRootfsOutput::new(1, Vec::new(), Vec::new())),
        _ => Err(RunRootfsError::UnsupportedApplet(program.clone())),
    }?;

    if let Some(path) = redirect_stdout {
        write_redirect(vfs, &path, output.stdout())?;
        output = RunRootfsOutput::new(output.status(), Vec::new(), output.stderr().to_vec());
    }
    Ok(output)
}

fn execute_shell_busybox(
    vfs: &mut VirtualFileSystem,
    args: &[String],
    stdin: &[u8],
) -> Result<RunRootfsOutput, RunRootfsError> {
    let Some((applet, applet_args)) = args.split_first() else {
        return Err(RunRootfsError::UnsupportedApplet("busybox".to_owned()));
    };
    match applet.as_str() {
        "echo" => busybox_echo(&string_args_to_guest(applet_args)),
        "ls" => busybox_ls(vfs, &string_args_to_guest(applet_args)),
        "cat" => command_cat(vfs, &string_args_to_guest(applet_args), stdin),
        "head" => command_head(vfs, &string_args_to_guest(applet_args), stdin),
        "sh" => dispatch_shell(vfs, &string_args_to_guest(applet_args)),
        _ => Err(RunRootfsError::UnsupportedApplet(applet.clone())),
    }
}

fn parse_shell_command(
    tokens: &[ShellToken],
) -> Result<(Vec<String>, Option<String>), RunRootfsError> {
    let mut argv = Vec::new();
    let mut redirect_stdout = None;
    let mut index = 0;
    while index < tokens.len() {
        match &tokens[index] {
            ShellToken::Word(word) => argv.push(word.clone()),
            ShellToken::RedirectStdout => {
                let Some(ShellToken::Word(path)) = tokens.get(index + 1) else {
                    return Err(RunRootfsError::UnsupportedShell(format_tokens(tokens)));
                };
                redirect_stdout = Some(path.clone());
                index += 1;
            }
            ShellToken::Pipe | ShellToken::AndIf => {
                return Err(RunRootfsError::UnsupportedShell(format_tokens(tokens)));
            }
        }
        index += 1;
    }
    Ok((argv, redirect_stdout))
}

fn write_redirect(
    vfs: &mut VirtualFileSystem,
    path: &str,
    bytes: &[u8],
) -> Result<(), RunRootfsError> {
    let fd = vfs.openat(
        AT_FDCWD,
        path,
        mcr_vfs::OpenFlags::new(mcr_vfs::O_WRONLY | mcr_vfs::O_CREAT | mcr_vfs::O_TRUNC),
        0o666,
    )?;
    vfs.write(fd, bytes)?;
    vfs.close(fd)?;
    Ok(())
}

fn string_args_to_guest(args: &[String]) -> Vec<Vec<u8>> {
    args.iter().map(|arg| arg.as_bytes().to_vec()).collect()
}

fn split_tokens(
    tokens: &[ShellToken],
    delimiter: ShellToken,
) -> impl Iterator<Item = &[ShellToken]> {
    tokens.split(move |token| *token == delimiter)
}

fn format_tokens(tokens: &[ShellToken]) -> String {
    tokens
        .iter()
        .map(ShellToken::as_display)
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ShellToken {
    Word(String),
    Pipe,
    AndIf,
    RedirectStdout,
}

impl ShellToken {
    fn as_display(&self) -> String {
        match self {
            Self::Word(word) => word.clone(),
            Self::Pipe => "|".to_owned(),
            Self::AndIf => "&&".to_owned(),
            Self::RedirectStdout => ">".to_owned(),
        }
    }
}

fn lex_shell(script: &str) -> Result<Vec<ShellToken>, RunRootfsError> {
    let mut tokens = Vec::new();
    let mut chars = script.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => {}
            '|' => tokens.push(ShellToken::Pipe),
            '>' => tokens.push(ShellToken::RedirectStdout),
            '&' => {
                if chars.next() == Some('&') {
                    tokens.push(ShellToken::AndIf);
                } else {
                    return Err(RunRootfsError::UnsupportedShell(script.to_owned()));
                }
            }
            '\'' | '"' => tokens.push(ShellToken::Word(read_quoted_word(&mut chars, ch, script)?)),
            _ => tokens.push(ShellToken::Word(read_word(&mut chars, ch, script)?)),
        }
    }
    Ok(tokens)
}

fn read_word(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    first: char,
    script: &str,
) -> Result<String, RunRootfsError> {
    let mut word = String::from(first);
    while let Some(&ch) = chars.peek() {
        match ch {
            ch if ch.is_whitespace() || matches!(ch, '|' | '&' | '>') => break,
            '\'' | '"' => {
                chars.next();
                word.push_str(&read_quoted_word(chars, ch, script)?);
            }
            _ => {
                chars.next();
                word.push(ch);
            }
        }
    }
    Ok(word)
}

fn read_quoted_word(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    quote: char,
    script: &str,
) -> Result<String, RunRootfsError> {
    let mut word = String::new();
    for ch in chars.by_ref() {
        if ch == quote {
            return Ok(word);
        }
        word.push(ch);
    }
    Err(RunRootfsError::UnsupportedShell(script.to_owned()))
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

    tree.mount_minimal_devfs()?;
    tree.mount_minimal_procfs()?;
    materialize_minimal_dns_config(&mut tree)?;

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

fn materialize_minimal_dns_config(tree: &mut PathTree) -> Result<(), RunRootfsError> {
    create_dir_if_missing(tree, "/etc")?;
    create_file_if_missing(
        tree,
        "/etc/hosts",
        b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n",
        0o644,
    )?;
    create_file_if_missing(tree, "/etc/resolv.conf", b"nameserver 1.1.1.1\n", 0o644)?;
    create_file_if_missing(
        tree,
        "/etc/nsswitch.conf",
        b"hosts: files dns\npasswd: files\ngroup: files\n",
        0o644,
    )?;
    Ok(())
}

fn create_dir_if_missing(tree: &mut PathTree, path: &str) -> Result<(), RunRootfsError> {
    match tree.create_dir(path) {
        Ok(_) | Err(VfsError::AlreadyExists) => Ok(()),
        Err(error) => Err(RunRootfsError::Vfs(error)),
    }
}

fn create_file_if_missing(
    tree: &mut PathTree,
    path: &str,
    content: &'static [u8],
    mode: u32,
) -> Result<(), RunRootfsError> {
    match tree.create_file_with_content(path, content, mode) {
        Ok(_) | Err(VfsError::AlreadyExists) => Ok(()),
        Err(error) => Err(RunRootfsError::Vfs(error)),
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use mcr_sys::{LinuxErrno, Syscall};
    use mcr_testkit::elf::{ET_DYN, Elf64Builder, Elf64ProgramHeader, PF_R, PF_W, PF_X, PT_INTERP};

    use super::{RunRootfsConfig, RunRootfsError, run_rootfs};

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

        let output =
            run_rootfs(RunRootfsConfig::new(rootfs.path(), b"/bin/guest".to_vec())).unwrap();

        assert_eq!(output.status(), 7);
        assert_eq!(output.stdout(), b"hello from guest\n");
        assert_eq!(output.stderr(), b"");
    }

    #[test]
    fn run_rootfs_guest_fork_exec_wait4_without_mvp_emulator() {
        let rootfs = TestRootfs::new("guest-fork-exec-wait4");
        rootfs.write_guest_fork_exec_parent_elf("/bin/parent", "/bin/child");
        rootfs.write_guest_syscall_elf("/bin/child", b"child exec\n", 23);

        let output =
            run_rootfs(RunRootfsConfig::new(rootfs.path(), b"/bin/parent".to_vec())).unwrap();

        assert_eq!(output.status(), 0);
        assert_eq!(output.stdout(), b"child exec\n");
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

        match error {
            RunRootfsError::Linux(errno) => assert_eq!(errno, LinuxErrno::ENOEXEC),
            other => panic!("expected guest runtime ENOEXEC, got {other:?}"),
        }
    }

    fn emulated_config(rootfs: &TestRootfs, program: &[u8]) -> RunRootfsConfig {
        RunRootfsConfig::new(rootfs.path(), program.to_vec()).with_mvp_emulator(true)
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
        assert!(register < 8);
        code.push(0xb8 + register);
        code.extend_from_slice(&value.to_le_bytes());
    }
}
