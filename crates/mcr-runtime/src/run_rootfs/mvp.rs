use mcr_vfs::{AT_FDCWD, Fd, O_DIRECTORY, O_RDONLY, VirtualFileSystem};

use super::{RunRootfsError, RunRootfsOutput, guest_arg_to_string};

pub(super) fn dispatch_mvp_program(
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
