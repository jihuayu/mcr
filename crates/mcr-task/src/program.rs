use mcr_elf::{GuestMemoryImage, InitialStackConfig, parse_load_plan};

use crate::{DEFAULT_STACK_SIZE, DEFAULT_STACK_TOP, TaskError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestExecutable {
    path: Vec<u8>,
    bytes: Vec<u8>,
}

impl GuestExecutable {
    #[must_use]
    pub fn new(path: impl Into<Vec<u8>>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            bytes: bytes.into(),
        }
    }

    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestProgram {
    executable: GuestExecutable,
    interpreter: Option<GuestExecutable>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
}

impl GuestProgram {
    #[must_use]
    pub fn new(executable: GuestExecutable) -> Self {
        let argv = vec![executable.path().to_vec()];
        Self {
            executable,
            interpreter: None,
            argv,
            envp: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_interpreter(mut self, interpreter: GuestExecutable) -> Self {
        self.interpreter = Some(interpreter);
        self
    }

    #[must_use]
    pub fn with_args<I, A>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<Vec<u8>>,
    {
        self.argv = argv.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_env<I, E>(mut self, envp: I) -> Self
    where
        I: IntoIterator<Item = E>,
        E: Into<Vec<u8>>,
    {
        self.envp = envp.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn executable(&self) -> &GuestExecutable {
        &self.executable
    }

    #[must_use]
    pub fn interpreter(&self) -> Option<&GuestExecutable> {
        self.interpreter.as_ref()
    }

    #[must_use]
    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    #[must_use]
    pub fn envp(&self) -> &[Vec<u8>] {
        &self.envp
    }

    fn into_parts(self) -> GuestProgramParts {
        GuestProgramParts {
            executable: self.executable,
            interpreter: self.interpreter,
            argv: self.argv,
            envp: self.envp,
        }
    }
}

#[derive(Debug)]
struct GuestProgramParts {
    executable: GuestExecutable,
    interpreter: Option<GuestExecutable>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestImageState {
    pub(crate) executable: GuestExecutable,
    pub(crate) interpreter: Option<GuestExecutable>,
    pub(crate) argv: Vec<Vec<u8>>,
    pub(crate) envp: Vec<Vec<u8>>,
    pub(crate) memory: GuestMemoryImage,
}

impl GuestImageState {
    #[must_use]
    pub fn executable(&self) -> &GuestExecutable {
        &self.executable
    }

    #[must_use]
    pub fn interpreter(&self) -> Option<&GuestExecutable> {
        self.interpreter.as_ref()
    }

    #[must_use]
    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    #[must_use]
    pub fn envp(&self) -> &[Vec<u8>] {
        &self.envp
    }

    #[must_use]
    pub fn memory(&self) -> &GuestMemoryImage {
        &self.memory
    }
}

pub(crate) fn load_program(program: GuestProgram) -> Result<GuestImageState, TaskError> {
    let parts = program.into_parts();
    let load_plan = parse_load_plan(parts.executable.bytes())?;
    let memory = mcr_elf::build_guest_memory_image_with_interpreter(
        &load_plan,
        parts.executable.bytes(),
        parts.interpreter.as_ref().map(GuestExecutable::bytes),
        InitialStackConfig::new(
            DEFAULT_STACK_TOP,
            DEFAULT_STACK_SIZE,
            parts.executable.path().to_vec(),
        )
        .with_argv(parts.argv.clone())
        .with_envp(parts.envp.clone()),
    )?;

    Ok(GuestImageState {
        executable: parts.executable,
        interpreter: parts.interpreter,
        argv: parts.argv,
        envp: parts.envp,
        memory,
    })
}
