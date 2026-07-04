use std::{error::Error, fmt};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildPlan {
    instructions: Vec<DockerfileInstruction>,
}

impl BuildPlan {
    #[must_use]
    pub fn new(instructions: Vec<DockerfileInstruction>) -> Self {
        Self { instructions }
    }

    #[must_use]
    pub fn instructions(&self) -> &[DockerfileInstruction] {
        &self.instructions
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DockerfileInstruction {
    From(String),
    Arg(String),
    Env(String),
    Workdir(String),
    Copy(String),
    Add(String),
    Run(String),
    Cmd(String),
    Entrypoint(String),
}

impl DockerfileInstruction {
    #[must_use]
    pub fn keyword(&self) -> &'static str {
        match self {
            Self::From(_) => "FROM",
            Self::Arg(_) => "ARG",
            Self::Env(_) => "ENV",
            Self::Workdir(_) => "WORKDIR",
            Self::Copy(_) => "COPY",
            Self::Add(_) => "ADD",
            Self::Run(_) => "RUN",
            Self::Cmd(_) => "CMD",
            Self::Entrypoint(_) => "ENTRYPOINT",
        }
    }

    #[must_use]
    pub fn raw_args(&self) -> &str {
        match self {
            Self::From(value)
            | Self::Arg(value)
            | Self::Env(value)
            | Self::Workdir(value)
            | Self::Copy(value)
            | Self::Add(value)
            | Self::Run(value)
            | Self::Cmd(value)
            | Self::Entrypoint(value) => value,
        }
    }
}

pub fn parse_dockerfile(input: &str) -> Result<BuildPlan, DockerfileParseError> {
    let mut instructions = Vec::new();
    let mut continuation = String::new();
    let mut continuation_start = 0usize;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if !continuation.is_empty() {
            continuation.push(' ');
        } else {
            continuation_start = line_number;
        }
        continuation.push_str(line.trim_end_matches('\\').trim_end());
        if line.ends_with('\\') {
            continue;
        }

        instructions.push(parse_instruction(continuation_start, &continuation)?);
        continuation.clear();
    }

    if !continuation.is_empty() {
        instructions.push(parse_instruction(continuation_start, &continuation)?);
    }

    Ok(BuildPlan::new(instructions))
}

fn parse_instruction(
    line_number: usize,
    line: &str,
) -> Result<DockerfileInstruction, DockerfileParseError> {
    let (keyword, args) = split_instruction(line)
        .ok_or_else(|| DockerfileParseError::missing_argument(line_number, line))?;
    if args.is_empty() {
        return Err(DockerfileParseError::missing_argument(line_number, keyword));
    }

    let instruction = match keyword.to_ascii_uppercase().as_str() {
        "FROM" => DockerfileInstruction::From(args.to_owned()),
        "ARG" => DockerfileInstruction::Arg(args.to_owned()),
        "ENV" => DockerfileInstruction::Env(args.to_owned()),
        "WORKDIR" => DockerfileInstruction::Workdir(args.to_owned()),
        "COPY" => DockerfileInstruction::Copy(args.to_owned()),
        "ADD" => DockerfileInstruction::Add(args.to_owned()),
        "RUN" => DockerfileInstruction::Run(args.to_owned()),
        "CMD" => DockerfileInstruction::Cmd(args.to_owned()),
        "ENTRYPOINT" => DockerfileInstruction::Entrypoint(args.to_owned()),
        unsupported => {
            return Err(DockerfileParseError::unsupported_instruction(
                line_number,
                unsupported,
            ));
        }
    };
    Ok(instruction)
}

fn split_instruction(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let split = trimmed.find(char::is_whitespace)?;
    Some((&trimmed[..split], trimmed[split..].trim()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerfileParseError {
    line: usize,
    kind: DockerfileParseErrorKind,
}

impl DockerfileParseError {
    fn unsupported_instruction(line: usize, instruction: impl Into<String>) -> Self {
        Self {
            line,
            kind: DockerfileParseErrorKind::UnsupportedInstruction(instruction.into()),
        }
    }

    fn missing_argument(line: usize, instruction: impl Into<String>) -> Self {
        Self {
            line,
            kind: DockerfileParseErrorKind::MissingArgument(instruction.into()),
        }
    }

    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    #[must_use]
    pub const fn kind(&self) -> &DockerfileParseErrorKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DockerfileParseErrorKind {
    UnsupportedInstruction(String),
    MissingArgument(String),
}

impl fmt::Display for DockerfileParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            DockerfileParseErrorKind::UnsupportedInstruction(instruction) => write!(
                formatter,
                "unsupported Dockerfile instruction `{instruction}` at line {}",
                self.line
            ),
            DockerfileParseErrorKind::MissingArgument(instruction) => write!(
                formatter,
                "Dockerfile instruction `{instruction}` at line {} is missing an argument",
                self.line
            ),
        }
    }
}

impl Error for DockerfileParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-build");
    }

    #[test]
    fn parses_supported_dockerfile_subset_into_plan() {
        let plan = parse_dockerfile(
            r#"
            # build fixture
            FROM alpine:3.21
            ARG PROFILE=release
            ENV RUST_LOG=info
            WORKDIR /src
            COPY . .
            ADD local.tar /opt/local
            RUN cargo build --release
            CMD ["/bin/app"]
            ENTRYPOINT ["/bin/sh", "-c"]
            "#,
        )
        .unwrap();

        assert_eq!(
            plan.instructions()
                .iter()
                .map(DockerfileInstruction::keyword)
                .collect::<Vec<_>>(),
            vec![
                "FROM",
                "ARG",
                "ENV",
                "WORKDIR",
                "COPY",
                "ADD",
                "RUN",
                "CMD",
                "ENTRYPOINT"
            ]
        );
        assert_eq!(plan.instructions()[0].raw_args(), "alpine:3.21");
        assert_eq!(plan.instructions()[6].raw_args(), "cargo build --release");
    }

    #[test]
    fn parses_line_continuations_without_executing_shell() {
        let plan = parse_dockerfile("FROM alpine\nRUN echo one \\\n    && echo two\n").unwrap();

        assert_eq!(
            plan.instructions(),
            &[
                DockerfileInstruction::From("alpine".to_owned()),
                DockerfileInstruction::Run("echo one && echo two".to_owned())
            ]
        );
    }

    #[test]
    fn rejects_unsupported_instruction_with_line_number() {
        let error = parse_dockerfile("FROM alpine\nHEALTHCHECK CMD true\n").unwrap_err();

        assert_eq!(error.line(), 2);
        assert_eq!(
            error.kind(),
            &DockerfileParseErrorKind::UnsupportedInstruction("HEALTHCHECK".to_owned())
        );
    }

    #[test]
    fn rejects_missing_arguments() {
        let error = parse_dockerfile("FROM\n").unwrap_err();

        assert_eq!(error.line(), 1);
        assert_eq!(
            error.kind(),
            &DockerfileParseErrorKind::MissingArgument("FROM".to_owned())
        );
    }
}
