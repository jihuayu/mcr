use super::*;
use mcr_snapshot::{SnapshotId, WritableUpperRoot};
use std::path::{Path, PathBuf};

#[test]
fn package_name_is_stable() {
    assert_eq!(CRATE_NAME, "mcr-build");
}

#[test]
fn loads_context_with_basic_dockerignore_rules() {
    let context = load_build_context(build_fixture("context-copy")).unwrap();
    let paths = context
        .entries()
        .iter()
        .map(|entry| entry.path().as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        paths,
        vec![
            ".dockerignore",
            "Dockerfile",
            "app",
            "app/main.txt",
            "local.txt"
        ]
    );
}

#[test]
fn plans_context_copy_and_local_add_against_snapshot_metadata() {
    let fixture = build_fixture("context-copy");
    let dockerfile = std::fs::read_to_string(fixture.join("Dockerfile")).unwrap();
    let plan = parse_dockerfile(&dockerfile).unwrap();
    let context = load_build_context(fixture).unwrap();

    let application = plan_context_application(&plan, &context).unwrap();

    assert_eq!(
        application.build_args().get("PROFILE"),
        Some(&Some("debug".to_owned()))
    );
    assert_eq!(application.env().get("APP_ENV"), Some(&"test".to_owned()));
    assert_eq!(
        application.env().get("PATH"),
        Some(&"/usr/bin:/bin".to_owned())
    );
    assert_eq!(application.workdir().as_str(), "/workspace");

    let destinations = application
        .operations()
        .iter()
        .map(|operation| operation.destination().as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        destinations,
        vec![
            "/workspace",
            "/opt",
            "/opt/app",
            "/opt/app/main.txt",
            "/workspace/local.txt"
        ]
    );

    let mut snapshot = SnapshotSpec::new(
        SnapshotId::new("copy-step").unwrap(),
        WritableUpperRoot::new("upper").unwrap(),
    );
    application.apply_metadata_to(&mut snapshot);
    let view = snapshot.deterministic_view();
    assert!(
        view.get(&SnapshotPath::new("/opt/app/main.txt").unwrap())
            .is_some()
    );
    assert!(
        view.get(&SnapshotPath::new("/workspace/local.txt").unwrap())
            .is_some()
    );
    assert!(
        view.get(&SnapshotPath::new("/opt/app/cache.tmp").unwrap())
            .is_none()
    );
}

#[test]
fn rejects_copy_sources_that_escape_context() {
    let context = load_build_context(build_fixture("context-copy")).unwrap();
    let plan = parse_dockerfile("FROM scratch\nCOPY ../secret /secret\n").unwrap();

    let error = plan_context_application(&plan, &context).unwrap_err();

    assert_eq!(
        error.kind(),
        &BuildApplicationErrorKind::ContextSourceEscape("../secret".to_owned())
    );
}

#[test]
fn rejects_ignored_copy_sources_as_missing_from_context() {
    let context = load_build_context(build_fixture("context-copy")).unwrap();
    let plan = parse_dockerfile("FROM scratch\nCOPY ignored.txt /ignored.txt\n").unwrap();

    let error = plan_context_application(&plan, &context).unwrap_err();

    assert_eq!(
        error.kind(),
        &BuildApplicationErrorKind::MissingContextSource("ignored.txt".to_owned())
    );
}

#[test]
fn rejects_remote_add_without_fetching() {
    let context = load_build_context(build_fixture("context-copy")).unwrap();
    let plan = parse_dockerfile("FROM scratch\nADD https://example.test/file /file\n").unwrap();

    let error = plan_context_application(&plan, &context).unwrap_err();

    assert_eq!(
        error.kind(),
        &BuildApplicationErrorKind::UnsupportedRemoteAdd("https://example.test/file".to_owned())
    );
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

fn build_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name)
}
