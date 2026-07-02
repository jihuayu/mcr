use mcr_testkit::{FixtureRoot, GoldenOutput, Result, SmokeCommand};

#[test]
fn smoke_command_executes_and_asserts_golden_output() -> Result<()> {
    let fixtures = FixtureRoot::discover()?;
    let golden = GoldenOutput::from_fixture_files(
        &fixtures,
        "golden/smoke.stdout",
        "golden/smoke.stderr",
        0,
    )?;

    let output = SmokeCommand::new(env!("CARGO_BIN_EXE_mcr-testkit-echo"))
        .arg("--stdout")
        .arg("hello from smoke\n")
        .arg("--stderr")
        .arg("warning from smoke\n")
        .expected(golden)
        .run_and_assert()?;

    assert_eq!(output.status_code(), Some(0));
    Ok(())
}
