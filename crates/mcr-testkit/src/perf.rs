use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfEnvironment {
    fields: BTreeMap<String, String>,
}

impl PerfEnvironment {
    #[must_use]
    pub fn capture() -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("target_os".to_owned(), env::consts::OS.to_owned());
        fields.insert("target_arch".to_owned(), env::consts::ARCH.to_owned());
        fields.insert("target_family".to_owned(), env::consts::FAMILY.to_owned());
        fields.insert(
            "debug_assertions".to_owned(),
            cfg!(debug_assertions).to_string(),
        );
        fields.insert(
            "timestamp_unix_ms".to_owned(),
            unix_timestamp_ms().to_string(),
        );

        for key in [
            "CI",
            "GITHUB_ACTIONS",
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_SHA",
            "GITHUB_REF_NAME",
            "MCR_BIN",
            "MCR_FIXTURES_DIR",
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_IDENTIFIER",
            "PROCESSOR_REVISION",
            "RUNNER_ARCH",
            "RUNNER_OS",
        ] {
            if let Some(value) = env::var_os(key) {
                fields.insert(env_key(key), value.to_string_lossy().into_owned());
            }
        }

        if let Ok(current_dir) = env::current_dir() {
            fields.insert(
                "current_dir".to_owned(),
                current_dir.to_string_lossy().into_owned(),
            );
        }

        Self { fields }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl ToString) -> Self {
        self.fields.insert(key.into(), value.to_string());
        self
    }

    #[must_use]
    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }
}

impl Default for PerfEnvironment {
    fn default() -> Self {
        Self::capture()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PerfMeasurement {
    name: String,
    operations: u64,
    wall_time: Duration,
    fields: BTreeMap<String, String>,
}

impl PerfMeasurement {
    #[must_use]
    pub fn new(name: impl Into<String>, operations: u64, wall_time: Duration) -> Self {
        assert!(operations > 0, "perf measurements require operation counts");
        Self {
            name: name.into(),
            operations,
            wall_time,
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl ToString) -> Self {
        self.fields.insert(key.into(), value.to_string());
        self
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn operations(&self) -> u64 {
        self.operations
    }

    #[must_use]
    pub const fn wall_time(&self) -> Duration {
        self.wall_time
    }

    #[must_use]
    pub fn operations_per_second(&self) -> f64 {
        let seconds = self.wall_time.as_secs_f64();
        if seconds == 0.0 {
            return f64::INFINITY;
        }
        self.operations as f64 / seconds
    }

    #[must_use]
    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PerfBaselineReport {
    suite: String,
    environment: PerfEnvironment,
    measurements: Vec<PerfMeasurement>,
}

impl PerfBaselineReport {
    #[must_use]
    pub fn new(suite: impl Into<String>) -> Self {
        Self::with_environment(suite, PerfEnvironment::capture())
    }

    #[must_use]
    pub fn with_environment(suite: impl Into<String>, environment: PerfEnvironment) -> Self {
        Self {
            suite: suite.into(),
            environment,
            measurements: Vec::new(),
        }
    }

    pub fn push(&mut self, measurement: PerfMeasurement) {
        self.measurements.push(measurement);
    }

    pub fn measure<T>(
        &mut self,
        name: impl Into<String>,
        operations: u64,
        f: impl FnOnce() -> T,
    ) -> T {
        let name = name.into();
        let (result, wall_time) = measure_wall_time(f);
        self.push(PerfMeasurement::new(name, operations, wall_time));
        result
    }

    #[must_use]
    pub fn suite(&self) -> &str {
        &self.suite
    }

    #[must_use]
    pub const fn environment(&self) -> &PerfEnvironment {
        &self.environment
    }

    #[must_use]
    pub fn measurements(&self) -> &[PerfMeasurement] {
        &self.measurements
    }

    #[must_use]
    pub fn render(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for PerfBaselineReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "mcr_perf_baseline.version=1")?;
        writeln!(formatter, "mcr_perf_baseline.suite={}", self.suite)?;
        for (key, value) in self.environment.fields() {
            writeln!(formatter, "environment.{key}={value}")?;
        }
        for (index, measurement) in self.measurements.iter().enumerate() {
            writeln!(formatter, "measurement.{index}.name={}", measurement.name())?;
            writeln!(
                formatter,
                "measurement.{index}.wall_ms={:.3}",
                duration_ms(measurement.wall_time())
            )?;
            writeln!(
                formatter,
                "measurement.{index}.operations={}",
                measurement.operations()
            )?;
            writeln!(
                formatter,
                "measurement.{index}.ops_per_sec={:.3}",
                measurement.operations_per_second()
            )?;
            for (key, value) in measurement.fields() {
                writeln!(formatter, "measurement.{index}.field.{key}={value}")?;
            }
        }
        Ok(())
    }
}

pub fn measure_wall_time<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let result = f();
    (result, start.elapsed())
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn unix_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn env_key(key: &str) -> String {
    format!("env_{}", key.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{PerfBaselineReport, PerfEnvironment, PerfMeasurement};
    use std::time::Duration;

    #[test]
    fn perf_baseline_report_renders_environment_and_measurements() {
        let environment = PerfEnvironment::capture().with_field("host", "unit-test");
        let mut report = PerfBaselineReport::with_environment("unit", environment);
        report.push(
            PerfMeasurement::new("dispatch", 10, Duration::from_millis(5))
                .with_field("syscall", "getpid"),
        );

        let rendered = report.render();

        assert!(rendered.contains("mcr_perf_baseline.version=1"));
        assert!(rendered.contains("mcr_perf_baseline.suite=unit"));
        assert!(rendered.contains("environment.host=unit-test"));
        assert!(rendered.contains("measurement.0.name=dispatch"));
        assert!(rendered.contains("measurement.0.operations=10"));
        assert!(rendered.contains("measurement.0.field.syscall=getpid"));
    }
}
