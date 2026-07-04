use std::env;
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use mcr_net::{DnsCache, DnsCacheQuery, DnsRecordType, GuestDnsConfig};
use mcr_task::{HOST_WORKER_POOL_MAX_WORKERS, HostWorkerPools};
use mcr_testkit::perf::{PerfBaselineReport, PerfMeasurement, measure_wall_time};
use mcr_testkit::{FixtureRoot, Result, SmokeCommand};

const ALPINE_ROOTFS: &str = "alpine-rootfs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestPerfWorkload {
    name: &'static str,
    script: &'static str,
    operations: u64,
    category: &'static str,
    requires_public_network: bool,
    gate_max_wall_ms: u64,
}

const SHELL_STARTUP: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_shell_startup_true",
    script: "true",
    operations: 1,
    category: "shell_fork_exec_wait4",
    requires_public_network: false,
    gate_max_wall_ms: 1_000,
};
const SMALL_FILE_IO: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_small_file_io",
    script: "i=0; while [ $i -lt 16 ]; do p=/tmp/mcr-perf-small-$$-$i; printf 'payload\n' > \"$p\" && cat \"$p\" >/dev/null && rm \"$p\"; i=$((i+1)); done",
    operations: 16,
    category: "small_file_io",
    requires_public_network: false,
    gate_max_wall_ms: 4_000,
};
const DIRECTORY_METADATA_WALK: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_directory_metadata_walk",
    script: "d=/tmp/mcr-perf-dir-$$; i=0; while [ $i -lt 32 ]; do rm -f \"$d/f$i\"; i=$((i+1)); done; rmdir \"$d\" 2>/dev/null || true; mkdir -p \"$d\"; i=0; while [ $i -lt 32 ]; do touch \"$d/f$i\"; i=$((i+1)); done; ls -l \"$d\" >/dev/null; i=0; while [ $i -lt 32 ]; do rm \"$d/f$i\"; i=$((i+1)); done; rmdir \"$d\"",
    operations: 32,
    category: "directory_metadata_walk",
    requires_public_network: false,
    gate_max_wall_ms: 8_000,
};
const CURL_EXAMPLE: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_curl_example",
    script: "curl -fsSL https://example.com >/dev/null",
    operations: 1,
    category: "network_smoke_curl",
    requires_public_network: true,
    gate_max_wall_ms: 3_000,
};
const GIT_LS_REMOTE: GuestPerfWorkload = GuestPerfWorkload {
    name: "guest_git_ls_remote",
    script: "git ls-remote https://github.com/octocat/Hello-World.git HEAD >/dev/null",
    operations: 1,
    category: "network_smoke_git",
    requires_public_network: true,
    gate_max_wall_ms: 5_000,
};

const GUEST_PERF_WORKLOADS: &[GuestPerfWorkload] = &[
    SHELL_STARTUP,
    SMALL_FILE_IO,
    DIRECTORY_METADATA_WALK,
    CURL_EXAMPLE,
    GIT_LS_REMOTE,
];

#[derive(Debug)]
struct GuestPerfContext {
    mcr: OsString,
    rootfs: PathBuf,
}

impl GuestPerfContext {
    fn discover() -> Result<Option<Self>> {
        let Some(mcr) = env::var_os("MCR_BIN") else {
            eprintln!("skipping guest perf baseline: set MCR_BIN to the mcr executable");
            return Ok(None);
        };

        if mcr.as_os_str().is_empty() {
            eprintln!("skipping guest perf baseline: MCR_BIN is empty");
            return Ok(None);
        }

        let fixtures = FixtureRoot::discover()?;
        let rootfs = fixtures.rootfs_fixture(ALPINE_ROOTFS)?;
        let rootfs_path = rootfs.absolute_path(&fixtures);
        if !rootfs.materialized(&fixtures) {
            eprintln!(
                "skipping guest perf baseline: materialize {} at {}",
                rootfs.name(),
                rootfs_path.display()
            );
            return Ok(None);
        }

        Ok(Some(Self {
            mcr: resolve_mcr_bin(mcr, &fixtures),
            rootfs: rootfs_path,
        }))
    }

    fn command(&self, workload: GuestPerfWorkload) -> SmokeCommand {
        SmokeCommand::new(self.mcr.clone())
            .arg("run-rootfs")
            .arg(self.rootfs.clone())
            .arg("/bin/sh")
            .arg("-c")
            .arg(workload.script)
    }
}

fn resolve_mcr_bin(mcr: OsString, fixtures: &FixtureRoot) -> OsString {
    let path = PathBuf::from(&mcr);
    if path.is_absolute() {
        return mcr;
    }

    let Some(workspace) = fixtures.path().parent().and_then(std::path::Path::parent) else {
        return mcr;
    };
    let candidate = workspace.join(&path);
    if candidate.exists() {
        return candidate.into_os_string();
    }

    mcr
}

#[test]
fn perf_baseline_guest_workloads_model_expected_commands() {
    let context = GuestPerfContext {
        mcr: OsString::from("mcr"),
        rootfs: PathBuf::from(ALPINE_ROOTFS),
    };

    for workload in GUEST_PERF_WORKLOADS {
        let command = context.command(*workload).command();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(command.get_program(), "mcr");
        assert_eq!(
            args,
            vec![
                "run-rootfs".to_owned(),
                ALPINE_ROOTFS.to_owned(),
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                workload.script.to_owned(),
            ],
            "guest perf workload `{}` must run through mcr run-rootfs",
            workload.name
        );
        assert!(workload.operations > 0);
        assert!(workload.gate_max_wall_ms > 0);
    }
}

#[test]
fn perf_gate_threshold_keys_are_stable() {
    assert_eq!(
        perf_threshold_env_key("guest_git_ls_remote"),
        "MCR_PERF_MAX_WALL_MS_GUEST_GIT_LS_REMOTE"
    );
}

#[test]
#[ignore = "requires MCR_BIN, materialized alpine-rootfs, and public network for curl/git workloads"]
fn perf_baseline_guest_smoke_workloads() -> Result<()> {
    let Some(context) = GuestPerfContext::discover()? else {
        return Ok(());
    };
    let mut report = PerfBaselineReport::new("mcr-testkit guest workload performance baseline");
    let run_public_network = env::var_os("MCR_PERF_PUBLIC_NETWORK").is_some();

    for workload in GUEST_PERF_WORKLOADS {
        if workload.requires_public_network && !run_public_network {
            eprintln!(
                "skipping guest perf workload `{}`: set MCR_PERF_PUBLIC_NETWORK=1",
                workload.name
            );
            continue;
        }

        let command = context.command(*workload);
        let (output_result, wall_time) = measure_wall_time(|| command.run());
        let output = output_result?;
        report.push(
            PerfMeasurement::new(workload.name, workload.operations, wall_time)
                .with_field("category", workload.category)
                .with_field("script", workload.script)
                .with_field("requires_public_network", workload.requires_public_network)
                .with_field("gate_max_wall_ms", workload.gate_max_wall_ms)
                .with_field("status", output.status_code().unwrap_or_default()),
        );

        assert_eq!(
            output.status_code(),
            Some(0),
            "guest perf workload `{}` failed\nstdout:\n{}\nstderr:\n{}",
            workload.name,
            String::from_utf8_lossy(output.stdout()),
            String::from_utf8_lossy(output.stderr())
        );
        enforce_guest_perf_gate(*workload, wall_time);
    }

    println!("{report}");
    Ok(())
}

fn enforce_guest_perf_gate(workload: GuestPerfWorkload, wall_time: Duration) {
    if env::var_os("MCR_PERF_ENFORCE_GATES").is_none() {
        return;
    }
    if workload.requires_public_network && env::var_os("MCR_PERF_ENFORCE_PUBLIC_NETWORK").is_none()
    {
        return;
    }

    let threshold_key = perf_threshold_env_key(workload.name);
    let max_wall_ms = env::var(&threshold_key)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| *value > 0.0)
        .unwrap_or(workload.gate_max_wall_ms as f64);
    let actual_wall_ms = wall_time.as_secs_f64() * 1_000.0;
    assert!(
        actual_wall_ms <= max_wall_ms,
        "guest perf workload `{}` exceeded wall-time gate: actual {actual_wall_ms:.3}ms > max {max_wall_ms:.3}ms; override with {threshold_key}",
        workload.name
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

#[test]
#[ignore = "requires MCR_BIN and a materialized alpine-rootfs"]
fn perf_fork_exec_baseline() -> Result<()> {
    let Some(context) = GuestPerfContext::discover()? else {
        return Ok(());
    };
    let mut report = PerfBaselineReport::new("mcr-testkit fork/exec performance baseline");

    let command = context.command(SHELL_STARTUP);
    let (output_result, wall_time) = measure_wall_time(|| command.run());
    let output = output_result?;
    report.push(
        PerfMeasurement::new(SHELL_STARTUP.name, SHELL_STARTUP.operations, wall_time)
            .with_field("category", SHELL_STARTUP.category)
            .with_field("script", SHELL_STARTUP.script)
            .with_field("status", output.status_code().unwrap_or_default()),
    );

    assert_eq!(
        output.status_code(),
        Some(0),
        "guest fork/exec workload failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(output.stdout()),
        String::from_utf8_lossy(output.stderr())
    );

    println!("{report}");
    Ok(())
}

#[test]
#[ignore = "captures DNS cache performance baseline output without guest network access"]
fn perf_dns_cache_baseline() {
    let report = dns_cache_baseline_report("mcr-testkit DNS cache performance baseline");

    println!("{report}");
}

#[test]
#[ignore = "captures worker-pool diagnostics performance baseline output"]
fn perf_worker_pool_diagnostics_baseline() {
    let report =
        worker_pool_diagnostics_baseline_report("mcr-testkit worker-pool diagnostics baseline");

    println!("{report}");
}

fn dns_cache_baseline_report(suite: &str) -> PerfBaselineReport {
    let entries = env_usize("MCR_PERF_DNS_CACHE_ENTRIES", 256);
    let lookup_passes = env_usize("MCR_PERF_DNS_CACHE_LOOKUP_PASSES", 8);
    let queries = dns_cache_queries(entries);
    let mut cache = DnsCache::new(dns_config(b"nameserver 1.1.1.1\n"));
    let mut report = PerfBaselineReport::new(suite);

    let (inserted, insert_wall_time) = measure_wall_time(|| {
        for (index, query) in queries.iter().enumerate() {
            assert!(cache.insert_addresses(
                query.clone(),
                vec![sample_dns_address(index)],
                Duration::from_secs(60),
                Duration::from_secs(10),
            ));
        }
        cache.len()
    });
    assert_eq!(inserted, entries);
    report.push(
        PerfMeasurement::new("dns_cache_insert", entries as u64, insert_wall_time)
            .with_field("entries", entries)
            .with_field("record_type", "A")
            .with_field("ttl_seconds", 60),
    );

    let (hits, lookup_wall_time) = measure_wall_time(|| {
        let mut hits = 0usize;
        for _ in 0..lookup_passes {
            for query in &queries {
                let addresses = cache
                    .lookup_addresses(query, Duration::from_secs(20))
                    .expect("seeded DNS cache entry should be live");
                assert_eq!(addresses.len(), 1);
                hits += 1;
            }
        }
        hits
    });
    assert_eq!(hits, entries * lookup_passes);
    report.push(
        PerfMeasurement::new("dns_cache_lookup_hit", hits as u64, lookup_wall_time)
            .with_field("entries", entries)
            .with_field("lookup_passes", lookup_passes)
            .with_field("resolver_config", "stable"),
    );

    let (purged, purge_wall_time) =
        measure_wall_time(|| cache.purge_expired(Duration::from_secs(71)));
    assert_eq!(purged, entries);
    assert!(cache.is_empty());
    report.push(
        PerfMeasurement::new("dns_cache_purge_expired", entries as u64, purge_wall_time)
            .with_field("entries", entries)
            .with_field("expired_at_seconds", 71),
    );

    report
}

fn worker_pool_diagnostics_baseline_report(suite: &str) -> PerfBaselineReport {
    let snapshots = env_usize("MCR_PERF_WORKER_POOL_DIAGNOSTIC_SNAPSHOTS", 4_096);
    let pools = HostWorkerPools::default_bounded();
    let diagnostics = pools.diagnostics();

    assert_eq!(diagnostics.len(), 2);
    assert!(diagnostics.iter().all(|pool| {
        pool.max_workers() > 0
            && pool.max_workers() <= HOST_WORKER_POOL_MAX_WORKERS
            && pool.active_workers() == 0
            && pool.queued_jobs() == 0
    }));

    let (checksum, wall_time) = measure_wall_time(|| {
        let mut checksum = 0usize;
        for _ in 0..snapshots {
            for pool in pools.diagnostics() {
                checksum = checksum
                    .wrapping_add(pool.max_workers())
                    .wrapping_add(pool.active_workers())
                    .wrapping_add(pool.queued_jobs());
            }
        }
        checksum
    });
    assert!(checksum > 0);

    let mut report = PerfBaselineReport::new(suite);
    report.push(
        PerfMeasurement::new(
            "worker_pool_diagnostics_snapshot",
            (snapshots * diagnostics.len()) as u64,
            wall_time,
        )
        .with_field("snapshots", snapshots)
        .with_field("diagnostic_records_per_snapshot", diagnostics.len())
        .with_field("max_worker_limit", HOST_WORKER_POOL_MAX_WORKERS)
        .with_field("guest_task_max_workers", diagnostics[0].max_workers())
        .with_field("io_completion_max_workers", diagnostics[1].max_workers()),
    );

    report
}

fn dns_config(resolv_conf: &[u8]) -> GuestDnsConfig {
    GuestDnsConfig::from_guest_file_contents(
        b"127.0.0.1 localhost\n",
        resolv_conf,
        b"hosts: files dns\n",
    )
}

fn dns_cache_queries(entries: usize) -> Vec<DnsCacheQuery> {
    (0..entries)
        .map(|index| DnsCacheQuery::new(format!("perf-{index}.example.com"), DnsRecordType::A))
        .collect()
}

fn sample_dns_address(index: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, (index % 250 + 1) as u8))
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
