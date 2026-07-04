use mcr_task::{HOST_WORKER_POOL_MAX_WORKERS, HostWorkerPools};
use mcr_testkit::perf::{PerfBaselineReport, PerfMeasurement, measure_wall_time};

#[test]
#[ignore = "captures worker-pool diagnostics performance baseline output"]
fn perf_worker_pool_diagnostics_baseline() {
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

    let mut report = PerfBaselineReport::new("mcr-task worker-pool diagnostics baseline");
    report.push(
        PerfMeasurement::new(
            "task_worker_pool_diagnostics_snapshot",
            (snapshots * diagnostics.len()) as u64,
            wall_time,
        )
        .with_field("snapshots", snapshots)
        .with_field("diagnostic_records_per_snapshot", diagnostics.len())
        .with_field("max_worker_limit", HOST_WORKER_POOL_MAX_WORKERS)
        .with_field("guest_task_max_workers", diagnostics[0].max_workers())
        .with_field("io_completion_max_workers", diagnostics[1].max_workers()),
    );

    println!("{report}");
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
