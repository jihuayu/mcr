use mcr_task::{
    HOST_WORKER_POOL_MAX_QUEUED_JOBS, HOST_WORKER_POOL_MAX_WORKERS, HostWorkerPoolBoundary,
    HostWorkerPoolConfig, HostWorkerPoolRole, HostWorkerPools,
};
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
            && pool.max_queued_jobs() > 0
            && pool.max_queued_jobs() <= HOST_WORKER_POOL_MAX_QUEUED_JOBS
            && pool.active_workers() == 0
            && pool.queued_jobs() == 0
            && pool.submitted_jobs() == 0
            && pool.completed_jobs() == 0
            && pool.rejected_jobs() == 0
    }));

    let (checksum, wall_time) = measure_wall_time(|| {
        let mut checksum = 0usize;
        for _ in 0..snapshots {
            for pool in pools.diagnostics() {
                checksum = checksum
                    .wrapping_add(pool.max_workers())
                    .wrapping_add(pool.max_queued_jobs())
                    .wrapping_add(pool.active_workers())
                    .wrapping_add(pool.queued_jobs())
                    .wrapping_add(pool.submitted_jobs())
                    .wrapping_add(pool.completed_jobs())
                    .wrapping_add(pool.rejected_jobs());
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
        .with_field("max_queue_limit", HOST_WORKER_POOL_MAX_QUEUED_JOBS)
        .with_field("guest_task_max_workers", diagnostics[0].max_workers())
        .with_field(
            "guest_task_queue_capacity",
            diagnostics[0].max_queued_jobs(),
        )
        .with_field("io_completion_max_workers", diagnostics[1].max_workers())
        .with_field(
            "io_completion_queue_capacity",
            diagnostics[1].max_queued_jobs(),
        ),
    );

    let submit_jobs = env_usize("MCR_PERF_WORKER_POOL_SUBMISSIONS", 256)
        .clamp(4, HOST_WORKER_POOL_MAX_QUEUED_JOBS);
    let mut submission_pool = HostWorkerPoolBoundary::new(
        HostWorkerPoolConfig::with_queue_capacity(
            HostWorkerPoolRole::GuestTaskExecution,
            2,
            submit_jobs - 2,
        )
        .unwrap(),
    );
    let (accepted_jobs, submit_wall_time) = measure_wall_time(|| {
        let mut accepted_jobs = 0usize;
        for _ in 0..submit_jobs {
            if submission_pool.try_submit().is_ok() {
                accepted_jobs += 1;
            }
        }
        accepted_jobs
    });
    assert_eq!(accepted_jobs, submit_jobs);
    assert!(submission_pool.try_submit().is_err());
    let diagnostics = submission_pool.diagnostics();
    assert_eq!(diagnostics.active_workers(), 2);
    assert_eq!(diagnostics.queued_jobs(), submit_jobs - 2);
    assert_eq!(diagnostics.submitted_jobs(), submit_jobs);
    assert_eq!(diagnostics.rejected_jobs(), 1);

    let (completed_jobs, drain_wall_time) = measure_wall_time(|| {
        let mut completed_jobs = 0usize;
        for _ in 0..submit_jobs {
            submission_pool.complete_one().unwrap();
            completed_jobs += 1;
        }
        completed_jobs
    });
    assert_eq!(completed_jobs, submit_jobs);
    let diagnostics = submission_pool.diagnostics();
    assert_eq!(diagnostics.active_workers(), 0);
    assert_eq!(diagnostics.queued_jobs(), 0);
    assert_eq!(diagnostics.completed_jobs(), submit_jobs);
    report.push(
        PerfMeasurement::new(
            "task_worker_pool_bounded_submit",
            submit_jobs as u64,
            submit_wall_time,
        )
        .with_field("submissions", submit_jobs)
        .with_field("max_workers", 2)
        .with_field("queue_capacity", submit_jobs - 2)
        .with_field("rejected_jobs", diagnostics.rejected_jobs()),
    );
    report.push(
        PerfMeasurement::new(
            "task_worker_pool_bounded_complete",
            completed_jobs as u64,
            drain_wall_time,
        )
        .with_field("completed_jobs", completed_jobs),
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
