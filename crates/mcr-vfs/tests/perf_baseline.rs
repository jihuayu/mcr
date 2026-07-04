use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mcr_vfs::{
    AT_FDCWD, FdTable, O_CREAT, O_DIRECTORY, O_RDONLY, O_TRUNC, O_WRONLY, OpenFlags, PathTree,
    Rootfs, VirtualFileSystem,
};

#[test]
#[ignore = "captures VFS performance baseline output"]
fn perf_baseline_vfs_file_and_directory_paths() -> Result<(), Box<dyn std::error::Error>> {
    let mut measurements = Vec::new();

    let mut file_vfs = sample_vfs()?;
    let (file_result, file_wall_time) = measure_wall_time(|| small_file_io(&mut file_vfs, 256));
    file_result?;
    measurements.push(
        PerfMeasurement::new("vfs_small_file_io", 256 * 6, file_wall_time)
            .with_field("files", 256)
            .with_field("bytes_per_file", 32)
            .with_field("operations_model", "open_write_close_open_read_close"),
    );

    let mut dir_vfs = sample_vfs()?;
    seed_directory(&mut dir_vfs, "/tmp/perf-dir", 128)?;
    let (dir_result, dir_wall_time) =
        measure_wall_time(|| directory_metadata_walk(&mut dir_vfs, "/tmp/perf-dir", 128, 16));
    dir_result?;
    measurements.push(
        PerfMeasurement::new("vfs_directory_metadata_walk", 16 * (128 + 1), dir_wall_time)
            .with_field("entries", 128)
            .with_field("passes", 16)
            .with_field("operations_model", "getdents64_plus_statx_per_entry"),
    );

    print_perf_report("mcr-vfs local performance baseline", &measurements);
    Ok(())
}

fn sample_vfs() -> Result<VirtualFileSystem, Box<dyn std::error::Error>> {
    let rootfs = Rootfs::new("/perf/root");
    let mut tree = PathTree::new();
    tree.create_dir("/tmp")?;
    Ok(VirtualFileSystem::from_parts(
        rootfs,
        tree,
        FdTable::with_stdio(),
    ))
}

fn small_file_io(
    vfs: &mut VirtualFileSystem,
    iterations: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = [b'x'; 32];
    let mut buffer = [0; 32];

    for index in 0..iterations {
        let path = format!("/tmp/perf-small-{index}");
        let fd = vfs.openat(
            AT_FDCWD,
            &path,
            OpenFlags::new(O_CREAT | O_WRONLY | O_TRUNC),
            0o644,
        )?;
        assert_eq!(vfs.write(fd, &payload)?, payload.len());
        vfs.close(fd)?;

        let fd = vfs.openat(AT_FDCWD, &path, OpenFlags::new(O_RDONLY), 0)?;
        assert_eq!(vfs.read(fd, &mut buffer)?, payload.len());
        assert_eq!(buffer, payload);
        vfs.close(fd)?;
    }

    Ok(())
}

struct PerfMeasurement {
    name: &'static str,
    operations: u64,
    wall_time: Duration,
    fields: Vec<(&'static str, String)>,
}

impl PerfMeasurement {
    fn new(name: &'static str, operations: u64, wall_time: Duration) -> Self {
        assert!(operations > 0);
        Self {
            name,
            operations,
            wall_time,
            fields: Vec::new(),
        }
    }

    fn with_field(mut self, key: &'static str, value: impl ToString) -> Self {
        self.fields.push((key, value.to_string()));
        self
    }
}

fn measure_wall_time<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let result = f();
    (result, start.elapsed())
}

fn print_perf_report(suite: &str, measurements: &[PerfMeasurement]) {
    println!("mcr_perf_baseline.version=1");
    println!("mcr_perf_baseline.suite={suite}");
    println!("environment.target_os={}", std::env::consts::OS);
    println!("environment.target_arch={}", std::env::consts::ARCH);
    println!("environment.target_family={}", std::env::consts::FAMILY);
    println!("environment.debug_assertions={}", cfg!(debug_assertions));
    println!("environment.timestamp_unix_ms={}", unix_timestamp_ms());
    for (index, measurement) in measurements.iter().enumerate() {
        let wall_ms = measurement.wall_time.as_secs_f64() * 1_000.0;
        let ops_per_sec = measurement.operations as f64 / measurement.wall_time.as_secs_f64();
        println!("measurement.{index}.name={}", measurement.name);
        println!("measurement.{index}.wall_ms={wall_ms:.3}");
        println!("measurement.{index}.operations={}", measurement.operations);
        println!("measurement.{index}.ops_per_sec={ops_per_sec:.3}");
        for (key, value) in &measurement.fields {
            println!("measurement.{index}.field.{key}={value}");
        }
    }
}

fn unix_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn seed_directory(
    vfs: &mut VirtualFileSystem,
    path: &str,
    entries: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    vfs.mkdirat(AT_FDCWD, path, 0o755)?;
    for index in 0..entries {
        let file_path = format!("{path}/file-{index:04}");
        let fd = vfs.openat(
            AT_FDCWD,
            &file_path,
            OpenFlags::new(O_CREAT | O_WRONLY | O_TRUNC),
            0o644,
        )?;
        vfs.close(fd)?;
    }
    Ok(())
}

fn directory_metadata_walk(
    vfs: &mut VirtualFileSystem,
    path: &str,
    entries: usize,
    passes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..passes {
        let fd = vfs.openat(AT_FDCWD, path, OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)?;
        let dir_entries = vfs.getdents64(fd, 64 * 1024)?;
        assert!(
            dir_entries.len() >= entries,
            "expected at least {entries} directory entries"
        );
        vfs.close(fd)?;

        for index in 0..entries {
            let file_path = format!("{path}/file-{index:04}");
            vfs.statx(AT_FDCWD, &file_path, 0)?;
        }
    }

    Ok(())
}
