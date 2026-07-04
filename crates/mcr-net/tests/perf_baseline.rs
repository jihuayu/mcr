#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mcr_net::{
    GuestSocketTable, SocketAddress, SocketDomain, SocketProtocol, SocketSpec, SocketType,
    WinHostSocketTransport,
};

#[test]
#[ignore = "captures high-concurrency loopback socket performance baseline output"]
fn perf_baseline_high_concurrency_loopback_sockets() -> Result<(), Box<dyn std::error::Error>> {
    let connections = std::env::var("MCR_PERF_LOOPBACK_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(32);
    let mut table = GuestSocketTable::with_transport(WinHostSocketTransport::new()?);
    let listener = table.create_socket_from_spec(tcp_stream_spec()?)?;
    table.bind(listener, SocketAddress::inet([127, 0, 0, 1], 0))?;
    table.listen(listener, connections as u32)?;
    let local: SocketAddr = table
        .local_address(listener)?
        .expect("listener has local address")
        .into();

    let clients = spawn_loopback_clients(local, connections);
    let (server_result, wall_time) =
        measure_wall_time(|| serve_loopback_clients(&mut table, listener, connections));
    server_result?;
    for client in clients {
        client.join().expect("loopback client thread panicked")?;
    }
    table.close(listener)?;

    let measurements = [PerfMeasurement::new(
        "net_high_concurrency_loopback_accept_echo",
        (connections as u64) * 3,
        wall_time,
    )
    .with_field("connections", connections)
    .with_field("operations_model", "accept_recv_send")
    .with_field("transport", "WinHostSocketTransport")];
    print_perf_report("mcr-net loopback performance baseline", &measurements);
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

fn tcp_stream_spec() -> Result<SocketSpec, Box<dyn std::error::Error>> {
    Ok(SocketSpec::new(
        SocketDomain::Inet,
        SocketType::Stream,
        SocketProtocol::Tcp,
    )?)
}

fn spawn_loopback_clients(
    local: SocketAddr,
    connections: usize,
) -> Vec<thread::JoinHandle<std::io::Result<()>>> {
    (0..connections)
        .map(|index| {
            thread::spawn(move || {
                let mut stream = TcpStream::connect(local)?;
                let byte = [index as u8];
                stream.write_all(&byte)?;
                let mut response = [0];
                stream.read_exact(&mut response)?;
                assert_eq!(response, byte);
                Ok(())
            })
        })
        .collect()
}

fn serve_loopback_clients(
    table: &mut GuestSocketTable,
    listener: mcr_net::SocketId,
    connections: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..connections {
        let (accepted, _) = table.accept(listener)?;
        let mut byte = [0];
        assert_eq!(table.recv_connected(accepted, &mut byte)?, 1);
        assert_eq!(table.send_connected(accepted, &byte)?, 1);
        table.close(accepted)?;
    }
    Ok(())
}
