#[cfg(not(windows))]
use std::time::Instant;
#[cfg(windows)]
use std::time::UNIX_EPOCH;
use std::time::{Duration, SystemTime};

use crate::error::HostResult;
#[cfg(windows)]
use crate::error::{HostError, HostOperation};

/// Queries the host wall clock.
pub fn system_time() -> HostResult<SystemTime> {
    system_time_platform()
}

/// Queries a monotonic host clock as a duration from an unspecified origin.
pub fn monotonic_time() -> HostResult<Duration> {
    monotonic_time_platform()
}

/// Sleeps the current host thread for at least `duration`.
pub fn sleep_for(duration: Duration) -> HostResult<()> {
    sleep_for_platform(duration)
}

#[cfg(not(windows))]
fn system_time_platform() -> HostResult<SystemTime> {
    Ok(SystemTime::now())
}

#[cfg(not(windows))]
fn monotonic_time_platform() -> HostResult<Duration> {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    Ok(START.get_or_init(Instant::now).elapsed())
}

#[cfg(not(windows))]
fn sleep_for_platform(duration: Duration) -> HostResult<()> {
    std::thread::sleep(duration);
    Ok(())
}

#[cfg(windows)]
fn system_time_platform() -> HostResult<SystemTime> {
    let mut file_time = FileTime {
        low_date_time: 0,
        high_date_time: 0,
    };
    // SAFETY: The pointer is valid for writes to a FILETIME-sized value.
    unsafe {
        GetSystemTimePreciseAsFileTime(&mut file_time);
    }

    let ticks = ((file_time.high_date_time as u64) << 32) | u64::from(file_time.low_date_time);
    let Some(unix_ticks) = ticks.checked_sub(WINDOWS_TICKS_TO_UNIX_EPOCH) else {
        return Err(HostError::new(
            HostOperation::QueryClock,
            crate::HostErrorKind::Other,
        ));
    };
    Ok(UNIX_EPOCH + Duration::from_nanos(unix_ticks.saturating_mul(100)))
}

#[cfg(windows)]
fn monotonic_time_platform() -> HostResult<Duration> {
    let mut frequency = 0_i64;
    let mut counter = 0_i64;
    // SAFETY: Pointers are valid for writes to i64 counters.
    let frequency_ok = unsafe { QueryPerformanceFrequency(&mut frequency) };
    if frequency_ok == crate::windows::FALSE || frequency <= 0 {
        return Err(crate::error::last_windows_error(HostOperation::QueryClock));
    }
    // SAFETY: Pointer is valid for writes to an i64 counter.
    let counter_ok = unsafe { QueryPerformanceCounter(&mut counter) };
    if counter_ok == crate::windows::FALSE || counter < 0 {
        return Err(crate::error::last_windows_error(HostOperation::QueryClock));
    }

    let nanos = (counter as u128)
        .saturating_mul(1_000_000_000)
        .checked_div(frequency as u128)
        .unwrap_or(0);
    Ok(Duration::from_nanos(nanos.min(u64::MAX as u128) as u64))
}

#[cfg(windows)]
fn sleep_for_platform(duration: Duration) -> HostResult<()> {
    // SAFETY: `Sleep` accepts any u32 millisecond duration.
    unsafe {
        Sleep(duration_to_millis(duration));
    }
    Ok(())
}

#[cfg(windows)]
fn duration_to_millis(duration: Duration) -> u32 {
    if duration.is_zero() {
        return 0;
    }

    let millis = duration.as_millis().saturating_add(1);
    millis.min(u128::from(u32::MAX)) as u32
}

#[cfg(windows)]
const WINDOWS_TICKS_TO_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

#[cfg(windows)]
#[repr(C)]
struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemTimePreciseAsFileTime(file_time: *mut FileTime);
    fn QueryPerformanceCounter(counter: *mut i64) -> crate::windows::Bool;
    fn QueryPerformanceFrequency(frequency: *mut i64) -> crate::windows::Bool;
    fn Sleep(milliseconds: u32);
}

#[cfg(test)]
mod tests {
    #[test]
    fn monotonic_time_can_be_queried() {
        let first = super::monotonic_time().unwrap();
        let second = super::monotonic_time().unwrap();

        assert!(second >= first);
    }
}
