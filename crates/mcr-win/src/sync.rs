use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::error::{HostError, HostOperation, HostResult};

/// Result of waiting on a host address.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AddressWaitResult {
    ValueChanged,
    Woken,
    TimedOut,
}

/// Waits while `address` still equals `expected`.
pub fn wait_on_address_u32(
    address: &AtomicU32,
    expected: u32,
    timeout: Option<Duration>,
) -> HostResult<AddressWaitResult> {
    if address.load(Ordering::SeqCst) != expected {
        return Ok(AddressWaitResult::ValueChanged);
    }

    wait_on_address_u32_platform(address, expected, timeout)
}

/// Wakes one waiter blocked on `address`.
pub fn wake_by_address_single_u32(address: &AtomicU32) -> HostResult<()> {
    wake_by_address_single_u32_platform(address)
}

/// Wakes all waiters blocked on `address`.
pub fn wake_by_address_all_u32(address: &AtomicU32) -> HostResult<()> {
    wake_by_address_all_u32_platform(address)
}

#[cfg(not(windows))]
fn wait_on_address_u32_platform(
    address: &AtomicU32,
    expected: u32,
    timeout: Option<Duration>,
) -> HostResult<AddressWaitResult> {
    let cell = wait_cell(address);
    let guard = cell.lock.lock().map_err(|_| {
        HostError::new(HostOperation::WaitOnAddress, crate::HostErrorKind::Poisoned)
    })?;

    if address.load(Ordering::SeqCst) != expected {
        return Ok(AddressWaitResult::ValueChanged);
    }

    match timeout {
        Some(timeout) => {
            let (_guard, timeout_result) = cell
                .condvar
                .wait_timeout_while(guard, timeout, |_| {
                    address.load(Ordering::SeqCst) == expected
                })
                .map_err(|_| {
                    HostError::new(HostOperation::WaitOnAddress, crate::HostErrorKind::Poisoned)
                })?;
            if timeout_result.timed_out() && address.load(Ordering::SeqCst) == expected {
                Ok(AddressWaitResult::TimedOut)
            } else if address.load(Ordering::SeqCst) != expected {
                Ok(AddressWaitResult::ValueChanged)
            } else {
                Ok(AddressWaitResult::Woken)
            }
        }
        None => {
            let _guard = cell
                .condvar
                .wait_while(guard, |_| address.load(Ordering::SeqCst) == expected)
                .map_err(|_| {
                    HostError::new(HostOperation::WaitOnAddress, crate::HostErrorKind::Poisoned)
                })?;
            Ok(AddressWaitResult::ValueChanged)
        }
    }
}

#[cfg(not(windows))]
fn wake_by_address_single_u32_platform(address: &AtomicU32) -> HostResult<()> {
    wait_cell(address).condvar.notify_one();
    Ok(())
}

#[cfg(not(windows))]
fn wake_by_address_all_u32_platform(address: &AtomicU32) -> HostResult<()> {
    wait_cell(address).condvar.notify_all();
    Ok(())
}

#[cfg(not(windows))]
struct WaitCell {
    lock: std::sync::Mutex<()>,
    condvar: std::sync::Condvar,
}

#[cfg(not(windows))]
fn wait_cell(address: &AtomicU32) -> std::sync::Arc<WaitCell> {
    static REGISTRY: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, std::sync::Arc<WaitCell>>>,
    > = std::sync::OnceLock::new();

    let registry = REGISTRY.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    registry
        .entry(address.as_ptr() as usize)
        .or_insert_with(|| {
            std::sync::Arc::new(WaitCell {
                lock: std::sync::Mutex::new(()),
                condvar: std::sync::Condvar::new(),
            })
        })
        .clone()
}

#[cfg(windows)]
fn wait_on_address_u32_platform(
    address: &AtomicU32,
    expected: u32,
    timeout: Option<Duration>,
) -> HostResult<AddressWaitResult> {
    let compare = expected;
    let timeout_ms = timeout.map(duration_to_millis);
    let timeout_ptr = timeout_ms
        .as_ref()
        .map_or(std::ptr::null(), std::ptr::from_ref);

    // SAFETY: AtomicU32 exposes a stable pointer to the u32 storage for address waits.
    let ok = unsafe {
        WaitOnAddress(
            address.as_ptr().cast(),
            std::ptr::from_ref(&compare).cast(),
            std::mem::size_of::<u32>(),
            timeout_ptr,
        )
    };

    if ok != crate::windows::FALSE {
        return Ok(AddressWaitResult::Woken);
    }

    let code = crate::windows::last_error();
    if crate::error::windows_kind(code) == crate::HostErrorKind::TimedOut {
        Ok(AddressWaitResult::TimedOut)
    } else {
        Err(crate::error::windows_error(
            HostOperation::WaitOnAddress,
            code,
        ))
    }
}

#[cfg(windows)]
fn wake_by_address_single_u32_platform(address: &AtomicU32) -> HostResult<()> {
    // SAFETY: AtomicU32 exposes a stable pointer to the u32 storage for address wakes.
    unsafe {
        WakeByAddressSingle(address.as_ptr().cast());
    }
    Ok(())
}

#[cfg(windows)]
fn wake_by_address_all_u32_platform(address: &AtomicU32) -> HostResult<()> {
    // SAFETY: AtomicU32 exposes a stable pointer to the u32 storage for address wakes.
    unsafe {
        WakeByAddressAll(address.as_ptr().cast());
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
#[link(name = "kernel32")]
unsafe extern "system" {
    fn WaitOnAddress(
        address: *mut std::ffi::c_void,
        compare_address: *const std::ffi::c_void,
        address_size: usize,
        milliseconds: *const u32,
    ) -> crate::windows::Bool;
    fn WakeByAddressSingle(address: *mut std::ffi::c_void);
    fn WakeByAddressAll(address: *mut std::ffi::c_void);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{AddressWaitResult, wait_on_address_u32, wake_by_address_all_u32};

    #[test]
    fn wait_returns_value_changed_when_value_does_not_match() {
        let value = std::sync::atomic::AtomicU32::new(2);

        let result = wait_on_address_u32(&value, 1, None).unwrap();

        assert_eq!(result, AddressWaitResult::ValueChanged);
    }

    #[test]
    fn wait_times_out_when_value_is_unchanged() {
        let value = std::sync::atomic::AtomicU32::new(1);

        let result =
            wait_on_address_u32(&value, 1, Some(std::time::Duration::from_millis(1))).unwrap();

        assert_eq!(result, AddressWaitResult::TimedOut);
    }

    #[test]
    fn wake_all_releases_waiter_after_value_changes() {
        let value = Arc::new(std::sync::atomic::AtomicU32::new(1));
        let waiter_value = Arc::clone(&value);
        let waiter = std::thread::spawn(move || wait_on_address_u32(&waiter_value, 1, None));

        std::thread::sleep(std::time::Duration::from_millis(10));
        value.store(2, std::sync::atomic::Ordering::SeqCst);
        wake_by_address_all_u32(&value).unwrap();

        assert_eq!(
            waiter.join().unwrap().unwrap(),
            AddressWaitResult::ValueChanged
        );
    }
}
