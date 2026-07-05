#[allow(unused_imports)]
use super::*;

#[derive(Debug)]
struct FutexWaitEntry {
    value: AtomicU32,
    waiters: AtomicU64,
}

impl FutexWaitEntry {
    #[cfg(test)]
    fn new(value: u32) -> Self {
        Self {
            value: AtomicU32::new(value),
            waiters: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FutexRegistry {
    entries: Arc<Mutex<BTreeMap<u64, Arc<FutexWaitEntry>>>>,
}

impl FutexRegistry {
    #[cfg(test)]
    pub(crate) fn wait(
        &mut self,
        uaddr: u64,
        value: u32,
        timeout: Option<Duration>,
        memory_changed: impl Fn() -> bool,
    ) -> Result<u64, LinuxErrno> {
        let entry = {
            let mut entries = self.lock_entries();
            entries
                .entry(uaddr)
                .or_insert_with(|| Arc::new(FutexWaitEntry::new(value)))
                .clone()
        };
        entry.value.store(value, Ordering::SeqCst);
        entry.waiters.fetch_add(1, Ordering::SeqCst);

        if memory_changed() {
            self.finish_wait(uaddr, &entry);
            return Ok(0);
        }
        let result = mcr_win::wait_on_address_u32(&entry.value, value, timeout);
        match result {
            Ok(mcr_win::AddressWaitResult::TimedOut) => {
                self.finish_wait(uaddr, &entry);
                Err(LinuxErrno::ETIMEDOUT)
            }
            Ok(mcr_win::AddressWaitResult::ValueChanged | mcr_win::AddressWaitResult::Woken) => {
                Ok(0)
            }
            Err(error) => {
                self.finish_wait(uaddr, &entry);
                Err(host_sync_errno(error.kind()))
            }
        }
    }

    pub(crate) fn wake(&mut self, uaddr: u64, count: u32) -> u64 {
        if count == 0 {
            return 0;
        }

        let Some(entry) = self.lock_entries().get(&uaddr).cloned() else {
            return 0;
        };
        let woken = reserve_wake_count(&entry.waiters, u64::from(count));
        if woken == 0 {
            self.prune_entry(uaddr, &entry);
            return 0;
        }

        entry.value.fetch_add(1, Ordering::SeqCst);
        for _ in 0..woken {
            if mcr_win::wake_by_address_single_u32(&entry.value).is_err() {
                break;
            }
        }
        self.prune_entry(uaddr, &entry);
        woken
    }

    #[cfg(test)]
    fn finish_wait(&self, uaddr: u64, entry: &Arc<FutexWaitEntry>) {
        decrement_waiter(&entry.waiters);
        self.prune_entry(uaddr, entry);
    }

    fn prune_entry(&self, uaddr: u64, entry: &Arc<FutexWaitEntry>) {
        if entry.waiters.load(Ordering::SeqCst) != 0 {
            return;
        }
        let mut entries = self.lock_entries();
        if entries
            .get(&uaddr)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(&uaddr);
        }
    }

    fn lock_entries(&self) -> MutexGuard<'_, BTreeMap<u64, Arc<FutexWaitEntry>>> {
        match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[cfg(test)]
    pub(crate) fn waiter_count(&self, uaddr: u64) -> u64 {
        self.lock_entries()
            .get(&uaddr)
            .map_or(0, |entry| entry.waiters.load(Ordering::SeqCst))
    }
}

fn reserve_wake_count(waiters: &AtomicU64, count: u64) -> u64 {
    let mut current = waiters.load(Ordering::SeqCst);
    loop {
        let woken = current.min(count);
        if woken == 0 {
            return 0;
        }
        match waiters.compare_exchange(current, current - woken, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return woken,
            Err(updated) => current = updated,
        }
    }
}

#[cfg(test)]
fn decrement_waiter(waiters: &AtomicU64) {
    let mut current = waiters.load(Ordering::SeqCst);
    while current != 0 {
        match waiters.compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(updated) => current = updated,
        }
    }
}

pub(crate) fn host_sync_errno(kind: mcr_win::HostErrorKind) -> LinuxErrno {
    match kind {
        mcr_win::HostErrorKind::InvalidInput => LinuxErrno::EINVAL,
        mcr_win::HostErrorKind::Interrupted => LinuxErrno::EINTR,
        mcr_win::HostErrorKind::TimedOut => LinuxErrno::ETIMEDOUT,
        mcr_win::HostErrorKind::OutOfMemory => LinuxErrno::ENOMEM,
        _ => LinuxErrno::EIO,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EpollWatch {
    pub(crate) fd: Fd,
    pub(crate) events: u32,
    pub(crate) data: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EpollInstance {
    pub(crate) watches: BTreeMap<Fd, EpollWatch>,
}

#[derive(Debug, Default)]
pub(crate) struct EpollRegistry {
    next_id: u64,
    instances: BTreeMap<u64, EpollInstance>,
}

impl EpollRegistry {
    pub(crate) fn create(&mut self) -> Result<u64, LinuxErrno> {
        self.next_id = self.next_id.checked_add(1).ok_or(LinuxErrno::EMFILE)?;
        let id = self.next_id;
        self.instances.insert(id, EpollInstance::default());
        Ok(id)
    }

    pub(crate) fn close(&mut self, id: u64) {
        self.instances.remove(&id);
    }

    pub(crate) fn instance(&self, id: u64) -> Result<&EpollInstance, LinuxErrno> {
        self.instances.get(&id).ok_or(LinuxErrno::EBADF)
    }

    pub(crate) fn instance_mut(&mut self, id: u64) -> Result<&mut EpollInstance, LinuxErrno> {
        self.instances.get_mut(&id).ok_or(LinuxErrno::EBADF)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuestSignalAltStack {
    pub(crate) sp: u64,
    pub(crate) flags: u32,
    pub(crate) size: u64,
}

impl GuestSignalAltStack {
    const DISABLED: Self = Self {
        sp: 0,
        flags: LINUX_SS_DISABLE,
        size: 0,
    };

    pub(crate) const fn disabled(self) -> bool {
        self.flags & LINUX_SS_DISABLE != 0
    }
}

impl Default for GuestSignalAltStack {
    fn default() -> Self {
        Self::DISABLED
    }
}
