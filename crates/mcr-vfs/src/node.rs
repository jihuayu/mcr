use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inode {
    id: InodeId,
    backend: InodeBackend,
    link_count: u32,
}

impl Inode {
    pub fn new(id: InodeId, backend: InodeBackend) -> Self {
        Self {
            id,
            backend,
            link_count: 1,
        }
    }

    pub fn id(&self) -> InodeId {
        self.id
    }

    pub fn backend(&self) -> &InodeBackend {
        &self.backend
    }

    pub fn link_count(&self) -> u32 {
        self.link_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InodeBackend {
    HostPath(HostPathRef),
    ProcVirtual(ProcNode),
    DevVirtual(DevNode),
    Pipe(PipeNode),
    Socket(SocketNode),
    Epoll(EpollNode),
    Eventfd(EventfdNode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPathRef {
    path: Arc<PathBuf>,
}

impl HostPathRef {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcNode {
    name: String,
}

impl ProcNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevNode {
    kind: DevNodeKind,
}

impl DevNode {
    pub fn new(kind: DevNodeKind) -> Self {
        Self { kind }
    }

    pub fn name(&self) -> &str {
        self.kind.name()
    }

    pub fn kind(&self) -> DevNodeKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevNodeKind {
    Null,
    Zero,
    Urandom,
    Stdin,
    Stdout,
    Stderr,
}

impl DevNodeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Zero => "zero",
            Self::Urandom => "urandom",
            Self::Stdin => "stdin",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PipeNode {
    id: u64,
    inner: Arc<PipeInner>,
}

impl PartialEq for PipeNode {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PipeNode {}

impl PipeNode {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            inner: Arc::new(PipeInner::new(DEFAULT_PIPE_CAPACITY)),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, PipeState> {
        self.inner.state.lock().expect("pipe mutex poisoned")
    }

    pub(crate) fn notify_readable(&self) {
        self.inner.readable.notify_all();
    }

    pub(crate) fn notify_writable(&self) {
        self.inner.writable.notify_all();
    }

    pub(crate) fn host_pair(&self) -> Option<&mcr_win::HostPipePair> {
        self.inner.host_pair.as_ref()
    }
}

impl Drop for PipeNode {
    fn drop(&mut self) {
        self.inner.readable.notify_all();
        self.inner.writable.notify_all();
    }
}

#[derive(Debug)]
struct PipeInner {
    state: Mutex<PipeState>,
    readable: Condvar,
    writable: Condvar,
    host_pair: Option<mcr_win::HostPipePair>,
}

impl PipeInner {
    fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(PipeState::new(capacity)),
            readable: Condvar::new(),
            writable: Condvar::new(),
            host_pair: mcr_win::HostPipePair::create_overlapped().ok(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PipeState {
    pub(crate) buffer: VecDeque<u8>,
    pub(crate) capacity: usize,
    pub(crate) readers: usize,
    pub(crate) writers: usize,
}

impl PipeState {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::new(),
            capacity,
            readers: 0,
            writers: 0,
        }
    }

    pub(crate) fn available(&self) -> usize {
        self.buffer.len()
    }

    pub(crate) fn read(&mut self, buffer: &mut [u8]) -> usize {
        let count = self.buffer.len().min(buffer.len());
        for item in buffer.iter_mut().take(count) {
            *item = self
                .buffer
                .pop_front()
                .expect("pipe buffer length was checked");
        }
        count
    }

    pub(crate) fn discard_readable(&mut self, count: usize) {
        for _ in 0..count.min(self.buffer.len()) {
            self.buffer
                .pop_front()
                .expect("pipe buffer length was checked");
        }
    }

    pub(crate) fn set_capacity(&mut self, capacity: usize) -> VfsResult<usize> {
        let capacity = capacity.max(MIN_PIPE_CAPACITY);
        if capacity < self.buffer.len() {
            return Err(VfsError::Busy);
        }
        self.capacity = capacity;
        Ok(self.capacity)
    }

    pub(crate) fn write(&mut self, buffer: &[u8]) -> VfsResult<usize> {
        let available = self.capacity.saturating_sub(self.buffer.len());
        if available == 0 && !buffer.is_empty() {
            return Err(VfsError::WouldBlock);
        }

        let count = available.min(buffer.len());
        self.buffer.extend(buffer[..count].iter().copied());
        Ok(count)
    }

    pub(crate) fn record_written(&mut self, count: usize) -> VfsResult<usize> {
        let available = self.capacity.saturating_sub(self.buffer.len());
        if count > available {
            return Err(VfsError::WouldBlock);
        }
        self.buffer.extend(std::iter::repeat_n(0, count));
        Ok(count)
    }

    pub(crate) fn register_endpoint(&mut self, kind: FileKind) {
        match kind {
            FileKind::PipeRead => self.readers += 1,
            FileKind::PipeWrite => self.writers += 1,
            _ => {}
        }
    }

    pub(crate) fn unregister_endpoint(&mut self, kind: FileKind) {
        match kind {
            FileKind::PipeRead => self.readers = self.readers.saturating_sub(1),
            FileKind::PipeWrite => self.writers = self.writers.saturating_sub(1),
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketNode {
    id: u64,
}

impl SocketNode {
    pub fn new(id: u64) -> Self {
        Self { id }
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpollNode {
    id: u64,
}

impl EpollNode {
    pub fn new(id: u64) -> Self {
        Self { id }
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

#[derive(Clone, Debug)]
pub struct EventfdNode {
    id: u64,
    inner: Arc<Mutex<EventfdState>>,
}

impl PartialEq for EventfdNode {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for EventfdNode {}

impl EventfdNode {
    pub fn new(id: u64, initial: u64) -> Self {
        Self {
            id,
            inner: Arc::new(Mutex::new(EventfdState::new(initial))),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, EventfdState> {
        self.inner.lock().expect("eventfd mutex poisoned")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EventfdState {
    pub(crate) counter: u64,
}

impl EventfdState {
    const MAX_COUNTER: u64 = u64::MAX - 1;

    const fn new(counter: u64) -> Self {
        Self { counter }
    }

    pub(crate) const fn readable(&self) -> bool {
        self.counter > 0
    }

    pub(crate) const fn writable(&self) -> bool {
        self.counter < Self::MAX_COUNTER
    }

    pub(crate) fn read(&mut self, buffer: &mut [u8]) -> VfsResult<usize> {
        if buffer.len() < 8 {
            return Err(VfsError::InvalidPath);
        }
        if self.counter == 0 {
            return Err(VfsError::WouldBlock);
        }

        let value = self.counter;
        self.counter = 0;
        buffer[..8].copy_from_slice(&value.to_le_bytes());
        Ok(8)
    }

    pub(crate) fn write(&mut self, buffer: &[u8]) -> VfsResult<usize> {
        if buffer.len() < 8 {
            return Err(VfsError::InvalidPath);
        }
        let value = u64::from_le_bytes(buffer[..8].try_into().expect("eventfd value length"));
        if value == u64::MAX {
            return Err(VfsError::InvalidPath);
        }
        let Some(next) = self.counter.checked_add(value) else {
            return Err(VfsError::WouldBlock);
        };
        if next > Self::MAX_COUNTER {
            return Err(VfsError::WouldBlock);
        }

        self.counter = next;
        Ok(8)
    }
}
