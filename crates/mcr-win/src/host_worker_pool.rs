use std::collections::VecDeque;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const HOST_WORKER_POOL_MAX_WORKERS: usize = 64;
pub const HOST_WORKER_POOL_MAX_QUEUED_JOBS: usize = 4096;
pub const DEFAULT_GUEST_TASK_WORKERS: usize = 4;
pub const DEFAULT_IO_COMPLETION_WORKERS: usize = 4;
pub const DEFAULT_GUEST_TASK_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_IO_COMPLETION_QUEUE_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HostWorkerPoolRole {
    GuestTaskExecution,
    IoCompletion,
}

impl HostWorkerPoolRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuestTaskExecution => "guest-task-execution",
            Self::IoCompletion => "io-completion",
        }
    }

    #[must_use]
    pub const fn default_max_workers(self) -> usize {
        match self {
            Self::GuestTaskExecution => DEFAULT_GUEST_TASK_WORKERS,
            Self::IoCompletion => DEFAULT_IO_COMPLETION_WORKERS,
        }
    }

    #[must_use]
    pub const fn default_queue_capacity(self) -> usize {
        match self {
            Self::GuestTaskExecution => DEFAULT_GUEST_TASK_QUEUE_CAPACITY,
            Self::IoCompletion => DEFAULT_IO_COMPLETION_QUEUE_CAPACITY,
        }
    }
}

impl fmt::Display for HostWorkerPoolRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostWorkerPoolConfig {
    role: HostWorkerPoolRole,
    max_workers: usize,
    queue_capacity: usize,
}

impl HostWorkerPoolConfig {
    pub const fn new(
        role: HostWorkerPoolRole,
        max_workers: usize,
    ) -> Result<Self, HostWorkerPoolConfigError> {
        Self::with_queue_capacity(role, max_workers, role.default_queue_capacity())
    }

    pub const fn with_queue_capacity(
        role: HostWorkerPoolRole,
        max_workers: usize,
        queue_capacity: usize,
    ) -> Result<Self, HostWorkerPoolConfigError> {
        if max_workers == 0 {
            return Err(HostWorkerPoolConfigError::ZeroWorkers { role });
        }
        if max_workers > HOST_WORKER_POOL_MAX_WORKERS {
            return Err(HostWorkerPoolConfigError::TooManyWorkers {
                role,
                max_workers,
                max_allowed: HOST_WORKER_POOL_MAX_WORKERS,
            });
        }
        if queue_capacity == 0 {
            return Err(HostWorkerPoolConfigError::ZeroQueueCapacity { role });
        }
        if queue_capacity > HOST_WORKER_POOL_MAX_QUEUED_JOBS {
            return Err(HostWorkerPoolConfigError::TooManyQueuedJobs {
                role,
                queue_capacity,
                max_allowed: HOST_WORKER_POOL_MAX_QUEUED_JOBS,
            });
        }

        Ok(Self {
            role,
            max_workers,
            queue_capacity,
        })
    }

    #[must_use]
    pub const fn default_for(role: HostWorkerPoolRole) -> Self {
        Self {
            role,
            max_workers: role.default_max_workers(),
            queue_capacity: role.default_queue_capacity(),
        }
    }

    #[must_use]
    pub const fn role(self) -> HostWorkerPoolRole {
        self.role
    }

    #[must_use]
    pub const fn max_workers(self) -> usize {
        self.max_workers
    }

    #[must_use]
    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWorkerPoolConfigError {
    ZeroWorkers {
        role: HostWorkerPoolRole,
    },
    TooManyWorkers {
        role: HostWorkerPoolRole,
        max_workers: usize,
        max_allowed: usize,
    },
    ZeroQueueCapacity {
        role: HostWorkerPoolRole,
    },
    TooManyQueuedJobs {
        role: HostWorkerPoolRole,
        queue_capacity: usize,
        max_allowed: usize,
    },
}

impl fmt::Display for HostWorkerPoolConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroWorkers { role } => {
                write!(
                    formatter,
                    "{role} worker pool must have at least one worker"
                )
            }
            Self::TooManyWorkers {
                role,
                max_workers,
                max_allowed,
            } => write!(
                formatter,
                "{role} worker pool max {max_workers} exceeds bounded limit {max_allowed}"
            ),
            Self::ZeroQueueCapacity { role } => {
                write!(
                    formatter,
                    "{role} worker pool queue must accept at least one job"
                )
            }
            Self::TooManyQueuedJobs {
                role,
                queue_capacity,
                max_allowed,
            } => write!(
                formatter,
                "{role} worker pool queue capacity {queue_capacity} exceeds bounded limit {max_allowed}"
            ),
        }
    }
}

impl std::error::Error for HostWorkerPoolConfigError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostWorkerPoolDiagnostics {
    role: HostWorkerPoolRole,
    max_workers: usize,
    max_queued_jobs: usize,
    active_workers: usize,
    queued_jobs: usize,
    submitted_jobs: usize,
    completed_jobs: usize,
    rejected_jobs: usize,
}

impl HostWorkerPoolDiagnostics {
    #[must_use]
    pub const fn new(
        role: HostWorkerPoolRole,
        max_workers: usize,
        max_queued_jobs: usize,
        active_workers: usize,
        queued_jobs: usize,
        submitted_jobs: usize,
        completed_jobs: usize,
        rejected_jobs: usize,
    ) -> Self {
        Self {
            role,
            max_workers,
            max_queued_jobs,
            active_workers,
            queued_jobs,
            submitted_jobs,
            completed_jobs,
            rejected_jobs,
        }
    }

    #[must_use]
    pub const fn role(self) -> HostWorkerPoolRole {
        self.role
    }

    #[must_use]
    pub const fn max_workers(self) -> usize {
        self.max_workers
    }

    #[must_use]
    pub const fn max_queued_jobs(self) -> usize {
        self.max_queued_jobs
    }

    #[must_use]
    pub const fn active_workers(self) -> usize {
        self.active_workers
    }

    #[must_use]
    pub const fn queued_jobs(self) -> usize {
        self.queued_jobs
    }

    #[must_use]
    pub const fn submitted_jobs(self) -> usize {
        self.submitted_jobs
    }

    #[must_use]
    pub const fn completed_jobs(self) -> usize {
        self.completed_jobs
    }

    #[must_use]
    pub const fn rejected_jobs(self) -> usize {
        self.rejected_jobs
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWorkerPoolSubmission {
    Started,
    Queued,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWorkerPoolSubmitError {
    QueueFull {
        role: HostWorkerPoolRole,
        active_workers: usize,
        queued_jobs: usize,
        max_workers: usize,
        max_queued_jobs: usize,
    },
    Shutdown {
        role: HostWorkerPoolRole,
    },
}

impl fmt::Display for HostWorkerPoolSubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull {
                role,
                active_workers,
                queued_jobs,
                max_workers,
                max_queued_jobs,
            } => write!(
                formatter,
                "{role} worker pool is full: active {active_workers}/{max_workers}, queued {queued_jobs}/{max_queued_jobs}"
            ),
            Self::Shutdown { role } => write!(formatter, "{role} worker pool is shut down"),
        }
    }
}

impl std::error::Error for HostWorkerPoolSubmitError {}

#[derive(Debug)]
pub struct HostWorkerPoolJob<T> {
    submission: HostWorkerPoolSubmission,
    receiver: Receiver<T>,
}

impl<T> HostWorkerPoolJob<T> {
    #[must_use]
    pub const fn submission(&self) -> HostWorkerPoolSubmission {
        self.submission
    }

    pub fn recv(self) -> Result<T, HostWorkerPoolJobError> {
        self.receiver
            .recv()
            .map_err(|_| HostWorkerPoolJobError::Panicked)
    }

    pub fn recv_timeout(self, timeout: Duration) -> Result<T, HostWorkerPoolJobError> {
        self.receiver
            .recv_timeout(timeout)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => HostWorkerPoolJobError::TimedOut,
                RecvTimeoutError::Disconnected => HostWorkerPoolJobError::Panicked,
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWorkerPoolJobError {
    Panicked,
    TimedOut,
}

impl fmt::Display for HostWorkerPoolJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Panicked => formatter.write_str("host worker job panicked or was cancelled"),
            Self::TimedOut => formatter.write_str("host worker job timed out"),
        }
    }
}

impl std::error::Error for HostWorkerPoolJobError {}

type HostWorkerJob = Box<dyn FnOnce() + Send + 'static>;

/// Bounded host worker pool that can execute runtime and I/O completion jobs.
#[derive(Debug)]
pub struct HostWorkerPoolExecutor {
    config: HostWorkerPoolConfig,
    state: Arc<HostWorkerPoolExecutorState>,
    workers: Vec<JoinHandle<()>>,
}

impl HostWorkerPoolExecutor {
    pub fn new(config: HostWorkerPoolConfig) -> std::io::Result<Self> {
        let state = Arc::new(HostWorkerPoolExecutorState {
            inner: Mutex::new(HostWorkerPoolExecutorInner {
                queue: VecDeque::with_capacity(config.queue_capacity()),
                active_workers: 0,
                submitted_jobs: 0,
                completed_jobs: 0,
                rejected_jobs: 0,
                shutdown: false,
            }),
            available: Condvar::new(),
        });
        let mut workers = Vec::with_capacity(config.max_workers());
        for index in 0..config.max_workers() {
            let worker_state = state.clone();
            let worker = thread::Builder::new()
                .name(format!("mcr-{}-{index}", config.role()))
                .spawn(move || host_worker_loop(worker_state))?;
            workers.push(worker);
        }

        Ok(Self {
            config,
            state,
            workers,
        })
    }

    pub fn submit(
        &self,
        job: impl FnOnce() + Send + 'static,
    ) -> Result<HostWorkerPoolSubmission, HostWorkerPoolSubmitError> {
        let mut inner = self
            .state
            .inner
            .lock()
            .expect("host worker pool mutex poisoned");
        if inner.shutdown {
            inner.rejected_jobs += 1;
            return Err(HostWorkerPoolSubmitError::Shutdown {
                role: self.config.role(),
            });
        }
        if inner.queue.len() >= self.config.queue_capacity() {
            inner.rejected_jobs += 1;
            return Err(HostWorkerPoolSubmitError::QueueFull {
                role: self.config.role(),
                active_workers: inner.active_workers,
                queued_jobs: inner.queue.len(),
                max_workers: self.config.max_workers(),
                max_queued_jobs: self.config.queue_capacity(),
            });
        }

        inner.queue.push_back(Box::new(job));
        inner.submitted_jobs += 1;
        drop(inner);
        self.state.available.notify_one();
        Ok(HostWorkerPoolSubmission::Queued)
    }

    pub fn submit_result<T>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<HostWorkerPoolJob<T>, HostWorkerPoolSubmitError>
    where
        T: Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        let submission = self.submit(move || {
            let _ = sender.send(job());
        })?;
        Ok(HostWorkerPoolJob {
            submission,
            receiver,
        })
    }

    #[must_use]
    pub fn diagnostics(&self) -> HostWorkerPoolDiagnostics {
        let inner = self
            .state
            .inner
            .lock()
            .expect("host worker pool mutex poisoned");
        HostWorkerPoolDiagnostics::new(
            self.config.role(),
            self.config.max_workers(),
            self.config.queue_capacity(),
            inner.active_workers,
            inner.queue.len(),
            inner.submitted_jobs,
            inner.completed_jobs,
            inner.rejected_jobs,
        )
    }

    pub fn shutdown(mut self) {
        self.shutdown_workers();
    }

    fn shutdown_workers(&mut self) {
        {
            let mut inner = self
                .state
                .inner
                .lock()
                .expect("host worker pool mutex poisoned");
            inner.shutdown = true;
        }
        self.state.available.notify_all();
        while let Some(worker) = self.workers.pop() {
            let _ = worker.join();
        }
    }
}

impl Drop for HostWorkerPoolExecutor {
    fn drop(&mut self) {
        self.shutdown_workers();
    }
}

#[derive(Debug)]
struct HostWorkerPoolExecutorState {
    inner: Mutex<HostWorkerPoolExecutorInner>,
    available: Condvar,
}

struct HostWorkerPoolExecutorInner {
    queue: VecDeque<HostWorkerJob>,
    active_workers: usize,
    submitted_jobs: usize,
    completed_jobs: usize,
    rejected_jobs: usize,
    shutdown: bool,
}

impl fmt::Debug for HostWorkerPoolExecutorInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostWorkerPoolExecutorInner")
            .field("queued_jobs", &self.queue.len())
            .field("active_workers", &self.active_workers)
            .field("submitted_jobs", &self.submitted_jobs)
            .field("completed_jobs", &self.completed_jobs)
            .field("rejected_jobs", &self.rejected_jobs)
            .field("shutdown", &self.shutdown)
            .finish()
    }
}

fn host_worker_loop(state: Arc<HostWorkerPoolExecutorState>) {
    loop {
        let job = {
            let mut inner = state.inner.lock().expect("host worker pool mutex poisoned");
            loop {
                if let Some(job) = inner.queue.pop_front() {
                    inner.active_workers += 1;
                    break job;
                }
                if inner.shutdown {
                    return;
                }
                inner = state
                    .available
                    .wait(inner)
                    .expect("host worker pool mutex poisoned");
            }
        };

        let _ = catch_unwind(AssertUnwindSafe(job));
        let mut inner = state.inner.lock().expect("host worker pool mutex poisoned");
        inner.active_workers -= 1;
        inner.completed_jobs += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn pool_config_rejects_zero_and_unbounded_worker_limits() {
        assert_eq!(
            HostWorkerPoolConfig::new(HostWorkerPoolRole::GuestTaskExecution, 0),
            Err(HostWorkerPoolConfigError::ZeroWorkers {
                role: HostWorkerPoolRole::GuestTaskExecution
            })
        );
        assert_eq!(
            HostWorkerPoolConfig::new(
                HostWorkerPoolRole::IoCompletion,
                HOST_WORKER_POOL_MAX_WORKERS + 1,
            ),
            Err(HostWorkerPoolConfigError::TooManyWorkers {
                role: HostWorkerPoolRole::IoCompletion,
                max_workers: HOST_WORKER_POOL_MAX_WORKERS + 1,
                max_allowed: HOST_WORKER_POOL_MAX_WORKERS,
            })
        );
        assert_eq!(
            HostWorkerPoolConfig::with_queue_capacity(HostWorkerPoolRole::GuestTaskExecution, 1, 0),
            Err(HostWorkerPoolConfigError::ZeroQueueCapacity {
                role: HostWorkerPoolRole::GuestTaskExecution
            })
        );
        assert_eq!(
            HostWorkerPoolConfig::with_queue_capacity(
                HostWorkerPoolRole::IoCompletion,
                1,
                HOST_WORKER_POOL_MAX_QUEUED_JOBS + 1,
            ),
            Err(HostWorkerPoolConfigError::TooManyQueuedJobs {
                role: HostWorkerPoolRole::IoCompletion,
                queue_capacity: HOST_WORKER_POOL_MAX_QUEUED_JOBS + 1,
                max_allowed: HOST_WORKER_POOL_MAX_QUEUED_JOBS,
            })
        );
    }

    #[test]
    fn executor_runs_jobs_and_reports_active_queued_and_completed_counts() {
        let config =
            HostWorkerPoolConfig::with_queue_capacity(HostWorkerPoolRole::IoCompletion, 2, 4)
                .unwrap();
        let executor = HostWorkerPoolExecutor::new(config).unwrap();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        for id in 0..2 {
            let release = release.clone();
            let started_tx = started_tx.clone();
            let done_tx = done_tx.clone();
            assert_eq!(
                executor.submit(move || {
                    started_tx.send(id).unwrap();
                    let (lock, cvar) = &*release;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = cvar.wait(released).unwrap();
                    }
                    done_tx.send(id).unwrap();
                }),
                Ok(HostWorkerPoolSubmission::Queued)
            );
        }

        let _ = started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let _ = started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let diagnostics = executor.diagnostics();
        assert_eq!(diagnostics.active_workers(), 2);
        assert_eq!(diagnostics.queued_jobs(), 0);
        assert_eq!(diagnostics.submitted_jobs(), 2);

        let done_tx_queued = done_tx.clone();
        assert_eq!(
            executor.submit(move || {
                done_tx_queued.send(2).unwrap();
            }),
            Ok(HostWorkerPoolSubmission::Queued)
        );
        assert_eq!(executor.diagnostics().queued_jobs(), 1);

        {
            let (lock, cvar) = &*release;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }

        let mut completed = [
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        ];
        completed.sort_unstable();
        assert_eq!(completed, [0, 1, 2]);

        let diagnostics = executor.diagnostics();
        assert_eq!(diagnostics.active_workers(), 0);
        assert_eq!(diagnostics.queued_jobs(), 0);
        assert_eq!(diagnostics.completed_jobs(), 3);
        executor.shutdown();
    }

    #[test]
    fn executor_returns_typed_job_results() {
        let config =
            HostWorkerPoolConfig::with_queue_capacity(HostWorkerPoolRole::IoCompletion, 1, 2)
                .unwrap();
        let executor = HostWorkerPoolExecutor::new(config).unwrap();

        let job = executor.submit_result(|| 42usize).unwrap();

        assert_eq!(job.submission(), HostWorkerPoolSubmission::Queued);
        assert_eq!(job.recv_timeout(Duration::from_secs(2)), Ok(42));
        let diagnostics = executor.diagnostics();
        assert_eq!(diagnostics.submitted_jobs(), 1);
        assert_eq!(diagnostics.completed_jobs(), 1);
        executor.shutdown();
    }

    #[test]
    fn executor_result_job_reports_panic_as_disconnected() {
        let config =
            HostWorkerPoolConfig::with_queue_capacity(HostWorkerPoolRole::IoCompletion, 1, 2)
                .unwrap();
        let executor = HostWorkerPoolExecutor::new(config).unwrap();

        let job = executor
            .submit_result(|| -> usize {
                panic!("worker result failure");
            })
            .unwrap();

        assert_eq!(
            job.recv_timeout(Duration::from_secs(2)),
            Err(HostWorkerPoolJobError::Panicked)
        );
        assert_eq!(executor.diagnostics().completed_jobs(), 1);
        executor.shutdown();
    }

    #[test]
    fn executor_rejects_full_queue_without_losing_diagnostics() {
        let config =
            HostWorkerPoolConfig::with_queue_capacity(HostWorkerPoolRole::GuestTaskExecution, 1, 1)
                .unwrap();
        let executor = HostWorkerPoolExecutor::new(config).unwrap();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel();

        let release_running = release.clone();
        executor
            .submit(move || {
                started_tx.send(()).unwrap();
                let (lock, cvar) = &*release_running;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = cvar.wait(released).unwrap();
                }
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        executor.submit(|| {}).unwrap();
        assert_eq!(
            executor.submit(|| {}),
            Err(HostWorkerPoolSubmitError::QueueFull {
                role: HostWorkerPoolRole::GuestTaskExecution,
                active_workers: 1,
                queued_jobs: 1,
                max_workers: 1,
                max_queued_jobs: 1,
            })
        );

        let diagnostics = executor.diagnostics();
        assert_eq!(diagnostics.active_workers(), 1);
        assert_eq!(diagnostics.queued_jobs(), 1);
        assert_eq!(diagnostics.submitted_jobs(), 2);
        assert_eq!(diagnostics.rejected_jobs(), 1);

        {
            let (lock, cvar) = &*release;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        executor.shutdown();
    }
}
