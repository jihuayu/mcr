use std::fmt;

use mcr_win::{
    HostWorkerPoolConfig, HostWorkerPoolConfigError, HostWorkerPoolDiagnostics, HostWorkerPoolRole,
    HostWorkerPoolSubmission, HostWorkerPoolSubmitError,
};

#[cfg(test)]
use mcr_win::{HOST_WORKER_POOL_MAX_QUEUED_JOBS, HOST_WORKER_POOL_MAX_WORKERS};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWorkerPoolCompletion {
    IdleWorkerReleased,
    QueuedJobStarted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWorkerPoolCompletionError {
    NoActiveWorker { role: HostWorkerPoolRole },
}

impl fmt::Display for HostWorkerPoolCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoActiveWorker { role } => {
                write!(
                    formatter,
                    "{role} worker pool has no active worker to complete"
                )
            }
        }
    }
}

impl std::error::Error for HostWorkerPoolCompletionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostWorkerPoolBoundary {
    config: HostWorkerPoolConfig,
    active_workers: usize,
    queued_jobs: usize,
    submitted_jobs: usize,
    completed_jobs: usize,
    rejected_jobs: usize,
}

impl HostWorkerPoolBoundary {
    #[must_use]
    pub const fn new(config: HostWorkerPoolConfig) -> Self {
        Self {
            config,
            active_workers: 0,
            queued_jobs: 0,
            submitted_jobs: 0,
            completed_jobs: 0,
            rejected_jobs: 0,
        }
    }

    #[must_use]
    pub const fn config(&self) -> HostWorkerPoolConfig {
        self.config
    }

    #[must_use]
    pub const fn diagnostics(&self) -> HostWorkerPoolDiagnostics {
        HostWorkerPoolDiagnostics::new(
            self.config.role(),
            self.config.max_workers(),
            self.config.queue_capacity(),
            self.active_workers,
            self.queued_jobs,
            self.submitted_jobs,
            self.completed_jobs,
            self.rejected_jobs,
        )
    }

    pub fn try_submit(&mut self) -> Result<HostWorkerPoolSubmission, HostWorkerPoolSubmitError> {
        if self.active_workers < self.config.max_workers() {
            self.active_workers += 1;
            self.submitted_jobs += 1;
            return Ok(HostWorkerPoolSubmission::Started);
        }

        if self.queued_jobs < self.config.queue_capacity() {
            self.queued_jobs += 1;
            self.submitted_jobs += 1;
            return Ok(HostWorkerPoolSubmission::Queued);
        }

        self.rejected_jobs += 1;
        Err(HostWorkerPoolSubmitError::QueueFull {
            role: self.config.role(),
            active_workers: self.active_workers,
            queued_jobs: self.queued_jobs,
            max_workers: self.config.max_workers(),
            max_queued_jobs: self.config.queue_capacity(),
        })
    }

    pub fn complete_one(
        &mut self,
    ) -> Result<HostWorkerPoolCompletion, HostWorkerPoolCompletionError> {
        if self.active_workers == 0 {
            return Err(HostWorkerPoolCompletionError::NoActiveWorker {
                role: self.config.role(),
            });
        }

        self.completed_jobs += 1;
        if self.queued_jobs > 0 {
            self.queued_jobs -= 1;
            Ok(HostWorkerPoolCompletion::QueuedJobStarted)
        } else {
            self.active_workers -= 1;
            Ok(HostWorkerPoolCompletion::IdleWorkerReleased)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostWorkerPools {
    guest_tasks: HostWorkerPoolBoundary,
    io_completions: HostWorkerPoolBoundary,
}

impl HostWorkerPools {
    pub const fn new(
        guest_task_workers: usize,
        io_completion_workers: usize,
    ) -> Result<Self, HostWorkerPoolConfigError> {
        let guest_tasks = match HostWorkerPoolConfig::new(
            HostWorkerPoolRole::GuestTaskExecution,
            guest_task_workers,
        ) {
            Ok(config) => HostWorkerPoolBoundary::new(config),
            Err(error) => return Err(error),
        };
        let io_completions = match HostWorkerPoolConfig::new(
            HostWorkerPoolRole::IoCompletion,
            io_completion_workers,
        ) {
            Ok(config) => HostWorkerPoolBoundary::new(config),
            Err(error) => return Err(error),
        };

        Ok(Self {
            guest_tasks,
            io_completions,
        })
    }

    #[must_use]
    pub const fn default_bounded() -> Self {
        Self {
            guest_tasks: HostWorkerPoolBoundary::new(HostWorkerPoolConfig::default_for(
                HostWorkerPoolRole::GuestTaskExecution,
            )),
            io_completions: HostWorkerPoolBoundary::new(HostWorkerPoolConfig::default_for(
                HostWorkerPoolRole::IoCompletion,
            )),
        }
    }

    #[must_use]
    pub const fn guest_tasks(&self) -> &HostWorkerPoolBoundary {
        &self.guest_tasks
    }

    pub fn guest_tasks_mut(&mut self) -> &mut HostWorkerPoolBoundary {
        &mut self.guest_tasks
    }

    #[must_use]
    pub const fn io_completions(&self) -> &HostWorkerPoolBoundary {
        &self.io_completions
    }

    pub fn io_completions_mut(&mut self) -> &mut HostWorkerPoolBoundary {
        &mut self.io_completions
    }

    #[must_use]
    pub const fn diagnostics(&self) -> [HostWorkerPoolDiagnostics; 2] {
        [
            self.guest_tasks.diagnostics(),
            self.io_completions.diagnostics(),
        ]
    }
}

impl Default for HostWorkerPools {
    fn default() -> Self {
        Self::default_bounded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_limits_are_bounded_and_observable() {
        let pools = HostWorkerPools::default_bounded();
        let diagnostics = pools.diagnostics();

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(
            diagnostics[0].role(),
            HostWorkerPoolRole::GuestTaskExecution
        );
        assert_eq!(
            diagnostics[0].max_workers(),
            HostWorkerPoolRole::GuestTaskExecution.default_max_workers()
        );
        assert_eq!(
            diagnostics[0].max_queued_jobs(),
            HostWorkerPoolRole::GuestTaskExecution.default_queue_capacity()
        );
        assert_eq!(diagnostics[0].active_workers(), 0);
        assert_eq!(diagnostics[0].queued_jobs(), 0);
        assert_eq!(diagnostics[0].submitted_jobs(), 0);
        assert_eq!(diagnostics[0].completed_jobs(), 0);
        assert_eq!(diagnostics[0].rejected_jobs(), 0);
        assert_eq!(diagnostics[1].role(), HostWorkerPoolRole::IoCompletion);
        assert_eq!(
            diagnostics[1].max_workers(),
            HostWorkerPoolRole::IoCompletion.default_max_workers()
        );
        assert_eq!(
            diagnostics[1].max_queued_jobs(),
            HostWorkerPoolRole::IoCompletion.default_queue_capacity()
        );
        assert_eq!(diagnostics[1].active_workers(), 0);
        assert_eq!(diagnostics[1].queued_jobs(), 0);
        assert_eq!(diagnostics[1].submitted_jobs(), 0);
        assert_eq!(diagnostics[1].completed_jobs(), 0);
        assert_eq!(diagnostics[1].rejected_jobs(), 0);
        assert!(diagnostics.iter().all(|pool| {
            pool.max_workers() > 0
                && pool.max_workers() <= HOST_WORKER_POOL_MAX_WORKERS
                && pool.max_queued_jobs() > 0
                && pool.max_queued_jobs() <= HOST_WORKER_POOL_MAX_QUEUED_JOBS
        }));
    }

    #[test]
    fn submissions_are_bounded_queued_promoted_and_rejected() {
        let config =
            HostWorkerPoolConfig::with_queue_capacity(HostWorkerPoolRole::GuestTaskExecution, 2, 1)
                .unwrap();
        let mut pool = HostWorkerPoolBoundary::new(config);

        assert_eq!(pool.try_submit(), Ok(HostWorkerPoolSubmission::Started));
        assert_eq!(pool.try_submit(), Ok(HostWorkerPoolSubmission::Started));
        assert_eq!(pool.try_submit(), Ok(HostWorkerPoolSubmission::Queued));
        assert_eq!(
            pool.try_submit(),
            Err(HostWorkerPoolSubmitError::QueueFull {
                role: HostWorkerPoolRole::GuestTaskExecution,
                active_workers: 2,
                queued_jobs: 1,
                max_workers: 2,
                max_queued_jobs: 1,
            })
        );

        let diagnostics = pool.diagnostics();
        assert_eq!(diagnostics.active_workers(), 2);
        assert_eq!(diagnostics.queued_jobs(), 1);
        assert_eq!(diagnostics.submitted_jobs(), 3);
        assert_eq!(diagnostics.completed_jobs(), 0);
        assert_eq!(diagnostics.rejected_jobs(), 1);

        assert_eq!(
            pool.complete_one(),
            Ok(HostWorkerPoolCompletion::QueuedJobStarted)
        );
        let diagnostics = pool.diagnostics();
        assert_eq!(diagnostics.active_workers(), 2);
        assert_eq!(diagnostics.queued_jobs(), 0);
        assert_eq!(diagnostics.completed_jobs(), 1);

        assert_eq!(
            pool.complete_one(),
            Ok(HostWorkerPoolCompletion::IdleWorkerReleased)
        );
        assert_eq!(
            pool.complete_one(),
            Ok(HostWorkerPoolCompletion::IdleWorkerReleased)
        );
        let diagnostics = pool.diagnostics();
        assert_eq!(diagnostics.active_workers(), 0);
        assert_eq!(diagnostics.queued_jobs(), 0);
        assert_eq!(diagnostics.completed_jobs(), 3);
        assert_eq!(
            pool.complete_one(),
            Err(HostWorkerPoolCompletionError::NoActiveWorker {
                role: HostWorkerPoolRole::GuestTaskExecution,
            })
        );
    }
}
