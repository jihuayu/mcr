use std::fmt;

pub const HOST_WORKER_POOL_MAX_WORKERS: usize = 64;
pub const DEFAULT_GUEST_TASK_WORKERS: usize = 4;
pub const DEFAULT_IO_COMPLETION_WORKERS: usize = 4;

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
}

impl HostWorkerPoolConfig {
    pub const fn new(
        role: HostWorkerPoolRole,
        max_workers: usize,
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

        Ok(Self { role, max_workers })
    }

    #[must_use]
    pub const fn default_for(role: HostWorkerPoolRole) -> Self {
        Self {
            role,
            max_workers: role.default_max_workers(),
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
        }
    }
}

impl std::error::Error for HostWorkerPoolConfigError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostWorkerPoolDiagnostics {
    role: HostWorkerPoolRole,
    max_workers: usize,
    active_workers: usize,
    queued_jobs: usize,
}

impl HostWorkerPoolDiagnostics {
    #[must_use]
    pub const fn role(self) -> HostWorkerPoolRole {
        self.role
    }

    #[must_use]
    pub const fn max_workers(self) -> usize {
        self.max_workers
    }

    #[must_use]
    pub const fn active_workers(self) -> usize {
        self.active_workers
    }

    #[must_use]
    pub const fn queued_jobs(self) -> usize {
        self.queued_jobs
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostWorkerPoolBoundary {
    config: HostWorkerPoolConfig,
    active_workers: usize,
    queued_jobs: usize,
}

impl HostWorkerPoolBoundary {
    #[must_use]
    pub const fn new(config: HostWorkerPoolConfig) -> Self {
        Self {
            config,
            active_workers: 0,
            queued_jobs: 0,
        }
    }

    #[must_use]
    pub const fn config(&self) -> HostWorkerPoolConfig {
        self.config
    }

    #[must_use]
    pub const fn diagnostics(&self) -> HostWorkerPoolDiagnostics {
        HostWorkerPoolDiagnostics {
            role: self.config.role(),
            max_workers: self.config.max_workers(),
            active_workers: self.active_workers,
            queued_jobs: self.queued_jobs,
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

    #[must_use]
    pub const fn io_completions(&self) -> &HostWorkerPoolBoundary {
        &self.io_completions
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
        assert_eq!(diagnostics[0].active_workers(), 0);
        assert_eq!(diagnostics[0].queued_jobs(), 0);
        assert_eq!(diagnostics[1].role(), HostWorkerPoolRole::IoCompletion);
        assert_eq!(
            diagnostics[1].max_workers(),
            HostWorkerPoolRole::IoCompletion.default_max_workers()
        );
        assert_eq!(diagnostics[1].active_workers(), 0);
        assert_eq!(diagnostics[1].queued_jobs(), 0);
        assert!(diagnostics.iter().all(
            |pool| pool.max_workers() > 0 && pool.max_workers() <= HOST_WORKER_POOL_MAX_WORKERS
        ));
    }

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
    }
}
