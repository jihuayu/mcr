mod clone;
mod exec;
mod signal;
mod syscalls;
mod wait;

use std::collections::{BTreeMap, BTreeSet};

use mcr_sys::{GuestAddress, GuestPid, GuestTid};

use crate::{
    ExitState, GuestFdTable, GuestProcess, GuestProgram, GuestTask, HostWorkerPoolDiagnostics,
    HostWorkerPools, INITIAL_GUEST_PID, INITIAL_GUEST_TID, SignalState, TaskError, TaskState,
    X86_64_SYSCALL_INSTRUCTION_LEN, program::load_program,
};

pub struct GuestKernel {
    next_pid: GuestPid,
    next_tid: GuestTid,
    processes: BTreeMap<GuestPid, GuestProcess>,
    tasks: BTreeMap<GuestTid, GuestTask>,
    runnable_tids: BTreeSet<GuestTid>,
    child_wait_tids: BTreeSet<GuestTid>,
    fd_wait_tids: BTreeSet<GuestTid>,
    futex_wait_tids: BTreeMap<crate::FutexWaitKey, BTreeSet<GuestTid>>,
    host_worker_pools: HostWorkerPools,
}

impl GuestKernel {
    pub fn new(program: GuestProgram) -> Result<Self, TaskError> {
        let mut kernel = Self {
            next_pid: INITIAL_GUEST_PID,
            next_tid: INITIAL_GUEST_TID,
            processes: BTreeMap::new(),
            tasks: BTreeMap::new(),
            runnable_tids: BTreeSet::new(),
            child_wait_tids: BTreeSet::new(),
            fd_wait_tids: BTreeSet::new(),
            futex_wait_tids: BTreeMap::new(),
            host_worker_pools: HostWorkerPools::default_bounded(),
        };
        kernel.create_initial_process(program)?;
        Ok(kernel)
    }

    #[must_use]
    pub const fn next_pid(&self) -> GuestPid {
        self.next_pid
    }

    #[must_use]
    pub const fn next_tid(&self) -> GuestTid {
        self.next_tid
    }

    #[must_use]
    pub fn process(&self, pid: GuestPid) -> Option<&GuestProcess> {
        self.processes.get(&pid)
    }

    #[must_use]
    pub fn process_mut(&mut self, pid: GuestPid) -> Option<&mut GuestProcess> {
        self.processes.get_mut(&pid)
    }

    #[must_use]
    pub fn task(&self, tid: GuestTid) -> Option<&GuestTask> {
        self.tasks.get(&tid)
    }

    #[must_use]
    pub fn task_mut(&mut self, tid: GuestTid) -> Option<&mut GuestTask> {
        self.tasks.get_mut(&tid)
    }

    pub fn tasks(&self) -> impl Iterator<Item = &GuestTask> {
        self.tasks.values()
    }

    #[must_use]
    pub const fn host_worker_pools(&self) -> &HostWorkerPools {
        &self.host_worker_pools
    }

    #[must_use]
    pub const fn host_worker_pool_diagnostics(&self) -> [HostWorkerPoolDiagnostics; 2] {
        self.host_worker_pools.diagnostics()
    }

    fn create_initial_process(&mut self, program: GuestProgram) -> Result<(), TaskError> {
        let pid = self.allocate_pid()?;
        let tid = self.allocate_tid()?;
        let image = load_program(program)?;
        let task = GuestTask::initial(tid, pid, image.memory());

        self.processes.insert(
            pid,
            GuestProcess {
                pid,
                parent: None,
                pgid: pid,
                sid: pid,
                image,
                files: GuestFdTable::with_stdio(),
                signals: SignalState::default(),
                pending_signals: BTreeSet::new(),
                children: BTreeSet::new(),
                exit_state: ExitState::Running,
            },
        );
        self.insert_task(task);

        Ok(())
    }

    pub(super) fn insert_task(&mut self, task: GuestTask) {
        self.index_task_state(task.tid, task.state);
        self.tasks.insert(task.tid, task);
    }

    pub(super) fn remove_task(&mut self, tid: GuestTid) -> Option<GuestTask> {
        let task = self.tasks.remove(&tid)?;
        self.unindex_task_state(task.tid, task.state);
        Some(task)
    }

    pub(super) fn set_task_state(&mut self, tid: GuestTid, state: TaskState) -> Option<TaskState> {
        let previous = self.tasks.get(&tid)?.state;
        if previous == state {
            return Some(previous);
        }
        self.unindex_task_state(tid, previous);
        let task = self.tasks.get_mut(&tid)?;
        task.state = state;
        self.index_task_state(tid, state);
        Some(previous)
    }

    fn index_task_state(&mut self, tid: GuestTid, state: TaskState) {
        match state {
            TaskState::Runnable => {
                self.runnable_tids.insert(tid);
            }
            TaskState::WaitingForChild { .. } => {
                self.child_wait_tids.insert(tid);
            }
            TaskState::WaitingForFd { .. } => {
                self.fd_wait_tids.insert(tid);
            }
            TaskState::WaitingForFutex { key } => {
                self.futex_wait_tids.entry(key).or_default().insert(tid);
            }
            TaskState::WaitingForVfork { .. }
            | TaskState::WaitingForSleep
            | TaskState::WaitingForSignalSet { .. }
            | TaskState::Exited { .. } => {}
        }
    }

    fn unindex_task_state(&mut self, tid: GuestTid, state: TaskState) {
        match state {
            TaskState::Runnable => {
                self.runnable_tids.remove(&tid);
            }
            TaskState::WaitingForChild { .. } => {
                self.child_wait_tids.remove(&tid);
            }
            TaskState::WaitingForFd { .. } => {
                self.fd_wait_tids.remove(&tid);
            }
            TaskState::WaitingForFutex { key } => {
                let mut remove_key = false;
                if let Some(waiters) = self.futex_wait_tids.get_mut(&key) {
                    waiters.remove(&tid);
                    remove_key = waiters.is_empty();
                }
                if remove_key {
                    self.futex_wait_tids.remove(&key);
                }
            }
            TaskState::WaitingForVfork { .. }
            | TaskState::WaitingForSleep
            | TaskState::WaitingForSignalSet { .. }
            | TaskState::Exited { .. } => {}
        }
    }

    fn allocate_pid(&mut self) -> Result<GuestPid, TaskError> {
        let pid = self.next_pid;
        self.next_pid = self
            .next_pid
            .checked_add(1)
            .ok_or(TaskError::PidExhausted)?;
        Ok(pid)
    }

    fn allocate_tid(&mut self) -> Result<GuestTid, TaskError> {
        let tid = self.next_tid;
        self.next_tid = self
            .next_tid
            .checked_add(1)
            .ok_or(TaskError::TidExhausted)?;
        Ok(tid)
    }
}

pub(super) fn current_syscall_return_rip(kernel: &GuestKernel, tid: GuestTid) -> GuestAddress {
    kernel.task(tid).map_or(0, |task| {
        task.regs()
            .rip()
            .saturating_add(X86_64_SYSCALL_INSTRUCTION_LEN)
    })
}
