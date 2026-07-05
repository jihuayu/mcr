mod clone;
mod exec;
mod signal;
mod syscalls;
mod wait;

use std::collections::{BTreeMap, BTreeSet};

use mcr_sys::{GuestAddress, GuestPid, GuestTid};

use crate::{
    ExitState, GuestFdTable, GuestProcess, GuestProgram, GuestTask, HostWorkerPoolDiagnostics,
    HostWorkerPools, INITIAL_GUEST_PID, INITIAL_GUEST_TID, SignalState, TaskError,
    X86_64_SYSCALL_INSTRUCTION_LEN, program::load_program,
};

pub struct GuestKernel {
    next_pid: GuestPid,
    next_tid: GuestTid,
    processes: BTreeMap<GuestPid, GuestProcess>,
    tasks: BTreeMap<GuestTid, GuestTask>,
    host_worker_pools: HostWorkerPools,
}

impl GuestKernel {
    pub fn new(program: GuestProgram) -> Result<Self, TaskError> {
        let mut kernel = Self {
            next_pid: INITIAL_GUEST_PID,
            next_tid: INITIAL_GUEST_TID,
            processes: BTreeMap::new(),
            tasks: BTreeMap::new(),
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
                children: BTreeSet::new(),
                exit_state: ExitState::Running,
            },
        );
        self.tasks.insert(tid, task);

        Ok(())
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
