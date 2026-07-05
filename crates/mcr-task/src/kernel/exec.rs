use mcr_sys::{GuestTid, SyscallOutcome};

use super::GuestKernel;
use crate::{
    ExitState, GprState, GuestProgram, TaskError, TaskState, TlsState, program::load_program,
};

impl GuestKernel {
    pub fn execve_current(&mut self, tid: GuestTid, program: GuestProgram) -> SyscallOutcome {
        match self.exec_task(tid, program) {
            Ok(()) => SyscallOutcome::success(0),
            Err(error) => error.into_outcome(),
        }
    }

    pub fn exec_task(&mut self, tid: GuestTid, program: GuestProgram) -> Result<(), TaskError> {
        let pid = self
            .task(tid)
            .ok_or(TaskError::UnknownTid(tid))
            .map(|task| task.pid)?;
        let image = load_program(program)?;

        {
            let process = self.process_mut(pid).ok_or(TaskError::UnknownPid(pid))?;
            process.files.close_on_exec();
            process.image = image;
            process.exit_state = ExitState::Running;
        }

        let (entrypoint, stack_pointer) = {
            let memory = self
                .process(pid)
                .ok_or(TaskError::UnknownPid(pid))?
                .image
                .memory();
            (memory.entrypoint(), memory.initial_stack_pointer())
        };
        let task = self.task_mut(tid).ok_or(TaskError::UnknownTid(tid))?;
        task.regs = GprState::new(entrypoint, stack_pointer);
        task.tls = TlsState::new();
        task.state = TaskState::Runnable;
        task.robust_list = None;
        task.clear_child_tid = None;

        self.resume_vfork_parent(pid);
        Ok(())
    }
}
