use mcr_sys::{
    CloneSyscallArgs, GuestAddress, GuestPid, GuestTid, KillSyscallArgs, LinuxErrno, LinuxUtsname,
    RtSigactionSyscallArgs, RtSigprocmaskSyscallArgs, SetRobustListSyscallArgs,
    SetTidAddressSyscallArgs, Syscall, SyscallOutcome, SyscallRequest, TaskSyscalls,
    TgkillSyscallArgs, TkillSyscallArgs, Wait4SyscallArgs,
};

use super::GuestKernel;
use crate::{
    ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_FS, ARCH_SET_GS, GuestProcess, GuestProgram,
    X86_64_SYSCALL_INSTRUCTION_LEN,
};

impl GuestKernel {
    pub fn dispatch_for_current_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        let tid = request.context.tid;
        let Some(task) = self.tasks.get(&tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };

        if task.pid != request.context.pid {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        }

        match request.syscall {
            Syscall::Getpid => SyscallOutcome::success(u64::from(task.pid)),
            Syscall::Gettid => SyscallOutcome::success(u64::from(task.tid)),
            Syscall::Getppid => {
                SyscallOutcome::success(u64::from(task_process(self, task.pid).parent.unwrap_or(0)))
            }
            Syscall::Getpgrp => {
                SyscallOutcome::success(u64::from(task_process(self, task.pid).pgid))
            }
            Syscall::Getpgid => self.getpgid_current(task.pid, arg(request, 0)),
            Syscall::Getsid => self.getsid_current(task.pid, arg(request, 0)),
            Syscall::Getuid | Syscall::Geteuid | Syscall::Getgid | Syscall::Getegid => {
                SyscallOutcome::success(0)
            }
            Syscall::Setuid | Syscall::Setgid | Syscall::Setreuid | Syscall::Setregid => {
                SyscallOutcome::success(0)
            }
            Syscall::Setpgid => self.setpgid_current(task.pid, arg(request, 0), arg(request, 1)),
            Syscall::Setsid => self.setsid_current(task.pid),
            Syscall::Fork => self.fork_like_current(tid, "fork", child_return_rip(request)),
            Syscall::Vfork => self.vfork_current(tid),
            Syscall::Clone => self.clone_current_with_return(
                tid,
                CloneSyscallArgs::new(
                    arg(request, 0),
                    arg(request, 1),
                    arg(request, 2),
                    arg(request, 3),
                    arg(request, 4),
                ),
                child_return_rip(request),
            ),
            Syscall::Exit => self.exit_task(tid, low_exit_status(arg(request, 0))),
            Syscall::ExitGroup => self.exit_group(task.pid, low_exit_status(arg(request, 0))),
            Syscall::Wait4 => self.wait4_current_with_return(
                tid,
                Wait4SyscallArgs::new(
                    arg(request, 0) as i32,
                    arg(request, 1),
                    arg(request, 2) as u32,
                    arg(request, 3),
                ),
                child_return_rip(request),
            ),
            Syscall::RtSigaction => self.rt_sigaction_current(
                tid,
                RtSigactionSyscallArgs::new(
                    arg(request, 0) as u32,
                    arg(request, 1),
                    arg(request, 2),
                    arg(request, 3),
                ),
            ),
            Syscall::RtSigprocmask => self.rt_sigprocmask_current(
                tid,
                RtSigprocmaskSyscallArgs::new(
                    arg(request, 0) as u32,
                    arg(request, 1),
                    arg(request, 2),
                    arg(request, 3),
                ),
            ),
            Syscall::RtSigreturn => SyscallOutcome::success(0),
            Syscall::RtSigtimedwait => self.rt_sigtimedwait_current(tid, 0, arg(request, 3), false),
            Syscall::Kill => self.kill_current(KillSyscallArgs::new(
                arg(request, 0) as i32,
                arg(request, 1) as u32,
            )),
            Syscall::Tkill => self.tkill_current(TkillSyscallArgs::new(
                arg(request, 0) as i32,
                arg(request, 1) as u32,
            )),
            Syscall::Tgkill => self.tgkill_current(TgkillSyscallArgs::new(
                arg(request, 0) as i32,
                arg(request, 1) as i32,
                arg(request, 2) as u32,
            )),
            Syscall::SetTidAddress => {
                self.set_tid_address_current(tid, SetTidAddressSyscallArgs::new(arg(request, 0)))
            }
            Syscall::SetRobustList => self.set_robust_list_current(
                tid,
                SetRobustListSyscallArgs::new(arg(request, 0), arg(request, 1)),
            ),
            Syscall::Uname => self.uname(arg(request, 0)),
            Syscall::ArchPrctl => self.arch_prctl(tid, arg(request, 0), arg(request, 1)),
            Syscall::Execve => {
                let image = &task_process(self, task.pid).image;
                let mut program = GuestProgram::new(image.executable.clone());
                if let Some(interpreter) = &image.interpreter {
                    program = program.with_interpreter(interpreter.clone());
                }
                self.execve_current(tid, program)
            }
            _ => SyscallOutcome::unsupported(),
        }
    }

    fn setpgid_current(
        &mut self,
        current_pid: GuestPid,
        raw_pid: u64,
        raw_pgid: u64,
    ) -> SyscallOutcome {
        let pid = if raw_pid == 0 {
            current_pid
        } else {
            match GuestPid::try_from(raw_pid) {
                Ok(pid) => pid,
                Err(_) => return SyscallOutcome::errno(LinuxErrno::EINVAL),
            }
        };
        let pgid = if raw_pgid == 0 {
            pid
        } else {
            match GuestPid::try_from(raw_pgid) {
                Ok(pgid) => pgid,
                Err(_) => return SyscallOutcome::errno(LinuxErrno::EINVAL),
            }
        };
        let Some(process) = self.processes.get_mut(&pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        if process.parent != Some(current_pid) && pid != current_pid {
            return SyscallOutcome::errno(LinuxErrno::EPERM);
        }
        process.pgid = pgid;
        SyscallOutcome::success(0)
    }

    fn setsid_current(&mut self, current_pid: GuestPid) -> SyscallOutcome {
        let Some(process) = self.processes.get_mut(&current_pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        process.sid = current_pid;
        process.pgid = current_pid;
        SyscallOutcome::success(current_pid.into())
    }

    fn getpgid_current(&self, current_pid: GuestPid, raw_pid: u64) -> SyscallOutcome {
        let pid = if raw_pid == 0 {
            current_pid
        } else {
            match GuestPid::try_from(raw_pid) {
                Ok(pid) => pid,
                Err(_) => return SyscallOutcome::errno(LinuxErrno::ESRCH),
            }
        };
        let Some(process) = self.processes.get(&pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        SyscallOutcome::success(u64::from(process.pgid))
    }

    fn getsid_current(&self, current_pid: GuestPid, raw_pid: u64) -> SyscallOutcome {
        let pid = if raw_pid == 0 {
            current_pid
        } else {
            match GuestPid::try_from(raw_pid) {
                Ok(pid) => pid,
                Err(_) => return SyscallOutcome::errno(LinuxErrno::ESRCH),
            }
        };
        let Some(process) = self.processes.get(&pid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };
        SyscallOutcome::success(u64::from(process.sid))
    }

    pub fn arch_prctl(
        &mut self,
        tid: GuestTid,
        code: u64,
        address: GuestAddress,
    ) -> SyscallOutcome {
        let Some(task) = self.tasks.get_mut(&tid) else {
            return SyscallOutcome::errno(LinuxErrno::ESRCH);
        };

        match code {
            ARCH_SET_FS => {
                task.tls.fs_base = address;
                SyscallOutcome::success(0).with_decoded_field("fs_base", format!("{address:#x}"))
            }
            ARCH_SET_GS => {
                task.tls.gs_base = address;
                SyscallOutcome::success(0).with_decoded_field("gs_base", format!("{address:#x}"))
            }
            ARCH_GET_FS => SyscallOutcome::success(task.tls.fs_base)
                .with_decoded_field("fs_base", format!("{:#x}", task.tls.fs_base)),
            ARCH_GET_GS => SyscallOutcome::success(task.tls.gs_base)
                .with_decoded_field("gs_base", format!("{:#x}", task.tls.gs_base)),
            _ => SyscallOutcome::errno(LinuxErrno::EINVAL)
                .with_decoded_field("arch_prctl_code", format!("{code:#x}")),
        }
    }

    pub fn uname(&self, buffer: GuestAddress) -> SyscallOutcome {
        if buffer == 0 {
            return SyscallOutcome::errno(LinuxErrno::EFAULT);
        }

        SyscallOutcome::success(0)
            .with_decoded_field("sysname", "Linux")
            .with_decoded_field("nodename", "mcr")
            .with_decoded_field("release", "6.6.0-mcr")
            .with_decoded_field("version", "#1 MCR")
            .with_decoded_field("machine", "x86_64")
            .with_decoded_field("domainname", "(none)")
    }

    #[must_use]
    pub fn uname_value(&self) -> LinuxUtsname {
        linux_utsname()
    }
}

impl TaskSyscalls for GuestKernel {
    fn dispatch_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        self.dispatch_for_current_task(request)
    }
}

fn task_process(kernel: &GuestKernel, pid: GuestPid) -> &GuestProcess {
    kernel
        .process(pid)
        .expect("validated task pid must reference a process")
}

fn arg(request: &SyscallRequest, index: usize) -> u64 {
    request.arg(index).unwrap_or_default()
}

const fn child_return_rip(request: &SyscallRequest) -> GuestAddress {
    request
        .context
        .rip
        .saturating_add(X86_64_SYSCALL_INSTRUCTION_LEN)
}

fn low_exit_status(raw: u64) -> i32 {
    (raw & 0xff) as i32
}

fn linux_utsname() -> LinuxUtsname {
    let mut uts = LinuxUtsname::default();
    write_uts_field(&mut uts.sysname, b"Linux");
    write_uts_field(&mut uts.nodename, b"mcr");
    write_uts_field(&mut uts.release, b"6.6.0-mcr");
    write_uts_field(&mut uts.version, b"#1 MCR");
    write_uts_field(&mut uts.machine, b"x86_64");
    write_uts_field(&mut uts.domainname, b"(none)");
    uts
}

fn write_uts_field(field: &mut [u8], value: &[u8]) {
    let len = value.len().min(field.len().saturating_sub(1));
    field[..len].copy_from_slice(&value[..len]);
}
