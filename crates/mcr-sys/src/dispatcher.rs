use crate::abi::{GuestPid, GuestTid, SyscallArgs, SyscallRegisters};
use crate::errno::LinuxErrno;
use crate::return_value::SyscallReturn;
use crate::syscall::{Syscall, SyscallNumber};
use crate::trace::{
    HostErrorTrace, SyscallEnterEvent, SyscallExitEvent, SyscallTraceEvent, TraceContext,
    TraceField, UnsupportedSyscallEvent,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestContext {
    pub pid: GuestPid,
    pub tid: GuestTid,
    pub registers: SyscallRegisters,
}

impl GuestContext {
    #[must_use]
    pub const fn new(pid: GuestPid, tid: GuestTid, registers: SyscallRegisters) -> Self {
        Self {
            pid,
            tid,
            registers,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallRequest {
    pub context: TraceContext,
    pub syscall: Syscall,
    pub number: SyscallNumber,
    pub args: SyscallArgs,
}

impl SyscallRequest {
    #[must_use]
    pub fn from_guest_context(context: GuestContext) -> Self {
        let registers = context.registers;
        let number = registers.number();

        Self {
            context: TraceContext {
                pid: context.pid,
                tid: context.tid,
                rip: registers.rip,
            },
            syscall: Syscall::from_number(number),
            number,
            args: registers.args(),
        }
    }

    #[must_use]
    pub const fn arg(self, index: usize) -> Option<u64> {
        self.args.get(index)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallSubsystem {
    File,
    Memory,
    Task,
    Time,
    Network,
    Event,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallDescriptor {
    pub syscall: Syscall,
    pub subsystem: SyscallSubsystem,
}

impl SyscallDescriptor {
    #[must_use]
    pub const fn new(syscall: Syscall, subsystem: SyscallSubsystem) -> Self {
        Self { syscall, subsystem }
    }
}

pub const SYSCALL_DISPATCH_TABLE: &[SyscallDescriptor] = &[
    SyscallDescriptor::new(Syscall::Read, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Write, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Open, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Close, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Stat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Fstat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Lstat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Fsync, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Fdatasync, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Poll, SyscallSubsystem::Event),
    SyscallDescriptor::new(Syscall::Lseek, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Mmap, SyscallSubsystem::Memory),
    SyscallDescriptor::new(Syscall::Mprotect, SyscallSubsystem::Memory),
    SyscallDescriptor::new(Syscall::Munmap, SyscallSubsystem::Memory),
    SyscallDescriptor::new(Syscall::Brk, SyscallSubsystem::Memory),
    SyscallDescriptor::new(Syscall::RtSigaction, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::RtSigprocmask, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::RtSigreturn, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Ioctl, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Pread64, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Readv, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Writev, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Access, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Pipe, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Select, SyscallSubsystem::Event),
    SyscallDescriptor::new(Syscall::SchedYield, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Madvise, SyscallSubsystem::Memory),
    SyscallDescriptor::new(Syscall::Gettimeofday, SyscallSubsystem::Time),
    SyscallDescriptor::new(Syscall::Getrlimit, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getrusage, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Sysinfo, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getuid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getgid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Setuid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Setgid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Geteuid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getegid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Setpgid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getppid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getpgrp, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Setsid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Setreuid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Setregid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getpgid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getsid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Sigaltstack, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Statfs, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Fstatfs, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Nanosleep, SyscallSubsystem::Time),
    SyscallDescriptor::new(Syscall::Dup, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Dup2, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Getpid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Socket, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Connect, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Accept, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Sendto, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Recvfrom, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Sendmsg, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Recvmsg, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Shutdown, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Bind, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Listen, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Getsockname, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Getpeername, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Setsockopt, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Getsockopt, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::Clone, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Fork, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Vfork, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Execve, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Exit, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Wait4, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Kill, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Uname, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Fcntl, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Ftruncate, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Getdents, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Getcwd, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Chdir, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Rename, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Mkdir, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Rmdir, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Link, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Unlink, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Symlink, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Readlink, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Chmod, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Chown, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Umask, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Prctl, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::ArchPrctl, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Gettid, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Futex, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getdents64, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::SetTidAddress, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::ClockGettime, SyscallSubsystem::Time),
    SyscallDescriptor::new(Syscall::ClockGetres, SyscallSubsystem::Time),
    SyscallDescriptor::new(Syscall::ExitGroup, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::EpollWait, SyscallSubsystem::Event),
    SyscallDescriptor::new(Syscall::EpollCtl, SyscallSubsystem::Event),
    SyscallDescriptor::new(Syscall::Tgkill, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Openat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Mkdirat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Newfstatat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Unlinkat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Linkat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Symlinkat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Readlinkat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Utimensat, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Ppoll, SyscallSubsystem::Event),
    SyscallDescriptor::new(Syscall::SetRobustList, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Eventfd2, SyscallSubsystem::Event),
    SyscallDescriptor::new(Syscall::Accept4, SyscallSubsystem::Network),
    SyscallDescriptor::new(Syscall::EpollCreate1, SyscallSubsystem::Event),
    SyscallDescriptor::new(Syscall::Dup3, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Pipe2, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Prlimit64, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Getcpu, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Renameat2, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Getrandom, SyscallSubsystem::Time),
    SyscallDescriptor::new(Syscall::Membarrier, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Statx, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Rseq, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::Clone3, SyscallSubsystem::Task),
    SyscallDescriptor::new(Syscall::CloseRange, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Openat2, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::Faccessat2, SyscallSubsystem::File),
    SyscallDescriptor::new(Syscall::EpollPwait2, SyscallSubsystem::Event),
];

const SYSCALL_DESCRIPTOR_INDEX_LEN: usize = Syscall::EPOLL_PWAIT2.raw() as usize + 1;

static SYSCALL_DESCRIPTOR_INDEX: [Option<usize>; SYSCALL_DESCRIPTOR_INDEX_LEN] =
    build_syscall_descriptor_index();

const fn build_syscall_descriptor_index() -> [Option<usize>; SYSCALL_DESCRIPTOR_INDEX_LEN] {
    let mut index = [None; SYSCALL_DESCRIPTOR_INDEX_LEN];
    let mut table_index = 0;

    while table_index < SYSCALL_DISPATCH_TABLE.len() {
        let syscall_number = SYSCALL_DISPATCH_TABLE[table_index].syscall.number().raw() as usize;
        index[syscall_number] = Some(table_index);
        table_index += 1;
    }

    index
}

#[must_use]
pub fn syscall_descriptor(syscall: Syscall) -> Option<&'static SyscallDescriptor> {
    if matches!(syscall, Syscall::Unknown(_)) {
        return None;
    }

    syscall_descriptor_by_number(syscall.number())
}

#[must_use]
pub fn syscall_descriptor_by_number(number: SyscallNumber) -> Option<&'static SyscallDescriptor> {
    let number = usize::try_from(number.raw()).ok()?;
    let table_index = SYSCALL_DESCRIPTOR_INDEX.get(number).copied().flatten()?;
    SYSCALL_DISPATCH_TABLE.get(table_index)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyscallOutcome {
    pub result: SyscallReturn,
    pub decoded: Vec<TraceField>,
    pub host_error: Option<HostErrorTrace>,
    pub unsupported: bool,
}

impl SyscallOutcome {
    #[must_use]
    pub fn from_return(result: impl Into<SyscallReturn>) -> Self {
        Self {
            result: result.into(),
            decoded: Vec::new(),
            host_error: None,
            unsupported: false,
        }
    }

    #[must_use]
    pub fn success(value: u64) -> Self {
        Self::from_return(SyscallReturn::success(value))
    }

    #[must_use]
    pub fn errno(errno: LinuxErrno) -> Self {
        Self::from_return(SyscallReturn::errno(errno))
    }

    #[must_use]
    pub fn unsupported() -> Self {
        Self {
            result: SyscallReturn::unsupported(),
            decoded: Vec::new(),
            host_error: None,
            unsupported: true,
        }
    }

    #[must_use]
    pub fn with_decoded_field(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.decoded.push(TraceField::new(name, value));
        self
    }

    #[must_use]
    pub fn with_decoded_fields(mut self, decoded: impl IntoIterator<Item = TraceField>) -> Self {
        self.decoded.extend(decoded);
        self
    }

    #[must_use]
    pub fn with_host_error(mut self, host_error: HostErrorTrace) -> Self {
        self.host_error = Some(host_error);
        self
    }

    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        self.unsupported
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallDispatchResult {
    pub result: SyscallReturn,
    pub encoded_rax: u64,
}

impl SyscallDispatchResult {
    #[must_use]
    pub const fn from_return(result: SyscallReturn) -> Self {
        Self {
            result,
            encoded_rax: result.encode_u64(),
        }
    }
}

pub trait SyscallTracer {
    fn enabled(&self) -> bool {
        true
    }

    fn records_decoded_fields(&self) -> bool {
        self.enabled()
    }

    fn record(&mut self, event: SyscallTraceEvent);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopSyscallTracer;

impl SyscallTracer for NoopSyscallTracer {
    fn enabled(&self) -> bool {
        false
    }

    fn record(&mut self, _event: SyscallTraceEvent) {}
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemorySyscallTracer {
    events: Vec<SyscallTraceEvent>,
}

impl InMemorySyscallTracer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn events(&self) -> &[SyscallTraceEvent] {
        &self.events
    }

    #[must_use]
    pub fn into_events(self) -> Vec<SyscallTraceEvent> {
        self.events
    }
}

impl SyscallTracer for InMemorySyscallTracer {
    fn record(&mut self, event: SyscallTraceEvent) {
        self.events.push(event);
    }
}

pub trait FileSyscalls {
    fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        unsupported_outcome(request)
    }
}

pub trait MemorySyscalls {
    fn dispatch_memory(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        unsupported_outcome(request)
    }
}

pub trait TaskSyscalls {
    fn dispatch_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        unsupported_outcome(request)
    }

    fn supports_fast_task(&self, _request: &SyscallRequest) -> bool {
        false
    }

    fn dispatch_fast_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        unsupported_outcome(request)
    }
}

pub trait TimeSyscalls {
    fn dispatch_time(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        unsupported_outcome(request)
    }
}

pub trait NetworkSyscalls {
    fn dispatch_network(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        unsupported_outcome(request)
    }
}

pub trait EventSyscalls {
    fn dispatch_event(&mut self, request: &SyscallRequest) -> SyscallOutcome {
        unsupported_outcome(request)
    }
}

pub trait SyscallSubsystems:
    FileSyscalls + MemorySyscalls + TaskSyscalls + TimeSyscalls + NetworkSyscalls + EventSyscalls
{
}

impl<T> SyscallSubsystems for T where
    T: FileSyscalls
        + MemorySyscalls
        + TaskSyscalls
        + TimeSyscalls
        + NetworkSyscalls
        + EventSyscalls
{
}

pub struct SyscallDispatcher<S, T = NoopSyscallTracer> {
    subsystems: S,
    tracer: T,
}

impl<S> SyscallDispatcher<S, NoopSyscallTracer> {
    #[must_use]
    pub fn new(subsystems: S) -> Self {
        Self::with_tracer(subsystems, NoopSyscallTracer)
    }
}

impl<S, T> SyscallDispatcher<S, T> {
    #[must_use]
    pub const fn with_tracer(subsystems: S, tracer: T) -> Self {
        Self { subsystems, tracer }
    }

    #[must_use]
    pub const fn subsystems(&self) -> &S {
        &self.subsystems
    }

    #[must_use]
    pub const fn subsystems_mut(&mut self) -> &mut S {
        &mut self.subsystems
    }

    #[must_use]
    pub const fn tracer(&self) -> &T {
        &self.tracer
    }

    #[must_use]
    pub const fn tracer_mut(&mut self) -> &mut T {
        &mut self.tracer
    }

    #[must_use]
    pub fn into_parts(self) -> (S, T) {
        (self.subsystems, self.tracer)
    }
}

impl<S, T> SyscallDispatcher<S, T>
where
    S: SyscallSubsystems,
    T: SyscallTracer,
{
    pub fn dispatch(&mut self, context: GuestContext) -> SyscallDispatchResult {
        let request = SyscallRequest::from_guest_context(context);
        if let Some(result) = self.dispatch_fast_no_memory_syscall(&request) {
            return result;
        }

        let Some(descriptor) = syscall_descriptor(request.syscall) else {
            if !self.tracer.enabled() {
                return SyscallDispatchResult::from_return(SyscallReturn::unsupported());
            }
            let mut event =
                UnsupportedSyscallEvent::new(request.context, request.number, request.args);
            if self.tracer.records_decoded_fields() {
                event =
                    event.with_decoded_fields(decode_syscall_fields(request.syscall, request.args));
            }
            let result = event.result;
            self.tracer.record(SyscallTraceEvent::Unsupported(event));
            return SyscallDispatchResult::from_return(result);
        };

        let decoded = self.trace_decoded_fields(request.syscall, request.args);
        self.record_enter(&request, decoded.clone());

        let outcome = match descriptor.subsystem {
            SyscallSubsystem::File => self.subsystems.dispatch_file(&request),
            SyscallSubsystem::Memory => self.subsystems.dispatch_memory(&request),
            SyscallSubsystem::Task => self.subsystems.dispatch_task(&request),
            SyscallSubsystem::Time => self.subsystems.dispatch_time(&request),
            SyscallSubsystem::Network => self.subsystems.dispatch_network(&request),
            SyscallSubsystem::Event => self.subsystems.dispatch_event(&request),
        };
        self.record_outcome(&request, decoded, outcome)
    }

    fn dispatch_fast_no_memory_syscall(
        &mut self,
        request: &SyscallRequest,
    ) -> Option<SyscallDispatchResult> {
        if !matches!(request.syscall, Syscall::Getpid | Syscall::Gettid)
            || !self.subsystems.supports_fast_task(request)
        {
            return None;
        }

        let decoded = self.trace_decoded_fields(request.syscall, request.args);
        self.record_enter(request, decoded.clone());
        let outcome = self.subsystems.dispatch_fast_task(request);
        Some(self.record_outcome(request, decoded, outcome))
    }

    fn trace_decoded_fields(&self, syscall: Syscall, args: SyscallArgs) -> Vec<TraceField> {
        if self.tracer.records_decoded_fields() {
            decode_syscall_fields(syscall, args)
        } else {
            Vec::new()
        }
    }

    fn record_enter(&mut self, request: &SyscallRequest, decoded: Vec<TraceField>) {
        if !self.tracer.enabled() {
            return;
        }
        self.tracer
            .record(SyscallTraceEvent::Enter(SyscallEnterEvent {
                context: request.context,
                syscall: request.syscall,
                args: request.args,
                decoded,
            }));
    }

    fn record_outcome(
        &mut self,
        request: &SyscallRequest,
        decoded: Vec<TraceField>,
        mut outcome: SyscallOutcome,
    ) -> SyscallDispatchResult {
        let result = outcome.result;
        if !self.tracer.enabled() {
            return SyscallDispatchResult::from_return(result);
        }
        let mut exit_decoded = decoded;
        if self.tracer.records_decoded_fields() {
            exit_decoded.append(&mut outcome.decoded);
        }

        if outcome.is_unsupported() {
            self.tracer.record(SyscallTraceEvent::Unsupported(
                UnsupportedSyscallEvent::for_syscall(
                    request.context,
                    request.syscall,
                    request.args,
                    exit_decoded,
                ),
            ));
        } else {
            self.tracer
                .record(SyscallTraceEvent::Exit(SyscallExitEvent {
                    context: request.context,
                    syscall: request.syscall,
                    args: request.args,
                    result,
                    decoded: exit_decoded,
                    host_error: outcome.host_error,
                }));
        }

        SyscallDispatchResult::from_return(result)
    }
}

#[must_use]
pub fn decode_syscall_fields(syscall: Syscall, args: SyscallArgs) -> Vec<TraceField> {
    let arg = |index| args.get(index).unwrap_or_default();

    match syscall {
        Syscall::Read | Syscall::Write => {
            vec![
                decimal_field("fd", arg(0)),
                hex_field("buf", arg(1)),
                decimal_field("count", arg(2)),
            ]
        }
        Syscall::Readv | Syscall::Writev => {
            vec![
                decimal_field("fd", arg(0)),
                hex_field("iov", arg(1)),
                decimal_field("iovcnt", arg(2)),
            ]
        }
        Syscall::Close | Syscall::Dup => vec![decimal_field("fd", arg(0))],
        Syscall::CloseRange => vec![
            decimal_field("first", arg(0)),
            decimal_field("last", arg(1)),
            hex_field("flags", arg(2)),
        ],
        Syscall::Dup2 => vec![
            decimal_field("oldfd", arg(0)),
            decimal_field("newfd", arg(1)),
        ],
        Syscall::Dup3 => vec![
            decimal_field("oldfd", arg(0)),
            decimal_field("newfd", arg(1)),
            hex_field("flags", arg(2)),
        ],
        Syscall::Fstat => vec![decimal_field("fd", arg(0)), hex_field("statbuf", arg(1))],
        Syscall::Fsync | Syscall::Fdatasync => vec![decimal_field("fd", arg(0))],
        Syscall::Pread64 => vec![
            decimal_field("fd", arg(0)),
            hex_field("buf", arg(1)),
            decimal_field("count", arg(2)),
            signed_field("offset", arg(3)),
        ],
        Syscall::Lseek => vec![
            decimal_field("fd", arg(0)),
            signed_field("offset", arg(1)),
            decimal_field("whence", arg(2)),
        ],
        Syscall::Open => vec![
            hex_field("path_ptr", arg(0)),
            hex_field("flags", arg(1)),
            octal_field("mode", arg(2)),
        ],
        Syscall::Openat => vec![
            signed_field("dirfd", arg(0)),
            hex_field("path_ptr", arg(1)),
            hex_field("flags", arg(2)),
            octal_field("mode", arg(3)),
        ],
        Syscall::Openat2 => vec![
            signed_field("dirfd", arg(0)),
            hex_field("path_ptr", arg(1)),
            hex_field("how", arg(2)),
            decimal_field("size", arg(3)),
        ],
        Syscall::Stat | Syscall::Lstat | Syscall::Access | Syscall::Readlink => {
            vec![hex_field("path_ptr", arg(0)), hex_field("buf", arg(1))]
        }
        Syscall::Statfs => vec![hex_field("path_ptr", arg(0)), hex_field("buf", arg(1))],
        Syscall::Fstatfs => vec![decimal_field("fd", arg(0)), hex_field("buf", arg(1))],
        Syscall::Newfstatat | Syscall::Readlinkat => vec![
            signed_field("dirfd", arg(0)),
            hex_field("path_ptr", arg(1)),
            hex_field("buf", arg(2)),
            hex_field("flags", arg(3)),
        ],
        Syscall::Faccessat2 => vec![
            signed_field("dirfd", arg(0)),
            hex_field("path_ptr", arg(1)),
            hex_field("mode", arg(2)),
            hex_field("flags", arg(3)),
        ],
        Syscall::Statx => vec![
            signed_field("dirfd", arg(0)),
            hex_field("path_ptr", arg(1)),
            hex_field("flags", arg(2)),
            hex_field("mask", arg(3)),
            hex_field("statxbuf", arg(4)),
        ],
        Syscall::Getdents | Syscall::Getdents64 => vec![
            decimal_field("fd", arg(0)),
            hex_field("dirent", arg(1)),
            decimal_field("count", arg(2)),
        ],
        Syscall::Mkdir => vec![hex_field("path_ptr", arg(0)), octal_field("mode", arg(1))],
        Syscall::Rmdir => vec![hex_field("path_ptr", arg(0))],
        Syscall::Symlink => vec![
            hex_field("target_ptr", arg(0)),
            hex_field("linkpath_ptr", arg(1)),
        ],
        Syscall::Link | Syscall::Rename => vec![
            hex_field("oldpath_ptr", arg(0)),
            hex_field("newpath_ptr", arg(1)),
        ],
        Syscall::Unlink => vec![hex_field("path_ptr", arg(0))],
        Syscall::Chmod => vec![hex_field("path_ptr", arg(0)), octal_field("mode", arg(1))],
        Syscall::Chown => vec![
            hex_field("path_ptr", arg(0)),
            decimal_field("uid", arg(1)),
            decimal_field("gid", arg(2)),
        ],
        Syscall::Utimensat => vec![
            signed_field("dirfd", arg(0)),
            hex_field("path_ptr", arg(1)),
            hex_field("times", arg(2)),
            hex_field("flags", arg(3)),
        ],
        Syscall::Mkdirat | Syscall::Unlinkat => vec![
            signed_field("dirfd", arg(0)),
            hex_field("path_ptr", arg(1)),
            hex_field("flags_or_mode", arg(2)),
        ],
        Syscall::Linkat => vec![
            signed_field("olddirfd", arg(0)),
            hex_field("oldpath_ptr", arg(1)),
            signed_field("newdirfd", arg(2)),
            hex_field("newpath_ptr", arg(3)),
            hex_field("flags", arg(4)),
        ],
        Syscall::Symlinkat => vec![
            hex_field("target_ptr", arg(0)),
            signed_field("newdirfd", arg(1)),
            hex_field("linkpath_ptr", arg(2)),
        ],
        Syscall::Renameat2 => vec![
            signed_field("olddirfd", arg(0)),
            hex_field("oldpath_ptr", arg(1)),
            signed_field("newdirfd", arg(2)),
            hex_field("newpath_ptr", arg(3)),
            hex_field("flags", arg(4)),
        ],
        Syscall::Pipe | Syscall::Pipe2 => {
            vec![hex_field("pipefd", arg(0)), hex_field("flags", arg(1))]
        }
        Syscall::Fcntl | Syscall::Ioctl => vec![
            decimal_field("fd", arg(0)),
            hex_field("cmd", arg(1)),
            hex_field("arg", arg(2)),
        ],
        Syscall::Ftruncate => vec![decimal_field("fd", arg(0)), signed_field("length", arg(1))],
        Syscall::Getcwd => vec![hex_field("buf", arg(0)), decimal_field("size", arg(1))],
        Syscall::Chdir => vec![hex_field("path_ptr", arg(0))],
        Syscall::Umask => vec![octal_field("mask", arg(0))],
        Syscall::Mmap => vec![
            hex_field("addr", arg(0)),
            decimal_field("length", arg(1)),
            hex_field("prot", arg(2)),
            hex_field("flags", arg(3)),
            signed_field("fd", arg(4)),
            signed_field("offset", arg(5)),
        ],
        Syscall::Mprotect | Syscall::Munmap => vec![
            hex_field("addr", arg(0)),
            decimal_field("length", arg(1)),
            hex_field("prot_or_flags", arg(2)),
        ],
        Syscall::Madvise => vec![
            hex_field("addr", arg(0)),
            decimal_field("length", arg(1)),
            decimal_field("advice", arg(2)),
        ],
        Syscall::Brk => vec![hex_field("addr", arg(0))],
        Syscall::Exit | Syscall::ExitGroup => vec![decimal_field("status", arg(0))],
        Syscall::Getpid
        | Syscall::Gettid
        | Syscall::Getppid
        | Syscall::Getpgrp
        | Syscall::Getuid
        | Syscall::Geteuid
        | Syscall::Getgid
        | Syscall::Getegid
        | Syscall::Setsid
        | Syscall::SchedYield
        | Syscall::RtSigreturn => Vec::new(),
        Syscall::Setuid | Syscall::Setgid => vec![decimal_field("id", arg(0))],
        Syscall::Setreuid | Syscall::Setregid => {
            vec![decimal_field("rid", arg(0)), decimal_field("eid", arg(1))]
        }
        Syscall::Setpgid => vec![decimal_field("pid", arg(0)), decimal_field("pgid", arg(1))],
        Syscall::Getpgid | Syscall::Getsid => vec![signed_field("pid", arg(0))],
        Syscall::Uname => vec![hex_field("buf", arg(0))],
        Syscall::Sysinfo => vec![hex_field("info", arg(0))],
        Syscall::Prctl => vec![
            decimal_field("option", arg(0)),
            hex_field("arg2", arg(1)),
            hex_field("arg3", arg(2)),
            hex_field("arg4", arg(3)),
            hex_field("arg5", arg(4)),
        ],
        Syscall::ArchPrctl => vec![hex_field("code", arg(0)), hex_field("addr", arg(1))],
        Syscall::Execve => vec![
            hex_field("path_ptr", arg(0)),
            hex_field("argv_ptr", arg(1)),
            hex_field("envp_ptr", arg(2)),
        ],
        Syscall::Clone3 => vec![hex_field("cl_args", arg(0)), decimal_field("size", arg(1))],
        Syscall::Clone => vec![
            hex_field("flags", arg(0)),
            hex_field("child_stack", arg(1)),
            hex_field("ptid", arg(2)),
            hex_field("ctid", arg(3)),
            hex_field("tls", arg(4)),
        ],
        Syscall::Fork | Syscall::Vfork => Vec::new(),
        Syscall::Wait4 => vec![
            signed_field("pid", arg(0)),
            hex_field("wstatus", arg(1)),
            hex_field("options", arg(2)),
            hex_field("rusage", arg(3)),
        ],
        Syscall::Getrusage => vec![signed_field("who", arg(0)), hex_field("usage", arg(1))],
        Syscall::Kill => vec![signed_field("pid", arg(0)), decimal_field("sig", arg(1))],
        Syscall::Tgkill => vec![
            signed_field("tgid", arg(0)),
            signed_field("tid", arg(1)),
            decimal_field("sig", arg(2)),
        ],
        Syscall::RtSigaction => vec![
            decimal_field("sig", arg(0)),
            hex_field("act", arg(1)),
            hex_field("oldact", arg(2)),
            decimal_field("sigsetsize", arg(3)),
        ],
        Syscall::RtSigprocmask => vec![
            decimal_field("how", arg(0)),
            hex_field("set", arg(1)),
            hex_field("oldset", arg(2)),
            decimal_field("sigsetsize", arg(3)),
        ],
        Syscall::Sigaltstack => {
            vec![hex_field("ss", arg(0)), hex_field("old_ss", arg(1))]
        }
        Syscall::SetTidAddress => vec![hex_field("tidptr", arg(0))],
        Syscall::SetRobustList => {
            vec![hex_field("head", arg(0)), decimal_field("len", arg(1))]
        }
        Syscall::Futex => vec![
            hex_field("uaddr", arg(0)),
            hex_field("op", arg(1)),
            decimal_field("val", arg(2)),
            hex_field("timeout", arg(3)),
            hex_field("uaddr2", arg(4)),
            decimal_field("val3", arg(5)),
        ],
        Syscall::Rseq => vec![
            hex_field("rseq", arg(0)),
            decimal_field("rseq_len", arg(1)),
            hex_field("flags", arg(2)),
            hex_field("sig", arg(3)),
        ],
        Syscall::ClockGettime => {
            vec![decimal_field("clockid", arg(0)), hex_field("tp", arg(1))]
        }
        Syscall::ClockGetres => {
            vec![decimal_field("clockid", arg(0)), hex_field("res", arg(1))]
        }
        Syscall::Gettimeofday => vec![hex_field("tv", arg(0)), hex_field("tz", arg(1))],
        Syscall::Nanosleep => vec![hex_field("req", arg(0)), hex_field("rem", arg(1))],
        Syscall::Getrandom => vec![
            hex_field("buf", arg(0)),
            decimal_field("buflen", arg(1)),
            hex_field("flags", arg(2)),
        ],
        Syscall::Getrlimit => vec![decimal_field("resource", arg(0)), hex_field("rlim", arg(1))],
        Syscall::Prlimit64 => vec![
            signed_field("pid", arg(0)),
            decimal_field("resource", arg(1)),
            hex_field("new_limit", arg(2)),
            hex_field("old_limit", arg(3)),
        ],
        Syscall::Getcpu => vec![
            hex_field("cpu", arg(0)),
            hex_field("node", arg(1)),
            hex_field("tcache", arg(2)),
        ],
        Syscall::Membarrier => vec![
            decimal_field("cmd", arg(0)),
            hex_field("flags", arg(1)),
            signed_field("cpu_id", arg(2)),
        ],
        Syscall::Socket => vec![
            decimal_field("domain", arg(0)),
            hex_field("type", arg(1)),
            decimal_field("protocol", arg(2)),
        ],
        Syscall::Connect | Syscall::Bind => vec![
            decimal_field("fd", arg(0)),
            hex_field("sockaddr", arg(1)),
            decimal_field("addrlen", arg(2)),
        ],
        Syscall::Accept | Syscall::Getsockname | Syscall::Getpeername => vec![
            decimal_field("fd", arg(0)),
            hex_field("sockaddr", arg(1)),
            hex_field("addrlen", arg(2)),
        ],
        Syscall::Accept4 => vec![
            decimal_field("fd", arg(0)),
            hex_field("sockaddr", arg(1)),
            hex_field("addrlen", arg(2)),
            hex_field("flags", arg(3)),
        ],
        Syscall::Listen => {
            vec![
                decimal_field("fd", arg(0)),
                decimal_field("backlog", arg(1)),
            ]
        }
        Syscall::Sendmsg | Syscall::Recvmsg => vec![
            decimal_field("fd", arg(0)),
            hex_field("msg", arg(1)),
            hex_field("flags", arg(2)),
        ],
        Syscall::Sendto | Syscall::Recvfrom => vec![
            decimal_field("fd", arg(0)),
            hex_field("buf", arg(1)),
            decimal_field("len", arg(2)),
            hex_field("flags", arg(3)),
            hex_field("sockaddr", arg(4)),
            hex_field("addrlen", arg(5)),
        ],
        Syscall::Shutdown => vec![decimal_field("fd", arg(0)), decimal_field("how", arg(1))],
        Syscall::Setsockopt => vec![
            decimal_field("fd", arg(0)),
            decimal_field("level", arg(1)),
            decimal_field("optname", arg(2)),
            hex_field("optval", arg(3)),
            decimal_field("optlen", arg(4)),
        ],
        Syscall::Getsockopt => vec![
            decimal_field("fd", arg(0)),
            decimal_field("level", arg(1)),
            decimal_field("optname", arg(2)),
            hex_field("optval", arg(3)),
            hex_field("optlen", arg(4)),
        ],
        Syscall::Poll => vec![
            hex_field("fds", arg(0)),
            decimal_field("nfds", arg(1)),
            signed_field("timeout", arg(2)),
        ],
        Syscall::Select => vec![
            decimal_field("nfds", arg(0)),
            hex_field("readfds", arg(1)),
            hex_field("writefds", arg(2)),
            hex_field("exceptfds", arg(3)),
            hex_field("timeout", arg(4)),
        ],
        Syscall::Ppoll => vec![
            hex_field("fds", arg(0)),
            decimal_field("nfds", arg(1)),
            hex_field("tsp", arg(2)),
            hex_field("sigmask", arg(3)),
            decimal_field("sigsetsize", arg(4)),
        ],
        Syscall::Eventfd2 => vec![decimal_field("initval", arg(0)), hex_field("flags", arg(1))],
        Syscall::EpollCreate1 => vec![hex_field("flags", arg(0))],
        Syscall::EpollCtl => vec![
            decimal_field("epfd", arg(0)),
            decimal_field("op", arg(1)),
            decimal_field("fd", arg(2)),
            hex_field("event", arg(3)),
        ],
        Syscall::EpollWait => vec![
            decimal_field("epfd", arg(0)),
            hex_field("events", arg(1)),
            decimal_field("maxevents", arg(2)),
            signed_field("timeout", arg(3)),
        ],
        Syscall::EpollPwait2 => vec![
            decimal_field("epfd", arg(0)),
            hex_field("events", arg(1)),
            decimal_field("maxevents", arg(2)),
            hex_field("timeout", arg(3)),
            hex_field("sigmask", arg(4)),
            decimal_field("sigsetsize", arg(5)),
        ],
        Syscall::Unknown(_) => (0..6)
            .map(|index| hex_field(format!("arg{index}"), arg(index)))
            .collect(),
    }
}

fn unsupported_outcome(request: &SyscallRequest) -> SyscallOutcome {
    SyscallOutcome::unsupported().with_decoded_field("unsupported", request.syscall.name())
}

fn decimal_field(name: impl Into<String>, value: u64) -> TraceField {
    TraceField::new(name, value.to_string())
}

fn signed_field(name: impl Into<String>, value: u64) -> TraceField {
    TraceField::new(name, (value as i64).to_string())
}

fn hex_field(name: impl Into<String>, value: u64) -> TraceField {
    TraceField::new(name, format!("{value:#x}"))
}

fn octal_field(name: impl Into<String>, value: u64) -> TraceField {
    TraceField::new(name, format!("{value:#o}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        EventSyscalls, FileSyscalls, GuestContext, InMemorySyscallTracer, MemorySyscalls,
        NetworkSyscalls, SYSCALL_DISPATCH_TABLE, SyscallDispatcher, SyscallOutcome, SyscallRequest,
        SyscallSubsystem, SyscallTracer, TaskSyscalls, TimeSyscalls, syscall_descriptor,
        syscall_descriptor_by_number,
    };
    use crate::abi::SyscallRegisters;
    use crate::errno::LinuxErrno;
    use crate::return_value::SyscallReturn;
    use crate::syscall::{Syscall, SyscallNumber};
    use crate::trace::SyscallTraceEvent;

    #[test]
    fn dispatcher_table_routes_core_runtime_syscalls() {
        assert_eq!(
            syscall_descriptor(Syscall::Read).map(|descriptor| descriptor.subsystem),
            Some(SyscallSubsystem::File)
        );
        assert_eq!(
            syscall_descriptor(Syscall::Mmap).map(|descriptor| descriptor.subsystem),
            Some(SyscallSubsystem::Memory)
        );
        assert_eq!(
            syscall_descriptor(Syscall::Getpid).map(|descriptor| descriptor.subsystem),
            Some(SyscallSubsystem::Task)
        );
        assert_eq!(
            syscall_descriptor(Syscall::ClockGettime).map(|descriptor| descriptor.subsystem),
            Some(SyscallSubsystem::Time)
        );
        assert_eq!(
            syscall_descriptor(Syscall::Socket).map(|descriptor| descriptor.subsystem),
            Some(SyscallSubsystem::Network)
        );
        assert_eq!(
            syscall_descriptor(Syscall::Accept4).map(|descriptor| descriptor.subsystem),
            Some(SyscallSubsystem::Network)
        );
        assert_eq!(
            syscall_descriptor(Syscall::EpollWait).map(|descriptor| descriptor.subsystem),
            Some(SyscallSubsystem::Event)
        );
        for syscall in [
            Syscall::Pipe,
            Syscall::Pipe2,
            Syscall::Dup,
            Syscall::Dup2,
            Syscall::Dup3,
            Syscall::Fcntl,
            Syscall::Ioctl,
            Syscall::Pread64,
            Syscall::Fsync,
            Syscall::Fdatasync,
        ] {
            assert_eq!(
                syscall_descriptor(syscall).map(|descriptor| descriptor.subsystem),
                Some(SyscallSubsystem::File)
            );
        }

        for (syscall, subsystem) in [
            (Syscall::SchedYield, SyscallSubsystem::Task),
            (Syscall::Madvise, SyscallSubsystem::Memory),
            (Syscall::Gettimeofday, SyscallSubsystem::Time),
            (Syscall::Getrlimit, SyscallSubsystem::Task),
            (Syscall::Getrusage, SyscallSubsystem::Task),
            (Syscall::Sysinfo, SyscallSubsystem::Task),
            (Syscall::Getpgid, SyscallSubsystem::Task),
            (Syscall::Getsid, SyscallSubsystem::Task),
            (Syscall::Statfs, SyscallSubsystem::File),
            (Syscall::Fstatfs, SyscallSubsystem::File),
            (Syscall::Prctl, SyscallSubsystem::Task),
            (Syscall::ClockGetres, SyscallSubsystem::Time),
            (Syscall::Prlimit64, SyscallSubsystem::Task),
            (Syscall::Getcpu, SyscallSubsystem::Task),
            (Syscall::Membarrier, SyscallSubsystem::Task),
            (Syscall::Rseq, SyscallSubsystem::Task),
            (Syscall::Clone3, SyscallSubsystem::Task),
            (Syscall::CloseRange, SyscallSubsystem::File),
            (Syscall::Openat2, SyscallSubsystem::File),
            (Syscall::Faccessat2, SyscallSubsystem::File),
            (Syscall::EpollPwait2, SyscallSubsystem::Event),
        ] {
            assert_eq!(
                syscall_descriptor(syscall).map(|descriptor| descriptor.subsystem),
                Some(subsystem),
                "{syscall} should route to {subsystem:?}"
            );
        }
    }

    #[test]
    fn dispatcher_table_has_unique_syscall_numbers() {
        let mut numbers = BTreeSet::new();

        for descriptor in SYSCALL_DISPATCH_TABLE {
            assert!(
                numbers.insert(descriptor.syscall.number().raw()),
                "duplicate syscall table entry for {}",
                descriptor.syscall
            );
            assert_eq!(syscall_descriptor(descriptor.syscall), Some(descriptor));
            assert_eq!(
                syscall_descriptor_by_number(descriptor.syscall.number()),
                Some(descriptor)
            );
        }
    }

    #[test]
    fn dispatcher_table_index_rejects_unknown_numbers() {
        assert_eq!(syscall_descriptor(Syscall::Unknown(Syscall::READ)), None);
        assert_eq!(syscall_descriptor_by_number(SyscallNumber::new(18)), None);
        assert_eq!(
            syscall_descriptor_by_number(SyscallNumber::new(u64::MAX)),
            None
        );
    }

    #[test]
    fn decodes_fake_syscall_fields() {
        for (syscall, args, expected) in [
            (Syscall::SchedYield, [1, 2, 3, 4, 5, 6], &[][..]),
            (
                Syscall::Madvise,
                [0x1000, 4096, 1, 0, 0, 0],
                &[("addr", "0x1000"), ("length", "4096"), ("advice", "1")][..],
            ),
            (
                Syscall::Gettimeofday,
                [0x2000, 0x3000, 0, 0, 0, 0],
                &[("tv", "0x2000"), ("tz", "0x3000")][..],
            ),
            (
                Syscall::Getrlimit,
                [7, 0x4000, 0, 0, 0, 0],
                &[("resource", "7"), ("rlim", "0x4000")][..],
            ),
            (
                Syscall::Getrusage,
                [u64::MAX, 0x5000, 0, 0, 0, 0],
                &[("who", "-1"), ("usage", "0x5000")][..],
            ),
            (
                Syscall::Sysinfo,
                [0x6000, 0, 0, 0, 0, 0],
                &[("info", "0x6000")][..],
            ),
            (
                Syscall::Getpgid,
                [123, 0, 0, 0, 0, 0],
                &[("pid", "123")][..],
            ),
            (Syscall::Getsid, [123, 0, 0, 0, 0, 0], &[("pid", "123")][..]),
            (
                Syscall::Statfs,
                [0x7000, 0x8000, 0, 0, 0, 0],
                &[("path_ptr", "0x7000"), ("buf", "0x8000")][..],
            ),
            (
                Syscall::Fstatfs,
                [3, 0x9000, 0, 0, 0, 0],
                &[("fd", "3"), ("buf", "0x9000")][..],
            ),
            (Syscall::Fsync, [4, 0, 0, 0, 0, 0], &[("fd", "4")][..]),
            (Syscall::Fdatasync, [5, 0, 0, 0, 0, 0], &[("fd", "5")][..]),
            (
                Syscall::Pread64,
                [6, 0x9100, 32, 7, 0, 0],
                &[
                    ("fd", "6"),
                    ("buf", "0x9100"),
                    ("count", "32"),
                    ("offset", "7"),
                ][..],
            ),
            (
                Syscall::Prctl,
                [1, 2, 3, 4, 5, 0],
                &[
                    ("option", "1"),
                    ("arg2", "0x2"),
                    ("arg3", "0x3"),
                    ("arg4", "0x4"),
                    ("arg5", "0x5"),
                ][..],
            ),
            (
                Syscall::ClockGetres,
                [1, 0xa000, 0, 0, 0, 0],
                &[("clockid", "1"), ("res", "0xa000")][..],
            ),
            (
                Syscall::Prlimit64,
                [123, 7, 0xb000, 0xc000, 0, 0],
                &[
                    ("pid", "123"),
                    ("resource", "7"),
                    ("new_limit", "0xb000"),
                    ("old_limit", "0xc000"),
                ][..],
            ),
            (
                Syscall::Getcpu,
                [0xd000, 0xe000, 0xf000, 0, 0, 0],
                &[("cpu", "0xd000"), ("node", "0xe000"), ("tcache", "0xf000")][..],
            ),
            (
                Syscall::Membarrier,
                [1, 2, u64::MAX, 0, 0, 0],
                &[("cmd", "1"), ("flags", "0x2"), ("cpu_id", "-1")][..],
            ),
            (
                Syscall::Rseq,
                [0x1000, 32, 0, 0x53053053, 0, 0],
                &[
                    ("rseq", "0x1000"),
                    ("rseq_len", "32"),
                    ("flags", "0x0"),
                    ("sig", "0x53053053"),
                ][..],
            ),
            (
                Syscall::Clone3,
                [0x1100, 88, 0, 0, 0, 0],
                &[("cl_args", "0x1100"), ("size", "88")][..],
            ),
            (
                Syscall::CloseRange,
                [3, 9, 1, 0, 0, 0],
                &[("first", "3"), ("last", "9"), ("flags", "0x1")][..],
            ),
            (
                Syscall::Openat2,
                [u64::MAX - 99, 0x1200, 0x1300, 24, 0, 0],
                &[
                    ("dirfd", "-100"),
                    ("path_ptr", "0x1200"),
                    ("how", "0x1300"),
                    ("size", "24"),
                ][..],
            ),
            (
                Syscall::Faccessat2,
                [u64::MAX - 99, 0x1400, 4, 0x100, 0, 0],
                &[
                    ("dirfd", "-100"),
                    ("path_ptr", "0x1400"),
                    ("mode", "0x4"),
                    ("flags", "0x100"),
                ][..],
            ),
            (
                Syscall::EpollPwait2,
                [5, 0x1500, 64, 0x1600, 0x1700, 8],
                &[
                    ("epfd", "5"),
                    ("events", "0x1500"),
                    ("maxevents", "64"),
                    ("timeout", "0x1600"),
                    ("sigmask", "0x1700"),
                    ("sigsetsize", "8"),
                ][..],
            ),
        ] {
            let decoded = super::decode_syscall_fields(syscall, crate::SyscallArgs::new(args));
            let decoded: Vec<_> = decoded
                .iter()
                .map(|field| (field.name.as_str(), field.value.as_str()))
                .collect();

            assert_eq!(decoded, expected, "{syscall}");
        }
    }

    #[derive(Default)]
    struct RecordingSubsystems {
        file_syscalls: Vec<Syscall>,
        task_syscalls: Vec<Syscall>,
    }

    impl FileSyscalls for RecordingSubsystems {
        fn dispatch_file(&mut self, request: &SyscallRequest) -> SyscallOutcome {
            self.file_syscalls.push(request.syscall);
            SyscallOutcome::success(12).with_decoded_field("bytes", "12")
        }
    }

    impl MemorySyscalls for RecordingSubsystems {}

    impl TaskSyscalls for RecordingSubsystems {
        fn dispatch_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
            self.task_syscalls.push(request.syscall);
            SyscallOutcome::success(u64::from(request.context.pid))
        }
    }

    impl TimeSyscalls for RecordingSubsystems {}
    impl NetworkSyscalls for RecordingSubsystems {}
    impl EventSyscalls for RecordingSubsystems {}

    #[derive(Default)]
    struct EventOnlyTracer {
        events: Vec<SyscallTraceEvent>,
    }

    impl SyscallTracer for EventOnlyTracer {
        fn records_decoded_fields(&self) -> bool {
            false
        }

        fn record(&mut self, event: SyscallTraceEvent) {
            self.events.push(event);
        }
    }

    #[derive(Default)]
    struct FastTaskSubsystems {
        fast_task_syscalls: Vec<Syscall>,
        task_syscalls: Vec<Syscall>,
    }

    impl FileSyscalls for FastTaskSubsystems {}
    impl MemorySyscalls for FastTaskSubsystems {}

    impl TaskSyscalls for FastTaskSubsystems {
        fn supports_fast_task(&self, request: &SyscallRequest) -> bool {
            matches!(request.syscall, Syscall::Getpid | Syscall::Gettid)
        }

        fn dispatch_fast_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
            self.fast_task_syscalls.push(request.syscall);
            match request.syscall {
                Syscall::Getpid => SyscallOutcome::success(u64::from(request.context.pid)),
                Syscall::Gettid => SyscallOutcome::success(u64::from(request.context.tid)),
                _ => SyscallOutcome::unsupported(),
            }
        }

        fn dispatch_task(&mut self, request: &SyscallRequest) -> SyscallOutcome {
            self.task_syscalls.push(request.syscall);
            SyscallOutcome::success(99)
        }
    }

    impl TimeSyscalls for FastTaskSubsystems {}
    impl NetworkSyscalls for FastTaskSubsystems {}
    impl EventSyscalls for FastTaskSubsystems {}

    #[test]
    fn dispatcher_calls_subsystem_and_records_enter_exit_trace() {
        let registers = SyscallRegisters {
            rax: Syscall::Write.number().raw(),
            rdi: 1,
            rsi: 0x2000,
            rdx: 12,
            rip: 0x401234,
            ..SyscallRegisters::default()
        };
        let mut dispatcher = SyscallDispatcher::with_tracer(
            RecordingSubsystems::default(),
            InMemorySyscallTracer::new(),
        );

        let result = dispatcher.dispatch(GuestContext::new(77, 78, registers));

        assert_eq!(result.result, SyscallReturn::Success(12));
        assert_eq!(result.encoded_rax, 12);
        assert_eq!(dispatcher.subsystems().file_syscalls, vec![Syscall::Write]);
        let events = dispatcher.tracer().events();
        assert_eq!(events.len(), 2);

        match &events[0] {
            SyscallTraceEvent::Enter(event) => {
                assert_eq!(event.context.pid, 77);
                assert_eq!(event.context.tid, 78);
                assert_eq!(event.context.rip, 0x401234);
                assert_eq!(event.syscall, Syscall::Write);
                assert_eq!(event.args.raw(), [1, 0x2000, 12, 0, 0, 0]);
                assert!(event.decoded.iter().any(|field| field.name == "fd"));
            }
            other => panic!("expected enter event, got {other:?}"),
        }

        match &events[1] {
            SyscallTraceEvent::Exit(event) => {
                assert_eq!(event.syscall, Syscall::Write);
                assert_eq!(event.result, SyscallReturn::Success(12));
                assert!(event.decoded.iter().any(|field| field.name == "bytes"));
                assert!(event.host_error.is_none());
            }
            other => panic!("expected exit event, got {other:?}"),
        }
    }

    #[test]
    fn dispatcher_skips_decoded_fields_when_tracer_does_not_consume_them() {
        let registers = SyscallRegisters {
            rax: Syscall::Write.number().raw(),
            rdi: 1,
            rsi: 0x2000,
            rdx: 12,
            rip: 0x401234,
            ..SyscallRegisters::default()
        };
        let mut dispatcher = SyscallDispatcher::with_tracer(
            RecordingSubsystems::default(),
            EventOnlyTracer::default(),
        );

        let result = dispatcher.dispatch(GuestContext::new(77, 78, registers));

        assert_eq!(result.result, SyscallReturn::Success(12));
        match dispatcher.tracer().events.as_slice() {
            [
                SyscallTraceEvent::Enter(enter),
                SyscallTraceEvent::Exit(exit),
            ] => {
                assert!(enter.decoded.is_empty());
                assert!(exit.decoded.is_empty());
            }
            other => panic!("expected enter and exit events, got {other:?}"),
        }
    }

    #[test]
    fn dispatcher_getpid_fast_path_records_standard_trace() {
        let registers = SyscallRegisters {
            rax: Syscall::Getpid.number().raw(),
            rip: 0x401234,
            ..SyscallRegisters::default()
        };
        let mut dispatcher = SyscallDispatcher::with_tracer(
            FastTaskSubsystems::default(),
            InMemorySyscallTracer::new(),
        );

        let result = dispatcher.dispatch(GuestContext::new(77, 78, registers));

        assert_eq!(result.result, SyscallReturn::Success(77));
        assert_eq!(result.encoded_rax, 77);
        assert_eq!(
            dispatcher.subsystems().fast_task_syscalls,
            vec![Syscall::Getpid]
        );
        assert!(dispatcher.subsystems().task_syscalls.is_empty());

        match dispatcher.tracer().events() {
            [
                SyscallTraceEvent::Enter(enter),
                SyscallTraceEvent::Exit(exit),
            ] => {
                assert_eq!(enter.context.pid, 77);
                assert_eq!(enter.context.tid, 78);
                assert_eq!(enter.context.rip, 0x401234);
                assert_eq!(enter.syscall, Syscall::Getpid);
                assert!(enter.decoded.is_empty());
                assert_eq!(exit.syscall, Syscall::Getpid);
                assert_eq!(exit.args.raw(), [0; 6]);
                assert_eq!(exit.result, SyscallReturn::Success(77));
                assert!(exit.decoded.is_empty());
                assert!(exit.host_error.is_none());
            }
            other => panic!("expected enter/exit events, got {other:?}"),
        }
    }

    #[derive(Default)]
    struct UnsupportedSubsystems;

    impl FileSyscalls for UnsupportedSubsystems {}
    impl MemorySyscalls for UnsupportedSubsystems {}
    impl TaskSyscalls for UnsupportedSubsystems {}
    impl TimeSyscalls for UnsupportedSubsystems {}
    impl NetworkSyscalls for UnsupportedSubsystems {}
    impl EventSyscalls for UnsupportedSubsystems {}

    #[test]
    fn known_syscall_without_subsystem_support_returns_enosys_and_traces_unsupported() {
        let registers = SyscallRegisters {
            rax: Syscall::Mmap.number().raw(),
            rsi: 4096,
            rip: 0x402000,
            ..SyscallRegisters::default()
        };
        let mut dispatcher =
            SyscallDispatcher::with_tracer(UnsupportedSubsystems, InMemorySyscallTracer::new());

        let result = dispatcher.dispatch(GuestContext::new(1, 2, registers));

        assert_eq!(result.result, SyscallReturn::Errno(LinuxErrno::ENOSYS));
        assert_eq!(result.encoded_rax as i64, -38);
        assert!(matches!(
            dispatcher.tracer().events(),
            [
                SyscallTraceEvent::Enter(_),
                SyscallTraceEvent::Unsupported(_)
            ]
        ));
    }

    #[test]
    fn unknown_syscall_returns_enosys_without_entering_a_subsystem() {
        let registers = SyscallRegisters {
            rax: 9999,
            rip: 0x403000,
            ..SyscallRegisters::default()
        };
        let mut dispatcher = SyscallDispatcher::with_tracer(
            RecordingSubsystems::default(),
            InMemorySyscallTracer::new(),
        );

        let result = dispatcher.dispatch(GuestContext::new(10, 11, registers));

        assert_eq!(result.result, SyscallReturn::unsupported());
        assert_eq!(result.encoded_rax as i64, -38);
        assert!(dispatcher.subsystems().file_syscalls.is_empty());
        assert!(dispatcher.subsystems().task_syscalls.is_empty());

        match dispatcher.tracer().events() {
            [SyscallTraceEvent::Unsupported(event)] => {
                assert_eq!(event.number, SyscallNumber::new(9999));
                assert_eq!(event.syscall, Syscall::Unknown(SyscallNumber::new(9999)));
                assert_eq!(event.context.rip, 0x403000);
                assert_eq!(event.result, SyscallReturn::unsupported());
            }
            other => panic!("expected one unsupported event, got {other:?}"),
        }
    }
}
