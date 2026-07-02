use crate::abi::{GuestAddress, GuestPid, GuestTid, SyscallArgs};
use crate::return_value::SyscallReturn;
use crate::syscall::{Syscall, SyscallNumber};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceContext {
    pub pid: GuestPid,
    pub tid: GuestTid,
    pub rip: GuestAddress,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceField {
    pub name: String,
    pub value: String,
}

impl TraceField {
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostErrorTrace {
    pub adapter: String,
    pub code: i64,
    pub message: Option<String>,
}

impl HostErrorTrace {
    #[must_use]
    pub fn new(adapter: impl Into<String>, code: i64, message: Option<String>) -> Self {
        Self {
            adapter: adapter.into(),
            code,
            message,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyscallEnterEvent {
    pub context: TraceContext,
    pub syscall: Syscall,
    pub args: SyscallArgs,
    pub decoded: Vec<TraceField>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyscallExitEvent {
    pub context: TraceContext,
    pub syscall: Syscall,
    pub args: SyscallArgs,
    pub result: SyscallReturn,
    pub decoded: Vec<TraceField>,
    pub host_error: Option<HostErrorTrace>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedSyscallEvent {
    pub context: TraceContext,
    pub syscall: Syscall,
    pub number: SyscallNumber,
    pub args: SyscallArgs,
    pub result: SyscallReturn,
    pub decoded: Vec<TraceField>,
}

impl UnsupportedSyscallEvent {
    #[must_use]
    pub fn new(context: TraceContext, number: SyscallNumber, args: SyscallArgs) -> Self {
        Self {
            context,
            syscall: Syscall::from_number(number),
            number,
            args,
            result: SyscallReturn::unsupported(),
            decoded: Vec::new(),
        }
    }

    #[must_use]
    pub fn for_syscall(
        context: TraceContext,
        syscall: Syscall,
        args: SyscallArgs,
        decoded: Vec<TraceField>,
    ) -> Self {
        Self {
            context,
            syscall,
            number: syscall.number(),
            args,
            result: SyscallReturn::unsupported(),
            decoded,
        }
    }

    #[must_use]
    pub fn with_decoded_fields(mut self, decoded: impl IntoIterator<Item = TraceField>) -> Self {
        self.decoded.extend(decoded);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyscallTraceEvent {
    Enter(SyscallEnterEvent),
    Exit(SyscallExitEvent),
    Unsupported(UnsupportedSyscallEvent),
}

impl SyscallTraceEvent {
    #[must_use]
    pub const fn context(&self) -> &TraceContext {
        match self {
            Self::Enter(event) => &event.context,
            Self::Exit(event) => &event.context,
            Self::Unsupported(event) => &event.context,
        }
    }

    #[must_use]
    pub const fn number(&self) -> SyscallNumber {
        match self {
            Self::Enter(event) => event.syscall.number(),
            Self::Exit(event) => event.syscall.number(),
            Self::Unsupported(event) => event.number,
        }
    }

    #[must_use]
    pub const fn result(&self) -> Option<SyscallReturn> {
        match self {
            Self::Enter(_) => None,
            Self::Exit(event) => Some(event.result),
            Self::Unsupported(event) => Some(event.result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SyscallEnterEvent, SyscallExitEvent, SyscallTraceEvent, TraceContext, TraceField,
        UnsupportedSyscallEvent,
    };
    use crate::abi::SyscallArgs;
    use crate::errno::LinuxErrno;
    use crate::return_value::SyscallReturn;
    use crate::syscall::{Syscall, SyscallNumber};

    #[test]
    fn trace_events_expose_required_syscall_fields() {
        let context = TraceContext {
            pid: 100,
            tid: 101,
            rip: 0x401000,
        };
        let args = SyscallArgs::new([1, 0x2000, 12, 0, 0, 0]);
        let event = SyscallTraceEvent::Exit(SyscallExitEvent {
            context,
            syscall: Syscall::Write,
            args,
            result: SyscallReturn::success(12),
            decoded: vec![TraceField::new("fd", "1")],
            host_error: None,
        });

        assert_eq!(event.context().pid, 100);
        assert_eq!(event.number(), Syscall::WRITE);
        assert_eq!(event.result(), Some(SyscallReturn::Success(12)));
    }

    #[test]
    fn unsupported_trace_event_defaults_to_enosys_result() {
        let context = TraceContext {
            pid: 1,
            tid: 1,
            rip: 0x1234,
        };
        let number = SyscallNumber::new(9999);
        let event = UnsupportedSyscallEvent::new(context, number, SyscallArgs::default());
        let trace = SyscallTraceEvent::Unsupported(event);

        assert_eq!(trace.number(), number);
        assert_eq!(
            trace.result(),
            Some(SyscallReturn::Errno(LinuxErrno::ENOSYS))
        );
    }

    #[test]
    fn enter_trace_event_has_no_result() {
        let event = SyscallTraceEvent::Enter(SyscallEnterEvent {
            context: TraceContext {
                pid: 7,
                tid: 8,
                rip: 9,
            },
            syscall: Syscall::Read,
            args: SyscallArgs::default(),
            decoded: Vec::new(),
        });

        assert_eq!(event.result(), None);
    }
}
