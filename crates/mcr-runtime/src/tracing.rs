#[allow(unused_imports)]
use super::*;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeDiagnosticsTracer {
    events: Vec<SyscallTraceEvent>,
    dropped_events: u64,
}

pub(crate) const RUNTIME_DIAGNOSTICS_EVENT_LIMIT: usize = 8192;
pub(crate) const RUNTIME_DIAGNOSTICS_EVENT_DRAIN: usize = 4096;

impl RuntimeDiagnosticsTracer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn events(&self) -> &[SyscallTraceEvent] {
        &self.events
    }

    #[must_use]
    pub fn last_syscall(&self) -> Option<DiagnosticSyscall> {
        self.events
            .iter()
            .rev()
            .find_map(DiagnosticSyscall::from_event)
    }

    #[must_use]
    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    #[must_use]
    pub fn into_events(self) -> Vec<SyscallTraceEvent> {
        self.events
    }
}

impl SyscallTracer for RuntimeDiagnosticsTracer {
    fn record(&mut self, event: SyscallTraceEvent) {
        if self.events.len() >= RUNTIME_DIAGNOSTICS_EVENT_LIMIT {
            self.events.drain(..RUNTIME_DIAGNOSTICS_EVENT_DRAIN);
            self.dropped_events = self
                .dropped_events
                .saturating_add(RUNTIME_DIAGNOSTICS_EVENT_DRAIN as u64);
        }
        self.events.push(event);
    }
}
