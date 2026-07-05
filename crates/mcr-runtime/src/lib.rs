#![allow(clippy::result_large_err)]
//! Runtime errors preserve native fault diagnostics and guest register snapshots.

mod access;
mod build_run;
mod diagnostics;
mod event_state;
mod filesystem;
mod linux_abi;
pub mod memory;
mod native_patch;
mod perf;
pub mod run_rootfs;
mod runtime;
mod subsystems;
mod tracing;

use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{self, IoSlice, IoSliceMut},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant, UNIX_EPOCH},
};

#[cfg(test)]
use std::sync::atomic::AtomicBool;

pub use access::{GuestMemoryAccess, GuestMemoryAccessError};
pub use build_run::{
    BuildRunCommand, BuildRunError, BuildRunResult, BuildRunSpec, execute_build_run,
};
pub use diagnostics::{
    CrashReport, DiagnosticPermissions, DiagnosticSyscall, DiagnosticTask, DiagnosticTaskState,
    DiagnosticVma, DiagnosticVmaKind, RuntimeDiagnostics, RuntimeStallDiagnostic, RuntimeStallKind,
};
pub(crate) use event_state::{
    EpollRegistry, EpollWatch, FutexRegistry, GuestSignalAltStack, host_sync_errno,
};
pub use filesystem::RuntimeFileSystem;
pub(crate) use linux_abi::*;
pub use memory::{
    DEFAULT_LIBC_STRLEN_MAX, DEFAULT_MMAP_BASE, GUEST_ADDRESS_SPACE_END, GUEST_PAGE_SIZE,
    GuestBrkOutcome, GuestLibcIntrinsic, GuestLibcIntrinsicError, GuestMemory, GuestMemoryError,
    GuestMemoryProtection, GuestVma, GuestVmaKind, MIN_GUEST_ADDRESS,
};
pub(crate) use native_patch::*;
pub(crate) use perf::RuntimePerfSummary;
pub use run_rootfs::{RunRootfsConfig, RunRootfsError, RunRootfsOutput, run_rootfs};
pub use runtime::{
    GuestExecutionError, GuestExecutionStep, GuestRunError, Runtime, RuntimeError,
    RuntimeWithTracer,
};
#[cfg(test)]
pub(crate) use runtime::{
    dispatch_guest_task_with_dispatcher, dispatch_native_libc_intrinsic_task,
};
pub(crate) use runtime::{guest_execution_errno, run_guest_until_exit_with_diagnostic_step_limit};
pub use subsystems::RuntimeSubsystems;
pub(crate) use subsystems::{EPOLL_EVENT_SIZE, MAX_SELECT_FDS, POLLFD_SIZE, SELECT_FD_BITS};
pub use tracing::RuntimeDiagnosticsTracer;
#[cfg(test)]
pub(crate) use tracing::{RUNTIME_DIAGNOSTICS_EVENT_DRAIN, RUNTIME_DIAGNOSTICS_EVENT_LIMIT};

use mcr_elf::{GuestVma as ElfGuestVma, GuestVmaKind as ElfGuestVmaKind, SegmentPermissions};
use mcr_jit::{
    ExecutionError, GuestBlock, GuestRegisters, LinearInstructionScanner, NativeFaultInstruction,
    NativeFaultStackWord, SameIsaExecutionCore,
};
use mcr_net::{
    GuestSocketTable, HostSocketTransport, ShutdownHow, SocketAddress, SocketId, SocketOperation,
    SocketOptionName, SocketProtocol, SocketSpec, SocketType,
};
use mcr_sys::{
    Accept4SyscallArgs, CloneSyscallArgs, Dup2SyscallArgs, Dup3SyscallArgs, DupSyscallArgs,
    EventSyscalls, FcntlSyscallArgs, FileSyscalls, FutexSyscallArgs, GuestContext,
    IoctlSyscallArgs, LINUX_AF_INET, LINUX_AF_INET6, LINUX_EPOLL_CLOEXEC, LINUX_EPOLL_CTL_ADD,
    LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD, LINUX_EPOLLERR, LINUX_EPOLLHUP, LINUX_EPOLLIN,
    LINUX_EPOLLOUT, LINUX_EPOLLPRI, LINUX_FUTEX_CMD_MASK, LINUX_FUTEX_PRIVATE_FLAG,
    LINUX_FUTEX_WAIT, LINUX_FUTEX_WAKE, LINUX_KERNEL_SIGSET_SIZE, LINUX_MSG_CMSG_CLOEXEC,
    LINUX_MSG_DONTWAIT, LINUX_MSG_NOSIGNAL, LINUX_POLLERR, LINUX_POLLHUP, LINUX_POLLIN,
    LINUX_POLLNVAL, LINUX_POLLOUT, LINUX_POLLPRI, LINUX_POLLRDNORM, LINUX_POLLWRNORM,
    LinuxEpollEvent, LinuxErrno, LinuxIovec, LinuxMsghdr, LinuxPollfd, LinuxStat, LinuxStatx,
    LinuxStatxTimestamp, LinuxTimespec, LinuxUtsname, MemorySyscalls, NetworkSyscalls,
    NoopSyscallTracer, Pipe2SyscallArgs, PipeSyscallArgs, SendRecvFromSyscallArgs,
    SendRecvMsgSyscallArgs, ShutdownSyscallArgs, SockaddrSyscallArgs, SocketSyscallArgs,
    SockoptSyscallArgs, SyscallDispatchResult, SyscallDispatcher, SyscallOutcome, SyscallRequest,
    SyscallReturn, SyscallTraceEvent, SyscallTracer, TimeSyscalls, TraceField,
};
use mcr_task::{
    CompletedWait, ExitState, FutexWaitKey, GprState, GuestExecutable, GuestKernel, GuestProcess,
    GuestProgram, GuestTask, HostWorkerPoolConfig, HostWorkerPoolDiagnostics,
    HostWorkerPoolExecutor, HostWorkerPoolJob, HostWorkerPoolRole, INITIAL_GUEST_PID,
    INITIAL_GUEST_TID, TaskError, TaskState,
};
use mcr_vfs::{
    AT_EMPTY_PATH, AT_REMOVEDIR, AT_SYMLINK_FOLLOW, AT_SYMLINK_NOFOLLOW, DirectoryEntry, Fd,
    FdReadiness, FdTable, FileKind, FileRef, FileTimes, LinuxFileAttr, LinuxFsKind, LinuxStatfs,
    OpenFlags, ProcSelfData, RegularFileCacheKey, SeekWhence, VfsError, VirtualFileSystem,
};
use mcr_win::SocketEvents;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

const HOST_STEP_TRACE_ENV: &str = "MCR_HOSTSTEP_TRACE";
const PERF_SUMMARY_TRACE_ENV: &str = "MCR_TRACE_PERF_SUMMARY";
const STICKY_SCHED_ENV: &str = "MCR_SCHED_STICKY";
const UNSAFE_SHARE_UNTIL_EXEC_ENV: &str = "MCR_UNSAFE_SHARE_UNTIL_EXEC";
#[cfg(test)]
static UNSAFE_SHARE_UNTIL_EXEC_TEST_OVERRIDE: AtomicBool = AtomicBool::new(false);

pub(crate) fn host_step_trace_enabled() -> bool {
    std::env::var_os(HOST_STEP_TRACE_ENV).is_some()
}

pub(crate) fn host_step_trace(message: fmt::Arguments<'_>) {
    if host_step_trace_enabled() {
        eprintln!("mcr hoststep: {message}");
    }
}

fn unsafe_share_until_exec_enabled() -> bool {
    if std::env::var_os(UNSAFE_SHARE_UNTIL_EXEC_ENV).is_some() {
        return true;
    }
    #[cfg(test)]
    {
        if UNSAFE_SHARE_UNTIL_EXEC_TEST_OVERRIDE.load(Ordering::SeqCst) {
            return true;
        }
    }
    false
}

pub(crate) fn host_step_elapsed_ms(start: Instant) -> u128 {
    start.elapsed().as_millis()
}

const LINUX_CLOCK_REALTIME: u64 = 0;
const LINUX_CLOCK_MONOTONIC: u64 = 1;
const LINUX_CLOCK_MONOTONIC_RAW: u64 = 4;
const LINUX_CLOCK_REALTIME_COARSE: u64 = 5;
const LINUX_CLOCK_MONOTONIC_COARSE: u64 = 6;
const LINUX_CLOCK_BOOTTIME: u64 = 7;
const LINUX_RUSAGE_SELF: i32 = 0;
const LINUX_RUSAGE_CHILDREN: i32 = -1;
const LINUX_RUSAGE_THREAD: i32 = 1;
const LINUX_PR_GET_DUMPABLE: u64 = 3;
const LINUX_PR_SET_DUMPABLE: u64 = 4;
const LINUX_PR_SET_NAME: u64 = 15;
const LINUX_PR_GET_NAME: u64 = 16;
const LINUX_PR_SET_TIMERSLACK: u64 = 29;
const LINUX_PR_GET_TIMERSLACK: u64 = 30;
const LINUX_PR_SET_NO_NEW_PRIVS: u64 = 38;
const LINUX_PR_GET_NO_NEW_PRIVS: u64 = 39;
const LINUX_PR_SET_THP_DISABLE: u64 = 41;
const LINUX_PR_GET_THP_DISABLE: u64 = 42;
const LINUX_PR_SET_VMA: u64 = 0x5356_4d41;
const LINUX_PR_SET_VMA_ANON_NAME: u64 = 0;
const LINUX_MEMBARRIER_CMD_QUERY: u64 = 0;
const LINUX_SS_DISABLE: u32 = 2;
const LINUX_SS_AUTODISARM: u32 = 1 << 31;
const LINUX_SS_SUPPORTED_FLAGS: u32 = LINUX_SS_DISABLE | LINUX_SS_AUTODISARM;
const LINUX_MINSIGSTKSZ: u64 = 2048;
const LINUX_STACK_T_FLAGS_OFFSET: u64 = 8;
const LINUX_STACK_T_SIZE_OFFSET: u64 = 16;
const LINUX_UTIME_NOW: i64 = 0x3fffffff;
const LINUX_UTIME_OMIT: i64 = 0x3ffffffe;

const LINUX_GRND_NONBLOCK: u64 = 0x0001;
const LINUX_GRND_RANDOM: u64 = 0x0002;
const LINUX_GRND_SUPPORTED_FLAGS: u64 = LINUX_GRND_NONBLOCK | LINUX_GRND_RANDOM;
#[cfg(all(windows, target_arch = "x86_64"))]
const WINDOWS_NATIVE_MMAP_BASE: u64 = 0x5000_0000;
const LINUX_EFD_NONBLOCK: u32 = mcr_vfs::O_NONBLOCK;
const LINUX_EFD_CLOEXEC: u32 = mcr_vfs::O_CLOEXEC;
const LINUX_EFD_SUPPORTED_FLAGS: u32 = LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC;
const LINUX_AT_EACCESS: u32 = 0x200;
const LINUX_FACCESSAT2_SUPPORTED_FLAGS: u32 =
    LINUX_AT_EACCESS | AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;
const LINUX_CLOSE_RANGE_SUPPORTED_FLAGS: u32 = 0;
const LINUX_OPEN_HOW_SIZE: usize = 24;
const LINUX_OPEN_HOW_MAX_SIZE: usize = 4096;
const LINUX_STATFS_SIZE: usize = 120;
const LINUX_EXT_SUPER_MAGIC: u64 = 0xef53;
const LINUX_TMPFS_MAGIC: u64 = 0x0102_1994;
const LINUX_STATFS_BLOCK_SIZE: u64 = 4096;

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard};

    static NATIVE_EXECUTION_TEST_LOCK: Mutex<()> = Mutex::new(());
    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) fn native_execution_test_guard() -> MutexGuard<'static, ()> {
        NATIVE_EXECUTION_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn env_test_guard() -> MutexGuard<'static, ()> {
        ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectInterest {
    fd: Fd,
    events: i16,
    read: bool,
    write: bool,
    exceptional: bool,
}

#[derive(Default)]
struct SelectReadyFds {
    read: Vec<Fd>,
    write: Vec<Fd>,
    exceptional: Vec<Fd>,
}

impl SelectReadyFds {
    fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty() && self.exceptional.is_empty()
    }

    fn count(&self) -> usize {
        let mut fds =
            Vec::with_capacity(self.read.len() + self.write.len() + self.exceptional.len());
        fds.extend_from_slice(&self.read);
        fds.extend_from_slice(&self.write);
        fds.extend_from_slice(&self.exceptional);
        fds.sort_unstable();
        fds.dedup();
        fds.len()
    }
}

const LINUX_EPOLL_SUPPORTED_EVENTS: u32 =
    LINUX_EPOLLIN | LINUX_EPOLLPRI | LINUX_EPOLLOUT | LINUX_EPOLLERR | LINUX_EPOLLHUP;

fn validate_epoll_events(events: u32) -> Result<(), LinuxErrno> {
    if events & !LINUX_EPOLL_SUPPORTED_EVENTS != 0 {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(())
}

fn zero_elf_load_bss_tail(vfs: &VirtualFileSystem, fd: Fd, mapped_offset: u64, bytes: &mut [u8]) {
    if bytes.is_empty() {
        return;
    }

    let Some(headers) = read_elf64_program_headers(vfs, fd) else {
        return;
    };
    let Some(mapped_end) = mapped_offset.checked_add(bytes.len() as u64) else {
        return;
    };

    for header in headers {
        if header.kind != ELF_PT_LOAD || header.mem_size <= header.file_size {
            continue;
        }

        let Some(tail_start) = header.offset.checked_add(header.file_size) else {
            continue;
        };
        let Some(tail_end) = header.offset.checked_add(header.mem_size) else {
            continue;
        };
        let overlap_start = tail_start.max(mapped_offset);
        let overlap_end = tail_end.min(mapped_end);
        if overlap_start >= overlap_end {
            continue;
        }

        let start = usize::try_from(overlap_start - mapped_offset).unwrap_or(bytes.len());
        let end = usize::try_from(overlap_end - mapped_offset).unwrap_or(bytes.len());
        bytes[start..end].fill(0);
    }
}

#[derive(Debug)]
struct Elf64ProgramHeaderView {
    kind: u32,
    offset: u64,
    file_size: u64,
    mem_size: u64,
}

const ELF_HEADER_LEN: usize = 64;
const ELF_PROGRAM_HEADER_MIN_LEN: usize = 56;
const ELF_PT_LOAD: u32 = 1;
const MAX_ELF_PROGRAM_HEADERS: usize = 1024;
const MAX_ELF_PROGRAM_HEADER_LEN: usize = 4096;

fn read_elf64_program_headers(
    vfs: &VirtualFileSystem,
    fd: Fd,
) -> Option<Vec<Elf64ProgramHeaderView>> {
    let mut elf_header = [0; ELF_HEADER_LEN];
    if vfs.pread(fd, 0, &mut elf_header).ok()? < ELF_HEADER_LEN {
        return None;
    }
    if elf_header.get(0..4) != Some(b"\x7fELF") || elf_header[4] != 2 || elf_header[5] != 1 {
        return None;
    }

    let ph_offset = le_u64(&elf_header[32..40]);
    let ph_entry_size = usize::from(le_u16(&elf_header[54..56]));
    let ph_count = usize::from(le_u16(&elf_header[56..58]));
    if !(ELF_PROGRAM_HEADER_MIN_LEN..=MAX_ELF_PROGRAM_HEADER_LEN).contains(&ph_entry_size)
        || ph_count > MAX_ELF_PROGRAM_HEADERS
    {
        return None;
    }

    let mut headers = Vec::with_capacity(ph_count);
    let mut ph_bytes = vec![0; ph_entry_size];
    for index in 0..ph_count {
        let entry_offset = ph_offset.checked_add((index * ph_entry_size) as u64)?;
        if vfs.pread(fd, entry_offset, &mut ph_bytes).ok()? < ELF_PROGRAM_HEADER_MIN_LEN {
            return None;
        }
        headers.push(Elf64ProgramHeaderView {
            kind: le_u32(&ph_bytes[0..4]),
            offset: le_u64(&ph_bytes[8..16]),
            file_size: le_u64(&ph_bytes[32..40]),
            mem_size: le_u64(&ph_bytes[40..48]),
        });
    }

    Some(headers)
}

fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("slice length checked by caller"))
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("slice length checked by caller"))
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("slice length checked by caller"))
}

fn poll_timeout(raw: u64) -> Result<Option<Duration>, LinuxErrno> {
    let timeout_ms = raw as i32;
    if timeout_ms < 0 {
        return Ok(None);
    }
    Ok(Some(Duration::from_millis(timeout_ms as u64)))
}

fn linux_timespec_from_system_time(time: std::time::SystemTime) -> LinuxTimespec {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    LinuxTimespec {
        tv_sec: duration.as_secs().min(i64::MAX as u64) as i64,
        tv_nsec: i64::from(duration.subsec_nanos()),
    }
}

fn linux_timespec_from_duration(duration: Duration) -> Result<LinuxTimespec, LinuxErrno> {
    let tv_sec = i64::try_from(duration.as_secs()).map_err(|_| LinuxErrno::EOVERFLOW)?;
    Ok(LinuxTimespec {
        tv_sec,
        tv_nsec: i64::from(duration.subsec_nanos()),
    })
}

fn resolve_utimensat_time(
    requested: LinuxTimespec,
    now: LinuxTimespec,
    current: Option<LinuxFileAttr>,
    atime: bool,
) -> Result<LinuxTimespec, LinuxErrno> {
    match requested.tv_nsec {
        LINUX_UTIME_NOW => Ok(now),
        LINUX_UTIME_OMIT => {
            let current = current.ok_or(LinuxErrno::ENOENT)?;
            if atime {
                Ok(LinuxTimespec {
                    tv_sec: current.atime_sec,
                    tv_nsec: current.atime_nsec,
                })
            } else {
                Ok(LinuxTimespec {
                    tv_sec: current.mtime_sec,
                    tv_nsec: current.mtime_nsec,
                })
            }
        }
        0..=999_999_999 if requested.tv_sec >= 0 => Ok(requested),
        _ => Err(LinuxErrno::EINVAL),
    }
}

fn read_required_timespec_duration(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<Duration, LinuxErrno> {
    let timespec = read_guest_timespec(memory, addr)?;
    if timespec.tv_sec < 0 || !(0..1_000_000_000).contains(&timespec.tv_nsec) {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(Duration::new(
        timespec.tv_sec as u64,
        timespec.tv_nsec as u32,
    ))
}

fn read_guest_timespec(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<LinuxTimespec, LinuxErrno> {
    Ok(LinuxTimespec {
        tv_sec: read_guest_i64(memory, addr)?,
        tv_nsec: read_guest_i64(memory, addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?)?,
    })
}

fn read_open_how(
    memory: &impl GuestMemoryAccess,
    addr: u64,
    size: usize,
) -> Result<LinuxOpenHow, LinuxErrno> {
    if addr == 0 {
        return Err(LinuxErrno::EFAULT);
    }
    if !(LINUX_OPEN_HOW_SIZE..=LINUX_OPEN_HOW_MAX_SIZE).contains(&size) {
        return Err(LinuxErrno::EINVAL);
    }
    let mut bytes = vec![0; size];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    if bytes[LINUX_OPEN_HOW_SIZE..].iter().any(|byte| *byte != 0) {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(LinuxOpenHow {
        flags: u64::from_le_bytes(bytes[0..8].try_into().expect("open_how flags")),
        mode: u64::from_le_bytes(bytes[8..16].try_into().expect("open_how mode")),
        resolve: u64::from_le_bytes(bytes[16..24].try_into().expect("open_how resolve")),
    })
}

fn write_guest_uname(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    uts: &LinuxUtsname,
) -> Result<(), LinuxErrno> {
    if addr == 0 {
        return Err(LinuxErrno::EFAULT);
    }
    memory
        .write_bytes(addr, &encode_linux_uname(uts))
        .map_err(memory_errno)
}

fn encode_linux_uname(uts: &LinuxUtsname) -> [u8; std::mem::size_of::<LinuxUtsname>()] {
    let mut bytes = [0; std::mem::size_of::<LinuxUtsname>()];
    let mut offset = 0;
    for field in [
        &uts.sysname,
        &uts.nodename,
        &uts.release,
        &uts.version,
        &uts.machine,
        &uts.domainname,
    ] {
        bytes[offset..offset + field.len()].copy_from_slice(field);
        offset += field.len();
    }
    bytes
}

fn write_guest_timespec(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    timespec: LinuxTimespec,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &timespec.tv_sec.to_le_bytes())
        .map_err(memory_errno)?;
    memory
        .write_bytes(
            addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?,
            &timespec.tv_nsec.to_le_bytes(),
        )
        .map_err(memory_errno)
}

fn validate_clock_id(clock_id: u64) -> Result<(), LinuxErrno> {
    match clock_id {
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_MONOTONIC
        | LINUX_CLOCK_MONOTONIC_RAW
        | LINUX_CLOCK_REALTIME_COARSE
        | LINUX_CLOCK_MONOTONIC_COARSE
        | LINUX_CLOCK_BOOTTIME => Ok(()),
        _ => Err(LinuxErrno::EINVAL),
    }
}

fn write_guest_timeval(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    timespec: LinuxTimespec,
) -> Result<(), LinuxErrno> {
    let usec = timespec.tv_nsec / 1_000;
    memory
        .write_bytes(addr, &timespec.tv_sec.to_le_bytes())
        .map_err(memory_errno)?;
    memory
        .write_bytes(
            addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?,
            &usec.to_le_bytes(),
        )
        .map_err(memory_errno)
}

fn write_guest_timezone_utc(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &0i32.to_le_bytes())
        .map_err(memory_errno)?;
    memory
        .write_bytes(
            addr.checked_add(4).ok_or(LinuxErrno::EFAULT)?,
            &0i32.to_le_bytes(),
        )
        .map_err(memory_errno)
}

fn fixed_rlimit(resource: u64) -> Result<(u64, u64), LinuxErrno> {
    const LINUX_RLIM_INFINITY: u64 = u64::MAX;
    const SOFT_STACK_LIMIT: u64 = 8 * 1024 * 1024;
    const OPEN_FILE_LIMIT: u64 = 1024;
    match resource {
        0 => Ok((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)),
        1 => Ok((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)),
        2 => Ok((0, LINUX_RLIM_INFINITY)),
        3 => Ok((SOFT_STACK_LIMIT, LINUX_RLIM_INFINITY)),
        4 => Ok((0, LINUX_RLIM_INFINITY)),
        5 => Ok((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)),
        6 => Ok((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)),
        7 => Ok((OPEN_FILE_LIMIT, OPEN_FILE_LIMIT)),
        8 => Ok((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)),
        9 => Ok((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)),
        10 => Ok((0, 0)),
        11 => Ok((0, 0)),
        12 => Ok((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)),
        13 => Ok((0, 0)),
        14 => Ok((0, 0)),
        15 => Ok((0, 0)),
        _ => Err(LinuxErrno::EINVAL),
    }
}

fn write_guest_rlimit(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    soft: u64,
    hard: u64,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &soft.to_le_bytes())
        .map_err(memory_errno)?;
    memory
        .write_bytes(
            addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?,
            &hard.to_le_bytes(),
        )
        .map_err(memory_errno)
}

fn read_guest_rlimit(memory: &impl GuestMemoryAccess, addr: u64) -> Result<(u64, u64), LinuxErrno> {
    Ok((
        read_guest_u64(memory, addr)?,
        read_guest_u64(memory, addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?)?,
    ))
}

fn write_zeroed(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    len: usize,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &vec![0; len])
        .map_err(memory_errno)
}

fn write_guest_sysinfo(memory: &mut impl GuestMemoryAccess, addr: u64) -> Result<(), LinuxErrno> {
    let mut bytes = [0; 112];
    bytes[0..8].copy_from_slice(&3600i64.to_le_bytes());
    bytes[8..16].copy_from_slice(&0u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&0u64.to_le_bytes());
    bytes[24..32].copy_from_slice(&0u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&(512 * 1024 * 1024u64).to_le_bytes());
    bytes[40..48].copy_from_slice(&(256 * 1024 * 1024u64).to_le_bytes());
    bytes[48..56].copy_from_slice(&(256 * 1024 * 1024u64).to_le_bytes());
    bytes[56..64].copy_from_slice(&0u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&0u64.to_le_bytes());
    bytes[72..80].copy_from_slice(&(32u64 * 1024).to_le_bytes());
    bytes[80..82].copy_from_slice(&1u16.to_le_bytes());
    bytes[88..96].copy_from_slice(&(512 * 1024 * 1024u64).to_le_bytes());
    bytes[96..104].copy_from_slice(&(256 * 1024 * 1024u64).to_le_bytes());
    bytes[104..108].copy_from_slice(&(4096u32).to_le_bytes());
    memory.write_bytes(addr, &bytes).map_err(memory_errno)
}

fn read_pollfd(memory: &impl GuestMemoryAccess, addr: u64) -> Result<LinuxPollfd, LinuxErrno> {
    let mut bytes = [0; POLLFD_SIZE];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(LinuxPollfd {
        fd: i32::from_le_bytes(bytes[0..4].try_into().expect("pollfd fd")),
        events: i16::from_le_bytes(bytes[4..6].try_into().expect("pollfd events")),
        revents: i16::from_le_bytes(bytes[6..8].try_into().expect("pollfd revents")),
    })
}

fn write_pollfd_revents(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    revents: i16,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(
            addr.checked_add(6).ok_or(LinuxErrno::EFAULT)?,
            &revents.to_le_bytes(),
        )
        .map_err(memory_errno)
}

fn select_nfds(raw: u64) -> Result<usize, LinuxErrno> {
    let signed = raw as i64;
    if signed < 0 {
        return Err(LinuxErrno::EINVAL);
    }
    let nfds = usize::try_from(signed).map_err(|_| LinuxErrno::EINVAL)?;
    if nfds > MAX_SELECT_FDS {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(nfds)
}

fn read_select_timeout(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<Option<Duration>, LinuxErrno> {
    if addr == 0 {
        return Ok(None);
    }
    let tv_sec = read_guest_i64(memory, addr)?;
    let tv_usec = read_guest_i64(memory, addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?)?;
    if tv_sec < 0 || !(0..1_000_000).contains(&tv_usec) {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(Some(Duration::new(
        tv_sec as u64,
        u32::try_from(tv_usec * 1_000).map_err(|_| LinuxErrno::EINVAL)?,
    )))
}

fn read_select_interests(
    memory: &impl GuestMemoryAccess,
    nfds: usize,
    readfds_addr: u64,
    writefds_addr: u64,
    exceptfds_addr: u64,
) -> Result<Vec<SelectInterest>, LinuxErrno> {
    let mut interests = Vec::new();
    for fd in 0..nfds {
        let read = select_fd_set_contains(memory, readfds_addr, fd)?;
        let write = select_fd_set_contains(memory, writefds_addr, fd)?;
        let exceptional = select_fd_set_contains(memory, exceptfds_addr, fd)?;
        if !read && !write && !exceptional {
            continue;
        }
        let mut events = 0;
        if read {
            events |= LINUX_POLLIN | LINUX_POLLRDNORM;
        }
        if write {
            events |= LINUX_POLLOUT | LINUX_POLLWRNORM;
        }
        if exceptional {
            events |= LINUX_POLLPRI;
        }
        interests.push(SelectInterest {
            fd: i32::try_from(fd).map_err(|_| LinuxErrno::EINVAL)?,
            events,
            read,
            write,
            exceptional,
        });
    }
    Ok(interests)
}

fn select_fd_set_contains(
    memory: &impl GuestMemoryAccess,
    set_addr: u64,
    fd: usize,
) -> Result<bool, LinuxErrno> {
    if set_addr == 0 {
        return Ok(false);
    }
    let word_addr = select_fd_word_addr(set_addr, fd)?;
    let word = read_guest_u64(memory, word_addr)?;
    Ok(word & select_fd_bit(fd) != 0)
}

fn write_select_fd_set(
    memory: &mut impl GuestMemoryAccess,
    set_addr: u64,
    nfds: usize,
    fds: &[Fd],
) -> Result<(), LinuxErrno> {
    if set_addr == 0 {
        return Ok(());
    }
    write_zeroed(memory, set_addr, select_fd_set_len(nfds)?)?;
    for fd in fds {
        if *fd < 0 {
            continue;
        }
        let fd = usize::try_from(*fd).map_err(|_| LinuxErrno::EINVAL)?;
        if fd >= nfds {
            continue;
        }
        let word_addr = select_fd_word_addr(set_addr, fd)?;
        let word = read_guest_u64(memory, word_addr)? | select_fd_bit(fd);
        memory
            .write_bytes(word_addr, &word.to_le_bytes())
            .map_err(memory_errno)?;
    }
    Ok(())
}

fn select_fd_set_len(nfds: usize) -> Result<usize, LinuxErrno> {
    nfds.checked_add(SELECT_FD_BITS - 1)
        .map(|bits| bits / SELECT_FD_BITS * 8)
        .ok_or(LinuxErrno::EINVAL)
}

fn select_fd_word_addr(set_addr: u64, fd: usize) -> Result<u64, LinuxErrno> {
    set_addr
        .checked_add(((fd / SELECT_FD_BITS) * 8) as u64)
        .ok_or(LinuxErrno::EFAULT)
}

fn select_fd_bit(fd: usize) -> u64 {
    1u64 << (fd % SELECT_FD_BITS)
}

fn read_epoll_event(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<LinuxEpollEvent, LinuxErrno> {
    let mut bytes = [0; EPOLL_EVENT_SIZE];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(LinuxEpollEvent {
        events: u32::from_le_bytes(bytes[0..4].try_into().expect("epoll events")),
        data: u64::from_le_bytes(bytes[4..12].try_into().expect("epoll data")),
    })
}

fn write_epoll_event(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    event: LinuxEpollEvent,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &event.events.to_le_bytes())
        .map_err(memory_errno)?;
    memory
        .write_bytes(
            addr.checked_add(4).ok_or(LinuxErrno::EFAULT)?,
            &event.data.to_le_bytes(),
        )
        .map_err(memory_errno)
}

fn epoll_events_to_poll_events(events: u32) -> i16 {
    let mut poll_events = 0;
    if events & LINUX_EPOLLIN != 0 {
        poll_events |= LINUX_POLLIN;
    }
    if events & LINUX_EPOLLOUT != 0 {
        poll_events |= LINUX_POLLOUT;
    }
    if events & LINUX_EPOLLPRI != 0 {
        poll_events |= LINUX_POLLPRI;
    }
    poll_events
}

fn poll_revents_to_epoll_events(revents: i16, interest: u32) -> u32 {
    let mut events = 0;
    if revents & LINUX_POLLIN != 0 && interest & LINUX_EPOLLIN != 0 {
        events |= LINUX_EPOLLIN;
    }
    if revents & LINUX_POLLOUT != 0 && interest & LINUX_EPOLLOUT != 0 {
        events |= LINUX_EPOLLOUT;
    }
    if revents & LINUX_POLLPRI != 0 && interest & LINUX_EPOLLPRI != 0 {
        events |= LINUX_EPOLLPRI;
    }
    if revents & LINUX_POLLERR != 0 {
        events |= LINUX_EPOLLERR;
    }
    if revents & LINUX_POLLHUP != 0 {
        events |= LINUX_EPOLLHUP;
    }
    events
}

fn poll_revents_from_vfs(readiness: FdReadiness, events: i16) -> i16 {
    let mut revents = 0;
    if readiness.readable && events & LINUX_POLL_READ_NORMAL != 0 {
        revents |= events & LINUX_POLL_READ_NORMAL;
    }
    if readiness.writable && events & LINUX_POLL_WRITE_NORMAL != 0 {
        revents |= events & LINUX_POLL_WRITE_NORMAL;
    }
    if readiness.error {
        revents |= LINUX_POLLERR;
    }
    if readiness.hang_up {
        revents |= LINUX_POLLHUP;
    }
    revents
}

const LINUX_POLL_READ_NORMAL: i16 = LINUX_POLLIN | LINUX_POLLRDNORM;
const LINUX_POLL_WRITE_NORMAL: i16 = LINUX_POLLOUT | LINUX_POLLWRNORM;

fn fd_wait_ready(fds: &FdTable, fd: Fd, write: bool) -> Result<bool, LinuxErrno> {
    let readiness = fds
        .poll_readiness(&mcr_vfs::PathTree::new(), fd)
        .map_err(vfs_errno)?;
    Ok(if write {
        readiness.writable || readiness.hang_up || readiness.error
    } else {
        readiness.readable || readiness.hang_up || readiness.error
    })
}

fn poll_interest_to_socket_events(events: i16) -> SocketEvents {
    SocketEvents {
        readable: events & LINUX_POLL_READ_NORMAL != 0,
        writable: events & LINUX_POLL_WRITE_NORMAL != 0,
        priority: events & LINUX_POLLPRI != 0,
        error: false,
        hang_up: false,
        invalid: false,
    }
}

fn poll_revents_from_socket_events(readiness: SocketEvents, events: i16) -> i16 {
    let mut revents = 0;
    if readiness.readable && events & LINUX_POLL_READ_NORMAL != 0 {
        revents |= events & LINUX_POLL_READ_NORMAL;
    }
    if readiness.writable && events & LINUX_POLL_WRITE_NORMAL != 0 {
        revents |= events & LINUX_POLL_WRITE_NORMAL;
    }
    if readiness.priority && events & LINUX_POLLPRI != 0 {
        revents |= LINUX_POLLPRI;
    }
    if readiness.error {
        revents |= LINUX_POLLERR;
    }
    if readiness.hang_up {
        revents |= LINUX_POLLHUP;
    }
    if readiness.invalid {
        revents |= LINUX_POLLNVAL;
    }
    revents
}

fn select_revents_readable(revents: i16) -> bool {
    revents & (LINUX_POLL_READ_NORMAL | LINUX_POLLERR | LINUX_POLLHUP) != 0
}

fn select_revents_writable(revents: i16) -> bool {
    revents & (LINUX_POLL_WRITE_NORMAL | LINUX_POLLERR | LINUX_POLLHUP) != 0
}

fn fork_child_pid(decoded: &[TraceField]) -> Option<mcr_sys::GuestPid> {
    decoded
        .iter()
        .find(|field| field.name == "guest_pid")
        .and_then(|field| field.value.parse().ok())
}

fn thread_child_tid(decoded: &[TraceField]) -> Option<mcr_sys::GuestTid> {
    decoded
        .iter()
        .find(|field| field.name == "guest_tid")
        .and_then(|field| field.value.parse().ok())
}

fn wait_status_from_decoded(decoded: &[TraceField]) -> Option<u32> {
    decoded
        .iter()
        .find(|field| field.name == "wait_status")
        .and_then(|field| {
            field.value.strip_prefix("0x").map_or_else(
                || field.value.parse().ok(),
                |hex| u32::from_str_radix(hex, 16).ok(),
            )
        })
}

fn read_guest_stack_t(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<GuestSignalAltStack, LinuxErrno> {
    Ok(GuestSignalAltStack {
        sp: read_guest_u64(memory, addr)?,
        flags: read_guest_u32(
            memory,
            addr.checked_add(LINUX_STACK_T_FLAGS_OFFSET)
                .ok_or(LinuxErrno::EFAULT)?,
        )?,
        size: read_guest_u64(
            memory,
            addr.checked_add(LINUX_STACK_T_SIZE_OFFSET)
                .ok_or(LinuxErrno::EFAULT)?,
        )?,
    })
}

fn write_guest_stack_t(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    stack: GuestSignalAltStack,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &stack.sp.to_le_bytes())
        .map_err(memory_errno)?;
    memory
        .write_bytes(
            addr.checked_add(LINUX_STACK_T_FLAGS_OFFSET)
                .ok_or(LinuxErrno::EFAULT)?,
            &stack.flags.to_le_bytes(),
        )
        .map_err(memory_errno)?;
    memory
        .write_bytes(
            addr.checked_add(LINUX_STACK_T_SIZE_OFFSET)
                .ok_or(LinuxErrno::EFAULT)?,
            &stack.size.to_le_bytes(),
        )
        .map_err(memory_errno)
}

fn validate_sigaltstack(stack: GuestSignalAltStack) -> Result<(), LinuxErrno> {
    if stack.flags & !LINUX_SS_SUPPORTED_FLAGS != 0 {
        return Err(LinuxErrno::EINVAL);
    }
    if !stack.disabled() && stack.size < LINUX_MINSIGSTKSZ {
        return Err(LinuxErrno::ENOMEM);
    }
    Ok(())
}

fn read_futex_timeout(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<Option<Duration>, LinuxErrno> {
    if addr == 0 {
        return Ok(None);
    }
    let tv_sec = read_guest_i64(memory, addr)?;
    let tv_nsec = read_guest_i64(memory, addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?)?;
    if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(Some(Duration::new(tv_sec as u64, tv_nsec as u32)))
}

fn read_guest_u32(memory: &impl GuestMemoryAccess, addr: u64) -> Result<u32, LinuxErrno> {
    let mut bytes = [0; 4];
    memory
        .read_bytes(addr, &mut bytes)
        .map_err(|_| LinuxErrno::EFAULT)?;
    Ok(u32::from_le_bytes(bytes))
}

fn write_guest_u32(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    value: u32,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &value.to_le_bytes())
        .map_err(|_| LinuxErrno::EFAULT)
}

fn read_guest_i64(memory: &impl GuestMemoryAccess, addr: u64) -> Result<i64, LinuxErrno> {
    let mut bytes = [0; 8];
    memory
        .read_bytes(addr, &mut bytes)
        .map_err(|_| LinuxErrno::EFAULT)?;
    Ok(i64::from_le_bytes(bytes))
}

fn read_guest_u64(memory: &impl GuestMemoryAccess, addr: u64) -> Result<u64, LinuxErrno> {
    let mut bytes = [0; 8];
    memory
        .read_bytes(addr, &mut bytes)
        .map_err(|_| LinuxErrno::EFAULT)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_guest_c_bytes(memory: &impl GuestMemoryAccess, addr: u64) -> Result<Vec<u8>, LinuxErrno> {
    const MAX_C_STRING_LEN: usize = 4096;
    let mut bytes = Vec::new();
    for offset in 0..MAX_C_STRING_LEN {
        let mut byte = [0];
        memory
            .read_bytes(
                addr.checked_add(offset as u64).ok_or(LinuxErrno::EFAULT)?,
                &mut byte,
            )
            .map_err(|_| LinuxErrno::EFAULT)?;
        if byte[0] == 0 {
            return Ok(bytes);
        }
        bytes.push(byte[0]);
    }
    Err(LinuxErrno::ENAMETOOLONG)
}

fn read_guest_vector(
    memory: &impl GuestMemoryAccess,
    vector_addr: u64,
) -> Result<Vec<Vec<u8>>, LinuxErrno> {
    const MAX_VECTOR_ITEMS: usize = 4096;
    if vector_addr == 0 {
        return Ok(Vec::new());
    }

    let mut values = Vec::new();
    for index in 0..MAX_VECTOR_ITEMS {
        let item_addr = vector_addr
            .checked_add((index * 8) as u64)
            .ok_or(LinuxErrno::EFAULT)?;
        let ptr = read_guest_u64(memory, item_addr)?;
        if ptr == 0 {
            return Ok(values);
        }
        values.push(read_guest_c_bytes(memory, ptr)?);
    }
    Err(LinuxErrno::E2BIG)
}

fn guest_bytes_to_path(bytes: &[u8]) -> Result<String, LinuxErrno> {
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(LinuxErrno::ENOENT);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| LinuxErrno::ENOENT)
}

fn read_vfs_file_to_end(
    vfs: &mut VirtualFileSystem,
    fd: Fd,
    output: &mut Vec<u8>,
) -> Result<(), LinuxErrno> {
    let mut buffer = [0; 8192];
    loop {
        let count = vfs.read(fd, &mut buffer).map_err(vfs_errno)?;
        if count == 0 {
            return Ok(());
        }
        output.len().checked_add(count).ok_or(LinuxErrno::EFBIG)?;
        output.extend_from_slice(&buffer[..count]);
    }
}

#[cfg(test)]
mod tests;
