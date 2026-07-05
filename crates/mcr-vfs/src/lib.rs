use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub type Fd = i32;
pub type InodeId = u64;

pub const AT_FDCWD: Fd = -100;
pub const AT_EMPTY_PATH: u32 = 0x1000;
pub const AT_REMOVEDIR: u32 = 0x200;
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const DEFAULT_UMASK: u32 = 0o022;
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;
pub const F_DUPFD: u32 = 0;
pub const F_GETFD: u32 = 1;
pub const F_SETFD: u32 = 2;
pub const F_GETFL: u32 = 3;
pub const F_SETFL: u32 = 4;
pub const F_DUPFD_CLOEXEC: u32 = 1030;
pub const F_SETPIPE_SZ: u32 = 1031;
pub const F_GETPIPE_SZ: u32 = 1032;
pub const FD_CLOEXEC: u32 = 1;
pub const F_OK: u32 = 0;
pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const FIONREAD: u64 = 0x541b;
pub const TCGETS: u64 = 0x5401;
pub const TCSETS: u64 = 0x5402;
pub const TCSETSW: u64 = 0x5403;
pub const TCSETSF: u64 = 0x5404;
pub const TIOCGPGRP: u64 = 0x540f;
pub const TIOCSPGRP: u64 = 0x5410;
pub const TIOCGWINSZ: u64 = 0x5413;
pub const R_OK: u32 = 4;
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const RENAME_WHITEOUT: u32 = 4;
pub const SUPPORTED_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;
pub const S_IFMT: u32 = 0o170000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFSOCK: u32 = 0o140000;
pub const W_OK: u32 = 2;
pub const X_OK: u32 = 1;

const DEV_NULL_INODE_ID: InodeId = 1 << 61;
const DEV_ZERO_INODE_ID: InodeId = DEV_NULL_INODE_ID + 1;
const DEV_URANDOM_INODE_ID: InodeId = DEV_NULL_INODE_ID + 2;
const FIRST_USER_FD: Fd = 3;
const FIRST_PIPE_INODE_ID: InodeId = 1 << 62;
const PROC_INODE_ID: InodeId = 1 << 60;
const PROC_SELF_INODE_ID: InodeId = PROC_INODE_ID + 1;
const PROC_SELF_EXE_INODE_ID: InodeId = PROC_INODE_ID + 2;
const PROC_SELF_CMDLINE_INODE_ID: InodeId = PROC_INODE_ID + 3;
const PROC_SELF_ENVIRON_INODE_ID: InodeId = PROC_INODE_ID + 4;
const PROC_SELF_FD_INODE_ID: InodeId = PROC_INODE_ID + 5;
const FIRST_PROC_SELF_FD_LINK_INODE_ID: InodeId = PROC_INODE_ID + 1024;
const DEFAULT_PIPE_CAPACITY: usize = 65_536;
const MIN_PIPE_CAPACITY: usize = 4096;
const ROOT_INODE_ID: InodeId = 1;
const FIRST_SOCKET_INODE_ID: InodeId = 1 << 59;
const FIRST_EPOLL_INODE_ID: InodeId = (1 << 59) + (1 << 58);
const FIRST_EVENTFD_INODE_ID: InodeId = (1 << 59) + (1 << 57);
const SETFL_MUTABLE_FLAGS: u32 = O_APPEND | O_NONBLOCK;
const SYMLINK_LIMIT: usize = 40;
const SMALL_READ_CACHE_LIMIT: usize = 4096;
const HOST_READ_HANDLE_CACHE_LIMIT: usize = 32;
mod cache;
mod error;
mod fd;
mod filesystem;
mod io_helpers;
mod node;
mod path;

#[cfg(test)]
mod tests;

pub use cache::RegularFileCacheKey;
pub use error::{VfsError, VfsResult};
pub use fd::{
    ClosedFdIds, FdEntry, FdReadiness, FdTable, FileKind, FileRef, IoctlReply, OpenFlags,
    SeekWhence, StdioKind,
};
pub use filesystem::VirtualFileSystem;
pub use node::{
    DevNode, DevNodeKind, EpollNode, EventfdNode, HostPathRef, Inode, InodeBackend, PipeNode,
    ProcNode, SocketNode,
};
pub use path::{
    DirectoryChild, DirectoryEntry, FileTimes, GuestPath, LinuxFileAttr, LinuxFsKind, LinuxStatfs,
    MetadataSidecar, PathNode, PathNodeKind, PathTree, ProcNodeKind, ProcSelfData, ResolveOptions,
    ResolvedPath, Rootfs,
};

pub(crate) use cache::VfsCache;
#[cfg(test)]
pub(crate) use cache::VfsCacheSnapshot;
pub(crate) use fd::eventfd_node;
pub(crate) use io_helpers::*;
pub(crate) use node::PipeState;
#[cfg(test)]
pub(crate) use path::parse_absolute_path;
