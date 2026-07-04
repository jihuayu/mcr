use std::path::Path;

use crate::error::{HostError, HostOperation, HostResult};
use crate::overlapped_io::{
    HostIoCompletion, HostIoDirection, HostIoFailure, HostIoFallback, HostIoFallbackReason,
    HostIoSubmission,
};
#[cfg(windows)]
use crate::overlapped_io::{PendingHostIo, WindowsOverlapped, WindowsPendingHostIo};

/// Host file access requested from the file adapter.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FileAccess {
    Read,
    Write,
    ReadWrite,
}

/// Host file creation behavior.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FileCreation {
    OpenExisting,
    CreateNew,
    CreateAlways,
    OpenAlways,
    TruncateExisting,
}

/// Host sharing flags for a Windows file handle.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FileShare {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

impl FileShare {
    /// Allows read, write, and delete sharing.
    pub const fn all() -> Self {
        Self {
            read: true,
            write: true,
            delete: true,
        }
    }

    /// Allows only read sharing.
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            delete: false,
        }
    }

    /// Disables all sharing.
    pub const fn none() -> Self {
        Self {
            read: false,
            write: false,
            delete: false,
        }
    }
}

/// Options for opening a host file.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FileOptions {
    pub access: FileAccess,
    pub creation: FileCreation,
    pub share: FileShare,
    pub overlapped_io: bool,
}

impl FileOptions {
    /// Creates open options.
    pub const fn new(access: FileAccess, creation: FileCreation) -> Self {
        Self {
            access,
            creation,
            share: FileShare::all(),
            overlapped_io: false,
        }
    }

    /// Sets host file sharing flags.
    pub const fn with_share(mut self, share: FileShare) -> Self {
        self.share = share;
        self
    }

    /// Opens the handle with Windows overlapped I/O support when available.
    pub const fn with_overlapped_io(mut self) -> Self {
        self.overlapped_io = true;
        self
    }
}

/// Rename behavior for the host file adapter.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RenameMode {
    FailIfExists,
    ReplaceExisting,
}

/// Owned host file handle.
#[derive(Debug)]
pub struct HostFile {
    #[cfg(windows)]
    handle: crate::windows::Handle,
    #[cfg(windows)]
    overlapped: bool,
    #[cfg(not(windows))]
    file: std::fs::File,
}

impl HostFile {
    /// Opens a host file.
    pub fn open(path: impl AsRef<Path>, options: FileOptions) -> HostResult<Self> {
        open_platform(path.as_ref(), options)
    }

    /// Reads bytes from the host file.
    pub fn read(&self, buf: &mut [u8]) -> HostResult<usize> {
        read_platform(self, buf)
    }

    /// Writes bytes to the host file.
    pub fn write(&self, buf: &[u8]) -> HostResult<usize> {
        write_platform(self, buf)
    }

    /// Submits a read through the future overlapped I/O boundary.
    ///
    /// The current backend keeps using synchronous host I/O and returns a
    /// fallback submission that owns the buffer until completion.
    pub fn submit_overlapped_read(&self, buffer: Vec<u8>) -> HostIoSubmission {
        HostIoSubmission::Fallback(HostIoFallback::new(
            HostIoDirection::Read,
            HostIoFallbackReason::SynchronousBackend,
            buffer,
        ))
    }

    /// Submits an offset-based read through the overlapped I/O boundary.
    pub fn submit_overlapped_read_at(&self, offset: u64, buffer: Vec<u8>) -> HostIoSubmission {
        submit_overlapped_at_platform(self, HostIoDirection::Read, offset, buffer)
    }

    /// Submits a write through the future overlapped I/O boundary.
    ///
    /// The current backend keeps using synchronous host I/O and returns a
    /// fallback submission that owns the buffer until completion.
    pub fn submit_overlapped_write(&self, buffer: Vec<u8>) -> HostIoSubmission {
        HostIoSubmission::Fallback(HostIoFallback::new(
            HostIoDirection::Write,
            HostIoFallbackReason::SynchronousBackend,
            buffer,
        ))
    }

    /// Submits an offset-based write through the overlapped I/O boundary.
    pub fn submit_overlapped_write_at(&self, offset: u64, buffer: Vec<u8>) -> HostIoSubmission {
        submit_overlapped_at_platform(self, HostIoDirection::Write, offset, buffer)
    }

    /// Flushes host file buffers.
    pub fn flush(&self) -> HostResult<()> {
        flush_platform(self)
    }
}

#[cfg(not(windows))]
fn submit_overlapped_at_platform(
    file: &HostFile,
    direction: HostIoDirection,
    offset: u64,
    mut buffer: Vec<u8>,
) -> HostIoSubmission {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut cloned = match file.file.try_clone() {
        Ok(cloned) => cloned,
        Err(error) => {
            return HostIoSubmission::Failed(HostIoFailure::new(
                direction,
                HostError::from_io(direction.operation(), error),
                buffer,
            ));
        }
    };
    if let Err(error) = cloned.seek(SeekFrom::Start(offset)) {
        return HostIoSubmission::Failed(HostIoFailure::new(
            direction,
            HostError::from_io(direction.operation(), error),
            buffer,
        ));
    }

    match direction {
        HostIoDirection::Read => match cloned.read(&mut buffer) {
            Ok(bytes_transferred) => HostIoSubmission::Completed(HostIoCompletion::new(
                direction,
                bytes_transferred,
                buffer,
            )),
            Err(error) => HostIoSubmission::Failed(HostIoFailure::new(
                direction,
                HostError::from_io(direction.operation(), error),
                buffer,
            )),
        },
        HostIoDirection::Write => match cloned.write(&buffer) {
            Ok(bytes_transferred) => HostIoSubmission::Completed(HostIoCompletion::new(
                direction,
                bytes_transferred,
                buffer,
            )),
            Err(error) => HostIoSubmission::Failed(HostIoFailure::new(
                direction,
                HostError::from_io(direction.operation(), error),
                buffer,
            )),
        },
    }
}

#[cfg(windows)]
impl Drop for HostFile {
    fn drop(&mut self) {
        crate::windows::close_handle(self.handle);
    }
}

/// Deletes a host file.
pub fn delete_file(path: impl AsRef<Path>) -> HostResult<()> {
    delete_file_platform(path.as_ref())
}

/// Renames or replaces a host file.
pub fn rename_file(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    mode: RenameMode,
) -> HostResult<()> {
    rename_file_platform(from.as_ref(), to.as_ref(), mode)
}

/// Replaces a host file with another host file.
pub fn replace_file(replaced: impl AsRef<Path>, replacement: impl AsRef<Path>) -> HostResult<()> {
    replace_file_platform(replaced.as_ref(), replacement.as_ref())
}

/// Creates a host hard link.
pub fn create_hard_link(link: impl AsRef<Path>, target: impl AsRef<Path>) -> HostResult<()> {
    create_hard_link_platform(link.as_ref(), target.as_ref())
}

/// Creates a host file symbolic link.
pub fn create_symlink_file(link: impl AsRef<Path>, target: impl AsRef<Path>) -> HostResult<()> {
    create_symlink_file_platform(link.as_ref(), target.as_ref())
}

#[cfg(not(windows))]
fn open_platform(path: &Path, options: FileOptions) -> HostResult<HostFile> {
    let mut open_options = std::fs::OpenOptions::new();
    match options.access {
        FileAccess::Read => {
            open_options.read(true);
        }
        FileAccess::Write => {
            open_options.write(true);
        }
        FileAccess::ReadWrite => {
            open_options.read(true).write(true);
        }
    }

    match options.creation {
        FileCreation::OpenExisting => {}
        FileCreation::CreateNew => {
            open_options.create_new(true);
        }
        FileCreation::CreateAlways => {
            open_options.create(true).truncate(true);
        }
        FileCreation::OpenAlways => {
            open_options.create(true);
        }
        FileCreation::TruncateExisting => {
            open_options.truncate(true);
        }
    }

    let file = open_options
        .open(path)
        .map_err(|error| HostError::from_io(HostOperation::OpenFile, error))?;
    Ok(HostFile { file })
}

#[cfg(not(windows))]
fn read_platform(file: &HostFile, buf: &mut [u8]) -> HostResult<usize> {
    use std::io::Read;

    let mut file = &file.file;
    file.read(buf)
        .map_err(|error| HostError::from_io(HostOperation::ReadFile, error))
}

#[cfg(not(windows))]
fn write_platform(file: &HostFile, buf: &[u8]) -> HostResult<usize> {
    use std::io::Write;

    let mut file = &file.file;
    file.write(buf)
        .map_err(|error| HostError::from_io(HostOperation::WriteFile, error))
}

#[cfg(not(windows))]
fn flush_platform(file: &HostFile) -> HostResult<()> {
    use std::io::Write;

    let mut file = &file.file;
    file.flush()
        .map_err(|error| HostError::from_io(HostOperation::FlushFile, error))
}

#[cfg(not(windows))]
fn delete_file_platform(path: &Path) -> HostResult<()> {
    std::fs::remove_file(path).map_err(|error| HostError::from_io(HostOperation::DeleteFile, error))
}

#[cfg(not(windows))]
fn rename_file_platform(from: &Path, to: &Path, mode: RenameMode) -> HostResult<()> {
    if mode == RenameMode::FailIfExists && to.exists() {
        return Err(HostError::new(
            HostOperation::RenameFile,
            crate::HostErrorKind::AlreadyExists,
        ));
    }

    std::fs::rename(from, to).map_err(|error| HostError::from_io(HostOperation::RenameFile, error))
}

#[cfg(not(windows))]
fn replace_file_platform(replaced: &Path, replacement: &Path) -> HostResult<()> {
    let _ = std::fs::remove_file(replaced);
    std::fs::rename(replacement, replaced)
        .map_err(|error| HostError::from_io(HostOperation::ReplaceFile, error))
}

#[cfg(not(windows))]
fn create_hard_link_platform(link: &Path, target: &Path) -> HostResult<()> {
    std::fs::hard_link(target, link)
        .map_err(|error| HostError::from_io(HostOperation::CreateHardLink, error))
}

#[cfg(all(not(windows), unix))]
fn create_symlink_file_platform(link: &Path, target: &Path) -> HostResult<()> {
    std::os::unix::fs::symlink(target, link)
        .map_err(|error| HostError::from_io(HostOperation::CreateSymlink, error))
}

#[cfg(all(not(windows), not(unix)))]
fn create_symlink_file_platform(_link: &Path, _target: &Path) -> HostResult<()> {
    Err(HostError::unsupported(HostOperation::CreateSymlink))
}

#[cfg(windows)]
fn open_platform(path: &Path, options: FileOptions) -> HostResult<HostFile> {
    let path = path_to_wide(path, HostOperation::OpenFile)?;
    // SAFETY: `path` is a null-terminated UTF-16 string and other pointers are intentionally null.
    let flags = if options.overlapped_io {
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            options.access.to_windows(),
            options.share.to_windows(),
            std::ptr::null_mut(),
            options.creation.to_windows(),
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == crate::windows::INVALID_HANDLE_VALUE {
        return Err(crate::error::last_windows_error(HostOperation::OpenFile));
    }
    Ok(HostFile {
        handle,
        overlapped: options.overlapped_io,
    })
}

#[cfg(windows)]
fn submit_overlapped_at_platform(
    file: &HostFile,
    direction: HostIoDirection,
    offset: u64,
    mut buffer: Vec<u8>,
) -> HostIoSubmission {
    if !file.overlapped {
        return HostIoSubmission::Fallback(HostIoFallback::new(
            direction,
            HostIoFallbackReason::SynchronousBackend,
            buffer,
        ));
    }

    let mut duplicate = std::ptr::null_mut();
    let current_process = unsafe {
        // SAFETY: `GetCurrentProcess` has no preconditions and returns a pseudo handle.
        GetCurrentProcess()
    };
    let duplicated = unsafe {
        // SAFETY: The source handle is owned by HostFile and `duplicate` is a valid out pointer.
        DuplicateHandle(
            current_process,
            file.handle,
            current_process,
            &mut duplicate,
            0,
            crate::windows::FALSE,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if duplicated == crate::windows::FALSE {
        return HostIoSubmission::Failed(HostIoFailure::new(
            direction,
            crate::error::last_windows_error(direction.operation()),
            buffer,
        ));
    }

    let event = unsafe {
        // SAFETY: Security attributes and name are intentionally null. The returned handle is owned.
        CreateEventW(
            std::ptr::null_mut(),
            TRUE,
            crate::windows::FALSE,
            std::ptr::null(),
        )
    };
    if event.is_null() {
        crate::windows::close_handle(duplicate);
        return HostIoSubmission::Failed(HostIoFailure::new(
            direction,
            crate::error::last_windows_error(direction.operation()),
            buffer,
        ));
    }

    let overlapped = WindowsOverlapped::new(offset, event);
    let mut pending_state = WindowsPendingHostIo::new(duplicate, overlapped);

    let len = buffer.len().min(u32::MAX as usize) as u32;
    let ok = unsafe {
        // SAFETY: The duplicated handle, buffer, and OVERLAPPED record live until completion.
        match direction {
            HostIoDirection::Read => ReadFile(
                pending_state.handle(),
                buffer.as_mut_ptr().cast(),
                len,
                std::ptr::null_mut(),
                pending_state.overlapped_mut_ptr(),
            ),
            HostIoDirection::Write => WriteFile(
                pending_state.handle(),
                buffer.as_ptr().cast(),
                len,
                std::ptr::null_mut(),
                pending_state.overlapped_mut_ptr(),
            ),
        }
    };

    if ok == crate::windows::FALSE {
        let error = crate::windows::last_error();
        if direction == HostIoDirection::Read && error == ERROR_HANDLE_EOF {
            return HostIoSubmission::Completed(HostIoCompletion::new(direction, 0, buffer));
        }
        if error != ERROR_IO_PENDING {
            return HostIoSubmission::Failed(HostIoFailure::new(
                direction,
                crate::error::windows_error(direction.operation(), error),
                buffer,
            ));
        }
    }

    let pending = PendingHostIo::from_windows_pending(direction, pending_state, buffer);
    if ok == crate::windows::FALSE {
        HostIoSubmission::Pending(pending)
    } else {
        pending.wait_complete().into()
    }
}

#[cfg(windows)]
fn read_platform(file: &HostFile, buf: &mut [u8]) -> HostResult<usize> {
    let read_len = buf.len().min(u32::MAX as usize) as u32;
    let mut bytes_read = 0;
    // SAFETY: The handle is owned by `HostFile`, and the output buffer is valid for `read_len`.
    let ok = unsafe {
        ReadFile(
            file.handle,
            buf.as_mut_ptr().cast(),
            read_len,
            &mut bytes_read,
            std::ptr::null_mut(),
        )
    };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(HostOperation::ReadFile));
    }
    Ok(bytes_read as usize)
}

#[cfg(windows)]
fn write_platform(file: &HostFile, buf: &[u8]) -> HostResult<usize> {
    let write_len = buf.len().min(u32::MAX as usize) as u32;
    let mut bytes_written = 0;
    // SAFETY: The handle is owned by `HostFile`, and the input buffer is valid for `write_len`.
    let ok = unsafe {
        WriteFile(
            file.handle,
            buf.as_ptr().cast(),
            write_len,
            &mut bytes_written,
            std::ptr::null_mut(),
        )
    };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(HostOperation::WriteFile));
    }
    Ok(bytes_written as usize)
}

#[cfg(windows)]
fn flush_platform(file: &HostFile) -> HostResult<()> {
    // SAFETY: The handle is owned by `HostFile`.
    let ok = unsafe { FlushFileBuffers(file.handle) };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(HostOperation::FlushFile));
    }
    Ok(())
}

#[cfg(windows)]
fn delete_file_platform(path: &Path) -> HostResult<()> {
    let path = path_to_wide(path, HostOperation::DeleteFile)?;
    // SAFETY: `path` is a null-terminated UTF-16 string.
    let ok = unsafe { DeleteFileW(path.as_ptr()) };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(HostOperation::DeleteFile));
    }
    Ok(())
}

#[cfg(windows)]
fn rename_file_platform(from: &Path, to: &Path, mode: RenameMode) -> HostResult<()> {
    let from = path_to_wide(from, HostOperation::RenameFile)?;
    let to = path_to_wide(to, HostOperation::RenameFile)?;
    let flags = match mode {
        RenameMode::FailIfExists => 0,
        RenameMode::ReplaceExisting => MOVEFILE_REPLACE_EXISTING,
    };

    // SAFETY: Both paths are null-terminated UTF-16 strings.
    let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(HostOperation::RenameFile));
    }
    Ok(())
}

#[cfg(windows)]
fn replace_file_platform(replaced: &Path, replacement: &Path) -> HostResult<()> {
    let replaced = path_to_wide(replaced, HostOperation::ReplaceFile)?;
    let replacement = path_to_wide(replacement, HostOperation::ReplaceFile)?;
    // SAFETY: Both paths are null-terminated UTF-16 strings; backup path and flags are unused.
    let ok = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(HostOperation::ReplaceFile));
    }
    Ok(())
}

#[cfg(windows)]
fn create_hard_link_platform(link: &Path, target: &Path) -> HostResult<()> {
    let link = path_to_wide(link, HostOperation::CreateHardLink)?;
    let target = path_to_wide(target, HostOperation::CreateHardLink)?;
    // SAFETY: Both paths are null-terminated UTF-16 strings and security attributes are unused.
    let ok = unsafe { CreateHardLinkW(link.as_ptr(), target.as_ptr(), std::ptr::null_mut()) };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(
            HostOperation::CreateHardLink,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn create_symlink_file_platform(link: &Path, target: &Path) -> HostResult<()> {
    let link = path_to_wide(link, HostOperation::CreateSymlink)?;
    let target = path_to_wide(target, HostOperation::CreateSymlink)?;
    // SAFETY: Both paths are null-terminated UTF-16 strings.
    let ok = unsafe {
        CreateSymbolicLinkW(
            link.as_ptr(),
            target.as_ptr(),
            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
        )
    };
    if ok == crate::windows::FALSE {
        return Err(crate::error::last_windows_error(
            HostOperation::CreateSymlink,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn path_to_wide(path: &Path, operation: HostOperation) -> HostResult<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(HostError::invalid_input(operation));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
impl FileAccess {
    const fn to_windows(self) -> u32 {
        match self {
            Self::Read => GENERIC_READ,
            Self::Write => GENERIC_WRITE,
            Self::ReadWrite => GENERIC_READ | GENERIC_WRITE,
        }
    }
}

#[cfg(windows)]
impl FileCreation {
    const fn to_windows(self) -> u32 {
        match self {
            Self::OpenExisting => OPEN_EXISTING,
            Self::CreateNew => CREATE_NEW,
            Self::CreateAlways => CREATE_ALWAYS,
            Self::OpenAlways => OPEN_ALWAYS,
            Self::TruncateExisting => TRUNCATE_EXISTING,
        }
    }
}

#[cfg(windows)]
impl FileShare {
    const fn to_windows(self) -> u32 {
        let mut flags = 0;
        if self.read {
            flags |= FILE_SHARE_READ;
        }
        if self.write {
            flags |= FILE_SHARE_WRITE;
        }
        if self.delete {
            flags |= FILE_SHARE_DELETE;
        }
        flags
    }
}

#[cfg(windows)]
const GENERIC_READ: u32 = 0x8000_0000;
#[cfg(windows)]
const GENERIC_WRITE: u32 = 0x4000_0000;
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(windows)]
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
#[cfg(windows)]
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
#[cfg(windows)]
const CREATE_NEW: u32 = 1;
#[cfg(windows)]
const CREATE_ALWAYS: u32 = 2;
#[cfg(windows)]
const OPEN_EXISTING: u32 = 3;
#[cfg(windows)]
const OPEN_ALWAYS: u32 = 4;
#[cfg(windows)]
const TRUNCATE_EXISTING: u32 = 5;
#[cfg(windows)]
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
#[cfg(windows)]
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
#[cfg(windows)]
const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
#[cfg(windows)]
const SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE: u32 = 0x2;
#[cfg(windows)]
const ERROR_IO_PENDING: u32 = 997;
#[cfg(windows)]
const ERROR_HANDLE_EOF: u32 = 38;
#[cfg(windows)]
const TRUE: crate::windows::Bool = 1;
#[cfg(windows)]
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *mut std::ffi::c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: crate::windows::Handle,
    ) -> crate::windows::Handle;
    fn ReadFile(
        file: crate::windows::Handle,
        buffer: *mut std::ffi::c_void,
        number_of_bytes_to_read: u32,
        number_of_bytes_read: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;
    fn WriteFile(
        file: crate::windows::Handle,
        buffer: *const std::ffi::c_void,
        number_of_bytes_to_write: u32,
        number_of_bytes_written: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;
    fn CreateEventW(
        event_attributes: *mut std::ffi::c_void,
        manual_reset: crate::windows::Bool,
        initial_state: crate::windows::Bool,
        name: *const u16,
    ) -> crate::windows::Handle;
    fn GetCurrentProcess() -> crate::windows::Handle;
    fn DuplicateHandle(
        source_process_handle: crate::windows::Handle,
        source_handle: crate::windows::Handle,
        target_process_handle: crate::windows::Handle,
        target_handle: *mut crate::windows::Handle,
        desired_access: u32,
        inherit_handle: crate::windows::Bool,
        options: u32,
    ) -> crate::windows::Bool;
    fn FlushFileBuffers(file: crate::windows::Handle) -> crate::windows::Bool;
    fn DeleteFileW(file_name: *const u16) -> crate::windows::Bool;
    fn MoveFileExW(
        existing_file_name: *const u16,
        new_file_name: *const u16,
        flags: u32,
    ) -> crate::windows::Bool;
    fn ReplaceFileW(
        replaced_file_name: *const u16,
        replacement_file_name: *const u16,
        backup_file_name: *const u16,
        replace_flags: u32,
        exclude: *mut std::ffi::c_void,
        reserved: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;
    fn CreateHardLinkW(
        file_name: *const u16,
        existing_file_name: *const u16,
        security_attributes: *mut std::ffi::c_void,
    ) -> crate::windows::Bool;
    fn CreateSymbolicLinkW(
        symlink_file_name: *const u16,
        target_file_name: *const u16,
        flags: u32,
    ) -> crate::windows::Bool;
}

#[cfg(test)]
mod tests {
    use super::{FileAccess, FileCreation, FileOptions, HostFile};
    use crate::HostIoSubmission;

    #[test]
    fn host_file_round_trips_bytes() {
        let path = std::env::temp_dir().join(format!("mcr-win-file-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let file = HostFile::open(
            &path,
            FileOptions::new(FileAccess::ReadWrite, FileCreation::CreateNew),
        )
        .unwrap();
        file.write(b"abc").unwrap();
        file.flush().unwrap();
        drop(file);

        let file = HostFile::open(
            &path,
            FileOptions::new(FileAccess::Read, FileCreation::OpenExisting),
        )
        .unwrap();
        let mut buf = [0; 3];
        file.read(&mut buf).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(&buf, b"abc");
    }

    #[cfg(windows)]
    #[test]
    fn host_file_overlapped_read_write_at_uses_real_completion_source() {
        let path = std::env::temp_dir().join(format!(
            "mcr-win-overlapped-file-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let file = HostFile::open(
            &path,
            FileOptions::new(FileAccess::ReadWrite, FileCreation::CreateNew).with_overlapped_io(),
        )
        .unwrap();

        let write = complete_real_overlapped(
            &file,
            file.submit_overlapped_write_at(0, b"abcdef".to_vec()),
        );
        assert_eq!(write.bytes_transferred(), 6);
        assert_eq!(write.buffer(), b"abcdef");
        file.flush().unwrap();

        let read = complete_real_overlapped(&file, file.submit_overlapped_read_at(1, vec![0; 3]));
        assert_eq!(read.bytes_transferred(), 3);
        assert_eq!(read.buffer(), b"bcd");

        let eof = complete_real_overlapped(&file, file.submit_overlapped_read_at(64, vec![0; 3]));
        assert_eq!(eof.bytes_transferred(), 0);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(windows)]
    fn complete_real_overlapped(
        file: &HostFile,
        submission: HostIoSubmission,
    ) -> crate::HostIoCompletion {
        match submission {
            HostIoSubmission::Fallback(fallback) => {
                panic!("expected real overlapped completion, got fallback {fallback:?}")
            }
            other => other.complete_or_fallback(file).unwrap(),
        }
    }
}
