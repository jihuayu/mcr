use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use mcr_vfs::{FdTable, PathTree, Rootfs, VfsError, VirtualFileSystem};

use super::RunRootfsError;

pub(super) fn load_rootfs(rootfs: &Path) -> Result<VirtualFileSystem, RunRootfsError> {
    const LARGE_FILE_TRACE_BYTES: u64 = 16 * 1024 * 1024;

    let mut tree = PathTree::new();
    let mut entries = Vec::new();
    let collect_start = Instant::now();
    crate::host_step_trace(format_args!(
        "load-rootfs collect start rootfs={}",
        rootfs.display()
    ));
    collect_rootfs_entries(rootfs, rootfs, &mut entries)?;
    entries.sort_by_key(|entry| (entry.depth, entry.relative.clone()));
    crate::host_step_trace(format_args!(
        "load-rootfs collect done entries={} elapsed_ms={}",
        entries.len(),
        crate::host_step_elapsed_ms(collect_start)
    ));

    let mut directories = 0usize;
    let mut symlinks = 0usize;
    let mut files = 0usize;
    let mut bytes = 0u64;
    let materialize_start = Instant::now();
    for entry in entries {
        let guest_path = format!("/{}", entry.relative.to_string_lossy().replace('\\', "/"));
        if entry.kind.is_dir() {
            directories += 1;
            tree.create_dir(&guest_path)?;
        } else if entry.kind.is_symlink() {
            symlinks += 1;
            let host_path = rootfs.join(&entry.relative);
            let target = fs::read_link(&host_path).map_err(|source| RunRootfsError::Io {
                path: host_path,
                source,
            })?;
            tree.create_symlink(&guest_path, target.to_string_lossy().into_owned())?;
        } else if entry.kind.is_file() {
            files += 1;
            let host_path = rootfs.join(&entry.relative);
            if entry.len >= LARGE_FILE_TRACE_BYTES {
                crate::host_step_trace(format_args!(
                    "load-rootfs large-file-deferred path={} bytes={}",
                    guest_path, entry.len
                ));
            }
            bytes = bytes.saturating_add(entry.len);
            tree.create_file_with_host_content(&guest_path, host_path, entry.len, 0o755)?;
            if crate::host_step_trace_enabled() && files % 256 == 0 {
                crate::host_step_trace(format_args!(
                    "load-rootfs register-progress files={} dirs={} symlinks={} deferred_bytes={} elapsed_ms={}",
                    files,
                    directories,
                    symlinks,
                    bytes,
                    crate::host_step_elapsed_ms(materialize_start)
                ));
            }
        }
    }
    crate::host_step_trace(format_args!(
        "load-rootfs registered files={} dirs={} symlinks={} deferred_bytes={} elapsed_ms={}",
        files,
        directories,
        symlinks,
        bytes,
        crate::host_step_elapsed_ms(materialize_start)
    ));

    tree.mount_minimal_devfs()?;
    tree.mount_minimal_procfs()?;
    materialize_minimal_dns_config(&mut tree)?;

    Ok(VirtualFileSystem::from_parts(
        Rootfs::new(rootfs),
        tree,
        FdTable::with_stdio(),
    ))
}

#[derive(Debug)]
struct RootfsEntry {
    relative: PathBuf,
    depth: usize,
    kind: fs::FileType,
    len: u64,
}

fn collect_rootfs_entries(
    rootfs: &Path,
    current: &Path,
    entries: &mut Vec<RootfsEntry>,
) -> Result<(), RunRootfsError> {
    for item in fs::read_dir(current).map_err(|source| RunRootfsError::Io {
        path: current.to_path_buf(),
        source,
    })? {
        let item = item.map_err(|source| RunRootfsError::Io {
            path: current.to_path_buf(),
            source,
        })?;
        let path = item.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| RunRootfsError::Io {
            path: path.clone(),
            source,
        })?;
        let relative = path
            .strip_prefix(rootfs)
            .expect("walked path is under rootfs")
            .to_path_buf();
        let depth = relative.components().count();
        let kind = metadata.file_type();
        entries.push(RootfsEntry {
            relative: relative.clone(),
            depth,
            kind,
            len: metadata.len(),
        });
        if kind.is_dir() {
            collect_rootfs_entries(rootfs, &path, entries)?;
        }
    }
    Ok(())
}

fn materialize_minimal_dns_config(tree: &mut PathTree) -> Result<(), RunRootfsError> {
    create_dir_if_missing(tree, "/etc")?;
    create_file_if_missing(
        tree,
        "/etc/hosts",
        b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n",
        0o644,
    )?;
    create_file_if_missing(tree, "/etc/resolv.conf", b"nameserver 1.1.1.1\n", 0o644)?;
    create_file_if_missing(
        tree,
        "/etc/nsswitch.conf",
        b"hosts: files dns\npasswd: files\ngroup: files\n",
        0o644,
    )?;
    Ok(())
}

fn create_dir_if_missing(tree: &mut PathTree, path: &str) -> Result<(), RunRootfsError> {
    match tree.create_dir(path) {
        Ok(_) | Err(VfsError::AlreadyExists) => Ok(()),
        Err(error) => Err(RunRootfsError::Vfs(error)),
    }
}

fn create_file_if_missing(
    tree: &mut PathTree,
    path: &str,
    content: &'static [u8],
    mode: u32,
) -> Result<(), RunRootfsError> {
    match tree.create_file_with_content(path, content, mode) {
        Ok(_) | Err(VfsError::AlreadyExists) => Ok(()),
        Err(error) => Err(RunRootfsError::Vfs(error)),
    }
}
