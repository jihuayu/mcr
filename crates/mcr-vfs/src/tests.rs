use super::*;

#[test]
fn package_name_is_stable() {
    assert_eq!(CRATE_NAME, "mcr-vfs");
}

#[test]
fn canonicalizes_dot_and_dot_dot_without_escaping_rootfs() {
    let rootfs = Rootfs::with_guest_root("/host/root", guest_path("/jail"));
    let mut tree = PathTree::new();
    tree.create_dir("/jail").unwrap();
    tree.create_dir("/jail/usr").unwrap();
    tree.create_dir("/jail/usr/local").unwrap();
    tree.create_dir("/jail/usr/bin").unwrap();

    let resolved = rootfs.resolve_path("/usr/./local/../bin", &tree).unwrap();

    assert_eq!(resolved.guest_path().to_string(), "/jail/usr/bin");
    assert_eq!(
        resolved.inode(),
        Some(
            tree.lookup_path(&guest_path("/jail/usr/bin"))
                .unwrap()
                .inode_id()
        )
    );
}

#[test]
fn root_escape_via_dot_dot_is_clamped_to_jail_root() {
    let mut rootfs = Rootfs::with_guest_root("/host/root", guest_path("/containers/rootfs"));
    let mut tree = PathTree::new();
    tree.create_dir("/containers").unwrap();
    tree.create_dir("/containers/rootfs").unwrap();
    tree.create_dir("/containers/rootfs/tmp").unwrap();
    rootfs
        .set_cwd(guest_path("/containers/rootfs/tmp"))
        .unwrap();

    let resolved = rootfs.resolve_path("../../../../etc", &tree).unwrap();

    assert_eq!(resolved.guest_path().to_string(), "/containers/rootfs/etc");
    assert_eq!(resolved.inode(), None);
}

#[test]
fn symlink_loop_placeholder_returns_eloop_shape() {
    let rootfs = Rootfs::new("/host/root");
    let mut tree = PathTree::new();
    tree.create_symlink("/loop-a", "/loop-b").unwrap();
    tree.create_symlink("/loop-b", "/loop-a").unwrap();

    let error = rootfs.resolve_path("/loop-a", &tree).unwrap_err();

    assert_eq!(error, VfsError::Loop);
}

#[test]
fn absolute_symlink_target_cannot_escape_guest_root() {
    let rootfs = Rootfs::with_guest_root("/host/root", guest_path("/jail"));
    let mut tree = PathTree::new();
    tree.create_dir("/jail").unwrap();
    tree.create_symlink("/jail/out", "/../../host-secret")
        .unwrap();

    let resolved = rootfs.resolve_path("/out", &tree).unwrap();

    assert_eq!(resolved.guest_path().to_string(), "/jail/host-secret");
    assert_eq!(resolved.inode(), None);
}

#[test]
fn host_paths_are_not_guest_inode_ids() {
    let host_path = PathBuf::from("/tmp/mcr-rootfs/bin/sh");
    let host_path_len = host_path.as_os_str().len() as u64;
    let inode = Inode::new(42, InodeBackend::HostPath(HostPathRef::new(host_path)));

    assert_eq!(inode.id(), 42);
    assert_ne!(inode.id(), host_path_len);
}

#[test]
fn fd_table_initializes_stdio_descriptors() {
    let table = FdTable::with_stdio();

    assert_eq!(
        table.get(0).unwrap().file().kind(),
        FileKind::Stdio(StdioKind::Stdin)
    );
    assert_eq!(
        table.get(1).unwrap().file().kind(),
        FileKind::Stdio(StdioKind::Stdout)
    );
    assert_eq!(
        table.get(2).unwrap().file().kind(),
        FileKind::Stdio(StdioKind::Stderr)
    );
    assert!(!table.cloexec(0).unwrap());
    assert!(!table.cloexec(1).unwrap());
    assert!(!table.cloexec(2).unwrap());
}

#[test]
fn stdio_writes_are_captured_and_can_be_taken() {
    let mut vfs = sample_vfs();

    assert_eq!(vfs.write(1, b"hello ").unwrap(), 6);
    assert_eq!(vfs.write(1, b"stdout").unwrap(), 6);
    assert_eq!(vfs.write(2, b"warn").unwrap(), 4);

    assert_eq!(vfs.stdout_snapshot(), b"hello stdout");
    assert_eq!(vfs.stderr_snapshot(), b"warn");
    assert_eq!(vfs.fds().stdout_snapshot(), b"hello stdout");
    assert_eq!(vfs.fds().stderr_snapshot(), b"warn");
    assert_eq!(vfs.take_stdout(), b"hello stdout");
    assert_eq!(vfs.take_stderr(), b"warn");
    assert_eq!(vfs.stdout_snapshot(), b"");
    assert_eq!(vfs.stderr_snapshot(), b"");
}

#[test]
fn stdio_stdin_stays_empty_and_not_writable() {
    let mut vfs = sample_vfs();
    let mut buffer = [0xaa; 8];

    assert_eq!(vfs.read(0, &mut buffer).unwrap(), 0);
    assert_eq!(buffer, [0xaa; 8]);
    assert_eq!(vfs.write(0, b"input").unwrap_err(), VfsError::BadFd);
    assert_eq!(vfs.stdout_snapshot(), b"");
    assert_eq!(vfs.stderr_snapshot(), b"");
}

#[test]
fn stdio_capture_survives_dup_and_fd_table_clone() {
    let mut vfs = sample_vfs();
    let stdout_dup = vfs.dup(1).unwrap();
    let stderr_dup = vfs.dup2(2, 9).unwrap();

    assert_eq!(vfs.write(stdout_dup, b"dup").unwrap(), 3);
    assert_eq!(vfs.write(stderr_dup, b"err").unwrap(), 3);

    let mut cloned_table = vfs.fds().clone();
    let mut tree = vfs.tree().clone();
    assert_eq!(cloned_table.write(&mut tree, 1, b"-clone").unwrap(), 6);
    assert_eq!(cloned_table.write(&mut tree, 2, b"-clone").unwrap(), 6);

    assert_eq!(vfs.stdout_snapshot(), b"dup-clone");
    assert_eq!(vfs.stderr_snapshot(), b"err-clone");
    assert_eq!(cloned_table.take_stdout(), b"dup-clone");
    assert_eq!(cloned_table.take_stderr(), b"err-clone");
    assert_eq!(vfs.stdout_snapshot(), b"");
    assert_eq!(vfs.stderr_snapshot(), b"");
}

#[test]
fn fd_allocation_reuses_lowest_closed_descriptor() {
    let mut table = FdTable::with_stdio();
    let first = table.insert(regular_file(10), false).unwrap();
    let second = table.insert(regular_file(11), false).unwrap();
    table.close(first).unwrap();

    let reused = table.insert(regular_file(12), false).unwrap();

    assert_eq!(first, 3);
    assert_eq!(second, 4);
    assert_eq!(reused, first);
}

#[test]
fn fd_lookup_and_close_report_bad_fd() {
    let mut table = FdTable::with_stdio();

    assert_eq!(table.get(99).unwrap_err(), VfsError::BadFd);
    assert_eq!(table.close(99).unwrap_err(), VfsError::BadFd);
    assert_eq!(
        table.insert_exact(-1, regular_file(1), false).unwrap_err(),
        VfsError::BadFd
    );
}

#[test]
fn eventfd_reads_writes_and_reports_readiness() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .eventfd(0, OpenFlags::new(O_CLOEXEC | O_NONBLOCK))
        .unwrap();
    assert!(vfs.fds().cloexec(fd).unwrap());
    assert_eq!(
        vfs.fds().get(fd).unwrap().flags().raw(),
        O_RDWR | O_NONBLOCK
    );

    let ready = vfs.poll_readiness(fd).unwrap();
    assert!(!ready.readable);
    assert!(ready.writable);

    let mut read_buffer = [0; 8];
    assert_eq!(
        vfs.read(fd, &mut read_buffer).unwrap_err(),
        VfsError::WouldBlock
    );
    assert_eq!(vfs.write(fd, &7u64.to_le_bytes()).unwrap(), 8);
    let ready = vfs.poll_readiness(fd).unwrap();
    assert!(ready.readable);
    assert!(ready.writable);
    assert_eq!(vfs.read(fd, &mut read_buffer).unwrap(), 8);
    assert_eq!(u64::from_le_bytes(read_buffer), 7);
    assert!(!vfs.poll_readiness(fd).unwrap().readable);
}

#[test]
fn pread_reads_regular_file_without_changing_fd_offset() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    assert_eq!(vfs.lseek(fd, 2, SeekWhence::Set).unwrap(), 2);
    let mut buffer = [0; 3];

    let count = vfs.pread(fd, 1, &mut buffer).unwrap();

    assert_eq!(count, 3);
    assert_eq!(&buffer, b"ell");
    assert_eq!(vfs.fds().get(fd).unwrap().offset(), 2);
}

#[test]
fn cloexec_flags_are_tracked_and_closed_on_exec() {
    let mut table = FdTable::with_stdio();
    let keep = table.insert(regular_file(20), false).unwrap();
    let close = table.insert(regular_file(21), true).unwrap();

    assert!(!table.cloexec(keep).unwrap());
    assert!(table.cloexec(close).unwrap());

    table.set_cloexec(keep, true).unwrap();
    table.set_cloexec(close, false).unwrap();
    assert!(table.close_on_exec().is_empty());

    assert_eq!(table.get(keep).unwrap_err(), VfsError::BadFd);
    assert!(table.get(close).is_ok());
    assert!(table.get(0).is_ok());
}

#[test]
fn cloexec_pipe_fds_unregister_endpoints_on_exec() {
    let mut table = FdTable::with_stdio();
    let [read_fd, write_fd] = table.pipe(OpenFlags::new(O_CLOEXEC)).unwrap();

    assert!(table.close_on_exec().is_empty());

    assert_eq!(table.get(read_fd).unwrap_err(), VfsError::BadFd);
    assert_eq!(table.get(write_fd).unwrap_err(), VfsError::BadFd);
}

#[test]
fn fd_duplication_clones_open_file_state_and_tracks_descriptor_flags() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDWR | O_CLOEXEC), 0)
        .unwrap();
    assert_eq!(fd, 3);
    let dup = vfs.dup(fd).unwrap();
    let dup_min = vfs.fcntl(fd, F_DUPFD_CLOEXEC, 10).unwrap() as Fd;

    assert_eq!(dup, 4);
    assert_eq!(dup_min, 10);
    assert!(!vfs.fds().cloexec(dup).unwrap());
    assert!(vfs.fds().cloexec(dup_min).unwrap());

    assert_eq!(vfs.lseek(fd, 2, SeekWhence::Set).unwrap(), 2);
    assert_eq!(vfs.fds().get(dup).unwrap().offset(), 2);
    assert_eq!(vfs.fcntl(dup, F_GETFD, 0).unwrap(), 0);
    assert_eq!(
        vfs.fcntl(dup_min, F_GETFD, 0).unwrap(),
        u64::from(FD_CLOEXEC)
    );
    assert_eq!(vfs.fcntl(dup, F_SETFD, u64::from(FD_CLOEXEC)).unwrap(), 0);
    assert!(vfs.fds().cloexec(dup).unwrap());

    assert_eq!(
        vfs.fcntl(fd, F_SETFL, u64::from(O_APPEND | O_NONBLOCK))
            .unwrap(),
        0
    );
    assert_eq!(
        vfs.fcntl(dup, F_GETFL, 0).unwrap() as u32 & (O_APPEND | O_NONBLOCK),
        O_APPEND | O_NONBLOCK
    );
    assert_eq!(vfs.fcntl(fd, F_SETLK, 0x1234).unwrap(), 0);
    assert_eq!(vfs.fcntl(fd, F_SETLKW, 0x1234).unwrap(), 0);
    assert_eq!(vfs.fcntl(99, F_SETLK, 0x1234).unwrap_err(), VfsError::BadFd);

    assert_eq!(vfs.dup2(fd, 1).unwrap(), 1);
    assert_eq!(vfs.dup3(fd, 11, OpenFlags::new(O_CLOEXEC)).unwrap(), 11);
    assert!(vfs.fds().cloexec(11).unwrap());
    assert_eq!(
        vfs.dup3(fd, fd, OpenFlags::new(O_CLOEXEC)).unwrap_err(),
        VfsError::InvalidPath
    );
}

#[test]
fn pipes_move_bytes_and_report_nonblocking_and_capacity_state() {
    let mut vfs = sample_vfs();
    let [read_fd, write_fd] = vfs.pipe(OpenFlags::new(O_CLOEXEC | O_NONBLOCK)).unwrap();
    let mut buffer = [0; 5];

    #[cfg(windows)]
    assert!(
        pipe_node(vfs.fds().get(read_fd).unwrap().file())
            .unwrap()
            .host_pair()
            .is_some()
    );
    assert!(vfs.fds().cloexec(read_fd).unwrap());
    assert!(vfs.fds().cloexec(write_fd).unwrap());
    assert_eq!(
        vfs.fds().get(read_fd).unwrap().flags().raw(),
        O_RDONLY | O_NONBLOCK
    );
    assert_eq!(
        vfs.fds().get(write_fd).unwrap().flags().raw(),
        O_WRONLY | O_NONBLOCK
    );
    assert_eq!(
        vfs.read(read_fd, &mut buffer).unwrap_err(),
        VfsError::WouldBlock
    );

    assert_eq!(vfs.write(write_fd, b"hello").unwrap(), 5);
    assert_eq!(vfs.ioctl(read_fd, FIONREAD).unwrap(), IoctlReply::U32(5));
    assert_eq!(vfs.read(read_fd, &mut buffer).unwrap(), 5);
    assert_eq!(&buffer, b"hello");
    assert_eq!(
        vfs.fcntl(read_fd, F_GETPIPE_SZ, 0).unwrap(),
        DEFAULT_PIPE_CAPACITY as u64
    );
    assert_eq!(vfs.fcntl(read_fd, F_SETPIPE_SZ, 1024).unwrap(), 4096);

    vfs.close(read_fd).unwrap();
    assert_eq!(vfs.write(write_fd, b"!").unwrap_err(), VfsError::BrokenPipe);
}

#[test]
fn socket_fds_share_guest_fd_namespace_and_metadata() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .insert_socket(42, OpenFlags::new(O_RDWR | O_CLOEXEC | O_NONBLOCK))
        .unwrap();
    let mut buffer = [0; 8];

    assert_eq!(fd, 3);
    let entry = vfs.fds().get(fd).unwrap();
    assert_eq!(entry.file().kind(), FileKind::Socket);
    assert_eq!(entry.flags().raw(), O_RDWR | O_NONBLOCK);
    assert!(vfs.fds().cloexec(fd).unwrap());
    let InodeBackend::Socket(socket) = entry.file().inode().backend() else {
        panic!("socket fd should reference a socket inode");
    };
    assert_eq!(socket.id(), 42);
    assert_eq!(vfs.socket_id_for_fd(fd).unwrap(), 42);

    let stat = vfs.fstat(fd).unwrap();
    assert!(stat.is_socket());
    assert_eq!(stat.kind_bits(), S_IFSOCK);
    assert_eq!(stat.mode & 0o777, 0o666);
    assert_eq!(stat.inode, socket_inode_id(42).unwrap());
    assert_eq!(vfs.ioctl(fd, FIONREAD).unwrap(), IoctlReply::U32(0));
    assert_eq!(
        vfs.lseek(fd, 0, SeekWhence::Set).unwrap_err(),
        VfsError::NotSeekable
    );
    assert_eq!(vfs.read(fd, &mut buffer).unwrap_err(), VfsError::BadFd);
    assert_eq!(vfs.write(fd, b"ignored").unwrap_err(), VfsError::BadFd);

    assert_eq!(vfs.fcntl(fd, F_GETFD, 0).unwrap(), u64::from(FD_CLOEXEC));
    assert_eq!(
        vfs.fcntl(fd, F_GETFL, 0).unwrap() as u32,
        O_RDWR | O_NONBLOCK
    );
    assert_eq!(vfs.fcntl(fd, F_SETFL, 0).unwrap(), 0);
    assert_eq!(vfs.fcntl(fd, F_GETFL, 0).unwrap() as u32, O_RDWR);

    let dup = vfs.dup(fd).unwrap();
    let dup3 = vfs.dup3(fd, 10, OpenFlags::new(O_CLOEXEC)).unwrap();
    assert_eq!(dup, 4);
    assert_eq!(dup3, 10);
    assert!(!vfs.fds().cloexec(dup).unwrap());
    assert!(vfs.fds().cloexec(dup3).unwrap());
    assert!(vfs.fstat(dup).unwrap().is_socket());
    assert_eq!(vfs.socket_id_for_fd(dup).unwrap(), 42);
    assert_eq!(vfs.socket_id_for_fd(dup3).unwrap(), 42);
    vfs.close(fd).unwrap();
    assert_eq!(vfs.fstat(fd).unwrap_err(), VfsError::BadFd);
    assert_eq!(vfs.socket_id_for_fd(fd).unwrap_err(), VfsError::BadFd);
    assert!(vfs.fstat(dup).unwrap().is_socket());
}

#[test]
fn socket_id_lookup_rejects_non_socket_descriptors() {
    let mut vfs = sample_vfs();
    let regular = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDONLY), 0)
        .unwrap();

    assert_eq!(
        vfs.socket_id_for_fd(regular).unwrap_err(),
        VfsError::NotSocket
    );
    assert_eq!(vfs.socket_id_for_fd(99).unwrap_err(), VfsError::BadFd);
}

#[test]
fn epoll_fds_have_anonymous_metadata_and_cloexec() {
    let mut vfs = sample_vfs();
    vfs.mount_minimal_procfs().unwrap();
    let fd = vfs.insert_epoll(7, OpenFlags::new(O_CLOEXEC)).unwrap();
    let mut buffer = [0; 64];

    assert_eq!(fd, 3);
    assert_eq!(vfs.epoll_id_for_fd(fd).unwrap(), 7);
    assert_eq!(vfs.socket_id_for_fd(fd).unwrap_err(), VfsError::NotSocket);
    assert!(vfs.fds().cloexec(fd).unwrap());
    assert_eq!(vfs.fcntl(fd, F_GETFD, 0).unwrap(), u64::from(FD_CLOEXEC));

    let stat = vfs.fstat(fd).unwrap();
    assert!(stat.is_regular());
    assert_eq!(stat.mode & 0o777, 0o600);
    assert_eq!(stat.inode, epoll_inode_id(7).unwrap());
    assert_eq!(
        vfs.lseek(fd, 0, SeekWhence::Set).unwrap_err(),
        VfsError::NotSeekable
    );
    assert_eq!(vfs.read(fd, &mut buffer).unwrap_err(), VfsError::BadFd);
    assert_eq!(vfs.write(fd, b"ignored").unwrap_err(), VfsError::BadFd);

    let count = vfs.readlink("/proc/self/fd/3", &mut buffer).unwrap();
    assert_eq!(
        std::str::from_utf8(&buffer[..count]).unwrap(),
        format!("anon_inode:[eventpoll:{}]", epoll_inode_id(7).unwrap())
    );

    vfs.close(fd).unwrap();
    assert_eq!(vfs.epoll_id_for_fd(fd).unwrap_err(), VfsError::BadFd);
}

#[test]
fn ioctl_subset_reports_terminal_errors_without_tty_completeness() {
    let vfs = sample_vfs();

    assert_eq!(vfs.ioctl(1, TIOCGWINSZ).unwrap_err(), VfsError::NotTerminal);
    assert_eq!(vfs.ioctl(1, TCGETS).unwrap_err(), VfsError::NotTerminal);
    assert_eq!(vfs.ioctl(99, FIONREAD).unwrap_err(), VfsError::BadFd);
}

#[test]
fn minimal_devfs_nodes_have_linux_device_behaviors() {
    let mut vfs = VirtualFileSystem::new("/host/root");
    let null_fd = vfs
        .openat(AT_FDCWD, "/dev/null", OpenFlags::new(O_RDWR), 0)
        .unwrap();
    let zero_fd = vfs
        .openat(AT_FDCWD, "/dev/zero", OpenFlags::new(O_RDWR), 0)
        .unwrap();
    let urandom_fd = vfs
        .openat(AT_FDCWD, "/dev/urandom", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    let mut buffer = [0xaa; 16];

    assert_eq!(vfs.read(null_fd, &mut buffer).unwrap(), 0);
    assert_eq!(buffer, [0xaa; 16]);
    assert_eq!(vfs.write(null_fd, b"discarded").unwrap(), 9);
    assert_eq!(
        vfs.lseek(null_fd, 0, SeekWhence::Set).unwrap_err(),
        VfsError::NotSeekable
    );
    assert!(vfs.fstat(null_fd).unwrap().is_character_device());

    assert_eq!(vfs.read(zero_fd, &mut buffer).unwrap(), buffer.len());
    assert_eq!(buffer, [0; 16]);
    assert_eq!(vfs.write(zero_fd, b"ignored").unwrap(), 7);

    buffer.fill(0);
    assert_eq!(vfs.read(urandom_fd, &mut buffer).unwrap(), buffer.len());
    assert_ne!(buffer, [0; 16]);
    assert!(vfs.fstat(urandom_fd).unwrap().is_character_device());
}

#[test]
fn minimal_devfs_directory_lists_character_devices() {
    let mut vfs = VirtualFileSystem::new("/host/root");
    let dev_fd = vfs
        .openat(AT_FDCWD, "/dev", OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)
        .unwrap();
    let entries = vfs.getdents64(dev_fd, 4096).unwrap();
    let entries = entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry.file_type))
        .collect::<Vec<_>>();

    assert_eq!(
        entries,
        vec![
            (".", DT_DIR),
            ("..", DT_DIR),
            ("null", DT_CHR),
            ("urandom", DT_CHR),
            ("zero", DT_CHR),
        ]
    );
}

#[test]
fn minimal_procfs_nodes_have_linux_metadata_shapes() {
    let mut vfs = sample_vfs();
    vfs.mount_minimal_procfs().unwrap();

    let proc_stat = vfs.newfstatat(AT_FDCWD, "/proc", 0).unwrap();
    let self_stat = vfs.newfstatat(AT_FDCWD, "/proc/self", 0).unwrap();
    let fd_stat = vfs.newfstatat(AT_FDCWD, "/proc/self/fd", 0).unwrap();
    let exe_stat = vfs
        .newfstatat(AT_FDCWD, "/proc/self/exe", AT_SYMLINK_NOFOLLOW)
        .unwrap();
    let cmdline_stat = vfs.newfstatat(AT_FDCWD, "/proc/self/cmdline", 0).unwrap();
    let environ_stat = vfs.newfstatat(AT_FDCWD, "/proc/self/environ", 0).unwrap();

    assert!(proc_stat.is_directory());
    assert_eq!(proc_stat.mode & 0o777, 0o555);
    assert!(self_stat.is_directory());
    assert!(fd_stat.is_directory());
    assert!(exe_stat.is_symlink());
    assert_eq!(exe_stat.mode & 0o777, 0o777);
    assert!(cmdline_stat.is_regular());
    assert_eq!(cmdline_stat.mode & 0o777, 0o444);
    assert!(environ_stat.is_regular());
    assert_eq!(environ_stat.mode & 0o777, 0o400);
    assert!(vfs.access("/proc/self/cmdline", R_OK).is_ok());
    assert_eq!(
        vfs.access("/proc/self/environ", W_OK).unwrap_err(),
        VfsError::PermissionDenied
    );
}

#[test]
fn mount_minimal_procfs_takes_over_existing_rootfs_directories() {
    let mut vfs = sample_vfs();
    vfs.tree_mut().create_dir("/proc").unwrap();
    vfs.tree_mut().create_dir("/proc/self").unwrap();
    vfs.tree_mut().create_dir("/proc/self/fd").unwrap();

    vfs.mount_minimal_procfs().unwrap();
    vfs.mount_minimal_procfs().unwrap();

    let proc_stat = vfs.newfstatat(AT_FDCWD, "/proc", 0).unwrap();
    let self_stat = vfs.newfstatat(AT_FDCWD, "/proc/self", 0).unwrap();
    let fd_stat = vfs.newfstatat(AT_FDCWD, "/proc/self/fd", 0).unwrap();
    assert_eq!(proc_stat.inode, PROC_INODE_ID);
    assert_eq!(self_stat.inode, PROC_SELF_INODE_ID);
    assert_eq!(fd_stat.inode, PROC_SELF_FD_INODE_ID);
    assert_eq!(proc_stat.mode & 0o777, 0o555);

    let proc_fd = vfs
        .openat(AT_FDCWD, "/proc", OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)
        .unwrap();
    let proc_entries = vfs.getdents64(proc_fd, 4096).unwrap();
    let proc_entries = proc_entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry.file_type))
        .collect::<Vec<_>>();
    assert_eq!(
        proc_entries,
        vec![(".", DT_DIR), ("..", DT_DIR), ("self", DT_DIR)]
    );
}

#[test]
fn mount_minimal_procfs_rejects_existing_non_directory_proc_path() {
    let mut vfs = sample_vfs();
    vfs.tree_mut()
        .create_file_with_content("/proc", b"not a directory", 0o644)
        .unwrap();

    assert_eq!(
        vfs.mount_minimal_procfs().unwrap_err(),
        VfsError::AlreadyExists
    );
}

#[test]
fn minimal_procfs_directories_list_proc_entry_types() {
    let mut vfs = sample_vfs();
    vfs.mount_minimal_procfs().unwrap();

    let proc_fd = vfs
        .openat(AT_FDCWD, "/proc", OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)
        .unwrap();
    let proc_entries = vfs.getdents64(proc_fd, 4096).unwrap();
    let proc_entries = proc_entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry.file_type))
        .collect::<Vec<_>>();
    assert_eq!(
        proc_entries,
        vec![(".", DT_DIR), ("..", DT_DIR), ("self", DT_DIR)]
    );

    let self_fd = vfs
        .openat(
            AT_FDCWD,
            "/proc/self",
            OpenFlags::new(O_RDONLY | O_DIRECTORY),
            0,
        )
        .unwrap();
    let self_entries = vfs.getdents64(self_fd, 4096).unwrap();
    let self_entries = self_entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry.file_type))
        .collect::<Vec<_>>();
    assert_eq!(
        self_entries,
        vec![
            (".", DT_DIR),
            ("..", DT_DIR),
            ("cmdline", DT_REG),
            ("environ", DT_REG),
            ("exe", DT_LNK),
            ("fd", DT_DIR),
        ]
    );
}

#[test]
fn proc_self_reads_process_backed_cmdline_environ_and_exe() {
    let mut vfs = sample_vfs();
    vfs.mount_minimal_procfs().unwrap();
    vfs.set_proc_self(ProcSelfData::new(
        b"/bin/app".to_vec(),
        [b"/bin/app".to_vec(), b"--flag".to_vec()],
        [b"PATH=/bin".to_vec(), b"LANG=C".to_vec()],
    ));

    let cmdline = vfs
        .openat(AT_FDCWD, "/proc/self/cmdline", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    let mut cmdline_bytes = [0; 64];
    let cmdline_count = vfs.read(cmdline, &mut cmdline_bytes).unwrap();
    assert_eq!(&cmdline_bytes[..cmdline_count], b"/bin/app\0--flag\0");
    assert_eq!(vfs.read(cmdline, &mut cmdline_bytes).unwrap(), 0);

    let environ = vfs
        .openat(AT_FDCWD, "/proc/self/environ", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    let mut environ_bytes = [0; 64];
    let environ_count = vfs.read(environ, &mut environ_bytes).unwrap();
    assert_eq!(&environ_bytes[..environ_count], b"PATH=/bin\0LANG=C\0");

    let mut target = [0; 64];
    let target_count = vfs.readlink("/proc/self/exe", &mut target).unwrap();
    assert_eq!(&target[..target_count], b"/bin/app");
}

#[test]
fn proc_self_fd_directory_exposes_current_fd_links() {
    let mut vfs = sample_vfs();
    vfs.mount_minimal_devfs().unwrap();
    vfs.mount_minimal_procfs().unwrap();
    let file_fd = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    let dev_fd = vfs
        .openat(AT_FDCWD, "/dev/null", OpenFlags::new(O_RDWR), 0)
        .unwrap();
    let [pipe_read, pipe_write] = vfs.pipe(OpenFlags::new(0)).unwrap();

    let proc_fd = vfs
        .openat(
            AT_FDCWD,
            "/proc/self/fd",
            OpenFlags::new(O_RDONLY | O_DIRECTORY),
            0,
        )
        .unwrap();
    let entries = vfs.getdents64(proc_fd, 4096).unwrap();
    let names = entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry.file_type))
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            (".", DT_DIR),
            ("..", DT_DIR),
            ("0", DT_LNK),
            ("1", DT_LNK),
            ("2", DT_LNK),
            ("3", DT_LNK),
            ("4", DT_LNK),
            ("5", DT_LNK),
            ("6", DT_LNK),
            ("7", DT_LNK),
        ]
    );
    assert!(pipe_write > pipe_read);

    let mut target = [0; 64];
    let file_target = format!("/proc/self/fd/{file_fd}");
    let count = vfs.readlink(&file_target, &mut target).unwrap();
    assert_eq!(&target[..count], b"/tmp/file");

    let dev_target = format!("/proc/self/fd/{dev_fd}");
    let count = vfs.readlink(&dev_target, &mut target).unwrap();
    assert_eq!(&target[..count], b"/dev/null");

    let pipe_target = format!("/proc/self/fd/{pipe_read}");
    let count = vfs.readlink(&pipe_target, &mut target).unwrap();
    assert!(String::from_utf8_lossy(&target[..count]).starts_with("pipe:["));
    assert!(
        vfs.newfstatat(AT_FDCWD, &pipe_target, AT_SYMLINK_NOFOLLOW)
            .unwrap()
            .is_symlink()
    );

    vfs.close(file_fd).unwrap();
    assert_eq!(
        vfs.readlink(&file_target, &mut target).unwrap_err(),
        VfsError::NoEntry
    );
}

#[test]
fn vfs_open_read_write_lseek_and_close_follow_linux_fd_errors() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDWR), 0)
        .unwrap();
    let mut buffer = [0; 5];

    assert_eq!(vfs.read(fd, &mut buffer).unwrap(), 5);
    assert_eq!(&buffer, b"hello");
    assert_eq!(vfs.lseek(fd, -2, SeekWhence::Cur).unwrap(), 3);
    assert_eq!(vfs.write(fd, b"p!").unwrap(), 2);
    assert_eq!(vfs.lseek(fd, 0, SeekWhence::Set).unwrap(), 0);

    let mut all = [0; 5];
    assert_eq!(vfs.read(fd, &mut all).unwrap(), 5);
    assert_eq!(&all, b"help!");
    vfs.close(fd).unwrap();
    assert_eq!(vfs.read(fd, &mut all).unwrap_err(), VfsError::BadFd);
}

#[test]
fn vfs_openat_creates_truncates_and_checks_directory_flags() {
    let mut vfs = sample_vfs();
    let created = vfs
        .openat(
            AT_FDCWD,
            "/tmp/new",
            OpenFlags::new(O_CREAT | O_EXCL | O_WRONLY),
            0o600,
        )
        .unwrap();

    assert_eq!(vfs.write(created, b"new").unwrap(), 3);
    assert_eq!(
        vfs.openat(
            AT_FDCWD,
            "/tmp/new",
            OpenFlags::new(O_CREAT | O_EXCL | O_WRONLY),
            0o600,
        )
        .unwrap_err(),
        VfsError::AlreadyExists
    );

    let truncated = vfs
        .openat(AT_FDCWD, "/tmp/new", OpenFlags::new(O_WRONLY | O_TRUNC), 0)
        .unwrap();
    assert_eq!(vfs.fstat(truncated).unwrap().size, 0);
    assert_eq!(
        vfs.openat(AT_FDCWD, "/tmp/new", OpenFlags::new(O_DIRECTORY), 0)
            .unwrap_err(),
        VfsError::NotDirectory
    );
}

#[test]
fn vfs_openat_allows_created_readonly_file_to_use_requested_fd_access() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(
            AT_FDCWD,
            "/tmp/pack",
            OpenFlags::new(O_CREAT | O_EXCL | O_RDWR),
            0o444,
        )
        .unwrap();

    assert_eq!(vfs.write(fd, b"pack").unwrap(), 4);
    assert_eq!(
        vfs.newfstatat(AT_FDCWD, "/tmp/pack", 0).unwrap().mode & 0o777,
        0o444
    );
    vfs.close(fd).unwrap();

    assert_eq!(
        vfs.openat(AT_FDCWD, "/tmp/pack", OpenFlags::new(O_WRONLY), 0)
            .unwrap_err(),
        VfsError::PermissionDenied
    );
}

#[test]
fn vfs_sync_fd_validates_descriptor_without_persistence_side_effects() {
    let mut vfs = sample_vfs();
    let file = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    let dir = vfs
        .openat(AT_FDCWD, "/tmp", OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)
        .unwrap();
    let [pipe_read, _pipe_write] = vfs.pipe(OpenFlags::new(0)).unwrap();

    assert_eq!(vfs.sync_fd(file), Ok(()));
    assert_eq!(vfs.sync_fd(dir), Ok(()));
    assert_eq!(vfs.sync_fd(pipe_read).unwrap_err(), VfsError::InvalidPath);
    assert_eq!(vfs.sync_fd(99).unwrap_err(), VfsError::BadFd);
}

#[test]
fn vfs_reports_linux_errno_shapes_for_paths_fds_and_permissions() {
    let mut vfs = sample_vfs();
    vfs.tree_mut()
        .lookup_path_mut(&guest_path("/private"))
        .unwrap()
        .set_mode(0o600);

    assert_eq!(
        vfs.openat(AT_FDCWD, "/missing", OpenFlags::new(O_RDONLY), 0)
            .unwrap_err(),
        VfsError::NoEntry
    );
    assert_eq!(
        vfs.openat(99, "child", OpenFlags::new(O_RDONLY), 0)
            .unwrap_err(),
        VfsError::BadFd
    );
    let file_fd = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    assert_eq!(
        vfs.openat(file_fd, "child", OpenFlags::new(O_RDONLY), 0)
            .unwrap_err(),
        VfsError::NotDirectory
    );
    assert_eq!(
        vfs.access("/private/secret", R_OK).unwrap_err(),
        VfsError::PermissionDenied
    );
    vfs.tree_mut().create_dir("/readonly").unwrap();
    vfs.tree_mut()
        .lookup_path_mut(&guest_path("/readonly"))
        .unwrap()
        .set_mode(0o500);
    assert_eq!(
        vfs.openat(
            AT_FDCWD,
            "/readonly/created",
            OpenFlags::new(O_CREAT | O_WRONLY),
            0o600,
        )
        .unwrap_err(),
        VfsError::PermissionDenied
    );
    assert_eq!(
        vfs.newfstatat(AT_FDCWD, "/readonly/created", 0)
            .unwrap_err(),
        VfsError::NoEntry
    );
    assert_eq!(VfsError::PermissionDenied.linux_errno(), 13);
    assert_eq!(VfsError::NotDirectory.linux_errno(), 20);
    assert_eq!(VfsError::NoEntry.linux_errno(), 2);
    assert_eq!(VfsError::BadFd.linux_errno(), 9);
}

#[test]
fn stat_access_and_readlink_use_linux_metadata_shapes() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDONLY), 0)
        .unwrap();

    let stat = vfs.fstat(fd).unwrap();
    assert_eq!(stat.size, 5);
    assert_eq!(stat.kind_bits(), S_IFREG);
    assert!(vfs.access("/tmp/file", R_OK).is_ok());
    assert_eq!(
        vfs.access("/tmp/file", X_OK).unwrap_err(),
        VfsError::PermissionDenied
    );

    let link_stat = vfs
        .newfstatat(AT_FDCWD, "/link", AT_SYMLINK_NOFOLLOW)
        .unwrap();
    assert!(link_stat.is_symlink());
    assert_eq!(vfs.statx(AT_FDCWD, "/link", 0).unwrap().size, 5);

    let mut link = [0; 32];
    let count = vfs.readlink("/link", &mut link).unwrap();
    assert_eq!(&link[..count], b"/tmp/file");
}

#[test]
fn metadata_cache_tracks_generation_and_invalidates_on_metadata_update() {
    let mut vfs = sample_vfs();

    let original = vfs.newfstatat(AT_FDCWD, "/tmp/file", 0).unwrap();
    let cached = vfs.newfstatat(AT_FDCWD, "/tmp/file", 0).unwrap();
    let snapshot = vfs.cache_snapshot();

    assert_eq!(cached, original);
    assert_eq!(snapshot.metadata_entries, 1);

    vfs.chmod("/tmp/file", 0o600).unwrap();
    let updated = vfs.newfstatat(AT_FDCWD, "/tmp/file", 0).unwrap();
    let updated_snapshot = vfs.cache_snapshot();

    assert_eq!(updated.mode & 0o777, 0o600);
    assert!(updated.ctime_nsec > original.ctime_nsec);
    assert!(updated_snapshot.generation > snapshot.generation);
    assert_eq!(updated_snapshot.metadata_entries, 1);
}

#[test]
fn small_read_cache_invalidates_after_regular_file_write() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDWR), 0)
        .unwrap();
    let mut buffer = [0; 5];

    assert_eq!(vfs.read(fd, &mut buffer).unwrap(), 5);
    assert_eq!(&buffer, b"hello");
    let cached = vfs.cache_snapshot();
    assert_eq!(cached.small_read_entries, 1);

    vfs.lseek(fd, 0, SeekWhence::Set).unwrap();
    assert_eq!(vfs.write(fd, b"HELLO").unwrap(), 5);
    let invalidated = vfs.cache_snapshot();
    assert!(invalidated.generation > cached.generation);
    assert_eq!(invalidated.small_read_entries, 0);

    vfs.lseek(fd, 0, SeekWhence::Set).unwrap();
    assert_eq!(vfs.read(fd, &mut buffer).unwrap(), 5);
    assert_eq!(&buffer, b"HELLO");
    assert_eq!(vfs.cache_snapshot().small_read_entries, 1);
}

#[test]
fn regular_file_readv_writev_fast_path_moves_multiple_buffers_once() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDWR), 0)
        .unwrap();

    assert!(vfs.can_regular_writev_fast_path(fd).unwrap());
    let write_buffers = vec![b"ab".to_vec(), b"cd".to_vec(), Vec::new(), b"ef".to_vec()];
    assert_eq!(vfs.writev_regular(fd, &write_buffers).unwrap(), Some(6));
    assert_eq!(vfs.fds().get(fd).unwrap().offset(), 6);
    assert_eq!(vfs.cache_snapshot().small_read_entries, 0);

    vfs.lseek(fd, 0, SeekWhence::Set).unwrap();
    assert!(vfs.can_regular_readv_fast_path(fd).unwrap());
    let mut read_buffers = vec![vec![0; 1], vec![0; 3], vec![0; 2]];
    assert_eq!(vfs.readv_regular(fd, &mut read_buffers).unwrap(), Some(6));
    assert_eq!(
        read_buffers,
        vec![b"a".to_vec(), b"bcd".to_vec(), b"ef".to_vec()]
    );
    assert_eq!(vfs.fds().get(fd).unwrap().offset(), 6);
}

#[test]
fn deferred_host_file_reads_do_not_materialize_on_open_or_read() {
    let host_path =
        std::env::temp_dir().join(format!("mcr-vfs-deferred-host-read-{}", std::process::id()));
    fs::write(&host_path, b"abcdef").unwrap();

    let rootfs = Rootfs::new("/host/root");
    let mut tree = PathTree::new();
    tree.create_dir("/tmp").unwrap();
    tree.create_file_with_host_content("/tmp/deferred", &host_path, 6, 0o644)
        .unwrap();
    let mut vfs = VirtualFileSystem::from_parts(rootfs, tree, FdTable::with_stdio());
    let guest_path = guest_path("/tmp/deferred");

    let fd = vfs
        .openat(AT_FDCWD, "/tmp/deferred", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    assert!(
        vfs.tree()
            .lookup_path(&guest_path)
            .unwrap()
            .deferred_host_path()
            .is_some()
    );

    assert_eq!(vfs.lseek(fd, 2, SeekWhence::Set).unwrap(), 2);
    let mut buffer = [0; 3];
    assert_eq!(vfs.read(fd, &mut buffer).unwrap(), 3);
    assert_eq!(&buffer, b"cde");
    assert_eq!(vfs.lseek(fd, 64, SeekWhence::Set).unwrap(), 64);
    assert_eq!(vfs.read(fd, &mut buffer).unwrap(), 0);
    assert!(
        vfs.tree()
            .lookup_path(&guest_path)
            .unwrap()
            .deferred_host_path()
            .is_some()
    );

    let _ = fs::remove_file(host_path);
}

#[test]
fn deferred_host_file_can_expose_readonly_host_mapping_without_materializing() {
    let host_path =
        std::env::temp_dir().join(format!("mcr-vfs-deferred-host-map-{}", std::process::id()));
    fs::write(&host_path, b"abcdef").unwrap();

    let rootfs = Rootfs::new("/host/root");
    let mut tree = PathTree::new();
    tree.create_dir("/tmp").unwrap();
    tree.create_file_with_host_content("/tmp/deferred", &host_path, 6, 0o644)
        .unwrap();
    let mut vfs = VirtualFileSystem::from_parts(rootfs, tree, FdTable::with_stdio());
    let fd = vfs
        .openat(AT_FDCWD, "/tmp/deferred", OpenFlags::new(O_RDONLY), 0)
        .unwrap();
    let mapping = vfs.map_readonly_regular_file_at(fd, 1, 3).unwrap().unwrap();
    assert_eq!(mapping.as_slice(), b"bcd");
    assert!(
        vfs.tree()
            .lookup_path(&guest_path("/tmp/deferred"))
            .unwrap()
            .deferred_host_path()
            .is_some()
    );

    drop(mapping);
    let _ = fs::remove_file(host_path);
}

#[test]
fn deferred_host_file_reads_reuse_cached_host_handle_until_write() {
    let host_path = std::env::temp_dir().join(format!(
        "mcr-vfs-deferred-host-cache-{}",
        std::process::id()
    ));
    fs::write(&host_path, b"abcdef").unwrap();

    let rootfs = Rootfs::new("/host/root");
    let mut tree = PathTree::new();
    tree.create_dir("/tmp").unwrap();
    tree.create_file_with_host_content("/tmp/deferred", &host_path, 6, 0o644)
        .unwrap();
    let mut vfs = VirtualFileSystem::from_parts(rootfs, tree, FdTable::with_stdio());
    let read_fd = vfs
        .openat(AT_FDCWD, "/tmp/deferred", OpenFlags::new(O_RDONLY), 0)
        .unwrap();

    let mut buffer = [0; 2];
    assert_eq!(vfs.read(read_fd, &mut buffer).unwrap(), 2);
    assert_eq!(&buffer, b"ab");
    assert_eq!(vfs.cache_snapshot().host_read_handle_entries, 1);

    assert_eq!(vfs.pread(read_fd, 2, &mut buffer).unwrap(), 2);
    assert_eq!(&buffer, b"cd");
    assert_eq!(vfs.cache_snapshot().host_read_handle_entries, 1);

    let write_fd = vfs
        .openat(AT_FDCWD, "/tmp/deferred", OpenFlags::new(O_RDWR), 0)
        .unwrap();
    assert_eq!(vfs.write(write_fd, b"XY").unwrap(), 2);
    assert_eq!(vfs.cache_snapshot().host_read_handle_entries, 0);
    assert!(
        vfs.tree()
            .lookup_path(&guest_path("/tmp/deferred"))
            .unwrap()
            .deferred_host_path()
            .is_none()
    );

    let _ = fs::remove_file(host_path);
}

#[test]
fn getdents64_entries_match_linux_record_layout() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(AT_FDCWD, "/tmp", OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)
        .unwrap();
    let entries = vfs.getdents64(fd, 4096).unwrap();
    let names = entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(names, vec![".", "..", "file"]);
    let mut bytes = Vec::new();
    for entry in &entries {
        let before = bytes.len();
        entry.encode_linux_dirent64(&mut bytes).unwrap();
        assert_eq!(entry.record_len() % 8, 0);
        assert_eq!(
            usize::from(u16::from_le_bytes([bytes[before + 16], bytes[before + 17]])),
            entry.record_len()
        );
        assert_eq!(bytes[before + 18], entry.file_type);
        assert_eq!(bytes[before + 19 + entry.name.len()], 0);
    }
    assert_eq!(entries.last().unwrap().file_type, DT_REG);
    vfs.lseek(fd, 0, SeekWhence::Set).unwrap();
    assert_eq!(vfs.getdents64(fd, 1).unwrap_err(), VfsError::InvalidPath);
}

#[test]
fn directory_listing_cache_survives_unrelated_directory_mutation() {
    let mut vfs = sample_vfs();
    let tmp_fd = vfs
        .openat(AT_FDCWD, "/tmp", OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)
        .unwrap();
    let private_fd = vfs
        .openat(
            AT_FDCWD,
            "/private",
            OpenFlags::new(O_RDONLY | O_DIRECTORY),
            0,
        )
        .unwrap();

    assert_eq!(
        entry_names(&vfs.getdents64(tmp_fd, 4096).unwrap()),
        vec![".", "..", "file"]
    );
    assert_eq!(
        entry_names(&vfs.getdents64(private_fd, 4096).unwrap()),
        vec![".", "..", "secret"]
    );
    let cached = vfs.cache_snapshot();
    assert_eq!(cached.directory_listing_entries, 2);

    vfs.mkdirat(AT_FDCWD, "/private/new", 0o755).unwrap();
    let invalidated = vfs.cache_snapshot();
    assert!(invalidated.generation > cached.generation);
    assert_eq!(invalidated.directory_listing_entries, 1);

    vfs.lseek(tmp_fd, 0, SeekWhence::Set).unwrap();
    assert_eq!(
        entry_names(&vfs.getdents64(tmp_fd, 4096).unwrap()),
        vec![".", "..", "file"]
    );
    assert_eq!(vfs.cache_snapshot().directory_listing_entries, 1);
}

#[test]
fn directory_listing_cache_batches_getdents_and_invalidates_on_mutation() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(AT_FDCWD, "/tmp", OpenFlags::new(O_RDONLY | O_DIRECTORY), 0)
        .unwrap();

    let first = vfs.getdents64(fd, 24).unwrap();
    assert_eq!(entry_names(&first), vec!["."]);
    let cached = vfs.cache_snapshot();
    assert_eq!(cached.directory_listing_entries, 1);

    let second = vfs.getdents64(fd, 24).unwrap();
    assert_eq!(entry_names(&second), vec![".."]);
    assert_eq!(vfs.cache_snapshot().directory_listing_entries, 1);

    vfs.mkdirat(AT_FDCWD, "/tmp/new", 0o755).unwrap();
    let invalidated = vfs.cache_snapshot();
    assert!(invalidated.generation > cached.generation);
    assert_eq!(invalidated.directory_listing_entries, 0);

    vfs.lseek(fd, 0, SeekWhence::Set).unwrap();
    let entries = vfs.getdents64(fd, 4096).unwrap();
    assert_eq!(entry_names(&entries), vec![".", "..", "file", "new"]);
    assert_eq!(vfs.cache_snapshot().directory_listing_entries, 1);
}

#[test]
fn proc_self_fd_directory_listing_stays_uncached() {
    let mut vfs = sample_vfs();
    vfs.mount_minimal_procfs().unwrap();
    let fd = vfs
        .openat(
            AT_FDCWD,
            "/proc/self/fd",
            OpenFlags::new(O_RDONLY | O_DIRECTORY),
            0,
        )
        .unwrap();

    let entries = vfs.getdents64(fd, 4096).unwrap();

    let fd_name = fd.to_string();
    assert!(entry_names(&entries).contains(&fd_name.as_str()));
    assert_eq!(vfs.cache_snapshot().directory_listing_entries, 0);
}

#[test]
fn writable_mutations_cover_mkdir_links_rename_and_metadata() {
    let mut vfs = sample_vfs();

    vfs.mkdirat(AT_FDCWD, "/tmp/pkg", 0o777).unwrap();
    assert_eq!(
        vfs.newfstatat(AT_FDCWD, "/tmp/pkg", 0).unwrap().mode & 0o777,
        0o755
    );
    assert_eq!(vfs.chdir("/tmp/pkg"), Ok(()));
    assert_eq!(vfs.getcwd().unwrap(), "/tmp/pkg");
    assert_eq!(vfs.umask(0o077), 0o022);

    vfs.symlinkat("../file", AT_FDCWD, "file-link").unwrap();
    let mut target = [0; 16];
    let count = vfs
        .readlinkat(AT_FDCWD, "/tmp/pkg/file-link", &mut target)
        .unwrap();
    assert_eq!(&target[..count], b"../file");

    vfs.linkat(AT_FDCWD, "/tmp/file", AT_FDCWD, "hard", 0)
        .unwrap();
    let original = vfs.newfstatat(AT_FDCWD, "/tmp/file", 0).unwrap();
    let linked = vfs.newfstatat(AT_FDCWD, "hard", 0).unwrap();
    assert_eq!(original.inode, linked.inode);
    assert_eq!(linked.nlink, 2);

    vfs.renameat2(AT_FDCWD, "hard", AT_FDCWD, "renamed", 0)
        .unwrap();
    assert_eq!(
        vfs.newfstatat(AT_FDCWD, "hard", 0).unwrap_err(),
        VfsError::NoEntry
    );
    assert_eq!(
        vfs.renameat2(AT_FDCWD, "renamed", AT_FDCWD, "/tmp/file", RENAME_NOREPLACE,)
            .unwrap_err(),
        VfsError::AlreadyExists
    );

    let before = vfs.newfstatat(AT_FDCWD, "renamed", 0).unwrap();
    let fd = vfs
        .openat(AT_FDCWD, "renamed", OpenFlags::new(O_RDWR), 0)
        .unwrap();
    vfs.ftruncate(fd, 9).unwrap();
    let after = vfs.fstat(fd).unwrap();
    assert_eq!(after.size, 9);
    assert!(after.ctime_nsec > before.ctime_nsec);
    assert!(after.mtime_nsec > before.mtime_nsec);
    vfs.fallocate(fd, 4, 12).unwrap();
    assert_eq!(vfs.fstat(fd).unwrap().size, 16);
    vfs.fallocate(fd, 1, 2).unwrap();
    assert_eq!(vfs.fstat(fd).unwrap().size, 16);
    vfs.close(fd).unwrap();

    vfs.utimensat(
        AT_FDCWD,
        "renamed",
        FileTimes {
            atime_sec: 10,
            atime_nsec: 20,
            mtime_sec: 30,
            mtime_nsec: 40,
        },
        0,
    )
    .unwrap();
    let touched = vfs.newfstatat(AT_FDCWD, "renamed", 0).unwrap();
    assert_eq!(touched.atime_sec, 10);
    assert_eq!(touched.atime_nsec, 20);
    assert_eq!(touched.mtime_sec, 30);
    assert_eq!(touched.mtime_nsec, 40);

    vfs.chmod("renamed", 0o600).unwrap();
    vfs.chown("renamed", Some(1000), Some(1001)).unwrap();
    let owned = vfs.newfstatat(AT_FDCWD, "renamed", 0).unwrap();
    assert_eq!(owned.mode & 0o777, 0o600);
    assert_eq!(owned.uid, 1000);
    assert_eq!(owned.gid, 1001);
}

#[test]
fn rename_over_existing_and_exchange_follow_linux_shapes() {
    let mut vfs = sample_vfs();
    vfs.mkdirat(AT_FDCWD, "/tmp/a", 0o755).unwrap();
    vfs.mkdirat(AT_FDCWD, "/tmp/b", 0o755).unwrap();
    vfs.openat(
        AT_FDCWD,
        "/tmp/a/file",
        OpenFlags::new(O_CREAT | O_WRONLY),
        0o644,
    )
    .unwrap();
    vfs.openat(
        AT_FDCWD,
        "/tmp/b/file",
        OpenFlags::new(O_CREAT | O_WRONLY),
        0o644,
    )
    .unwrap();

    vfs.renameat2(AT_FDCWD, "/tmp/a/file", AT_FDCWD, "/tmp/b/file", 0)
        .unwrap();
    assert_eq!(
        vfs.newfstatat(AT_FDCWD, "/tmp/a/file", 0).unwrap_err(),
        VfsError::NoEntry
    );
    assert!(vfs.newfstatat(AT_FDCWD, "/tmp/b/file", 0).is_ok());
    assert_eq!(
        vfs.renameat2(AT_FDCWD, "/tmp/a", AT_FDCWD, "/tmp/b", 0)
            .unwrap_err(),
        VfsError::NotEmpty
    );

    vfs.openat(
        AT_FDCWD,
        "/tmp/a/other",
        OpenFlags::new(O_CREAT | O_WRONLY),
        0o644,
    )
    .unwrap();
    vfs.renameat2(
        AT_FDCWD,
        "/tmp/a/other",
        AT_FDCWD,
        "/tmp/b/file",
        RENAME_EXCHANGE,
    )
    .unwrap();
    assert!(vfs.newfstatat(AT_FDCWD, "/tmp/a/other", 0).is_ok());
    assert!(vfs.newfstatat(AT_FDCWD, "/tmp/b/file", 0).is_ok());
}

#[test]
fn delayed_unlink_keeps_open_inode_until_close() {
    let mut vfs = sample_vfs();
    let fd = vfs
        .openat(AT_FDCWD, "/tmp/file", OpenFlags::new(O_RDWR), 0)
        .unwrap();
    vfs.unlinkat(AT_FDCWD, "/tmp/file", 0).unwrap();
    assert_eq!(
        vfs.newfstatat(AT_FDCWD, "/tmp/file", 0).unwrap_err(),
        VfsError::NoEntry
    );

    vfs.lseek(fd, 0, SeekWhence::Set).unwrap();
    let mut buffer = [0; 5];
    assert_eq!(vfs.read(fd, &mut buffer).unwrap(), 5);
    assert_eq!(&buffer, b"hello");
    assert_eq!(vfs.fstat(fd).unwrap().nlink, 0);

    let inode = vfs.fstat(fd).unwrap().inode;
    vfs.close(fd).unwrap();
    assert!(vfs.tree().lookup_inode(inode).is_none());
}

fn guest_path(path: &str) -> GuestPath {
    parse_absolute_path(path).unwrap()
}

fn regular_file(inode_id: InodeId) -> FileRef {
    FileRef::new(
        Arc::new(Inode::new(
            inode_id,
            InodeBackend::HostPath(HostPathRef::new(format!("/host/{inode_id}"))),
        )),
        FileKind::Regular,
    )
}

fn entry_names(entries: &[DirectoryEntry]) -> Vec<&str> {
    entries.iter().map(|entry| entry.name.as_str()).collect()
}

fn sample_vfs() -> VirtualFileSystem {
    let rootfs = Rootfs::new("/host/root");
    let mut tree = PathTree::new();
    tree.create_dir("/tmp").unwrap();
    tree.create_file_with_content("/tmp/file", b"hello", 0o644)
        .unwrap();
    tree.create_dir("/private").unwrap();
    tree.create_file_with_content("/private/secret", b"secret", 0o600)
        .unwrap();
    tree.create_symlink("/link", "/tmp/file").unwrap();
    VirtualFileSystem::from_parts(rootfs, tree, FdTable::with_stdio())
}
