use super::*;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn package_name_is_stable() {
    assert_eq!(CRATE_NAME, "mcr-snapshot");
}

#[test]
fn snapshot_model_preserves_identity_layers_and_upper_root() {
    let mut spec = SnapshotSpec::new(
        SnapshotId::new("build-step-2").unwrap(),
        WritableUpperRoot::new("target/mcr/upper").unwrap(),
    );
    spec.add_lower_layer(LayerRef::new(SnapshotId::new("base").unwrap()));
    spec.add_lower_layer(LayerRef::new(SnapshotId::new("build-step-1").unwrap()));

    assert_eq!(spec.id().as_str(), "build-step-2");
    assert_eq!(spec.upper_root().host_path(), Path::new("target/mcr/upper"));
    assert_eq!(
        spec.lower_layers()
            .iter()
            .map(|layer| layer.id().as_str())
            .collect::<Vec<_>>(),
        vec!["base", "build-step-1"]
    );
}

#[test]
fn deterministic_view_orders_sidecar_records_by_guest_path() {
    let mut spec = SnapshotSpec::new(
        SnapshotId::new("snapshot").unwrap(),
        WritableUpperRoot::new("upper").unwrap(),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/usr/bin/app").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Regular { size: 7 }, 0o755, 1000, 1000, 42),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/etc").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 1),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/lib/ld-musl-x86_64.so.1").unwrap(),
        LinuxMetadata::new(
            SnapshotFileKind::Symlink {
                target: "/lib/libc.musl-x86_64.so.1".to_owned(),
            },
            0o777,
            0,
            0,
            2,
        ),
    );

    let view = spec.deterministic_view();
    assert_eq!(
        view.entries()
            .iter()
            .map(|entry| entry.path().as_str())
            .collect::<Vec<_>>(),
        vec!["/etc", "/lib/ld-musl-x86_64.so.1", "/usr/bin/app"]
    );
    assert_eq!(
        view.get(&SnapshotPath::new("/usr/bin/app").unwrap())
            .unwrap()
            .metadata()
            .mode(),
        0o755
    );
}

#[test]
fn metadata_represents_linux_shapes_host_filesystems_may_not_store() {
    let hardlink_target = SnapshotPath::new("/usr/bin/tool").unwrap();
    let entries = [
        LinuxMetadata::new(
            SnapshotFileKind::Hardlink {
                target: hardlink_target.clone(),
            },
            0o755,
            0,
            0,
            10,
        ),
        LinuxMetadata::new(
            SnapshotFileKind::CharacterDevice { major: 1, minor: 3 },
            0o666,
            0,
            0,
            11,
        ),
        LinuxMetadata::new(SnapshotFileKind::Fifo, 0o644, 100, 200, 12),
    ];

    assert!(matches!(
        entries[0].kind(),
        SnapshotFileKind::Hardlink { target } if target == &hardlink_target
    ));
    assert!(matches!(
        entries[1].kind(),
        SnapshotFileKind::CharacterDevice { major: 1, minor: 3 }
    ));
    assert!(matches!(entries[2].kind(), SnapshotFileKind::Fifo));
}

#[test]
fn layer_plan_emits_deleted_lower_file_whiteouts() {
    let mut spec = SnapshotSpec::new(
        SnapshotId::new("delete-step").unwrap(),
        WritableUpperRoot::new("upper").unwrap(),
    );
    spec.delete_lower_path(SnapshotPath::new("/etc/removed.conf").unwrap())
        .unwrap();

    let plan = spec.deterministic_layer_plan().unwrap();
    assert_eq!(layer_paths(&plan), vec!["/etc/.wh.removed.conf"]);
    assert_eq!(
        plan.entries()[0].kind(),
        &LayerEntryKind::Whiteout {
            deleted_path: SnapshotPath::new("/etc/removed.conf").unwrap()
        }
    );
}

#[test]
fn layer_plan_emits_opaque_directory_markers() {
    let mut spec = SnapshotSpec::new(
        SnapshotId::new("opaque-step").unwrap(),
        WritableUpperRoot::new("upper").unwrap(),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/var/cache").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 5),
    );
    spec.mark_opaque_directory(SnapshotPath::new("/var/cache").unwrap());

    let plan = spec.deterministic_layer_plan().unwrap();
    assert_eq!(
        layer_paths(&plan),
        vec!["/var/cache", "/var/cache/.wh..wh..opq"]
    );
    assert_eq!(
        plan.entries()[1].kind(),
        &LayerEntryKind::OpaqueDirectory {
            directory_path: SnapshotPath::new("/var/cache").unwrap()
        }
    );
}

#[test]
fn layer_plan_preserves_symlink_and_hardlink_targets() {
    let mut spec = SnapshotSpec::new(
        SnapshotId::new("links-step").unwrap(),
        WritableUpperRoot::new("upper").unwrap(),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/lib/libc.so").unwrap(),
        LinuxMetadata::new(
            SnapshotFileKind::Symlink {
                target: "/lib/libc.musl-x86_64.so.1".to_owned(),
            },
            0o777,
            0,
            0,
            7,
        ),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/usr/bin/tool-copy").unwrap(),
        LinuxMetadata::new(
            SnapshotFileKind::Hardlink {
                target: SnapshotPath::new("/usr/bin/tool").unwrap(),
            },
            0o755,
            0,
            0,
            7,
        ),
    );

    let plan = spec.deterministic_layer_plan().unwrap();
    assert_eq!(
        plan.entries()[0].kind(),
        &LayerEntryKind::Filesystem {
            metadata: LinuxMetadata::new(
                SnapshotFileKind::Symlink {
                    target: "/lib/libc.musl-x86_64.so.1".to_owned(),
                },
                0o777,
                0,
                0,
                7,
            )
        }
    );
    assert_eq!(
        plan.entries()[1].kind(),
        &LayerEntryKind::Filesystem {
            metadata: LinuxMetadata::new(
                SnapshotFileKind::Hardlink {
                    target: SnapshotPath::new("/usr/bin/tool").unwrap(),
                },
                0o755,
                0,
                0,
                7,
            )
        }
    );
}

#[test]
fn layer_plan_models_rename_over_existing_as_final_entry_plus_source_whiteout() {
    let mut spec = SnapshotSpec::new(
        SnapshotId::new("rename-step").unwrap(),
        WritableUpperRoot::new("upper").unwrap(),
    );
    spec.delete_lower_path(SnapshotPath::new("/usr/bin/old-tool").unwrap())
        .unwrap();
    spec.upsert_sidecar(
        SnapshotPath::new("/usr/bin/tool").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Regular { size: 11 }, 0o755, 0, 0, 9),
    );

    let plan = spec.deterministic_layer_plan().unwrap();
    assert_eq!(
        layer_paths(&plan),
        vec!["/usr/bin/.wh.old-tool", "/usr/bin/tool"]
    );
    assert_eq!(
        plan.entries()[1].kind(),
        &LayerEntryKind::Filesystem {
            metadata: LinuxMetadata::new(SnapshotFileKind::Regular { size: 11 }, 0o755, 0, 0, 9)
        }
    );
}

#[test]
fn layer_plan_ordering_is_stable_across_insert_order() {
    let mut first = SnapshotSpec::new(
        SnapshotId::new("first").unwrap(),
        WritableUpperRoot::new("upper-a").unwrap(),
    );
    first.upsert_sidecar(
        SnapshotPath::new("/usr/bin/app").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Regular { size: 7 }, 0o755, 1000, 1000, 42),
    );
    first.upsert_sidecar(
        SnapshotPath::new("/etc/new.conf").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Regular { size: 2 }, 0o644, 0, 0, 3),
    );
    first
        .delete_lower_path(SnapshotPath::new("/etc/old.conf").unwrap())
        .unwrap();
    first.mark_opaque_directory(SnapshotPath::new("/var/cache").unwrap());

    let mut second = SnapshotSpec::new(
        SnapshotId::new("second").unwrap(),
        WritableUpperRoot::new("upper-b").unwrap(),
    );
    second.mark_opaque_directory(SnapshotPath::new("/var/cache").unwrap());
    second
        .delete_lower_path(SnapshotPath::new("/etc/old.conf").unwrap())
        .unwrap();
    second.upsert_sidecar(
        SnapshotPath::new("/etc/new.conf").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Regular { size: 2 }, 0o644, 0, 0, 3),
    );
    second.upsert_sidecar(
        SnapshotPath::new("/usr/bin/app").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Regular { size: 7 }, 0o755, 1000, 1000, 42),
    );

    let first_plan = first.deterministic_layer_plan().unwrap();
    let second_plan = second.deterministic_layer_plan().unwrap();
    assert_eq!(first_plan, second_plan);
    assert_eq!(
        layer_paths(&first_plan),
        vec![
            "/etc/.wh.old.conf",
            "/etc/new.conf",
            "/usr/bin/app",
            "/var/cache/.wh..wh..opq"
        ]
    );
}

#[test]
fn layer_plan_rejects_root_whiteouts_and_path_conflicts() {
    let mut root_delete = SnapshotSpec::new(
        SnapshotId::new("bad-delete").unwrap(),
        WritableUpperRoot::new("upper").unwrap(),
    );
    assert_eq!(
        root_delete.delete_lower_path(SnapshotPath::new("/").unwrap()),
        Err(SnapshotError::CannotWhiteoutRoot)
    );

    let mut conflict = SnapshotSpec::new(
        SnapshotId::new("conflict").unwrap(),
        WritableUpperRoot::new("upper").unwrap(),
    );
    conflict.upsert_sidecar(
        SnapshotPath::new("/etc/.wh.shadow").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Regular { size: 0 }, 0o644, 0, 0, 1),
    );
    conflict
        .delete_lower_path(SnapshotPath::new("/etc/shadow").unwrap())
        .unwrap();
    assert_eq!(
        conflict.deterministic_layer_plan(),
        Err(SnapshotError::ConflictingLayerEntry(
            SnapshotPath::new("/etc/.wh.shadow").unwrap()
        ))
    );
}

#[test]
fn invalid_identity_and_paths_are_rejected() {
    assert_eq!(SnapshotId::new(""), Err(SnapshotError::EmptySnapshotId));
    assert_eq!(
        SnapshotId::new("has space"),
        Err(SnapshotError::InvalidSnapshotId("has space".to_owned()))
    );
    assert_eq!(
        WritableUpperRoot::new(""),
        Err(SnapshotError::EmptyUpperRoot)
    );
    assert_eq!(
        SnapshotPath::new("relative"),
        Err(SnapshotError::RelativeSnapshotPath("relative".to_owned()))
    );
    assert_eq!(
        SnapshotPath::new("/a/../b"),
        Err(SnapshotError::InvalidSnapshotPath("/a/../b".to_owned()))
    );
    assert_eq!(
        SnapshotPath::new("/a//b"),
        Err(SnapshotError::InvalidSnapshotPath("/a//b".to_owned()))
    );
}

#[test]
fn layer_plan_exports_deterministic_uncompressed_tar() {
    let mut spec = SnapshotSpec::new(
        SnapshotId::new("tar-step").unwrap(),
        WritableUpperRoot::new("upper").unwrap(),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/etc").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 1_000_000_000),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/etc/config").unwrap(),
        LinuxMetadata::new(
            SnapshotFileKind::Regular { size: 9 },
            0o640,
            100,
            200,
            2_000_000_000,
        ),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/bin/sh").unwrap(),
        LinuxMetadata::new(
            SnapshotFileKind::Symlink {
                target: "../busybox".to_owned(),
            },
            0o777,
            0,
            0,
            3_000_000_000,
        ),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/bin/tool-copy").unwrap(),
        LinuxMetadata::new(
            SnapshotFileKind::Hardlink {
                target: SnapshotPath::new("/bin/tool").unwrap(),
            },
            0o755,
            0,
            0,
            4_000_000_000,
        ),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/var/cache").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 5_000_000_000),
    );
    spec.delete_lower_path(SnapshotPath::new("/etc/old").unwrap())
        .unwrap();
    spec.mark_opaque_directory(SnapshotPath::new("/var/cache").unwrap());

    let plan = spec.deterministic_layer_plan().unwrap();
    let mut content = BTreeMap::new();
    content.insert(
        SnapshotPath::new("/etc/config").unwrap(),
        b"name=mcr\n".to_vec(),
    );

    let first = plan.to_uncompressed_tar(&content).unwrap();
    let second = plan.to_uncompressed_tar(&content).unwrap();

    assert_eq!(first, second);
    assert_eq!(
        tar_entry_names(&first),
        vec![
            "bin/sh",
            "bin/tool-copy",
            "etc",
            "etc/.wh.old",
            "etc/config",
            "var/cache",
            "var/cache/.wh..wh..opq"
        ]
    );
    assert_eq!(
        tar_entry_payload(&first, "etc/config"),
        Some(b"name=mcr\n".as_slice())
    );

    let layer = BaseLayerSnapshot::from_uncompressed_tar(
        LayerRef::new(SnapshotId::new("exported").unwrap()),
        &first,
    )
    .unwrap();
    assert_eq!(
        layer
            .entries()
            .iter()
            .map(|entry| entry.path().as_str())
            .collect::<Vec<_>>(),
        vec![
            "/bin/sh",
            "/bin/tool-copy",
            "/etc",
            "/etc/.wh.old",
            "/etc/config",
            "/var/cache",
            "/var/cache/.wh..wh..opq"
        ]
    );
    assert_eq!(
        layer
            .get(&SnapshotPath::new("/etc/.wh.old").unwrap())
            .unwrap()
            .metadata()
            .kind(),
        &SnapshotFileKind::Regular { size: 0 }
    );
    assert_eq!(
        layer
            .get(&SnapshotPath::new("/bin/tool-copy").unwrap())
            .unwrap()
            .metadata()
            .kind(),
        &SnapshotFileKind::Hardlink {
            target: SnapshotPath::new("/bin/tool").unwrap()
        }
    );
}

#[test]
fn snapshot_spec_exports_upper_root_regular_content_to_layer_tar() {
    let upper = temp_root("upper-export");
    std::fs::create_dir_all(upper.join("etc")).unwrap();
    std::fs::write(upper.join("etc/config"), b"name=mcr\n").unwrap();

    let mut spec = SnapshotSpec::new(
        SnapshotId::new("upper-step").unwrap(),
        WritableUpperRoot::new(&upper).unwrap(),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/etc").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 0),
    );
    spec.upsert_sidecar(
        SnapshotPath::new("/etc/config").unwrap(),
        LinuxMetadata::new(SnapshotFileKind::Regular { size: 9 }, 0o640, 100, 200, 0),
    );
    spec.delete_lower_path(SnapshotPath::new("/etc/old").unwrap())
        .unwrap();

    let archive = spec.export_upper_layer_tar().unwrap();

    assert_eq!(
        tar_entry_names(&archive),
        vec!["etc", "etc/.wh.old", "etc/config"]
    );
    assert_eq!(
        tar_entry_payload(&archive, "etc/config"),
        Some(b"name=mcr\n".as_slice())
    );
    std::fs::remove_dir_all(upper).unwrap();
}

#[test]
fn layer_plan_export_rejects_missing_or_mismatched_regular_content() {
    let plan = SnapshotLayerPlan::from_parts(
        [SnapshotEntry::new(
            SnapshotPath::new("/payload").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Regular { size: 4 }, 0o644, 0, 0, 0),
        )],
        [],
        [],
    )
    .unwrap();

    assert_eq!(
        plan.to_uncompressed_tar(&BTreeMap::new()),
        Err(LayerExportError::MissingRegularContent(
            SnapshotPath::new("/payload").unwrap()
        ))
    );

    let mut content = BTreeMap::new();
    content.insert(SnapshotPath::new("/payload").unwrap(), b"too long".to_vec());
    assert_eq!(
        plan.to_uncompressed_tar(&content),
        Err(LayerExportError::RegularContentSizeMismatch {
            path: SnapshotPath::new("/payload").unwrap(),
            expected: 4,
            actual: 8,
        })
    );
}

#[test]
fn layer_plan_export_rejects_root_tar_entry() {
    let plan = SnapshotLayerPlan::from_parts(
        [SnapshotEntry::new(
            SnapshotPath::new("/").unwrap(),
            LinuxMetadata::new(SnapshotFileKind::Directory, 0o755, 0, 0, 0),
        )],
        [],
        [],
    )
    .unwrap();

    assert_eq!(
        plan.to_uncompressed_tar(&BTreeMap::new()),
        Err(LayerExportError::CannotExportRootEntry)
    );
}

fn layer_paths(plan: &SnapshotLayerPlan) -> Vec<&str> {
    plan.entries()
        .iter()
        .map(|entry| entry.path().as_str())
        .collect()
}

#[test]
fn base_layer_unpack_reads_uncompressed_tar_metadata() {
    let mut archive = Vec::new();
    append_tar_dir(&mut archive, "etc/", 0o755, 0, 0, 1);
    append_tar_file(&mut archive, "etc/hostname", b"mcr\n", 0o644, 100, 200, 2);
    append_tar_symlink(&mut archive, "bin/sh", "../busybox", 3);
    finish_tar(&mut archive);

    let layer = BaseLayerSnapshot::from_uncompressed_tar(
        LayerRef::new(SnapshotId::new("sha256-base").unwrap()),
        &archive,
    )
    .unwrap();

    assert_eq!(layer.layer().id().as_str(), "sha256-base");
    assert_eq!(
        layer
            .entries()
            .iter()
            .map(|entry| entry.path().as_str())
            .collect::<Vec<_>>(),
        vec!["/bin/sh", "/etc", "/etc/hostname"]
    );

    let hostname = layer
        .get(&SnapshotPath::new("/etc/hostname").unwrap())
        .unwrap();
    assert_eq!(
        hostname.metadata().kind(),
        &SnapshotFileKind::Regular { size: 4 }
    );
    assert_eq!(hostname.metadata().mode(), 0o644);
    assert_eq!(hostname.metadata().uid(), 100);
    assert_eq!(hostname.metadata().gid(), 200);
    assert_eq!(hostname.metadata().mtime_unix_nanos(), 2_000_000_000);

    let shell = layer.get(&SnapshotPath::new("/bin/sh").unwrap()).unwrap();
    assert_eq!(
        shell.metadata().kind(),
        &SnapshotFileKind::Symlink {
            target: "../busybox".to_owned()
        }
    );
}

#[test]
fn base_layer_unpack_rejects_paths_that_escape_guest_root() {
    let mut archive = Vec::new();
    append_tar_file(&mut archive, "../escape", b"x", 0o644, 0, 0, 1);
    finish_tar(&mut archive);

    assert!(matches!(
        BaseLayerSnapshot::from_uncompressed_tar(
            LayerRef::new(SnapshotId::new("bad").unwrap()),
            &archive,
        ),
        Err(LayerUnpackError::SnapshotPath(
            SnapshotError::InvalidSnapshotPath(_)
        ))
    ));
}

#[test]
fn base_layer_unpack_rejects_truncated_entry_data() {
    let mut archive = Vec::new();
    append_tar_file(&mut archive, "file", b"payload", 0o644, 0, 0, 1);
    archive.truncate(TAR_BLOCK_SIZE + 1);

    assert_eq!(
        BaseLayerSnapshot::from_uncompressed_tar(
            LayerRef::new(SnapshotId::new("truncated").unwrap()),
            &archive,
        ),
        Err(LayerUnpackError::TruncatedEntryData)
    );
}

fn append_tar_dir(archive: &mut Vec<u8>, name: &str, mode: u32, uid: u32, gid: u32, mtime: u64) {
    append_tar_entry(
        archive,
        name,
        b'5',
        &[],
        "",
        TarEntryMeta {
            mode,
            uid,
            gid,
            mtime,
        },
    );
}

fn append_tar_file(
    archive: &mut Vec<u8>,
    name: &str,
    data: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
) {
    append_tar_entry(
        archive,
        name,
        b'0',
        data,
        "",
        TarEntryMeta {
            mode,
            uid,
            gid,
            mtime,
        },
    );
}

fn append_tar_symlink(archive: &mut Vec<u8>, name: &str, target: &str, mtime: u64) {
    append_tar_entry(
        archive,
        name,
        b'2',
        &[],
        target,
        TarEntryMeta {
            mode: 0o777,
            uid: 0,
            gid: 0,
            mtime,
        },
    );
}

fn append_tar_entry(
    archive: &mut Vec<u8>,
    name: &str,
    entry_type: u8,
    data: &[u8],
    linkname: &str,
    meta: TarEntryMeta,
) {
    let mut header = [0u8; TAR_BLOCK_SIZE];
    write_tar_string(&mut header[0..100], name);
    write_tar_octal(&mut header[100..108], u64::from(meta.mode));
    write_tar_octal(&mut header[108..116], u64::from(meta.uid));
    write_tar_octal(&mut header[116..124], u64::from(meta.gid));
    write_tar_octal(&mut header[124..136], data.len() as u64);
    write_tar_octal(&mut header[136..148], meta.mtime);
    header[156] = entry_type;
    write_tar_string(&mut header[157..257], linkname);
    write_tar_string(&mut header[257..263], "ustar");
    write_tar_string(&mut header[263..265], "00");

    archive.extend_from_slice(&header);
    archive.extend_from_slice(data);
    let padding = (TAR_BLOCK_SIZE - (data.len() % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
    archive.extend(std::iter::repeat_n(0, padding));
}

#[derive(Clone, Copy)]
struct TarEntryMeta {
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
}

fn finish_tar(archive: &mut Vec<u8>) {
    archive.extend(std::iter::repeat_n(0, TAR_BLOCK_SIZE * 2));
}

fn write_tar_string(field: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    assert!(bytes.len() <= field.len());
    field[..bytes.len()].copy_from_slice(bytes);
}

fn write_tar_octal(field: &mut [u8], value: u64) {
    let encoded = format!("{value:0width$o}", width = field.len() - 1);
    field[..encoded.len()].copy_from_slice(encoded.as_bytes());
}

fn tar_entry_names(archive: &[u8]) -> Vec<String> {
    tar_entries(archive)
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

fn tar_entry_payload<'a>(archive: &'a [u8], name: &str) -> Option<&'a [u8]> {
    tar_entries(archive)
        .into_iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.payload)
}

fn tar_entries(archive: &[u8]) -> Vec<TarEntryView<'_>> {
    let mut offset = 0usize;
    let mut entries = Vec::new();
    while offset < archive.len() {
        let header_end = offset + TAR_BLOCK_SIZE;
        let header = &archive[offset..header_end];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let name = tar_string(&header[0..100], "name").unwrap();
        let prefix = tar_string(&header[345..500], "prefix").unwrap();
        let name = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let size = tar_octal(&header[124..136], "size").unwrap();
        let data_start = header_end;
        let data_len = usize::try_from(size).unwrap();
        let data_end = data_start + data_len;
        entries.push(TarEntryView {
            name,
            payload: &archive[data_start..data_end],
        });
        offset = data_start + padded_tar_len(size).unwrap();
    }
    entries
}

struct TarEntryView<'a> {
    name: String,
    payload: &'a [u8],
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mcr-snapshot-{label}-{}-{nanos}",
        std::process::id()
    ))
}
