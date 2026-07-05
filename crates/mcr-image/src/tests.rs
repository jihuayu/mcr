use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;

#[test]
fn package_name_is_stable() {
    assert_eq!(CRATE_NAME, "mcr-image");
}

#[test]
fn descriptor_parses_and_renders_sha256_digest() {
    let digest =
        OciDigest::parse("sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
    let mut descriptor = OciDescriptor::new(MEDIA_TYPE_OCI_CONFIG, digest, 12);
    descriptor.insert_annotation("org.opencontainers.image.title", "config");

    assert_eq!(descriptor.media_type(), MEDIA_TYPE_OCI_CONFIG);
    assert_eq!(descriptor.digest().algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(
        descriptor.digest().to_string(),
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(descriptor.size(), 12);
    assert_eq!(
        descriptor
            .annotations()
            .get("org.opencontainers.image.title"),
        Some(&"config".to_owned())
    );
}

#[test]
fn digest_validation_rejects_unsupported_or_malformed_values() {
    assert!(matches!(
        OciDigest::parse("sha512:0123"),
        Err(ImageError::UnsupportedDigestAlgorithm(_))
    ));
    assert!(matches!(
        OciDigest::parse("sha256:not-hex"),
        Err(ImageError::InvalidDigest(_))
    ));
    assert!(matches!(
        OciDigest::parse("missing-separator"),
        Err(ImageError::InvalidDigest(_))
    ));
}

#[test]
fn image_reference_normalizes_registry_repository_and_target() {
    let docker_hub = OciReference::parse("alpine:3.20").unwrap();
    assert_eq!(docker_hub.registry(), DEFAULT_REGISTRY);
    assert_eq!(docker_hub.repository(), "library/alpine");
    assert_eq!(docker_hub.tag(), Some("3.20"));
    assert_eq!(docker_hub.digest(), None);
    assert_eq!(
        docker_hub.to_string(),
        "registry-1.docker.io/library/alpine:3.20"
    );

    let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let pinned = OciReference::parse(&format!("localhost:5000/team/app@{digest}")).unwrap();
    assert_eq!(pinned.registry(), "localhost:5000");
    assert_eq!(pinned.repository(), "team/app");
    assert_eq!(pinned.tag(), None);
    assert_eq!(pinned.digest().unwrap().to_string(), digest);
    assert_eq!(
        pinned.to_string(),
        format!("localhost:5000/team/app@{digest}")
    );
}

#[test]
fn image_reference_rejects_invalid_repository_or_tag() {
    assert!(matches!(
        OciReference::parse("Team/App:latest"),
        Err(ImageError::InvalidRepository(_))
    ));
    assert!(matches!(
        OciReference::parse("team/app:bad tag"),
        Err(ImageError::InvalidReference(_))
    ));
    assert!(matches!(
        OciReference::parse("team/app:!"),
        Err(ImageError::InvalidTag(_))
    ));
}

#[test]
fn image_index_selects_linux_amd64_manifest() {
    let linux_amd64 = descriptor_for(MEDIA_TYPE_OCI_MANIFEST, b"amd64 manifest");
    let linux_arm64 = descriptor_for(MEDIA_TYPE_OCI_MANIFEST, b"arm64 manifest");
    let index = OciImageIndex::new(vec![
        OciIndexManifest::new(
            linux_arm64.clone(),
            OciPlatform::new("linux", "arm64", Option::<String>::None),
        ),
        OciIndexManifest::new(linux_amd64.clone(), OciPlatform::linux_amd64()),
    ]);

    assert_eq!(
        index.select_manifest(&OciPlatform::linux_amd64()).unwrap(),
        &linux_amd64
    );
}

#[test]
fn image_index_rejects_missing_linux_amd64_manifest() {
    let index = OciImageIndex::new(vec![OciIndexManifest::new(
        descriptor_for(MEDIA_TYPE_OCI_MANIFEST, b"arm64 manifest"),
        OciPlatform::new("linux", "arm64", Option::<String>::None),
    )]);

    assert!(matches!(
        index.select_manifest(&OciPlatform::linux_amd64()),
        Err(ImageError::NoCompatibleManifest { .. })
    ));
}

#[test]
fn image_config_serializes_deterministic_json() {
    let diff_ids = vec![
        OciDigest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap(),
        OciDigest::parse("sha256:2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap(),
    ];
    let config = OciContainerConfig::new()
        .with_env(["PATH=/usr/bin", "APP_ENV=prod"])
        .with_working_dir("/srv/app")
        .with_entrypoint(["/entrypoint"])
        .with_command(["serve", "--message=hello \"mcr\"\n"]);
    let image = OciImageConfig::new(
        OciPlatform::linux_amd64(),
        config,
        vec![
            OciHistoryEntry::new("FROM scratch").with_empty_layer(true),
            OciHistoryEntry::new("COPY app /srv/app").with_comment("build context"),
        ],
        diff_ids,
    );

    let first = image.to_json_bytes();
    let second = image.to_json_bytes();

    assert_eq!(first, second);
    assert_eq!(
        String::from_utf8(first).unwrap(),
        concat!(
            "{\"architecture\":\"amd64\",\"config\":{\"Cmd\":[\"serve\",",
            "\"--message=hello \\\"mcr\\\"\\n\"],\"Entrypoint\":[\"/entrypoint\"],",
            "\"Env\":[\"PATH=/usr/bin\",\"APP_ENV=prod\"],",
            "\"WorkingDir\":\"/srv/app\"},\"history\":[",
            "{\"created_by\":\"FROM scratch\",\"empty_layer\":true},",
            "{\"created_by\":\"COPY app /srv/app\",\"comment\":\"build context\"}],",
            "\"os\":\"linux\",\"rootfs\":{\"diff_ids\":[",
            "\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"",
            "],\"type\":\"layers\"}}"
        )
    );
}

#[test]
fn image_manifest_serializes_deterministic_descriptor_json() {
    let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
    let mut layer = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"layer-one");
    layer.insert_annotation("org.opencontainers.image.title", "layer");
    layer.insert_annotation("com.example.order", "first");
    let manifest = OciImageManifest::new(config.clone(), vec![layer.clone()]);

    let first = manifest.to_json_bytes();
    let second = manifest.to_json_bytes();

    assert_eq!(first, second);
    assert_eq!(
        String::from_utf8(first).unwrap(),
        format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"{}\",\"config\":{{\"mediaType\":\"{}\",\"digest\":\"{}\",\"size\":{}}},\"layers\":[{{\"mediaType\":\"{}\",\"digest\":\"{}\",\"size\":{},\"annotations\":{{\"com.example.order\":\"first\",\"org.opencontainers.image.title\":\"layer\"}}}}]}}",
            MEDIA_TYPE_OCI_MANIFEST,
            config.media_type(),
            config.digest(),
            config.size(),
            layer.media_type(),
            layer.digest(),
            layer.size()
        )
    );
}

#[test]
fn registry_pull_plan_preserves_manifest_layer_order() {
    let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
    let layer_one = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"layer-one");
    let layer_two = descriptor_for(MEDIA_TYPE_OCI_LAYER_GZIP, b"layer-two");
    let manifest = OciImageManifest::new(config.clone(), vec![layer_one.clone(), layer_two]);
    let manifest_descriptor = descriptor_for(MEDIA_TYPE_OCI_MANIFEST, b"manifest");

    let plan = RegistryPullPlan::from_manifest(
        OciReference::parse("alpine:3.20").unwrap(),
        OciPlatform::linux_amd64(),
        manifest_descriptor.clone(),
        manifest,
    )
    .unwrap();

    assert_eq!(plan.reference().repository(), "library/alpine");
    assert_eq!(plan.platform(), &OciPlatform::linux_amd64());
    assert_eq!(plan.manifest_descriptor(), &manifest_descriptor);
    assert_eq!(plan.config(), &config);
    assert_eq!(
        plan.layers()
            .iter()
            .map(OciDescriptor::media_type)
            .collect::<Vec<_>>(),
        vec![MEDIA_TYPE_OCI_LAYER, MEDIA_TYPE_OCI_LAYER_GZIP]
    );
    assert_eq!(plan.layers()[0], layer_one);
}

#[test]
fn registry_push_plan_uploads_missing_blobs_before_manifest() {
    let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
    let layer_one = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"layer-one");
    let layer_two = descriptor_for(MEDIA_TYPE_OCI_LAYER_GZIP, b"layer-two");
    let manifest =
        OciImageManifest::new(config.clone(), vec![layer_one.clone(), layer_two.clone()]);
    let manifest_descriptor = descriptor_for(MEDIA_TYPE_OCI_MANIFEST, &manifest.to_json_bytes());

    let plan = RegistryPushPlan::from_manifest(
        OciReference::parse("localhost:5000/team/app:test").unwrap(),
        manifest_descriptor.clone(),
        manifest,
        vec![layer_one.digest().clone()],
    )
    .unwrap();

    assert_eq!(plan.reference().registry(), "localhost:5000");
    assert_eq!(plan.manifest_descriptor(), &manifest_descriptor);
    assert_eq!(
        plan.uploads()
            .iter()
            .map(RegistryPushUpload::kind)
            .collect::<Vec<_>>(),
        vec![
            RegistryPushUploadKind::Blob,
            RegistryPushUploadKind::Blob,
            RegistryPushUploadKind::Manifest
        ]
    );
    assert_eq!(plan.uploads()[0].descriptor(), &config);
    assert_eq!(plan.uploads()[1].descriptor(), &layer_two);
    assert_eq!(plan.uploads()[2].descriptor(), &manifest_descriptor);
}

#[test]
fn registry_push_plan_deduplicates_blob_uploads() {
    let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
    let layer = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"same-layer");
    let manifest = OciImageManifest::new(config, vec![layer.clone(), layer.clone()]);
    let manifest_descriptor = descriptor_for(MEDIA_TYPE_OCI_MANIFEST, &manifest.to_json_bytes());

    let plan = RegistryPushPlan::from_manifest(
        OciReference::parse("example.com/team/app:test").unwrap(),
        manifest_descriptor.clone(),
        manifest,
        Vec::new(),
    )
    .unwrap();

    assert_eq!(plan.uploads().len(), 3);
    assert_eq!(plan.uploads()[1].descriptor(), &layer);
    assert_eq!(plan.uploads()[2].kind(), RegistryPushUploadKind::Manifest);
}

#[test]
fn registry_push_plan_rejects_invalid_media_types() {
    let config = descriptor_for(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#);
    let layer = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"layer");
    let manifest = OciImageManifest::new(config.clone(), vec![layer]);
    let config_descriptor = descriptor_for(MEDIA_TYPE_OCI_CONFIG, b"not-a-manifest");

    assert!(matches!(
        RegistryPushPlan::from_manifest(
            OciReference::parse("team/app:test").unwrap(),
            config_descriptor,
            manifest,
            Vec::new(),
        ),
        Err(ImageError::UnsupportedManifestMediaType(_))
    ));

    let bad_config = descriptor_for(MEDIA_TYPE_OCI_LAYER, b"bad-config");
    let manifest = OciImageManifest::new(bad_config, vec![config]);
    let manifest_descriptor = descriptor_for(MEDIA_TYPE_OCI_MANIFEST, &manifest.to_json_bytes());

    assert!(matches!(
        RegistryPushPlan::from_manifest(
            OciReference::parse("team/app:test").unwrap(),
            manifest_descriptor,
            manifest,
            Vec::new(),
        ),
        Err(ImageError::UnsupportedManifestMediaType(_))
    ));
}

#[test]
fn local_content_store_pushes_to_fake_registry_and_round_trips_pull_plan() {
    let root = temp_root("registry-push");
    let store = LocalContentStore::new(&root);
    let config = OciImageConfig::new(
        OciPlatform::linux_amd64(),
        OciContainerConfig::new()
            .with_env(["PATH=/usr/bin"])
            .with_command(["/bin/app"]),
        vec![OciHistoryEntry::new("FROM scratch")],
        vec![OciDigest::sha256(b"layer")],
    );
    let config_bytes = config.to_json_bytes();
    let config_descriptor = store
        .write_blob(MEDIA_TYPE_OCI_CONFIG, &config_bytes)
        .unwrap();
    let layer_bytes = b"layer";
    let layer_descriptor = store.write_blob(MEDIA_TYPE_OCI_LAYER, layer_bytes).unwrap();
    let manifest = OciImageManifest::new(config_descriptor.clone(), vec![layer_descriptor.clone()]);
    let reference = OciReference::parse("localhost:5000/team/app:test").unwrap();
    let mut registry = FakeRegistry::default();
    registry.seed_blob(&layer_descriptor, layer_bytes).unwrap();

    let plan = store
        .push_to_registry(reference.clone(), &manifest, &mut registry)
        .unwrap();

    assert_eq!(
        plan.uploads()
            .iter()
            .map(RegistryPushUpload::kind)
            .collect::<Vec<_>>(),
        vec![
            RegistryPushUploadKind::Blob,
            RegistryPushUploadKind::Manifest
        ]
    );
    assert_eq!(plan.uploads()[0].descriptor(), &config_descriptor);
    assert_eq!(
        registry.uploads,
        vec![
            RegistryPushUploadKind::Blob,
            RegistryPushUploadKind::Manifest
        ]
    );

    let (pushed_manifest_descriptor, pushed_manifest_bytes) =
        registry.manifest(&reference).unwrap();
    assert_eq!(pushed_manifest_descriptor, plan.manifest_descriptor());
    assert_eq!(pushed_manifest_bytes, manifest.to_json_bytes());

    let pull_plan = RegistryPullPlan::from_manifest(
        reference,
        OciPlatform::linux_amd64(),
        pushed_manifest_descriptor.clone(),
        manifest,
    )
    .unwrap();
    assert_eq!(pull_plan.manifest_descriptor(), pushed_manifest_descriptor);
    assert_eq!(
        registry.blob_bytes(pull_plan.config()).unwrap(),
        config_bytes
    );
    assert_eq!(
        registry.blob_bytes(&pull_plan.layers()[0]).unwrap(),
        layer_bytes
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verified_layer_blob_checks_digest_before_snapshot_unpack() {
    let archive = single_file_tar("etc/os-release", b"ID=mcr\n");
    let descriptor = descriptor_for(MEDIA_TYPE_OCI_LAYER, &archive);
    let verified = VerifiedLayerBlob::new(descriptor.clone(), archive.clone()).unwrap();
    let snapshot = verified
        .unpack_uncompressed_base_layer("sha256-layer")
        .unwrap();
    let os_release = snapshot
        .get(&mcr_snapshot::SnapshotPath::new("/etc/os-release").unwrap())
        .unwrap();

    assert_eq!(
        os_release.metadata().kind(),
        &mcr_snapshot::SnapshotFileKind::Regular { size: 7 }
    );
    assert_eq!(snapshot.layer().id().as_str(), "sha256-layer");

    let mut tampered = archive;
    tampered[0] = b'X';
    assert!(matches!(
        VerifiedLayerBlob::new(descriptor, tampered),
        Err(ImageError::DigestMismatch { .. })
    ));
}

#[test]
fn verified_layer_blob_keeps_compressed_layers_out_of_uncompressed_unpack_boundary() {
    let compressed_bytes = b"not actually gzip yet".to_vec();
    let descriptor = descriptor_for(MEDIA_TYPE_OCI_LAYER_GZIP, &compressed_bytes);
    let verified = VerifiedLayerBlob::new(descriptor, compressed_bytes).unwrap();

    assert!(matches!(
        verified.unpack_uncompressed_base_layer("gzip-layer"),
        Err(ImageError::UnsupportedLayerMediaType(_))
    ));
}

#[test]
fn local_content_store_writes_by_digest_and_verifies_reads() {
    let root = temp_root("content-store");
    let store = LocalContentStore::new(&root);
    let bytes = br#"{"architecture":"amd64","os":"linux"}"#;

    let descriptor = store.write_blob(MEDIA_TYPE_OCI_CONFIG, bytes).unwrap();
    assert_eq!(
        store.blob_path(descriptor.digest()).unwrap(),
        root.join("blobs")
            .join("sha256")
            .join(descriptor.digest().encoded())
    );
    assert_eq!(descriptor.size(), bytes.len() as u64);
    assert_eq!(store.read_blob(&descriptor).unwrap(), bytes);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_content_store_writes_deterministic_oci_layout() {
    let root = temp_root("oci-layout");
    let store = LocalContentStore::new(&root);
    let config = OciImageConfig::new(
        OciPlatform::linux_amd64(),
        OciContainerConfig::new()
            .with_env(["PATH=/usr/bin"])
            .with_command(["/bin/app"]),
        vec![OciHistoryEntry::new("FROM scratch").with_empty_layer(true)],
        vec![OciDigest::sha256(b"layer")],
    );
    let config_descriptor = store
        .write_blob(MEDIA_TYPE_OCI_CONFIG, &config.to_json_bytes())
        .unwrap();
    let layer_descriptor = store.write_blob(MEDIA_TYPE_OCI_LAYER, b"layer").unwrap();
    let manifest = OciImageManifest::new(config_descriptor, vec![layer_descriptor]);

    let manifest_descriptor = store.write_oci_layout(&manifest, Some("mcr:test")).unwrap();
    let first_index = fs::read_to_string(root.join("index.json")).unwrap();
    let second_descriptor = store.write_oci_layout(&manifest, Some("mcr:test")).unwrap();
    let second_index = fs::read_to_string(root.join("index.json")).unwrap();

    assert_eq!(manifest_descriptor, second_descriptor);
    assert_eq!(first_index, second_index);
    assert_eq!(
        fs::read_to_string(root.join("oci-layout")).unwrap(),
        "{\"imageLayoutVersion\":\"1.0.0\"}"
    );
    assert_eq!(
        first_index,
        format!(
            "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{}\",\"digest\":\"{}\",\"size\":{},\"annotations\":{{\"{}\":\"mcr:test\"}}}}]}}",
            MEDIA_TYPE_OCI_MANIFEST,
            manifest_descriptor.digest(),
            manifest_descriptor.size(),
            ANNOTATION_REF_NAME
        )
    );
    assert_eq!(
        store.read_blob(&manifest_descriptor).unwrap(),
        manifest.to_json_bytes()
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_content_store_writes_deterministic_docker_tar() {
    let root = temp_root("docker-tar");
    let store = LocalContentStore::new(&root);
    let config = OciImageConfig::new(
        OciPlatform::linux_amd64(),
        OciContainerConfig::new()
            .with_env(["PATH=/usr/bin"])
            .with_working_dir("/srv/app")
            .with_command(["/bin/app"]),
        vec![OciHistoryEntry::new("FROM scratch").with_empty_layer(true)],
        vec![OciDigest::sha256(b"layer")],
    );
    let config_bytes = config.to_json_bytes();
    let config_descriptor = store
        .write_blob(MEDIA_TYPE_OCI_CONFIG, &config_bytes)
        .unwrap();
    let layer_bytes = single_file_tar("srv/app/hello.txt", b"hello\n");
    let layer_descriptor = store
        .write_blob(MEDIA_TYPE_OCI_LAYER, &layer_bytes)
        .unwrap();
    let manifest = OciImageManifest::new(config_descriptor.clone(), vec![layer_descriptor.clone()]);

    let first = store
        .docker_tar_bytes(&manifest, Some("mcr/example:test"))
        .unwrap();
    let second = store
        .docker_tar_bytes(&manifest, Some("mcr/example:test"))
        .unwrap();
    let archive_path = root.join("exports").join("image.tar");
    store
        .write_docker_tar(&manifest, Some("mcr/example:test"), &archive_path)
        .unwrap();
    let entries = tar_entries(&first);
    let entry_names = entries
        .iter()
        .map(|(path, _)| path.as_str())
        .collect::<Vec<_>>();
    let config_file = docker_config_filename(&config_descriptor);
    let layer_file = docker_layer_filename(&layer_descriptor);

    assert_eq!(first, second);
    assert_eq!(fs::read(archive_path).unwrap(), first);
    assert_eq!(
        entry_names,
        vec![
            "manifest.json",
            config_file.as_str(),
            layer_file.as_str(),
            "repositories"
        ]
    );

    let entry_map = entries.into_iter().collect::<BTreeMap<_, _>>();
    assert_eq!(
        String::from_utf8(entry_map["manifest.json"].clone()).unwrap(),
        format!(
            "[{{\"Config\":\"{}\",\"RepoTags\":[\"mcr/example:test\"],\"Layers\":[\"{}\"]}}]",
            config_file, layer_file
        )
    );
    assert_eq!(entry_map[&config_file], config_bytes);
    assert_eq!(entry_map[&layer_file], layer_bytes);
    assert_eq!(
        String::from_utf8(entry_map["repositories"].clone()).unwrap(),
        format!(
            "{{\"mcr/example\":{{\"test\":\"{}\"}}}}",
            layer_descriptor.digest().encoded()
        )
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn docker_tar_rejects_compressed_layer_blob() {
    let root = temp_root("docker-tar-gzip");
    let store = LocalContentStore::new(&root);
    let config_descriptor = store
        .write_blob(MEDIA_TYPE_OCI_CONFIG, br#"{"architecture":"amd64"}"#)
        .unwrap();
    let layer_descriptor = store
        .write_blob(MEDIA_TYPE_OCI_LAYER_GZIP, b"gzip")
        .unwrap();
    let manifest = OciImageManifest::new(config_descriptor, vec![layer_descriptor]);

    assert!(matches!(
        store.docker_tar_bytes(&manifest, Some("mcr:test")),
        Err(ImageError::UnsupportedLayerMediaType(_))
    ));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_content_store_rejects_tampered_content_and_size_mismatch() {
    let root = temp_root("content-store-tampered");
    let store = LocalContentStore::new(&root);
    let descriptor = store.write_blob(MEDIA_TYPE_OCI_LAYER, b"original").unwrap();
    let path = store.blob_path(descriptor.digest()).unwrap();
    fs::write(&path, b"tampered").unwrap();

    assert!(matches!(
        store.read_blob(&descriptor),
        Err(ImageError::DigestMismatch { .. })
    ));

    let wrong_size = OciDescriptor::new(MEDIA_TYPE_OCI_LAYER, descriptor.digest().clone(), 99);
    assert!(matches!(
        store.read_blob(&wrong_size),
        Err(ImageError::SizeMismatch {
            expected: 99,
            actual: 8
        })
    ));

    fs::remove_dir_all(root).unwrap();
}

#[derive(Default)]
struct FakeRegistry {
    blobs: BTreeMap<OciDigest, (OciDescriptor, Vec<u8>)>,
    manifests: BTreeMap<String, (OciDescriptor, Vec<u8>)>,
    uploads: Vec<RegistryPushUploadKind>,
}

impl FakeRegistry {
    fn seed_blob(&mut self, descriptor: &OciDescriptor, bytes: &[u8]) -> Result<(), ImageError> {
        verify_descriptor_bytes(descriptor, bytes)?;
        self.blobs.insert(
            descriptor.digest().clone(),
            (descriptor.clone(), bytes.to_vec()),
        );
        Ok(())
    }

    fn blob_bytes(&self, descriptor: &OciDescriptor) -> Option<Vec<u8>> {
        let (_, bytes) = self.blobs.get(descriptor.digest())?;
        Some(bytes.clone())
    }

    fn manifest(&self, reference: &OciReference) -> Option<(&OciDescriptor, Vec<u8>)> {
        let (descriptor, bytes) = self.manifests.get(&reference.to_string())?;
        Some((descriptor, bytes.clone()))
    }
}

impl RegistryPushTarget for FakeRegistry {
    fn blob_exists(&self, digest: &OciDigest) -> Result<bool, ImageError> {
        Ok(self.blobs.contains_key(digest))
    }

    fn upload_blob(&mut self, descriptor: &OciDescriptor, bytes: &[u8]) -> Result<(), ImageError> {
        verify_descriptor_bytes(descriptor, bytes)?;
        self.uploads.push(RegistryPushUploadKind::Blob);
        self.blobs.insert(
            descriptor.digest().clone(),
            (descriptor.clone(), bytes.to_vec()),
        );
        Ok(())
    }

    fn upload_manifest(
        &mut self,
        reference: &OciReference,
        descriptor: &OciDescriptor,
        bytes: &[u8],
    ) -> Result<(), ImageError> {
        verify_descriptor_bytes(descriptor, bytes)?;
        self.uploads.push(RegistryPushUploadKind::Manifest);
        self.manifests
            .insert(reference.to_string(), (descriptor.clone(), bytes.to_vec()));
        Ok(())
    }
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("mcr-image-{label}-{}-{nanos}", std::process::id()))
}

fn descriptor_for(media_type: &str, bytes: &[u8]) -> OciDescriptor {
    OciDescriptor::new(media_type, OciDigest::sha256(bytes), bytes.len() as u64)
}

fn tar_entries(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    loop {
        assert!(offset + TAR_BLOCK_SIZE <= archive.len());
        let header = &archive[offset..offset + TAR_BLOCK_SIZE];
        if header.iter().all(|byte| *byte == 0) {
            assert!(
                archive[offset..offset + (TAR_BLOCK_SIZE * 2)]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            return entries;
        }

        let mut checksum_header = header.to_vec();
        checksum_header[148..156].fill(b' ');
        let expected_checksum = read_tar_octal(&header[148..156]);
        let actual_checksum = checksum_header
            .iter()
            .map(|byte| usize::from(*byte))
            .sum::<usize>();
        assert_eq!(expected_checksum, actual_checksum);

        let name = read_tar_string(&header[0..100]);
        let prefix = read_tar_string(&header[345..500]);
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let size = read_tar_octal(&header[124..136]);
        offset += TAR_BLOCK_SIZE;
        let data_end = offset + size;
        entries.push((path, archive[offset..data_end].to_vec()));
        offset = data_end + ((TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE);
    }
}

fn read_tar_string(field: &[u8]) -> String {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    String::from_utf8(field[..end].to_vec()).unwrap()
}

fn read_tar_octal(field: &[u8]) -> usize {
    let end = field
        .iter()
        .position(|byte| *byte == 0 || *byte == b' ')
        .unwrap_or(field.len());
    let value = std::str::from_utf8(&field[..end]).unwrap();
    usize::from_str_radix(value, 8).unwrap()
}

fn single_file_tar(path: &str, data: &[u8]) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut header = [0u8; 512];
    write_tar_string(&mut header[0..100], path);
    write_tar_octal(&mut header[100..108], 0o644);
    write_tar_octal(&mut header[108..116], 0);
    write_tar_octal(&mut header[116..124], 0);
    write_tar_octal(&mut header[124..136], data.len() as u64);
    write_tar_octal(&mut header[136..148], 1);
    header[156] = b'0';
    write_tar_string(&mut header[257..263], "ustar");
    write_tar_string(&mut header[263..265], "00");

    archive.extend_from_slice(&header);
    archive.extend_from_slice(data);
    let padding = (512 - (data.len() % 512)) % 512;
    archive.extend(std::iter::repeat_n(0, padding));
    archive.extend(std::iter::repeat_n(0, 1024));
    archive
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
