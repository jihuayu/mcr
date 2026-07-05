#[allow(unused_imports)]
use super::*;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecutableSyscallPatch {
    pub(crate) address: u64,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug, Default)]
pub(crate) struct ExecutableNativePatches {
    pub(crate) scanned_ranges: Vec<(u64, u64)>,
    pub(crate) syscall_patches: Vec<ExecutableSyscallPatch>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub(crate) fs_relative_patches: Vec<FsRelativePatchSite>,
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FsRelativePatch {
    pub(crate) original: [u8; 9],
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct FsRelativePatchSite {
    pub(crate) address: u64,
    pub(crate) patch: FsRelativePatch,
    pub(crate) materialized: bool,
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FsRelativePatchWork {
    None,
    New,
    All,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct NativeImagePatchKey {
    pub(crate) hash: u64,
    pub(crate) executable_len: u64,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug, Default)]
pub(crate) struct NativePatchMetadata {
    pub(crate) scanned_ranges: Vec<(u64, u64)>,
    pub(crate) syscall_patches: Vec<ExecutableSyscallPatch>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub(crate) fs_relative_patches: BTreeMap<u64, FsRelativePatch>,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug)]
pub(crate) struct NativePatchMetadataEntry {
    pub(crate) base: u64,
    pub(crate) metadata: NativePatchMetadata,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug)]
pub(crate) struct NativeImagePatchRanges {
    pub(crate) base: u64,
    pub(crate) ranges: Vec<(u64, u64)>,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) type NativeImagePatchKeyMap = BTreeMap<mcr_sys::GuestPid, NativeImagePatchKey>;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) type NativeImagePatchRangeMap = BTreeMap<mcr_sys::GuestPid, NativeImagePatchRanges>;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug)]
pub(crate) struct NativePatchCache {
    pub(crate) fs_base: u64,
    pub(crate) scanned_ranges: Vec<(u64, u64)>,
    pub(crate) image_metadata_checked: bool,
    pub(crate) image_metadata_eligible: bool,
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub(crate) fs_relative_patches: BTreeMap<u64, FsRelativePatch>,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
impl NativePatchCache {
    pub(crate) fn invalidate(&mut self) {
        self.scanned_ranges.clear();
        self.image_metadata_eligible = false;
        #[cfg(all(windows, target_arch = "x86_64"))]
        self.fs_relative_patches.clear();
    }

    pub(crate) fn invalidate_range(&mut self, start: u64, end: u64) {
        if !self
            .scanned_ranges
            .iter()
            .any(|(range_start, range_end)| ranges_overlap(start, end, *range_start, *range_end))
        {
            return;
        }
        self.image_metadata_eligible = false;
        self.scanned_ranges.retain(|(range_start, range_end)| {
            !ranges_overlap(start, end, *range_start, *range_end)
        });
        #[cfg(all(windows, target_arch = "x86_64"))]
        self.fs_relative_patches
            .retain(|address, _| !(*address >= start && *address < end));
    }

    pub(crate) fn merge_metadata(&mut self, metadata: &NativePatchMetadata) -> bool {
        for (start, end) in &metadata.scanned_ranges {
            if !range_is_covered(*start, *end, &self.scanned_ranges) {
                self.scanned_ranges.push((*start, *end));
            }
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let mut added_fs_patch = false;
            for (address, patch) in &metadata.fs_relative_patches {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    self.fs_relative_patches.entry(*address)
                {
                    entry.insert(*patch);
                    added_fs_patch = true;
                }
            }
            added_fs_patch
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        {
            let _ = metadata;
            false
        }
    }
}

impl Default for NativePatchCache {
    fn default() -> Self {
        Self {
            fs_base: 0,
            scanned_ranges: Vec::new(),
            image_metadata_checked: false,
            image_metadata_eligible: true,
            #[cfg(all(windows, target_arch = "x86_64"))]
            fs_relative_patches: BTreeMap::new(),
        }
    }
}

impl NativeImagePatchKey {
    pub(crate) fn file_name(&self) -> String {
        format!("{:016x}-{:016x}.bin", self.hash, self.executable_len)
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
const NATIVE_PATCH_CACHE_MAGIC: &[u8; 8] = b"MCRNPC01";
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
const NATIVE_PATCH_CACHE_VERSION: u32 = 2;
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
const FNV64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
const FNV64_PRIME: u64 = 0x0000_0100_0000_01b3;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn native_patch_cache_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("MCR_NATIVE_PATCH_CACHE_DIR")
        && !path.is_empty()
    {
        return Some(PathBuf::from(path));
    }
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|base| base.join("mcr").join("native-patch-cache"))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn native_image_patch_key_and_ranges(
    image: &mcr_elf::GuestMemoryImage,
) -> Option<(NativeImagePatchKey, NativeImagePatchRanges)> {
    let mut hash = FNV64_OFFSET;
    let mut executable_len = 0u64;
    let mut ranges = Vec::new();
    let executable_vmas = image
        .vmas()
        .iter()
        .filter(|vma| vma.permissions().execute())
        .collect::<Vec<_>>();
    let base = executable_vmas.first()?.start();
    for vma in executable_vmas {
        let len = vma.end().checked_sub(vma.start())?;
        let bytes = image.read(vma.start(), usize::try_from(len).ok()?)?;
        hash_u64(&mut hash, vma.start().checked_sub(base)?);
        hash_u64(&mut hash, vma.end().checked_sub(base)?);
        hash_u8(&mut hash, u8::from(vma.permissions().read()));
        hash_u8(&mut hash, u8::from(vma.permissions().write()));
        hash_u8(&mut hash, u8::from(vma.permissions().execute()));
        hash_bytes(&mut hash, bytes);
        executable_len = executable_len.checked_add(len)?;
        ranges.push((vma.start(), vma.end()));
    }
    if executable_len == 0 {
        return None;
    }
    Some((
        NativeImagePatchKey {
            hash,
            executable_len,
        },
        NativeImagePatchRanges { base, ranges },
    ))
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn native_executable_range_patch_key(
    memory: &GuestMemory,
    start: u64,
    end: u64,
    protection: GuestMemoryProtection,
) -> Result<NativeImagePatchKey, GuestExecutionError> {
    let len = end
        .checked_sub(start)
        .ok_or(GuestExecutionError::Memory(GuestMemoryError::InvalidLength))?;
    let len_usize = usize::try_from(len)
        .map_err(|_| GuestExecutionError::Memory(GuestMemoryError::RegionTooLarge))?;
    let mut bytes = vec![0; len_usize];
    memory.read(start, &mut bytes)?;

    let mut hash = FNV64_OFFSET;
    hash_u64(&mut hash, 0);
    hash_u64(&mut hash, len);
    hash_u8(&mut hash, u8::from(protection.read));
    hash_u8(&mut hash, u8::from(protection.write));
    hash_u8(&mut hash, u8::from(protection.execute));
    hash_bytes(&mut hash, &bytes);
    Ok(NativeImagePatchKey {
        hash,
        executable_len: len,
    })
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn hash_u8(hash: &mut u64, value: u8) {
    *hash ^= u64::from(value);
    *hash = hash.wrapping_mul(FNV64_PRIME);
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn hash_u64(hash: &mut u64, value: u64) {
    hash_bytes(hash, &value.to_le_bytes());
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        hash_u8(hash, *byte);
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn load_persistent_native_patch_metadata(
    key: &NativeImagePatchKey,
    base: u64,
) -> io::Result<Option<NativePatchMetadata>> {
    let Some(dir) = native_patch_cache_dir() else {
        return Ok(None);
    };
    load_persistent_native_patch_metadata_from_dir(key, base, &dir)
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn store_persistent_native_patch_metadata(
    key: &NativeImagePatchKey,
    metadata: &NativePatchMetadata,
    base: u64,
) -> io::Result<()> {
    let Some(dir) = native_patch_cache_dir() else {
        return Ok(());
    };
    store_persistent_native_patch_metadata_in_dir(key, metadata, base, &dir)
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn load_persistent_native_patch_metadata_from_dir(
    key: &NativeImagePatchKey,
    base: u64,
    dir: &Path,
) -> io::Result<Option<NativePatchMetadata>> {
    let path = dir.join(key.file_name());
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    decode_native_patch_metadata(key, &bytes, base).map(Some)
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn store_persistent_native_patch_metadata_in_dir(
    key: &NativeImagePatchKey,
    metadata: &NativePatchMetadata,
    base: u64,
    dir: &Path,
) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join(key.file_name());
    let temp_path = dir.join(format!("{}.{}.tmp", key.file_name(), std::process::id()));
    fs::write(
        &temp_path,
        encode_native_patch_metadata(key, metadata, base)?,
    )?;
    match fs::rename(&temp_path, &path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(temp_path);
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(temp_path);
            Err(error)
        }
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn encode_native_patch_metadata(
    key: &NativeImagePatchKey,
    metadata: &NativePatchMetadata,
    base: u64,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(NATIVE_PATCH_CACHE_MAGIC);
    push_cache_u32(&mut bytes, NATIVE_PATCH_CACHE_VERSION);
    push_cache_u64(&mut bytes, key.hash);
    push_cache_u64(&mut bytes, key.executable_len);
    push_cache_u32(&mut bytes, metadata.scanned_ranges.len() as u32);
    for (start, end) in &metadata.scanned_ranges {
        push_cache_u64(&mut bytes, cache_relative_offset(*start, base)?);
        push_cache_u64(&mut bytes, cache_relative_offset(*end, base)?);
    }
    push_cache_u32(&mut bytes, metadata.syscall_patches.len() as u32);
    for patch in &metadata.syscall_patches {
        push_cache_u64(&mut bytes, cache_relative_offset(patch.address, base)?);
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        push_cache_u32(&mut bytes, metadata.fs_relative_patches.len() as u32);
        for (address, patch) in &metadata.fs_relative_patches {
            push_cache_u64(&mut bytes, cache_relative_offset(*address, base)?);
            bytes.extend_from_slice(&patch.original);
        }
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        push_cache_u32(&mut bytes, 0);
    }
    Ok(bytes)
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn decode_native_patch_metadata(
    key: &NativeImagePatchKey,
    bytes: &[u8],
    base: u64,
) -> io::Result<NativePatchMetadata> {
    let mut reader = NativePatchMetadataReader::new(bytes);
    reader.expect_magic(NATIVE_PATCH_CACHE_MAGIC)?;
    let version = reader.read_u32()?;
    if version != NATIVE_PATCH_CACHE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported native patch cache version",
        ));
    }
    let stored_key = NativeImagePatchKey {
        hash: reader.read_u64()?,
        executable_len: reader.read_u64()?,
    };
    if &stored_key != key {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native patch cache key mismatch",
        ));
    }
    let mut metadata = NativePatchMetadata::default();
    for _ in 0..reader.read_u32()? {
        metadata.scanned_ranges.push((
            cache_absolute_address(reader.read_u64()?, base)?,
            cache_absolute_address(reader.read_u64()?, base)?,
        ));
    }
    for _ in 0..reader.read_u32()? {
        metadata.syscall_patches.push(ExecutableSyscallPatch {
            address: cache_absolute_address(reader.read_u64()?, base)?,
        });
    }
    let fs_count = reader.read_u32()?;
    for _ in 0..fs_count {
        let address = cache_absolute_address(reader.read_u64()?, base)?;
        let original = reader.read_array::<9>()?;
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            metadata
                .fs_relative_patches
                .insert(address, FsRelativePatch { original });
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        {
            let _ = (address, original);
        }
    }
    reader.expect_eof()?;
    Ok(metadata)
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn cache_relative_offset(address: u64, base: u64) -> io::Result<u64> {
    address.checked_sub(base).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native patch metadata address precedes cache base",
        )
    })
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn cache_absolute_address(offset: u64, base: u64) -> io::Result<u64> {
    base.checked_add(offset).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native patch metadata address overflows cache base",
        )
    })
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) struct NativePatchMetadataReader<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) offset: usize,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
impl<'a> NativePatchMetadataReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_magic(&mut self, magic: &[u8]) -> io::Result<()> {
        if self.read_slice(magic.len())? != magic {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native patch cache magic",
            ));
        }
        Ok(())
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        Ok(self
            .read_slice(N)?
            .try_into()
            .expect("slice length is checked"))
    }

    fn read_slice(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cache offset overflow"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated cache"))?;
        self.offset = end;
        Ok(slice)
    }

    fn expect_eof(&self) -> io::Result<()> {
        if self.offset != self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native patch cache has trailing bytes",
            ));
        }
        Ok(())
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn push_cache_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn push_cache_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn native_patch_metadata_from_patches(
    patches: &ExecutableNativePatches,
) -> NativePatchMetadata {
    NativePatchMetadata {
        scanned_ranges: patches.scanned_ranges.clone(),
        syscall_patches: patches.syscall_patches.clone(),
        #[cfg(all(windows, target_arch = "x86_64"))]
        fs_relative_patches: patches
            .fs_relative_patches
            .iter()
            .map(|site| (site.address, site.patch))
            .collect(),
    }
}

pub(crate) fn find_executable_native_patches(
    memory: &mut GuestMemory,
    skipped_ranges: &[(u64, u64)],
    previous_fs_base: u64,
    guest_task_worker_pool: Option<&HostWorkerPoolExecutor>,
) -> Result<ExecutableNativePatches, GuestExecutionError> {
    let executable_ranges = memory
        .vmas()
        .filter(|vma| vma.protection().execute)
        .filter(|vma| !range_is_covered(vma.start(), vma.end(), skipped_ranges))
        .map(|vma| (vma.start(), vma.end()))
        .collect::<Vec<_>>();

    if let Some(pool) = guest_task_worker_pool
        && let Some(patches) = try_find_executable_native_patches_on_worker_pool(
            memory,
            &executable_ranges,
            previous_fs_base,
            pool,
        )?
    {
        return Ok(patches);
    }

    find_executable_native_patches_synchronously(memory, &executable_ranges, previous_fs_base)
}

pub(crate) fn find_executable_native_patches_synchronously(
    memory: &GuestMemory,
    executable_ranges: &[(u64, u64)],
    previous_fs_base: u64,
) -> Result<ExecutableNativePatches, GuestExecutionError> {
    let mut patches = ExecutableNativePatches::default();
    for (start, end) in executable_ranges.iter().copied() {
        let bytes = read_executable_patch_range(memory, start, end)?;
        merge_executable_native_patches(
            &mut patches,
            scan_executable_native_patch_range(start, end, bytes, previous_fs_base),
        );
    }
    Ok(patches)
}

pub(crate) fn try_find_executable_native_patches_on_worker_pool(
    memory: &GuestMemory,
    executable_ranges: &[(u64, u64)],
    previous_fs_base: u64,
    pool: &HostWorkerPoolExecutor,
) -> Result<Option<ExecutableNativePatches>, GuestExecutionError> {
    let mut jobs = Vec::with_capacity(executable_ranges.len());
    for (start, end) in executable_ranges.iter().copied() {
        let bytes = read_executable_patch_range(memory, start, end)?;
        match pool.submit_result(move || {
            scan_executable_native_patch_range(start, end, bytes, previous_fs_base)
        }) {
            Ok(job) => jobs.push(job),
            Err(error) => {
                host_step_trace(format_args!(
                    "runtime native-patch-scan worker submit fallback range=[0x{start:016x}..0x{end:016x}) error={error}"
                ));
                drain_native_patch_scan_jobs(jobs);
                return Ok(None);
            }
        }
    }

    let mut patches = ExecutableNativePatches::default();
    for job in jobs {
        match job.recv() {
            Ok(range_patches) => merge_executable_native_patches(&mut patches, range_patches),
            Err(error) => {
                host_step_trace(format_args!(
                    "runtime native-patch-scan worker receive fallback error={error}"
                ));
                return Ok(None);
            }
        }
    }
    Ok(Some(patches))
}

pub(crate) fn drain_native_patch_scan_jobs(jobs: Vec<HostWorkerPoolJob<ExecutableNativePatches>>) {
    for job in jobs {
        let _ = job.recv();
    }
}

pub(crate) fn read_executable_patch_range(
    memory: &GuestMemory,
    start: u64,
    end: u64,
) -> Result<Vec<u8>, GuestExecutionError> {
    let len = usize::try_from(end - start)
        .map_err(|_| GuestExecutionError::Memory(GuestMemoryError::RegionTooLarge))?;
    let mut bytes = vec![0; len];
    memory.read(start, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn scan_executable_native_patch_range(
    start: u64,
    end: u64,
    bytes: Vec<u8>,
    previous_fs_base: u64,
) -> ExecutableNativePatches {
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    let _ = previous_fs_base;

    let range_start = Instant::now();
    host_step_trace(format_args!(
        "runtime native-patch-scan start range=[0x{start:016x}..0x{end:016x}) bytes={}",
        bytes.len()
    ));
    let mut patches = ExecutableNativePatches::default();
    patches.scanned_ranges.push((start, end));
    for site in mcr_jit::syscall_instruction_sites(&bytes, start) {
        patches
            .syscall_patches
            .push(ExecutableSyscallPatch { address: site.rip });
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    patches
        .fs_relative_patches
        .extend(fs_relative_patch_sites(&bytes, start, previous_fs_base));
    host_step_trace(format_args!(
        "runtime native-patch-scan done range=[0x{start:016x}..0x{end:016x}) syscall_patches={} fs_relative_patches={} elapsed_ms={}",
        patches.syscall_patches.len(),
        {
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                patches.fs_relative_patches.len()
            }
            #[cfg(not(all(windows, target_arch = "x86_64")))]
            {
                0
            }
        },
        host_step_elapsed_ms(range_start)
    ));
    patches
}

pub(crate) fn merge_executable_native_patches(
    target: &mut ExecutableNativePatches,
    range: ExecutableNativePatches,
) {
    target.scanned_ranges.extend(range.scanned_ranges);
    target.syscall_patches.extend(range.syscall_patches);
    #[cfg(all(windows, target_arch = "x86_64"))]
    target.fs_relative_patches.extend(range.fs_relative_patches);
}

pub(crate) fn apply_executable_syscall_patches(
    memory: &mut GuestMemory,
    patches: &[ExecutableSyscallPatch],
) -> Result<(), GuestExecutionError> {
    let patch_start = Instant::now();
    host_step_trace(format_args!(
        "runtime syscall-patch apply start patches={}",
        patches.len()
    ));
    memory.patch_code_fixed(patches.iter().map(|patch| (patch.address, [0xcc, 0x90])))?;
    host_step_trace(format_args!(
        "runtime syscall-patch apply done patches={} elapsed_ms={}",
        patches.len(),
        host_step_elapsed_ms(patch_start)
    ));
    Ok(())
}

pub(crate) fn apply_native_patch_metadata(
    memory: &mut GuestMemory,
    fs_base: u64,
    metadata: &NativePatchMetadata,
) -> Result<(), GuestExecutionError> {
    apply_executable_syscall_patches(memory, &metadata.syscall_patches)?;
    #[cfg(all(windows, target_arch = "x86_64"))]
    apply_fs_relative_patch_entries(
        memory,
        fs_base,
        metadata.fs_relative_patches.len(),
        metadata
            .fs_relative_patches
            .iter()
            .map(|(&address, &patch)| (address, patch)),
    )?;
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = fs_base;
    }
    Ok(())
}

pub(crate) fn metadata_for_ranges(
    metadata: &NativePatchMetadata,
    ranges: &[(u64, u64)],
) -> NativePatchMetadata {
    NativePatchMetadata {
        scanned_ranges: metadata
            .scanned_ranges
            .iter()
            .copied()
            .filter(|(start, end)| range_is_covered(*start, *end, ranges))
            .collect(),
        syscall_patches: metadata
            .syscall_patches
            .iter()
            .copied()
            .filter(|patch| address_in_ranges(patch.address, ranges))
            .collect(),
        #[cfg(all(windows, target_arch = "x86_64"))]
        fs_relative_patches: metadata
            .fs_relative_patches
            .iter()
            .filter_map(|(address, patch)| {
                address_in_ranges(*address, ranges).then_some((*address, *patch))
            })
            .collect(),
    }
}

pub(crate) fn rebase_native_patch_metadata(
    metadata: &NativePatchMetadata,
    source_base: u64,
    target_base: u64,
) -> Option<NativePatchMetadata> {
    Some(NativePatchMetadata {
        scanned_ranges: metadata
            .scanned_ranges
            .iter()
            .map(|(start, end)| {
                Some((
                    rebase_native_patch_address(*start, source_base, target_base)?,
                    rebase_native_patch_address(*end, source_base, target_base)?,
                ))
            })
            .collect::<Option<Vec<_>>>()?,
        syscall_patches: metadata
            .syscall_patches
            .iter()
            .map(|patch| {
                Some(ExecutableSyscallPatch {
                    address: rebase_native_patch_address(patch.address, source_base, target_base)?,
                })
            })
            .collect::<Option<Vec<_>>>()?,
        #[cfg(all(windows, target_arch = "x86_64"))]
        fs_relative_patches: metadata
            .fs_relative_patches
            .iter()
            .map(|(address, patch)| {
                Some((
                    rebase_native_patch_address(*address, source_base, target_base)?,
                    *patch,
                ))
            })
            .collect::<Option<BTreeMap<_, _>>>()?,
    })
}

pub(crate) fn rebase_native_patch_address(
    address: u64,
    source_base: u64,
    target_base: u64,
) -> Option<u64> {
    target_base.checked_add(address.checked_sub(source_base)?)
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn fs_relative_patch_work(
    cached_fs_base: u64,
    fs_base: u64,
    cached_patch_count: usize,
    new_unmaterialized_patch_count: usize,
    new_materialized_patch_count: usize,
) -> FsRelativePatchWork {
    if cached_fs_base != fs_base {
        if fs_base != 0 || cached_patch_count > 0 || new_materialized_patch_count > 0 {
            FsRelativePatchWork::All
        } else {
            FsRelativePatchWork::None
        }
    } else if fs_base != 0 && new_unmaterialized_patch_count > 0 {
        FsRelativePatchWork::New
    } else {
        FsRelativePatchWork::None
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn apply_fs_relative_patch_entries(
    memory: &mut GuestMemory,
    fs_base: u64,
    patch_count: usize,
    patches: impl IntoIterator<Item = (u64, FsRelativePatch)>,
) -> Result<(), GuestExecutionError> {
    let patch_start = Instant::now();
    host_step_trace(format_args!(
        "runtime fs-relative-patch apply start patches={} fs_base=0x{fs_base:016x}",
        patch_count
    ));
    memory.patch_code_fixed(patches.into_iter().map(|(address, patch)| {
        (
            address,
            fs_relative_replacement(patch.original, fs_base).unwrap_or(patch.original),
        )
    }))?;
    host_step_trace(format_args!(
        "runtime fs-relative-patch apply done patches={} elapsed_ms={}",
        patch_count,
        host_step_elapsed_ms(patch_start)
    ));
    Ok(())
}

pub(crate) fn range_is_covered(start: u64, end: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(range_start, range_end)| start >= *range_start && end <= *range_end)
}

pub(crate) fn address_in_ranges(address: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| *start <= address && address < *end)
}

pub(crate) fn ranges_overlap(
    left_start: u64,
    left_end: u64,
    right_start: u64,
    right_end: u64,
) -> bool {
    left_start < right_end && right_start < left_end
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn fs_relative_patch_sites(
    bytes: &[u8],
    range_start: u64,
    previous_fs_base: u64,
) -> Vec<FsRelativePatchSite> {
    let mut patches = Vec::new();
    for instruction in LinearInstructionScanner::new().scan(GuestBlock::new(bytes, range_start)) {
        let Some(offset) = instruction
            .rip
            .checked_sub(range_start)
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            continue;
        };
        if let Some(original) = fs_relative_original(&bytes[offset..]) {
            patches.push(FsRelativePatchSite {
                address: instruction.rip,
                patch: FsRelativePatch { original },
                materialized: false,
            });
        } else if previous_fs_base != 0
            && let Some(original) =
                fs_relative_original_from_replacement(&bytes[offset..], previous_fs_base)
        {
            patches.push(FsRelativePatchSite {
                address: instruction.rip,
                patch: FsRelativePatch { original },
                materialized: true,
            });
        }
    }

    patches
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn fs_relative_original(bytes: &[u8]) -> Option<[u8; 9]> {
    if bytes.len() < 9
        || bytes[0] != 0x64
        || bytes[1] & 0xf8 != 0x48
        || !matches!(bytes[2], 0x8b | 0x2b)
        || bytes[3] & 0xc7 != 0x04
        || bytes[4] != 0x25
    {
        return None;
    }

    Some(bytes[..9].try_into().expect("slice length checked"))
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn fs_relative_original_from_replacement(bytes: &[u8], fs_base: u64) -> Option<[u8; 9]> {
    if fs_base == 0
        || bytes.len() < 9
        || bytes[0] & 0xf8 != 0x48
        || !matches!(bytes[1], 0x8b | 0x2b)
        || bytes[2] & 0xc7 != 0x04
        || bytes[3] != 0x25
        || bytes[8] != 0x90
    {
        return None;
    }

    let absolute = u32::from_le_bytes(bytes[4..8].try_into().expect("slice length checked"));
    let displacement = i64::from(absolute) - fs_base as i64;
    let displacement = i32::try_from(displacement).ok()?.to_le_bytes();
    Some([
        0x64,
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        displacement[0],
        displacement[1],
        displacement[2],
        displacement[3],
    ])
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn fs_relative_replacement(original: [u8; 9], fs_base: u64) -> Option<[u8; 9]> {
    if fs_base == 0 {
        return None;
    }

    let displacement = i32::from_le_bytes([original[5], original[6], original[7], original[8]]);
    let absolute = if displacement >= 0 {
        fs_base.checked_add(displacement as u64)?
    } else {
        fs_base.checked_sub(displacement.unsigned_abs() as u64)?
    };
    if absolute > i32::MAX as u64 {
        return None;
    }

    let absolute = (absolute as u32).to_le_bytes();
    Some([
        original[1],
        original[2],
        original[3],
        original[4],
        absolute[0],
        absolute[1],
        absolute[2],
        absolute[3],
        0x90,
    ])
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn is_fork_like_syscall_number(number: u64) -> bool {
    number == mcr_sys::Syscall::Fork.number().raw()
        || number == mcr_sys::Syscall::Vfork.number().raw()
        || number == mcr_sys::Syscall::Clone.number().raw()
        || number == mcr_sys::Syscall::Clone3.number().raw()
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn blocking_fd_wait(fds: &FdTable, syscall_number: u64, fd: u64) -> Option<(Fd, bool)> {
    let fd = fd as Fd;
    if fds.get(fd).is_ok_and(|entry| entry.flags().nonblock()) {
        return None;
    }

    if syscall_number == mcr_sys::Syscall::Read.number().raw()
        || syscall_number == mcr_sys::Syscall::Readv.number().raw()
    {
        Some((fd, false))
    } else if syscall_number == mcr_sys::Syscall::Write.number().raw()
        || syscall_number == mcr_sys::Syscall::Writev.number().raw()
    {
        Some((fd, true))
    } else {
        None
    }
}

pub(crate) fn native_execution_error(
    error: mcr_win::NativeExecutionError,
    registers: mcr_win::HostCpuRegisters,
    fs_base: u64,
    instruction: Option<NativeFaultInstruction>,
    stack_words: Vec<NativeFaultStackWord>,
) -> GuestExecutionError {
    match error {
        mcr_win::NativeExecutionError::GuestFault {
            signal,
            rip,
            address,
        } => GuestExecutionError::Execution(ExecutionError::NativeFault {
            signal,
            rip,
            address,
            fs_base,
            registers: guest_registers_from_host(registers),
            instruction: instruction.map(Box::new),
            stack_words,
        }),
        mcr_win::NativeExecutionError::UnsupportedHost
        | mcr_win::NativeExecutionError::SignalHandler(_)
        | mcr_win::NativeExecutionError::HostFs => {
            GuestExecutionError::Execution(ExecutionError::NativeFault {
                signal: 0,
                rip: 0,
                address: 0,
                fs_base,
                registers: GuestRegisters::default(),
                instruction: None,
                stack_words: Vec::new(),
            })
        }
    }
}

pub(crate) fn native_fault_instruction(
    memory: &GuestMemory,
    rip: u64,
) -> Option<NativeFaultInstruction> {
    const MAX_INSTRUCTION_BYTES: usize = 15;

    let bytes = read_guest_block(memory, rip, MAX_INSTRUCTION_BYTES).ok()?;
    mcr_jit::decode_native_fault_instruction(&bytes, rip)
}

pub(crate) fn native_fault_stack_words(
    memory: &GuestMemory,
    rsp: u64,
) -> Vec<NativeFaultStackWord> {
    const STACK_WORDS: usize = 8;

    (0..STACK_WORDS)
        .filter_map(|index| {
            let address = rsp.checked_add((index * 8) as u64)?;
            let mut bytes = [0; 8];
            memory.read(address, &mut bytes).ok()?;
            Some(NativeFaultStackWord {
                address,
                value: u64::from_le_bytes(bytes),
            })
        })
        .collect()
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn native_fault_is_unrewritten_fs_relative(
    instruction: &NativeFaultInstruction,
) -> bool {
    fs_relative_original(&instruction.bytes).is_some()
}

pub(crate) fn read_guest_block(
    memory: &GuestMemory,
    rip: u64,
    max_len: usize,
) -> Result<Vec<u8>, GuestMemoryError> {
    let Some(vma) = memory.vma_containing(rip) else {
        return Err(GuestMemoryError::NotMapped);
    };
    if !vma.protection().execute {
        return Err(GuestMemoryError::AccessDenied);
    }

    let len = usize::try_from((vma.end() - rip).min(max_len as u64))
        .map_err(|_| GuestMemoryError::RegionTooLarge)?;
    let mut bytes = vec![0; len];
    memory.read(rip, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn registers_from_gpr(value: GprState) -> GuestRegisters {
    GuestRegisters {
        rax: value.rax(),
        rbx: value.rbx(),
        rcx: value.rcx(),
        rdx: value.rdx(),
        rsi: value.rsi(),
        rdi: value.rdi(),
        rbp: value.rbp(),
        rsp: value.rsp(),
        r8: value.r8(),
        r9: value.r9(),
        r10: value.r10(),
        r11: value.r11(),
        r12: value.r12(),
        r13: value.r13(),
        r14: value.r14(),
        r15: value.r15(),
        rip: value.rip(),
        rflags: value.rflags(),
        fs_base: 0,
    }
}

pub(crate) fn registers_from_gpr_with_fs_base(value: GprState, fs_base: u64) -> GuestRegisters {
    GuestRegisters {
        fs_base,
        ..registers_from_gpr(value)
    }
}

pub(crate) fn gpr_from_registers(value: GuestRegisters) -> GprState {
    GprState::with_full_registers(
        value.rip,
        value.rsp,
        [
            value.rax, value.rbx, value.rcx, value.rdx, value.rsi, value.rdi, value.rbp, value.r8,
            value.r9, value.r10, value.r11, value.r12, value.r13, value.r14, value.r15,
        ],
        value.rflags,
    )
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn host_registers_from_gpr(value: GprState) -> mcr_win::HostCpuRegisters {
    mcr_win::HostCpuRegisters {
        rax: value.rax(),
        rbx: value.rbx(),
        rcx: value.rcx(),
        rdx: value.rdx(),
        rsi: value.rsi(),
        rdi: value.rdi(),
        rbp: value.rbp(),
        rsp: value.rsp(),
        r8: value.r8(),
        r9: value.r9(),
        r10: value.r10(),
        r11: value.r11(),
        r12: value.r12(),
        r13: value.r13(),
        r14: value.r14(),
        r15: value.r15(),
        rip: value.rip(),
        rflags: value.rflags(),
        xmm: mcr_win::HostXmmRegisters::default(),
        mxcsr: mcr_win::DEFAULT_MXCSR,
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub(crate) fn guest_registers_from_host(value: mcr_win::HostCpuRegisters) -> GuestRegisters {
    GuestRegisters {
        rax: value.rax,
        rbx: value.rbx,
        rcx: value.rcx,
        rdx: value.rdx,
        rsi: value.rsi,
        rdi: value.rdi,
        rbp: value.rbp,
        rsp: value.rsp,
        r8: value.r8,
        r9: value.r9,
        r10: value.r10,
        r11: value.r11,
        r12: value.r12,
        r13: value.r13,
        r14: value.r14,
        r15: value.r15,
        rip: value.rip,
        rflags: value.rflags,
        fs_base: 0,
    }
}

#[derive(Debug, Default)]
pub(crate) struct FileBackedMappingCache {
    pub(crate) entries: BTreeMap<FileBackedMappingCacheKey, Arc<[u8]>>,
    pub(crate) hits: usize,
    pub(crate) misses: usize,
}

impl FileBackedMappingCache {
    pub(crate) fn lookup(&mut self, key: FileBackedMappingCacheKey) -> Option<Arc<[u8]>> {
        let bytes = self.entries.get(&key)?;
        self.hits += 1;
        Some(bytes.clone())
    }

    pub(crate) fn record_miss(&mut self) {
        self.misses += 1;
    }

    pub(crate) fn insert(&mut self, key: FileBackedMappingCacheKey, bytes: Vec<u8>) -> Arc<[u8]> {
        self.entries
            .retain(|cached, _| cached.file.generation() == key.file.generation());
        let bytes: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
        self.entries.insert(key, bytes.clone());
        bytes
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> FileBackedMappingCacheSnapshot {
        FileBackedMappingCacheSnapshot {
            entries: self.entries.len(),
            hits: self.hits,
            misses: self.misses,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FileBackedMappingCacheKey {
    pub(crate) file: RegularFileCacheKey,
    pub(crate) offset: u64,
    pub(crate) length: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileBackedMappingCacheSnapshot {
    pub(crate) entries: usize,
    pub(crate) hits: usize,
    pub(crate) misses: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileBackedLibcIntrinsicSymbol {
    pub(crate) value: u64,
    pub(crate) intrinsic: GuestLibcIntrinsic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ElfSectionHeader {
    pub(crate) section_type: u32,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) link: u32,
    pub(crate) entry_size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ElfLoadHeader {
    pub(crate) file_offset: u64,
    pub(crate) virtual_address: u64,
    pub(crate) file_size: u64,
    pub(crate) memory_size: u64,
}

const ELF64_MAGIC: &[u8; 4] = b"\x7fELF";
const ELF64_CLASS_64: u8 = 2;
const ELF64_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF64_MACHINE_X86_64: u16 = 62;
const ELF64_PT_LOAD: u32 = 1;
const ELF64_SHT_DYNSYM: u32 = 11;
const ELF64_STT_FUNC: u8 = 2;
const ELF64_STT_GNU_IFUNC: u8 = 10;
const ELF64_SYMBOL_SIZE: usize = 24;

pub(crate) fn parse_file_backed_libc_intrinsic_symbols(
    bytes: &[u8],
) -> Vec<FileBackedLibcIntrinsicSymbol> {
    let Some(sections) = elf_section_headers(bytes) else {
        return Vec::new();
    };
    let mut symbols = Vec::new();
    for section in sections
        .iter()
        .filter(|section| section.section_type == ELF64_SHT_DYNSYM)
    {
        let Some(strtab) = usize::try_from(section.link)
            .ok()
            .and_then(|index| sections.get(index))
            .and_then(|section| elf_range(bytes, section.offset, section.size))
        else {
            continue;
        };
        let entry_size = usize::try_from(section.entry_size)
            .ok()
            .filter(|size| *size >= ELF64_SYMBOL_SIZE)
            .unwrap_or(ELF64_SYMBOL_SIZE);
        let Some(dynsym) = elf_range(bytes, section.offset, section.size) else {
            continue;
        };
        for entry in dynsym.chunks_exact(entry_size) {
            let Some(symbol) = parse_file_backed_libc_intrinsic_symbol(entry, strtab) else {
                continue;
            };
            symbols.push(symbol);
        }
    }
    symbols
}

pub(crate) fn parse_file_backed_libc_intrinsic_symbol(
    entry: &[u8],
    strtab: &[u8],
) -> Option<FileBackedLibcIntrinsicSymbol> {
    let name_offset = elf_u32(entry, 0)? as usize;
    let symbol_type = *entry.get(4)? & 0x0f;
    if !matches!(symbol_type, ELF64_STT_FUNC | ELF64_STT_GNU_IFUNC) {
        return None;
    }
    let value = elf_u64(entry, 8)?;
    if value == 0 {
        return None;
    }
    let name = elf_cstr(strtab, name_offset)?;
    let intrinsic = GuestLibcIntrinsic::from_symbol_name(name)?;
    Some(FileBackedLibcIntrinsicSymbol { value, intrinsic })
}

pub(crate) fn elf_load_bias_for_mapping(
    bytes: &[u8],
    file_offset: u64,
    mapped: u64,
) -> Option<u64> {
    let page_size = GUEST_PAGE_SIZE;
    for load in elf_load_headers(bytes)? {
        let segment_file_start = elf_align_down(load.file_offset, page_size);
        let segment_file_end = align_up_checked(
            load.file_offset
                .checked_add(load.file_size.max(load.memory_size))?,
            page_size,
        )?;
        if file_offset < segment_file_start || file_offset >= segment_file_end {
            continue;
        }
        let segment_vaddr_start = elf_align_down(load.virtual_address, page_size);
        let mapped_image_address =
            segment_vaddr_start.checked_add(file_offset.checked_sub(segment_file_start)?)?;
        return mapped.checked_sub(mapped_image_address);
    }
    None
}

pub(crate) fn elf_section_headers(bytes: &[u8]) -> Option<Vec<ElfSectionHeader>> {
    validate_elf64_header(bytes)?;
    let section_offset = elf_u64(bytes, 40)?;
    let section_entry_size = usize::from(elf_u16(bytes, 58)?);
    let section_count = usize::from(elf_u16(bytes, 60)?);
    if section_entry_size < 64 {
        return None;
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = usize::try_from(section_offset)
            .ok()?
            .checked_add(index.checked_mul(section_entry_size)?)?;
        let section = bytes.get(offset..offset.checked_add(section_entry_size)?)?;
        sections.push(ElfSectionHeader {
            section_type: elf_u32(section, 4)?,
            offset: elf_u64(section, 24)?,
            size: elf_u64(section, 32)?,
            link: elf_u32(section, 40)?,
            entry_size: elf_u64(section, 56)?,
        });
    }
    Some(sections)
}

pub(crate) fn elf_load_headers(bytes: &[u8]) -> Option<Vec<ElfLoadHeader>> {
    validate_elf64_header(bytes)?;
    let program_offset = elf_u64(bytes, 32)?;
    let program_entry_size = usize::from(elf_u16(bytes, 54)?);
    let program_count = usize::from(elf_u16(bytes, 56)?);
    if program_entry_size < 56 {
        return None;
    }
    let mut loads = Vec::new();
    for index in 0..program_count {
        let offset = usize::try_from(program_offset)
            .ok()?
            .checked_add(index.checked_mul(program_entry_size)?)?;
        let header = bytes.get(offset..offset.checked_add(program_entry_size)?)?;
        if elf_u32(header, 0)? != ELF64_PT_LOAD {
            continue;
        }
        loads.push(ElfLoadHeader {
            file_offset: elf_u64(header, 8)?,
            virtual_address: elf_u64(header, 16)?,
            file_size: elf_u64(header, 32)?,
            memory_size: elf_u64(header, 40)?,
        });
    }
    Some(loads)
}

pub(crate) fn validate_elf64_header(bytes: &[u8]) -> Option<()> {
    if bytes.get(0..4)? != ELF64_MAGIC
        || *bytes.get(4)? != ELF64_CLASS_64
        || *bytes.get(5)? != ELF64_DATA_LITTLE_ENDIAN
        || elf_u16(bytes, 18)? != ELF64_MACHINE_X86_64
    {
        return None;
    }
    Some(())
}

pub(crate) fn elf_range(bytes: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
    let offset = usize::try_from(offset).ok()?;
    let len = usize::try_from(len).ok()?;
    bytes.get(offset..offset.checked_add(len)?)
}

pub(crate) fn elf_cstr(bytes: &[u8], offset: usize) -> Option<&str> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&tail[..end]).ok()
}

pub(crate) fn elf_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(crate) fn elf_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn elf_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

const fn elf_align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

pub(crate) fn align_up_checked(value: u64, alignment: u64) -> Option<u64> {
    let remainder = value % alignment;
    if remainder == 0 {
        return Some(value);
    }
    value.checked_add(alignment - remainder)
}
