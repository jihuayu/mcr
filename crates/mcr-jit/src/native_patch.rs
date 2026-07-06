use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

use crate::syscall_instruction_sites;

#[cfg(all(windows, target_arch = "x86_64"))]
use iced_x86::{Decoder, DecoderOptions, Register};

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableSyscallPatch {
    pub address: u64,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug, Default)]
pub struct ExecutableNativePatches {
    pub scanned_ranges: Vec<(u64, u64)>,
    pub syscall_patches: Vec<ExecutableSyscallPatch>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fs_relative_patches: Vec<FsRelativePatchSite>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fs_relative_traps: Vec<FsRelativeTrapSite>,
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsRelativePatch {
    pub original: [u8; 9],
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug)]
pub struct FsRelativePatchSite {
    pub address: u64,
    pub patch: FsRelativePatch,
    pub materialized: bool,
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsRelativeTrap {
    pub original: [u8; 15],
    pub len: u8,
}

#[cfg(all(windows, target_arch = "x86_64"))]
impl FsRelativeTrap {
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > 15 {
            return None;
        }
        let mut original = [0; 15];
        original[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            original,
            len: bytes.len() as u8,
        })
    }

    #[must_use]
    pub fn original_bytes(&self) -> &[u8] {
        &self.original[..usize::from(self.len)]
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug)]
pub struct FsRelativeTrapSite {
    pub address: u64,
    pub trap: FsRelativeTrap,
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsRelativePatchWork {
    None,
    New,
    All,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NativeImagePatchKey {
    pub hash: u64,
    pub executable_len: u64,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug, Default)]
pub struct NativePatchMetadata {
    pub scanned_ranges: Vec<(u64, u64)>,
    pub syscall_patches: Vec<ExecutableSyscallPatch>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fs_relative_patches: BTreeMap<u64, FsRelativePatch>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fs_relative_traps: BTreeMap<u64, FsRelativeTrap>,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug)]
pub struct NativePatchMetadataEntry {
    pub base: u64,
    pub metadata: NativePatchMetadata,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug)]
pub struct NativeImagePatchRanges {
    pub base: u64,
    pub ranges: Vec<(u64, u64)>,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub type NativeImagePatchKeyMap = BTreeMap<mcr_sys::GuestPid, NativeImagePatchKey>;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub type NativeImagePatchRangeMap = BTreeMap<mcr_sys::GuestPid, NativeImagePatchRanges>;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
#[derive(Clone, Debug)]
pub struct NativePatchCache {
    pub fs_base: u64,
    pub scanned_ranges: Vec<(u64, u64)>,
    pub executable_write_generation: u64,
    pub image_metadata_checked: bool,
    pub image_metadata_eligible: bool,
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fs_relative_patches: BTreeMap<u64, FsRelativePatch>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fs_relative_traps: BTreeMap<u64, FsRelativeTrap>,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
impl NativePatchCache {
    pub fn invalidate(&mut self) {
        self.scanned_ranges.clear();
        self.image_metadata_eligible = false;
        #[cfg(all(windows, target_arch = "x86_64"))]
        self.fs_relative_patches.clear();
        #[cfg(all(windows, target_arch = "x86_64"))]
        self.fs_relative_traps.clear();
    }

    pub fn invalidate_range(&mut self, start: u64, end: u64) {
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
        #[cfg(all(windows, target_arch = "x86_64"))]
        self.fs_relative_traps
            .retain(|address, _| !(*address >= start && *address < end));
    }

    pub fn merge_metadata(&mut self, metadata: &NativePatchMetadata) -> bool {
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
            for (address, trap) in &metadata.fs_relative_traps {
                self.fs_relative_traps.entry(*address).or_insert(*trap);
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
            executable_write_generation: 0,
            image_metadata_checked: false,
            image_metadata_eligible: true,
            #[cfg(all(windows, target_arch = "x86_64"))]
            fs_relative_patches: BTreeMap::new(),
            #[cfg(all(windows, target_arch = "x86_64"))]
            fs_relative_traps: BTreeMap::new(),
        }
    }
}

impl NativeImagePatchKey {
    pub fn file_name(&self) -> String {
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
/// Persistent native patch cache v3 stores:
/// magic, version, image key, scanned ranges, syscall patch addresses, and
/// FS-relative materialized originals plus trap originals as little-endian
/// offsets from the runtime base.
const NATIVE_PATCH_CACHE_VERSION: u32 = 3;
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
pub fn native_patch_cache_dir() -> Option<PathBuf> {
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
pub fn native_image_patch_key_and_ranges(
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativePatchProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub fn native_executable_range_patch_key_from_bytes(
    len: u64,
    protection: NativePatchProtection,
    bytes: &[u8],
) -> NativeImagePatchKey {
    let mut hash = FNV64_OFFSET;
    hash_u64(&mut hash, 0);
    hash_u64(&mut hash, len);
    hash_u8(&mut hash, u8::from(protection.read));
    hash_u8(&mut hash, u8::from(protection.write));
    hash_u8(&mut hash, u8::from(protection.execute));
    hash_bytes(&mut hash, bytes);
    NativeImagePatchKey {
        hash,
        executable_len: len,
    }
}
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub fn hash_u8(hash: &mut u64, value: u8) {
    *hash ^= u64::from(value);
    *hash = hash.wrapping_mul(FNV64_PRIME);
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub fn hash_u64(hash: &mut u64, value: u64) {
    hash_bytes(hash, &value.to_le_bytes());
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        hash_u8(hash, *byte);
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub fn load_persistent_native_patch_metadata(
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
pub fn store_persistent_native_patch_metadata(
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
pub fn load_persistent_native_patch_metadata_from_dir(
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
pub fn store_persistent_native_patch_metadata_in_dir(
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
pub fn encode_native_patch_metadata(
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
        push_cache_u32(&mut bytes, metadata.fs_relative_traps.len() as u32);
        for (address, trap) in &metadata.fs_relative_traps {
            push_cache_u64(&mut bytes, cache_relative_offset(*address, base)?);
            push_cache_u32(&mut bytes, u32::from(trap.len));
            bytes.extend_from_slice(&trap.original);
        }
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        push_cache_u32(&mut bytes, 0);
        push_cache_u32(&mut bytes, 0);
    }
    Ok(bytes)
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub fn decode_native_patch_metadata(
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
    let fs_trap_count = reader.read_u32()?;
    for _ in 0..fs_trap_count {
        let address = cache_absolute_address(reader.read_u64()?, base)?;
        let len = reader.read_u32()?;
        let original = reader.read_array::<15>()?;
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            let len = u8::try_from(len).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native patch cache FS trap length overflows u8",
                )
            })?;
            if len == 0 || usize::from(len) > original.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native patch cache has invalid FS trap length",
                ));
            }
            metadata
                .fs_relative_traps
                .insert(address, FsRelativeTrap { original, len });
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        {
            let _ = (address, len, original);
        }
    }
    reader.expect_eof()?;
    Ok(metadata)
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub fn cache_relative_offset(address: u64, base: u64) -> io::Result<u64> {
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
pub fn cache_absolute_address(offset: u64, base: u64) -> io::Result<u64> {
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
pub struct NativePatchMetadataReader<'a> {
    pub bytes: &'a [u8],
    pub offset: usize,
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
pub fn push_cache_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
pub fn push_cache_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub fn native_patch_metadata_from_patches(
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
        #[cfg(all(windows, target_arch = "x86_64"))]
        fs_relative_traps: patches
            .fs_relative_traps
            .iter()
            .map(|site| (site.address, site.trap))
            .collect(),
    }
}
pub fn scan_executable_native_patch_range(
    start: u64,
    end: u64,
    bytes: Vec<u8>,
    previous_fs_base: u64,
) -> ExecutableNativePatches {
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    let _ = previous_fs_base;

    let mut patches = ExecutableNativePatches::default();
    patches.scanned_ranges.push((start, end));
    for site in syscall_instruction_sites(&bytes, start) {
        patches
            .syscall_patches
            .push(ExecutableSyscallPatch { address: site.rip });
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let fs_sites = fs_relative_sites(&bytes, start, previous_fs_base);
        patches.fs_relative_patches.extend(fs_sites.patches);
        patches.fs_relative_traps.extend(fs_sites.traps);
    }
    patches
}

pub fn merge_executable_native_patches(
    target: &mut ExecutableNativePatches,
    range: ExecutableNativePatches,
) {
    target.scanned_ranges.extend(range.scanned_ranges);
    target.syscall_patches.extend(range.syscall_patches);
    #[cfg(all(windows, target_arch = "x86_64"))]
    target.fs_relative_patches.extend(range.fs_relative_patches);
    #[cfg(all(windows, target_arch = "x86_64"))]
    target.fs_relative_traps.extend(range.fs_relative_traps);
}

pub fn executable_syscall_patch_writes(
    patches: &[ExecutableSyscallPatch],
) -> impl Iterator<Item = (u64, [u8; 2])> + '_ {
    patches.iter().map(|patch| (patch.address, [0xcc, 0x90]))
}
pub fn metadata_for_ranges(
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
        #[cfg(all(windows, target_arch = "x86_64"))]
        fs_relative_traps: metadata
            .fs_relative_traps
            .iter()
            .filter_map(|(address, trap)| {
                address_in_ranges(*address, ranges).then_some((*address, *trap))
            })
            .collect(),
    }
}

pub fn rebase_native_patch_metadata(
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
        #[cfg(all(windows, target_arch = "x86_64"))]
        fs_relative_traps: metadata
            .fs_relative_traps
            .iter()
            .map(|(address, trap)| {
                Some((
                    rebase_native_patch_address(*address, source_base, target_base)?,
                    *trap,
                ))
            })
            .collect::<Option<BTreeMap<_, _>>>()?,
    })
}

pub fn rebase_native_patch_address(
    address: u64,
    source_base: u64,
    target_base: u64,
) -> Option<u64> {
    target_base.checked_add(address.checked_sub(source_base)?)
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub fn fs_relative_patch_work(
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
pub fn fs_relative_patch_writes(
    fs_base: u64,
    patches: impl IntoIterator<Item = (u64, FsRelativePatch)>,
) -> impl Iterator<Item = (u64, [u8; 9])> {
    patches.into_iter().map(move |(address, patch)| {
        (
            address,
            fs_relative_replacement(patch.original, fs_base).unwrap_or(patch.original),
        )
    })
}

pub fn range_is_covered(start: u64, end: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(range_start, range_end)| start >= *range_start && end <= *range_end)
}

pub fn address_in_ranges(address: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| *start <= address && address < *end)
}

pub fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub fn fs_relative_patch_sites(
    bytes: &[u8],
    range_start: u64,
    previous_fs_base: u64,
) -> Vec<FsRelativePatchSite> {
    fs_relative_sites(bytes, range_start, previous_fs_base).patches
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub fn fs_relative_trap_sites(
    bytes: &[u8],
    range_start: u64,
    previous_fs_base: u64,
) -> Vec<FsRelativeTrapSite> {
    fs_relative_sites(bytes, range_start, previous_fs_base).traps
}

#[cfg(all(windows, target_arch = "x86_64"))]
struct FsRelativeSites {
    patches: Vec<FsRelativePatchSite>,
    traps: Vec<FsRelativeTrapSite>,
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn fs_relative_sites(bytes: &[u8], range_start: u64, previous_fs_base: u64) -> FsRelativeSites {
    let mut patches = Vec::new();
    let mut traps = Vec::new();
    let mut decoder = Decoder::with_ip(
        crate::X86_64_BITNESS,
        bytes,
        range_start,
        DecoderOptions::NONE,
    );
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        let Some(offset) = instruction
            .ip()
            .checked_sub(range_start)
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            continue;
        };
        if let Some(original) = fs_relative_original(&bytes[offset..]) {
            patches.push(FsRelativePatchSite {
                address: instruction.ip(),
                patch: FsRelativePatch { original },
                materialized: false,
            });
        } else if previous_fs_base != 0
            && let Some(original) =
                fs_relative_original_from_replacement(&bytes[offset..], previous_fs_base)
        {
            patches.push(FsRelativePatchSite {
                address: instruction.ip(),
                patch: FsRelativePatch { original },
                materialized: true,
            });
        } else if instruction.memory_segment() == Register::FS
            && let Some(original) = bytes.get(offset..offset + instruction.len())
            && let Some(trap) = FsRelativeTrap::new(original)
        {
            traps.push(FsRelativeTrapSite {
                address: instruction.ip(),
                trap,
            });
        }
    }

    FsRelativeSites { patches, traps }
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub fn fs_relative_original(bytes: &[u8]) -> Option<[u8; 9]> {
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
pub fn fs_relative_instruction_bytes(bytes: &[u8]) -> bool {
    let mut decoder = Decoder::with_ip(crate::X86_64_BITNESS, bytes, 0, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return false;
    }
    let instruction = decoder.decode();
    !instruction.is_invalid() && instruction.memory_segment() == Register::FS
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub fn fs_relative_original_from_replacement(bytes: &[u8], fs_base: u64) -> Option<[u8; 9]> {
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
pub fn fs_relative_replacement(original: [u8; 9], fs_base: u64) -> Option<[u8; 9]> {
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
