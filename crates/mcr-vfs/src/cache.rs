use super::*;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct VfsCache {
    pub(crate) generation: u64,
    pub(crate) regular_file_generation: u64,
    pub(crate) directory_listings: BTreeMap<VfsCacheKey, Arc<[DirectoryEntry]>>,
    pub(crate) metadata: BTreeMap<VfsCacheKey, LinuxFileAttr>,
    pub(crate) small_reads: BTreeMap<VfsCacheKey, Arc<[u8]>>,
}

impl VfsCache {
    pub(crate) fn invalidate_all(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.regular_file_generation = self.regular_file_generation.wrapping_add(1);
        self.directory_listings.clear();
        self.metadata.clear();
        self.small_reads.clear();
    }

    pub(crate) fn invalidate_proc_views(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.directory_listings.clear();
        self.metadata.clear();
        self.small_reads.clear();
    }

    pub(crate) fn directory_listing(&self, inode: InodeId) -> Option<Arc<[DirectoryEntry]>> {
        self.directory_listings.get(&self.key(inode)).cloned()
    }

    pub(crate) fn insert_directory_listing(
        &mut self,
        inode: InodeId,
        entries: Arc<[DirectoryEntry]>,
    ) {
        self.directory_listings.insert(self.key(inode), entries);
    }

    pub(crate) fn metadata(&self, inode: InodeId) -> Option<LinuxFileAttr> {
        self.metadata.get(&self.key(inode)).copied()
    }

    pub(crate) fn insert_metadata(&mut self, inode: InodeId, attr: LinuxFileAttr) {
        self.metadata.insert(self.key(inode), attr);
    }

    pub(crate) fn small_read(&self, inode: InodeId) -> Option<Arc<[u8]>> {
        self.small_reads.get(&self.key(inode)).cloned()
    }

    pub(crate) fn insert_small_read(&mut self, inode: InodeId, data: Arc<[u8]>) {
        self.small_reads.insert(self.key(inode), data);
    }

    pub(crate) fn key(&self, inode: InodeId) -> VfsCacheKey {
        VfsCacheKey {
            inode,
            generation: self.generation,
        }
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> VfsCacheSnapshot {
        VfsCacheSnapshot {
            generation: self.generation,
            directory_listing_entries: self.directory_listings.len(),
            metadata_entries: self.metadata.len(),
            small_read_entries: self.small_reads.len(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct VfsCacheKey {
    pub(crate) inode: InodeId,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegularFileCacheKey {
    pub(crate) inode: InodeId,
    pub(crate) generation: u64,
}

impl RegularFileCacheKey {
    #[must_use]
    pub const fn inode(self) -> InodeId {
        self.inode
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VfsCacheSnapshot {
    pub(crate) generation: u64,
    pub(crate) directory_listing_entries: usize,
    pub(crate) metadata_entries: usize,
    pub(crate) small_read_entries: usize,
}
