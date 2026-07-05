use super::*;

#[derive(Clone, Debug, Default)]
pub(crate) struct VfsCache {
    /// Monotonic counter for observing invalidation events in tests and diagnostics.
    pub(crate) generation: u64,
    global_generation: u64,
    inode_generations: BTreeMap<InodeId, u64>,
    pub(crate) directory_listings: BTreeMap<VfsCacheKey, Arc<[DirectoryEntry]>>,
    pub(crate) metadata: BTreeMap<VfsCacheKey, LinuxFileAttr>,
    pub(crate) small_reads: BTreeMap<VfsCacheKey, Arc<[u8]>>,
    host_read_handles: BTreeMap<InodeId, HostReadHandleCacheEntry>,
    host_read_lru: VecDeque<InodeId>,
}

impl VfsCache {
    pub(crate) fn invalidate_all(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.global_generation = self.global_generation.wrapping_add(1);
        self.directory_listings.clear();
        self.metadata.clear();
        self.small_reads.clear();
        self.host_read_handles.clear();
        self.host_read_lru.clear();
    }

    pub(crate) fn invalidate_proc_views(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.directory_listings.clear();
        self.metadata.clear();
        self.small_reads.clear();
    }

    pub(crate) fn invalidate_inode(&mut self, inode: InodeId) {
        self.generation = self.generation.wrapping_add(1);
        self.bump_inode_generation(inode);
        self.remove_inode_entries(inode);
    }

    pub(crate) fn invalidate_inodes(&mut self, inodes: impl IntoIterator<Item = InodeId>) {
        let mut invalidated = false;
        for inode in inodes {
            invalidated = true;
            self.bump_inode_generation(inode);
            self.remove_inode_entries(inode);
        }
        if invalidated {
            self.generation = self.generation.wrapping_add(1);
        }
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

    pub(crate) fn host_read_handle(
        &mut self,
        inode: InodeId,
        path: &Path,
    ) -> VfsResult<Rc<mcr_win::HostFile>> {
        let generation = self.key_generation(inode);
        let cached = self
            .host_read_handles
            .get(&inode)
            .filter(|entry| entry.generation == generation && entry.path.as_path() == path)
            .map(|entry| entry.handle.clone());
        if let Some(handle) = cached {
            self.touch_host_read_lru(inode);
            return Ok(handle);
        }

        let handle = Rc::new(open_host_read_handle(path)?);
        self.host_read_handles.insert(
            inode,
            HostReadHandleCacheEntry {
                generation,
                path: path.to_path_buf(),
                handle: handle.clone(),
            },
        );
        self.touch_host_read_lru(inode);
        self.evict_host_read_handles();
        Ok(handle)
    }

    pub(crate) fn regular_file_generation(&self, inode: InodeId) -> u64 {
        self.key_generation(inode)
    }

    pub(crate) fn key(&self, inode: InodeId) -> VfsCacheKey {
        VfsCacheKey {
            inode,
            generation: self.key_generation(inode),
        }
    }

    fn key_generation(&self, inode: InodeId) -> u64 {
        self.global_generation
            .wrapping_add(*self.inode_generations.get(&inode).unwrap_or(&0))
    }

    fn bump_inode_generation(&mut self, inode: InodeId) {
        self.inode_generations
            .entry(inode)
            .and_modify(|generation| *generation = generation.wrapping_add(1))
            .or_insert(1);
    }

    fn remove_inode_entries(&mut self, inode: InodeId) {
        self.directory_listings.retain(|key, _| key.inode != inode);
        self.metadata.retain(|key, _| key.inode != inode);
        self.small_reads.retain(|key, _| key.inode != inode);
        self.host_read_handles.remove(&inode);
        self.host_read_lru
            .retain(|cached_inode| *cached_inode != inode);
    }

    fn touch_host_read_lru(&mut self, inode: InodeId) {
        self.host_read_lru
            .retain(|cached_inode| *cached_inode != inode);
        self.host_read_lru.push_back(inode);
    }

    fn evict_host_read_handles(&mut self) {
        while self.host_read_handles.len() > HOST_READ_HANDLE_CACHE_LIMIT {
            let Some(inode) = self.host_read_lru.pop_front() else {
                break;
            };
            self.host_read_handles.remove(&inode);
        }
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> VfsCacheSnapshot {
        VfsCacheSnapshot {
            generation: self.generation,
            directory_listing_entries: self.directory_listings.len(),
            metadata_entries: self.metadata.len(),
            small_read_entries: self.small_reads.len(),
            host_read_handle_entries: self.host_read_handles.len(),
        }
    }
}

#[derive(Clone, Debug)]
struct HostReadHandleCacheEntry {
    generation: u64,
    path: PathBuf,
    handle: Rc<mcr_win::HostFile>,
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
    pub(crate) host_read_handle_entries: usize,
}
