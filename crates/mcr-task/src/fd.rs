use std::collections::BTreeMap;

use crate::TaskError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestFdTable {
    entries: BTreeMap<i32, GuestFdEntry>,
}

impl GuestFdTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_stdio() -> Self {
        let mut table = Self::new();
        table
            .insert_exact(0, GuestFdEntry::stdio("stdin"), false)
            .expect("stdio fd 0 is available in a new fd table");
        table
            .insert_exact(1, GuestFdEntry::stdio("stdout"), false)
            .expect("stdio fd 1 is available in a new fd table");
        table
            .insert_exact(2, GuestFdEntry::stdio("stderr"), false)
            .expect("stdio fd 2 is available in a new fd table");
        table
    }

    pub fn insert_exact(
        &mut self,
        fd: i32,
        mut entry: GuestFdEntry,
        cloexec: bool,
    ) -> Result<(), TaskError> {
        if fd < 0 || self.entries.contains_key(&fd) {
            return Err(TaskError::BadFd(fd));
        }

        entry.cloexec = cloexec;
        self.entries.insert(fd, entry);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, fd: i32) -> Option<&GuestFdEntry> {
        self.entries.get(&fd)
    }

    #[must_use]
    pub fn contains(&self, fd: i32) -> bool {
        self.entries.contains_key(&fd)
    }

    pub fn set_cloexec(&mut self, fd: i32, cloexec: bool) -> Result<(), TaskError> {
        let entry = self.entries.get_mut(&fd).ok_or(TaskError::BadFd(fd))?;
        entry.cloexec = cloexec;
        Ok(())
    }

    pub fn close_on_exec(&mut self) {
        self.entries.retain(|_, entry| !entry.cloexec);
    }
}

impl Default for GuestFdTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestFdEntry {
    description: String,
    cloexec: bool,
}

impl GuestFdEntry {
    #[must_use]
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            cloexec: false,
        }
    }

    #[must_use]
    pub fn stdio(name: impl Into<String>) -> Self {
        Self::new(name)
    }

    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    #[must_use]
    pub const fn cloexec(&self) -> bool {
        self.cloexec
    }
}
