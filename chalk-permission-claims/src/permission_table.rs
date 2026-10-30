use std::collections::HashMap;

use crate::permission_set::{PermissionSet, CAPACITY};

/// A permission's position: its `chalk.auth.v1.Permission` enum number, which is also its bit in
/// a V2 bitset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PermissionIndex(u32);

impl PermissionIndex {
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Why a reader's permission table is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PermissionTableError {
    #[error("permission index {0} is unspecified or at least the set capacity {CAPACITY}")]
    IndexOutOfRange(u32),
    #[error("permission slug {0:?} appears more than once")]
    DuplicateSlug(String),
    #[error("permission index {0} appears more than once")]
    DuplicateIndex(u32),
}

/// The permissions a reader knows: each V1 slug and its index, built from the reader's own
/// `Permission` enum. Decoding drops every permission the table does not contain, so a reader
/// never grants a permission it cannot name.
#[derive(Clone, Debug)]
pub struct PermissionTable {
    by_slug: HashMap<String, PermissionIndex>,
    known: PermissionSet,
}

impl PermissionTable {
    /// Builds a table from `(index, slug)` pairs. Index 0 is `PERMISSION_UNSPECIFIED`, which is
    /// never a grant, so it is rejected along with indexes beyond the set capacity.
    pub fn new<S: Into<String>>(
        entries: impl IntoIterator<Item = (u32, S)>,
    ) -> Result<Self, PermissionTableError> {
        let mut by_slug = HashMap::new();
        let mut known = PermissionSet::default();
        for (index, slug) in entries {
            let slug = slug.into();
            if index == 0 || index as usize >= CAPACITY {
                return Err(PermissionTableError::IndexOutOfRange(index));
            }
            let index = PermissionIndex::new(index);
            if known.contains(index) {
                return Err(PermissionTableError::DuplicateIndex(index.get()));
            }
            if by_slug.contains_key(&slug) {
                return Err(PermissionTableError::DuplicateSlug(slug));
            }
            known.insert(index);
            by_slug.insert(slug, index);
        }
        Ok(Self { by_slug, known })
    }

    /// The index of a V1 slug, if this reader knows it.
    pub fn index_of(&self, slug: &str) -> Option<PermissionIndex> {
        self.by_slug.get(slug).copied()
    }

    pub fn knows(&self, index: PermissionIndex) -> bool {
        self.known.contains(index)
    }

    pub(crate) fn known(&self) -> &PermissionSet {
        &self.known
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_slugs_and_indexes() {
        let table =
            PermissionTable::new([(3, "query.online"), (11, "deploy.read")]).expect("valid table");
        assert_eq!(
            table.index_of("query.online"),
            Some(PermissionIndex::new(3))
        );
        assert_eq!(table.index_of("missing"), None);
        assert!(table.knows(PermissionIndex::new(11)));
        assert!(!table.knows(PermissionIndex::new(4)));
    }

    #[test]
    fn rejects_invalid_entries() {
        let error = |entries: Vec<(u32, &str)>| PermissionTable::new(entries).err();
        assert_eq!(
            error(vec![(0, "unspecified")]),
            Some(PermissionTableError::IndexOutOfRange(0))
        );
        assert_eq!(
            error(vec![(CAPACITY as u32, "too.high")]),
            Some(PermissionTableError::IndexOutOfRange(CAPACITY as u32))
        );
        assert_eq!(
            error(vec![(3, "a"), (3, "b")]),
            Some(PermissionTableError::DuplicateIndex(3))
        );
        assert_eq!(
            error(vec![(3, "a"), (4, "a")]),
            Some(PermissionTableError::DuplicateSlug("a".to_string()))
        );
    }
}
