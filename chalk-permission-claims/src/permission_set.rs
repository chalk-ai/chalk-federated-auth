use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::permission_table::{PermissionIndex, PermissionTable};

/// How many permission indexes a set can hold, matching the Go and C++ decoders.
pub const CAPACITY: usize = 128;

/// A set of permissions: the decoded form of a JWT Permissions V2 bitset.
///
/// Sets built by decoding hold only permissions the reader's [`PermissionTable`] knows, so
/// permissions from newer minters are dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PermissionSet {
    words: [u64; CAPACITY / 64],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BitsetError {
    #[error("bitset is not canonical unpadded base64url: {0}")]
    Encoding(#[from] base64::DecodeError),
    #[error("bitset sets bit 0 (unspecified)")]
    BitZero,
}

impl PermissionSet {
    pub(crate) fn insert(&mut self, index: PermissionIndex) {
        let n = index.get() as usize;
        if n < CAPACITY {
            self.words[n / 64] |= 1u64 << (n % 64);
        }
    }

    /// Builds a set from V1 permission slugs, ignoring slugs `table` does not know.
    pub fn from_slugs<'a>(
        table: &PermissionTable,
        slugs: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let mut set = Self::default();
        for index in slugs.into_iter().filter_map(|slug| table.index_of(slug)) {
            set.insert(index);
        }
        set
    }

    /// Decodes a canonical, unpadded base64url bitset in which permission n is bit `n % 8` of
    /// byte `n / 8`. Bits `table` does not know are ignored; bit 0 (unspecified) is malformed.
    pub fn from_base64url(table: &PermissionTable, encoded: &str) -> Result<Self, BitsetError> {
        // `URL_SAFE_NO_PAD` rejects padding, the standard alphabet, any other character, impossible
        // lengths, and non-zero unused bits in the last character, so only the canonical form decodes.
        let raw = URL_SAFE_NO_PAD.decode(encoded)?;
        let mut set = Self::default();
        for (byte_index, byte) in raw.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) == 0 {
                    continue;
                }
                let n = byte_index * 8 + bit;
                if n == 0 {
                    return Err(BitsetError::BitZero);
                }
                let Ok(n) = u32::try_from(n) else {
                    continue;
                };
                let index = PermissionIndex::new(n);
                if table.knows(index) {
                    set.insert(index);
                }
            }
        }
        Ok(set)
    }

    pub fn contains(&self, index: PermissionIndex) -> bool {
        let n = index.get() as usize;
        n < CAPACITY && self.words[n / 64] & (1u64 << (n % 64)) != 0
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// The set's permissions in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = PermissionIndex> + '_ {
        (1..CAPACITY as u32)
            .map(PermissionIndex::new)
            .filter(|index| self.contains(*index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> PermissionTable {
        PermissionTable::new([
            (3, "query.online"),
            (4, "query.offline"),
            (11, "deploy.read"),
        ])
        .expect("valid table")
    }

    fn indexes(set: &PermissionSet) -> Vec<u32> {
        set.iter().map(PermissionIndex::get).collect()
    }

    #[test]
    fn decodes_canonical_bitsets() {
        let cases: &[(&str, &[u32])] = &[
            ("", &[]),
            // query.online and deploy.read.
            ("CAg", &[3, 11]),
            ("CAgA", &[3, 11]),
            // Bit 42 is within capacity but not in the table.
            ("CAAAAAAE", &[3]),
            // 16 zero bytes, then 0xff: every bit is beyond capacity.
            ("AAAAAAAAAAAAAAAAAAAAAP8", &[]),
        ];
        for (encoded, expected) in cases {
            assert_eq!(
                PermissionSet::from_base64url(&table(), encoded).map(|set| indexes(&set)),
                Ok(expected.to_vec()),
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn rejects_noncanonical_bitsets() {
        for encoded in [
            "AQ", "CB", "CA==", "CA+", "CA/", "C\nA", "!!", "CAgAA", "CAé",
        ] {
            assert!(
                PermissionSet::from_base64url(&table(), encoded).is_err(),
                "{encoded:?} should be rejected"
            );
        }
        assert_eq!(
            PermissionSet::from_base64url(&table(), "AQ"),
            Err(BitsetError::BitZero)
        );
    }

    #[test]
    fn from_slugs_ignores_unknown_slugs() {
        let set =
            PermissionSet::from_slugs(&table(), ["query.online", "deploy.read", "fixture.unknown"]);
        assert_eq!(Ok(set), PermissionSet::from_base64url(&table(), "CAg"));
        assert!(set.contains(PermissionIndex::new(3)));
        assert!(!set.contains(PermissionIndex::new(4)));
        assert!(!set.is_empty());
        assert!(PermissionSet::default().is_empty());
    }
}
