//! Short-lived reuse of successful signature checks.
//!
//! Callers resolve signing keys first, so a reused result never outlives a
//! keyset change: entries are keyed by token digest and keyset revision.
//! Checks run inline. An RS256 verification costs tens of microseconds, less
//! than handing it to the blocking pool, so there is no admission or queue.
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use tokio::time::Instant;

use crate::{Claims, Result};

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Key {
    token: [u8; 32],
    revision: u64,
}

struct Entries {
    map: HashMap<Key, (Claims, Instant)>,
    next_sweep: Instant,
}

pub(crate) struct ResultCache {
    entries: Mutex<Entries>,
    capacity: usize,
    ttl: Duration,
}

impl ResultCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(Entries {
                map: HashMap::new(),
                next_sweep: Instant::now(),
            }),
            capacity,
            ttl,
        }
    }

    /// Return a reusable success for `token` under `revision`, or run `check`.
    /// Failures are never cached, and a full cache only skips caching.
    pub fn verify(
        &self,
        token: &str,
        revision: u64,
        require_exp: bool,
        check: impl FnOnce() -> Result<Claims>,
    ) -> Result<Claims> {
        if self.capacity == 0 || self.ttl.is_zero() {
            return check();
        }
        let key = Key {
            token: Sha256::digest(token).into(),
            revision,
        };
        if let Some(claims) = self.lookup(&key, require_exp) {
            return Ok(claims);
        }
        let claims = check()?;
        if unexpired(&claims, require_exp) {
            self.insert(key, claims.clone());
        }
        Ok(claims)
    }

    fn lookup(&self, key: &Key, require_exp: bool) -> Option<Claims> {
        let mut entries = self.entries.lock().unwrap();
        let (claims, until) = entries.map.get(key)?;
        if Instant::now() < *until && unexpired(claims, require_exp) {
            return Some(claims.clone());
        }
        entries.map.remove(key);
        None
    }

    fn insert(&self, key: Key, claims: Claims) {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap();
        // Sweep at most once per TTL, so a full cache is not rescanned per request.
        if now >= entries.next_sweep {
            entries.map.retain(|_, (_, until)| now < *until);
            entries.next_sweep = now + self.ttl;
        }
        if entries.map.len() < self.capacity || entries.map.contains_key(&key) {
            entries.map.insert(key, (claims, now + self.ttl));
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap().map.len()
    }
}

fn unexpired(claims: &Claims, require_exp: bool) -> bool {
    !require_exp
        || (claims.exp as u64)
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use std::cell::Cell;

    const TTL: Duration = Duration::from_secs(1);

    fn claims() -> Claims {
        Claims {
            sub: "user".into(),
            exp: usize::MAX,
            scopes: vec![],
        }
    }

    /// Runs `verify` and reports whether the check ran.
    fn checked(cache: &ResultCache, token: &str, revision: u64) -> bool {
        let ran = Cell::new(false);
        cache
            .verify(token, revision, true, || {
                ran.set(true);
                Ok(claims())
            })
            .unwrap();
        ran.get()
    }

    #[tokio::test(start_paused = true)]
    async fn successes_are_reused_until_the_ttl_or_a_revision_change() {
        let cache = ResultCache::new(8, TTL);
        assert!(checked(&cache, "a", 1));
        assert!(!checked(&cache, "a", 1));
        assert!(checked(&cache, "a", 2), "a new keyset revision re-verifies");
        tokio::time::advance(TTL).await;
        assert!(checked(&cache, "a", 1));
    }

    #[tokio::test(start_paused = true)]
    async fn failures_and_expired_claims_are_not_cached() {
        let cache = ResultCache::new(8, TTL);
        assert!(cache
            .verify("bad", 1, true, || Err(Error::Auth("bad signature".into())))
            .is_err());
        assert!(checked(&cache, "bad", 1));
        let expired = Claims { exp: 1, ..claims() };
        cache.verify("old", 1, true, || Ok(expired)).unwrap();
        assert!(checked(&cache, "old", 1));
        // Without required expiry, `exp` is not consulted.
        let ran = Cell::new(0);
        for _ in 0..2 {
            let expired = Claims { exp: 1, ..claims() };
            cache
                .verify("no-exp", 1, false, || {
                    ran.set(ran.get() + 1);
                    Ok(expired)
                })
                .unwrap();
        }
        assert_eq!(ran.get(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_cache_skips_caching_and_never_rejects() {
        let cache = ResultCache::new(2, TTL);
        assert!(checked(&cache, "a", 1));
        assert!(checked(&cache, "b", 1));
        assert!(checked(&cache, "c", 1));
        assert!(checked(&cache, "c", 1), "c was not cached");
        assert!(!checked(&cache, "a", 1), "existing entries survive");
        assert_eq!(cache.len(), 2);
        tokio::time::advance(TTL).await;
        assert!(checked(&cache, "c", 1));
        assert!(!checked(&cache, "c", 1), "expired entries were swept");
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_capacity_or_ttl_disables_reuse() {
        for cache in [
            ResultCache::new(0, TTL),
            ResultCache::new(8, Duration::ZERO),
        ] {
            assert!(checked(&cache, "a", 1));
            assert!(checked(&cache, "a", 1));
        }
    }
}
