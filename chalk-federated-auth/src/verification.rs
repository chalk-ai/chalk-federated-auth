//! Signature work starts only after key resolution and never runs on async workers.
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::{
    future::{BoxFuture, Shared},
    FutureExt,
};
use sha2::{Digest, Sha256};
use tokio::{sync::Semaphore, time::Instant};

use crate::{Claims, Error, Result};

const CAPACITY: usize = 4096;
const RESULT_TTL: Duration = Duration::from_secs(1);
const TIMEOUT: Duration = Duration::from_secs(3);
static CPU_BUDGET: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    Arc::new(Semaphore::new(
        std::thread::available_parallelism()
            .map_or(2, usize::from)
            .clamp(1, 16),
    ))
});

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Key {
    token: [u8; 32],
    revision: u64,
}
type Attempt = Shared<BoxFuture<'static, Result<Claims>>>;
enum Entry {
    Running(Attempt),
    Ready { claims: Claims, until: Instant },
}

pub(super) struct VerificationCache {
    entries: Mutex<HashMap<Key, Entry>>,
    budget: Arc<Semaphore>,
}
impl VerificationCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            budget: CPU_BUDGET.clone(),
        })
    }

    pub async fn verify(
        self: &Arc<Self>,
        token: &str,
        revision: u64,
        require_exp: bool,
        check: impl FnOnce() -> Result<Claims> + Send + 'static,
    ) -> Result<Claims> {
        let key = Key {
            token: Sha256::digest(token).into(),
            revision,
        };
        let attempt = {
            let mut entries = self.entries.lock().unwrap();
            if let Some(Entry::Ready { claims, until }) = entries.get(&key) {
                if Instant::now() < *until && cacheable(claims, require_exp) {
                    return Ok(claims.clone());
                }
            }
            if let Some(Entry::Running(attempt)) = entries.get(&key) {
                attempt.clone()
            } else {
                // Discard completed entries before rejecting new work. Followers
                // always join an admitted token, even when bookkeeping is full.
                entries.remove(&key);
                if entries.len() >= CAPACITY {
                    entries.retain(|_, entry| matches!(entry, Entry::Running(_)));
                }
                if entries.len() >= CAPACITY {
                    return Err(Error::Unavailable("signature verification is busy".into()));
                }
                let cache = self.clone();
                let attempt = async move {
                    let result = tokio::time::timeout(TIMEOUT, async {
                        let permit = cache.budget.clone().acquire_owned().await.map_err(|_| {
                            Error::Unavailable("signature verification is unavailable".into())
                        })?;
                        // A timed-out/aborted waiter cannot release the CPU permit
                        // while its blocking job is still running.
                        tokio::task::spawn_blocking(move || {
                            let _permit = permit;
                            check()
                        })
                        .await
                        .map_err(|_| {
                            Error::Unavailable("signature verification failed internally".into())
                        })?
                    })
                    .await
                    .unwrap_or_else(|_| {
                        Err(Error::Unavailable(
                            "signature verification timed out".into(),
                        ))
                    });
                    let mut entries = cache.entries.lock().unwrap();
                    entries.remove(&key);
                    if let Ok(claims) = &result {
                        if cacheable(claims, require_exp) {
                            entries.insert(
                                key,
                                Entry::Ready {
                                    claims: claims.clone(),
                                    until: Instant::now() + RESULT_TTL,
                                },
                            );
                        }
                    }
                    result
                }
                .boxed()
                .shared();
                entries.insert(key, Entry::Running(attempt.clone()));
                let driver = attempt.clone();
                tokio::spawn(async move {
                    let _ = driver.await;
                });
                attempt
            }
        };
        attempt.await
    }
}

fn cacheable(claims: &Claims, require_exp: bool) -> bool {
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
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    fn cache(slots: usize) -> Arc<VerificationCache> {
        Arc::new(VerificationCache {
            entries: Mutex::new(HashMap::new()),
            budget: Arc::new(Semaphore::new(slots)),
        })
    }
    fn claims() -> Claims {
        Claims {
            sub: "user".into(),
            exp: usize::MAX,
            scopes: vec![],
        }
    }

    #[tokio::test]
    async fn identical_bursts_share_one_blocking_check_and_survive_cancellation() {
        let cache = cache(2);
        let started = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let (release, wait) = mpsc::channel();
        let first = tokio::spawn({
            let (cache, started, calls) = (cache.clone(), started.clone(), calls.clone());
            async move {
                cache
                    .verify("same", 1, true, move || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started.notify_one();
                        wait.recv_timeout(Duration::from_secs(5)).unwrap();
                        Ok(claims())
                    })
                    .await
            }
        });
        started.notified().await;
        first.abort();
        let _ = first.await;
        let followers: Vec<_> = (0..512)
            .map(|_| {
                let cache = cache.clone();
                tokio::spawn(
                    async move { cache.verify("same", 1, true, || panic!("must share")).await },
                )
            })
            .collect();
        // A current-thread runtime remains responsive while the first check is
        // blocked, and an unrelated token can use the other CPU slot.
        assert!(cache
            .verify("other", 1, true, || Ok(claims()))
            .await
            .is_ok());
        release.send(()).unwrap();
        for follower in followers {
            assert!(follower.await.unwrap().is_ok());
        }
        assert!(cache
            .verify("same", 1, true, || panic!("must reuse result"))
            .await
            .is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(cache
            .verify("same", 2, true, || Err(Error::Auth("new keys".into())))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn expired_claims_failures_and_panics_are_not_memoized() {
        let cache = cache(1);
        let expired = Claims { exp: 1, ..claims() };
        cache
            .verify("expired", 1, true, || Ok(expired))
            .await
            .unwrap();
        assert!(cache
            .verify("expired", 1, true, || Err(Error::Auth("expired".into())))
            .await
            .is_err());
        for error in [
            Error::Auth("bad signature".into()),
            Error::Unavailable("busy".into()),
        ] {
            assert!(cache.verify("error", 1, true, || Err(error)).await.is_err());
            assert!(cache
                .verify("error", 1, true, || Ok(claims()))
                .await
                .is_ok());
            cache.entries.lock().unwrap().clear();
        }
        assert!(matches!(
            cache
                .verify("panic", 1, true, || panic!("check panic"))
                .await,
            Err(Error::Unavailable(_))
        ));
        assert!(cache
            .verify("panic", 1, true, || Ok(claims()))
            .await
            .is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn timing_out_a_blocking_check_keeps_its_cpu_permit_until_it_exits() {
        let cache = cache(1);
        let started = Arc::new(tokio::sync::Notify::new());
        let (release, wait) = mpsc::channel();
        let first = tokio::spawn({
            let (cache, started) = (cache.clone(), started.clone());
            async move {
                cache
                    .verify("first", 1, true, move || {
                        started.notify_one();
                        wait.recv_timeout(Duration::from_secs(5)).unwrap();
                        Ok(claims())
                    })
                    .await
            }
        });
        started.notified().await;
        tokio::time::advance(TIMEOUT).await;
        assert!(matches!(first.await.unwrap(), Err(Error::Unavailable(_))));
        assert_eq!(cache.budget.available_permits(), 0);
        release.send(()).unwrap();
        // No endpoint/token cooldown was recorded for the deadline.
        tokio::time::resume();
        assert!(cache
            .verify("first", 1, true, || Ok(claims()))
            .await
            .is_ok());
    }
}
