//! Endpoint-owned refreshes: callers share results, never admission slots.
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use futures_util::{
    future::{BoxFuture, Shared},
    FutureExt,
};
use tokio::{sync::OwnedSemaphorePermit, time::Instant};

use crate::{options::SharedLimits, Error, Result};

static NEXT_REVISION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(super) struct Policy {
    pub capacity: usize,
    pub deadline: Duration,
    pub cooldown: Duration,
}

pub(super) struct Cached<T> {
    pub value: T,
    pub fetched_at: Instant,
    pub revision: u64,
}
type Attempt<T> = Shared<BoxFuture<'static, Result<Arc<Cached<T>>>>>;

struct State<T> {
    value: Option<Arc<Cached<T>>>,
    inflight: Option<Attempt<T>>,
    failure: Option<(Instant, Error)>,
}
struct Cell<T> {
    state: Mutex<State<T>>,
}

pub(super) struct EndpointCache<T> {
    cells: Mutex<HashMap<String, Arc<Cell<T>>>>,
    limits: SharedLimits,
    policy: Policy,
}
impl<T: PartialEq + Send + Sync + 'static> EndpointCache<T> {
    pub fn new(limits: SharedLimits, policy: Policy) -> Self {
        Self {
            cells: Mutex::new(HashMap::new()),
            limits,
            policy,
        }
    }

    pub async fn get<F, Fut>(
        &self,
        endpoint: &str,
        reusable: impl Fn(&Cached<T>) -> bool,
        fetch: F,
    ) -> Result<Arc<Cached<T>>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let cell = {
            let mut cells = self.cells.lock().unwrap();
            if !cells.contains_key(endpoint) && cells.len() >= self.policy.capacity {
                return Err(Error::Unavailable("too many identity endpoints".into()));
            }
            cells
                .entry(endpoint.to_owned())
                .or_insert_with(|| {
                    Arc::new(Cell {
                        state: Mutex::new(State {
                            value: None,
                            inflight: None,
                            failure: None,
                        }),
                    })
                })
                .clone()
        };
        let attempt = {
            let mut state = cell.state.lock().unwrap();
            if let Some(value) = &state.value {
                if reusable(value) {
                    return Ok(value.clone());
                }
            }
            if let Some((until, error)) = &state.failure {
                if Instant::now() < *until {
                    return Err(error.clone());
                }
            }
            if let Some(attempt) = &state.inflight {
                attempt.clone()
            } else {
                let lease = self.limits.inner.refreshes.clone().try_acquire_owned();
                let lease = lease
                    .map_err(|_| Error::Unavailable("identity refresh capacity is busy".into()))?;
                let attempt = cell.start(
                    endpoint.to_owned(),
                    self.limits.clone(),
                    self.policy,
                    lease,
                    fetch,
                );
                state.inflight = Some(attempt.clone());
                attempt
            }
        };
        attempt.await
    }
}

impl<T: PartialEq + Send + Sync + 'static> Cell<T> {
    fn start<F, Fut>(
        self: &Arc<Self>,
        endpoint: String,
        limits: SharedLimits,
        policy: Policy,
        lease: OwnedSemaphorePermit,
        fetch: F,
    ) -> Attempt<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let cell = self.clone();
        let attempt = async move {
            let _lease = lease;
            let queued = Instant::now();
            let mut started = None;
            tracing::debug!(%endpoint, "identity refresh queued");
            // Queue-only timeouts are local pressure. Once admitted, even a
            // total timeout interrupted during HTTP earns endpoint backoff.
            let result =
                std::panic::AssertUnwindSafe(tokio::time::timeout(policy.deadline, async {
                    let _http = limits
                        .inner
                        .http
                        .acquire()
                        .await
                        .expect("HTTP budget stays open");
                    started = Some(Instant::now());
                    tracing::debug!(%endpoint, "identity fetch started");
                    fetch().await
                }))
                .catch_unwind()
                .await;
            let (result, backoff) = match result {
                Ok(Ok(result)) => (result, true),
                Ok(Err(_)) => (
                    Err(Error::Unavailable("identity refresh timed out".into())),
                    started.is_some(),
                ),
                Err(_) => (
                    Err(Error::Unavailable(
                        "identity refresh failed internally".into(),
                    )),
                    true,
                ),
            };
            let mut state = cell.state.lock().unwrap();
            state.inflight = None;
            let result = result.map(|value| match state.value.take() {
                // An unchanged response keeps its revision, so refreshes forced
                // by unknown key IDs do not invalidate reused signature checks.
                Some(previous) if previous.value == value => Arc::new(Cached {
                    value,
                    fetched_at: Instant::now(),
                    revision: previous.revision,
                }),
                _ => Arc::new(Cached {
                    value,
                    fetched_at: Instant::now(),
                    revision: NEXT_REVISION.fetch_add(1, Ordering::Relaxed),
                }),
            });
            match &result {
                Ok(value) => {
                    state.value = Some(value.clone());
                    state.failure = None;
                }
                Err(error) if backoff && !policy.cooldown.is_zero() => {
                    state.failure = Some((Instant::now() + policy.cooldown, error.clone()));
                }
                Err(_) => {}
            }
            drop(state);
            let queue_ms = started
                .unwrap_or_else(Instant::now)
                .duration_since(queued)
                .as_millis() as u64;
            let fetch_ms = started
                .map(|at| at.elapsed().as_millis() as u64)
                .unwrap_or(0);
            match &result {
                Ok(_) => tracing::debug!(
                    %endpoint, queue_ms, fetch_ms, "identity refresh completed"
                ),
                Err(error) => tracing::warn!(
                    %endpoint, %error, queue_ms, fetch_ms,
                    cooldown = backoff, "identity refresh failed"
                ),
            }
            result
        }
        .boxed()
        .shared();
        let driver = attempt.clone();
        tokio::spawn(async move {
            let _ = driver.await;
        });
        attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const REFRESH_TIMEOUT: Duration = Duration::from_secs(3);
    const FAILURE_COOLDOWN: Duration = Duration::from_secs(1);

    fn cache(http: usize, refreshes: usize) -> Arc<EndpointCache<usize>> {
        Arc::new(EndpointCache::new(
            SharedLimits::unchecked(http, refreshes),
            Policy {
                capacity: 1024,
                deadline: REFRESH_TIMEOUT,
                cooldown: FAILURE_COOLDOWN,
            },
        ))
    }

    #[tokio::test(start_paused = true)]
    async fn admission_timeout_does_not_mark_an_endpoint_failed() {
        let cache = cache(0, 1);
        let request = tokio::spawn({
            let cache = cache.clone();
            async move { cache.get("healthy", |_| true, || async { Ok(7) }).await }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(REFRESH_TIMEOUT).await;
        assert!(request.await.unwrap().is_err());
        cache.limits.inner.http.add_permits(1);
        assert_eq!(
            cache
                .get("healthy", |_| true, || async { Ok(7) })
                .await
                .unwrap()
                .value,
            7
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_after_admission_backs_off_even_when_queueing_shortens_the_fetch() {
        let cache = cache(0, 1);
        let started = Arc::new(tokio::sync::Notify::new());
        let request = tokio::spawn({
            let (cache, started) = (cache.clone(), started.clone());
            async move {
                cache
                    .get(
                        "hung",
                        |_| true,
                        move || async move {
                            started.notify_one();
                            std::future::pending().await
                        },
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1500)).await;
        cache.limits.inner.http.add_permits(1);
        started.notified().await;
        tokio::time::advance(Duration::from_millis(1500)).await;
        assert!(request.await.unwrap().is_err());
        assert!(cache
            .get("hung", |_| true, || async { panic!("must back off") })
            .await
            .is_err());
        // The failed endpoint does not retain the shared HTTP slot.
        assert_eq!(
            cache
                .get("healthy", |_| true, || async { Ok(8) })
                .await
                .unwrap()
                .value,
            8
        );
        tokio::time::advance(FAILURE_COOLDOWN).await;
        assert_eq!(
            cache
                .get("hung", |_| true, || async { Ok(7) })
                .await
                .unwrap()
                .value,
            7
        );
    }

    #[tokio::test]
    async fn many_followers_share_one_queued_owner_and_survive_cancellation() {
        let cache = cache(0, 1);
        let calls = Arc::new(AtomicUsize::new(0));
        let first = tokio::spawn({
            let (cache, calls) = (cache.clone(), calls.clone());
            async move {
                cache
                    .get(
                        "healthy",
                        |_| true,
                        move || async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(7)
                        },
                    )
                    .await
            }
        });
        while cache.limits.inner.refreshes.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        first.abort();
        let _ = first.await;
        assert!(cache
            .get("other", |_| true, || async { Ok(0) })
            .await
            .is_err());
        let followers: Vec<_> = (0..512)
            .map(|_| {
                tokio::spawn({
                    let cache = cache.clone();
                    async move {
                        cache
                            .get("healthy", |_| true, || async { panic!("must join") })
                            .await
                    }
                })
            })
            .collect();
        cache.limits.inner.http.add_permits(1);
        for follower in followers {
            assert_eq!(follower.await.unwrap().unwrap().value, 7);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.limits.inner.refreshes.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn actual_fetch_failures_and_panics_back_off_and_recover() {
        for panic in [false, true] {
            let cache = cache(1, 1);
            assert!(cache
                .get(
                    "offline",
                    |_| true,
                    move || async move {
                        if panic {
                            panic!("loader panic");
                        }
                        Err(Error::Unavailable("offline".into()))
                    }
                )
                .await
                .is_err());
            assert!(cache
                .get(
                    "offline",
                    |_| true,
                    || async { panic!("cooldown must skip fetch") }
                )
                .await
                .is_err());
            tokio::time::advance(FAILURE_COOLDOWN).await;
            assert_eq!(
                cache
                    .get("offline", |_| true, || async { Ok(7) })
                    .await
                    .unwrap()
                    .value,
                7
            );
            assert_eq!(cache.limits.inner.refreshes.available_permits(), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unchanged_responses_keep_their_revision() {
        let cache = cache(1, 1);
        let fetch = |value: usize| move || async move { Ok(value) };
        let first = cache.get("keys", |_| false, fetch(7)).await.unwrap();
        let same = cache.get("keys", |_| false, fetch(7)).await.unwrap();
        assert_eq!(same.revision, first.revision);
        assert!(same.fetched_at >= first.fetched_at);
        let changed = cache.get("keys", |_| false, fetch(8)).await.unwrap();
        assert_ne!(changed.revision, first.revision);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_cooldown_retries_the_next_request() {
        let cache = Arc::new(EndpointCache::new(
            SharedLimits::unchecked(1, 1),
            Policy {
                capacity: 1024,
                deadline: REFRESH_TIMEOUT,
                cooldown: Duration::ZERO,
            },
        ));
        assert!(cache
            .get(
                "flaky",
                |_| true,
                || async { Err(Error::Unavailable("offline".into())) }
            )
            .await
            .is_err());
        assert_eq!(
            cache
                .get("flaky", |_| true, || async { Ok(7) })
                .await
                .unwrap()
                .value,
            7
        );
    }

    #[tokio::test]
    async fn endpoint_capacity_is_enforced() {
        let cache = Arc::new(EndpointCache::new(
            SharedLimits::unchecked(1, 1),
            Policy {
                capacity: 1,
                deadline: REFRESH_TIMEOUT,
                cooldown: FAILURE_COOLDOWN,
            },
        ));
        assert!(cache.get("a", |_| true, || async { Ok(1) }).await.is_ok());
        assert!(matches!(
            cache.get("b", |_| true, || async { Ok(2) }).await,
            Err(Error::Unavailable(_))
        ));
    }
}
