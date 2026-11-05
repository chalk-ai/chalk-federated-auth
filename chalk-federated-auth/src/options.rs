//! Tunable limits and deadlines, validated when a registry is built.
use std::{
    fmt,
    sync::{Arc, LazyLock},
    time::Duration,
};

use tokio::sync::Semaphore;

use crate::{Error, Result};

/// How long a newly fetched keyset is authoritative for key IDs it lacks.
/// Fixed: the refresh, backoff, and rotation rules are reasoned against it.
pub(crate) const AUTHORITATIVE_WINDOW: Duration = Duration::from_secs(1);
const MAX_RESULT_CACHE_TTL: Duration = Duration::from_secs(60);

/// Process-level budgets for discovery/JWKS refreshes.
///
/// Registries that share one handle share its limits. [`SharedLimits::global`]
/// (the default) is one handle for the whole process; build a separate handle
/// only for registries that should not compete with the rest.
#[derive(Clone)]
pub struct SharedLimits {
    pub(crate) inner: Arc<Limits>,
}

pub(crate) struct Limits {
    /// Concurrent HTTP requests, admitted in FIFO order.
    pub(crate) http: Semaphore,
    /// Active and queued endpoint refreshes; callers that join one do not count.
    pub(crate) refreshes: Arc<Semaphore>,
    http_calls: usize,
    refresh_owners: usize,
}

static GLOBAL_LIMITS: LazyLock<SharedLimits> = LazyLock::new(|| SharedLimits::unchecked(16, 256));

impl SharedLimits {
    /// The process-wide default: 16 concurrent HTTP requests and 256 active or
    /// queued endpoint refreshes.
    pub fn global() -> Self {
        GLOBAL_LIMITS.clone()
    }

    /// A separate budget. `refresh_owners` counts active and queued endpoint
    /// refreshes, so it must be at least `http_calls`.
    pub fn new(http_calls: usize, refresh_owners: usize) -> Result<Self> {
        if http_calls == 0 {
            return Err(Error::Config("http_calls must be at least 1".into()));
        }
        if refresh_owners < http_calls {
            return Err(Error::Config(format!(
                "refresh_owners ({refresh_owners}) must be at least http_calls ({http_calls})"
            )));
        }
        if refresh_owners > Semaphore::MAX_PERMITS {
            return Err(Error::Config(format!(
                "refresh_owners must be at most {}",
                Semaphore::MAX_PERMITS
            )));
        }
        Ok(Self::unchecked(http_calls, refresh_owners))
    }

    pub(crate) fn unchecked(http_calls: usize, refresh_owners: usize) -> Self {
        Self {
            inner: Arc::new(Limits {
                http: Semaphore::new(http_calls),
                refreshes: Arc::new(Semaphore::new(refresh_owners)),
                http_calls,
                refresh_owners,
            }),
        }
    }

    pub fn http_calls(&self) -> usize {
        self.inner.http_calls
    }

    pub fn refresh_owners(&self) -> usize {
        self.inner.refresh_owners
    }
}

impl Default for SharedLimits {
    fn default() -> Self {
        Self::global()
    }
}

impl fmt::Debug for SharedLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedLimits")
            .field("http_calls", &self.inner.http_calls)
            .field("refresh_owners", &self.inner.refresh_owners)
            .finish()
    }
}

/// Deadlines, cache sizes, and refresh budgets for an [`crate::OidcRegistry`].
///
/// Start from [`RegistryOptions::default`] and assign the fields to change;
/// [`crate::OidcRegistry::with_options`] rejects inconsistent combinations.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RegistryOptions {
    /// Total time for one discovery or JWKS HTTP request, body included.
    pub http_timeout: Duration,
    /// Total time for one endpoint refresh, including the wait for an HTTP slot.
    /// Must exceed `http_timeout`, so a request that times out after admission
    /// is recorded as an endpoint failure.
    pub refresh_deadline: Duration,
    /// Deadline for one `try_validate` call. `None` leaves the deadline to the
    /// caller. Refreshes continue in the background either way.
    pub validate_deadline: Option<Duration>,
    /// How long a failed endpoint refresh is reused before retrying. Zero
    /// retries on the next request; concurrent requests still share one attempt.
    pub failure_cooldown: Duration,
    /// How long fetched signing keys are used before a refresh is required.
    pub jwks_ttl: Duration,
    /// Distinct discovery or JWKS endpoints each registry tracks.
    pub endpoint_capacity: usize,
    /// Successful signature checks kept for reuse. Zero disables reuse.
    /// When full, new results are not cached; requests are never rejected.
    pub result_cache_capacity: usize,
    /// How long a successful signature check is reused. At most 60 seconds.
    pub result_cache_ttl: Duration,
    /// Refresh budgets, shared with every registry holding the same handle.
    pub limits: SharedLimits,
}

impl Default for RegistryOptions {
    fn default() -> Self {
        Self {
            http_timeout: Duration::from_secs(2),
            refresh_deadline: Duration::from_secs(3),
            validate_deadline: Some(Duration::from_secs(3)),
            failure_cooldown: Duration::from_secs(1),
            jwks_ttl: Duration::from_secs(300),
            endpoint_capacity: 1024,
            result_cache_capacity: 4096,
            result_cache_ttl: Duration::from_secs(1),
            limits: SharedLimits::global(),
        }
    }
}

impl RegistryOptions {
    pub(crate) fn validate(&self, configured_endpoints: usize) -> Result<()> {
        let fail = |message: String| Err(Error::Config(message));
        if self.http_timeout.is_zero() {
            return fail("http_timeout must be positive".into());
        }
        if self.refresh_deadline <= self.http_timeout {
            return fail(format!(
                "refresh_deadline ({:?}) must exceed http_timeout ({:?})",
                self.refresh_deadline, self.http_timeout
            ));
        }
        if self.validate_deadline.is_some_and(|d| d.is_zero()) {
            return fail("validate_deadline must be positive when set".into());
        }
        if self.jwks_ttl <= AUTHORITATIVE_WINDOW {
            return fail(format!(
                "jwks_ttl ({:?}) must exceed {AUTHORITATIVE_WINDOW:?}",
                self.jwks_ttl
            ));
        }
        if self.failure_cooldown >= self.jwks_ttl {
            return fail(format!(
                "failure_cooldown ({:?}) must be less than jwks_ttl ({:?})",
                self.failure_cooldown, self.jwks_ttl
            ));
        }
        if self.endpoint_capacity < configured_endpoints {
            return fail(format!(
                "endpoint_capacity ({}) is below the {configured_endpoints} configured endpoints",
                self.endpoint_capacity
            ));
        }
        if self.result_cache_ttl > MAX_RESULT_CACHE_TTL {
            return fail(format!(
                "result_cache_ttl ({:?}) must be at most {MAX_RESULT_CACHE_TTL:?}",
                self.result_cache_ttl
            ));
        }
        Ok(())
    }
}
