use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use axum::{http::StatusCode, routing::get, Json, Router};
use base64::Engine;
use chalk_federated_auth::{Error, IssuerConfig, OidcRegistry, RegistryOptions, SharedLimits};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};
use tokio::sync::{Notify, Semaphore};

const SECRET: &str = "signing-secret-one";

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn new(app: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, task }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct KeyServer {
    server: Server,
    calls: Arc<AtomicUsize>,
    // 0: serve keys; 1: wait for release; 503: return an outage.
    mode: Arc<AtomicUsize>,
    keys: Arc<RwLock<Value>>,
    started: Arc<Notify>,
    release: Arc<Semaphore>,
}
impl KeyServer {
    async fn new() -> Self {
        let calls = Arc::new(AtomicUsize::new(0));
        let mode = Arc::new(AtomicUsize::new(0));
        let keys = Arc::new(RwLock::new(jwks("one", SECRET)));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let server = Server::new(Router::new().route(
            "/",
            get({
                let (calls, mode, keys, started, release) = (
                    calls.clone(),
                    mode.clone(),
                    keys.clone(),
                    started.clone(),
                    release.clone(),
                );
                move || {
                    let (calls, mode, keys, started, release) = (
                        calls.clone(),
                        mode.clone(),
                        keys.clone(),
                        started.clone(),
                        release.clone(),
                    );
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let mode = mode.load(Ordering::SeqCst);
                        if mode == 1 {
                            started.notify_one();
                            release.acquire().await.unwrap().forget();
                        }
                        if mode == 503 {
                            return Err(StatusCode::SERVICE_UNAVAILABLE);
                        }
                        Ok(Json(keys.read().unwrap().clone()))
                    }
                }
            }),
        ))
        .await;
        Self {
            server,
            calls,
            mode,
            keys,
            started,
            release,
        }
    }
    fn config(&self, issuer: &str) -> IssuerConfig {
        IssuerConfig {
            jwks_uri: Some(self.server.url.clone()),
            ..IssuerConfig::discovery(issuer)
        }
    }
}

// Generate each throwaway asymmetric key once; all concurrent refresh tests
// share small Ed25519 fixtures while retaining real signature verification.
fn test_key(name: &str) -> &'static (EncodingKey, Value) {
    static KEYS: LazyLock<HashMap<&str, (EncodingKey, Value)>> = LazyLock::new(|| {
        [
            SECRET,
            "signing-secret-two",
            "replacement-secret",
            "attacker-secret",
        ]
        .into_iter()
        .map(|name| {
            let der =
                Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new()).unwrap();
            let key = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
            let public =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref());
            let jwk = json!({"kty":"OKP", "crv":"Ed25519", "alg":"EdDSA", "use":"sig", "x":public});
            (name, (EncodingKey::from_ed_der(der.as_ref()), jwk))
        })
        .collect()
    });
    &KEYS[name]
}
fn jwks(kid: &str, key_name: &str) -> Value {
    let mut jwk = test_key(key_name).1.clone();
    jwk["kid"] = json!(kid);
    json!({"keys": [jwk]})
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn signed(claims: Value, kid: &str, secret: &str) -> String {
    let header = Header {
        alg: jsonwebtoken::Algorithm::EdDSA,
        kid: Some(kid.into()),
        ..Header::default()
    };
    encode(&header, &claims, &test_key(secret).0).unwrap()
}
fn token(issuer: &str, subject: &str, kid: &str, secret: &str) -> String {
    signed(
        json!({"iss":issuer,"sub":subject,"exp":now() + 600}),
        kid,
        secret,
    )
}
fn token_issued_at(issuer: &str, iat: u64, kid: &str, secret: &str) -> String {
    signed(
        json!({"iss":issuer,"sub":"user","iat":iat,"exp":now() + 600}),
        kid,
        secret,
    )
}
async fn advance(seconds: u64) {
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(seconds)).await;
    tokio::time::resume();
}

#[tokio::test]
async fn expired_keys_share_a_large_valid_burst_after_cancellation_without_blocking_another_issuer()
{
    let keys = KeyServer::new().await;
    let healthy = KeyServer::new().await;
    let registry = Arc::new(
        OidcRegistry::from_config(&[keys.config("burst"), healthy.config("healthy")]).unwrap(),
    );
    assert!(registry
        .try_validate(&token("burst", "warm", "one", SECRET))
        .await
        .unwrap()
        .is_ok());
    advance(301).await;
    keys.mode.store(1, Ordering::SeqCst);
    let first = tokio::spawn({
        let registry = registry.clone();
        async move {
            registry
                .try_validate(&token("burst", "cancelled", "one", SECRET))
                .await
        }
    });
    keys.started.notified().await;
    first.abort();
    let _ = first.await;
    let entered = Arc::new(AtomicUsize::new(0));
    let followers: Vec<_> = (0..512)
        .map(|i| {
            let (registry, entered) = (registry.clone(), entered.clone());
            tokio::spawn(async move {
                entered.fetch_add(1, Ordering::SeqCst);
                registry
                    .try_validate(&token("burst", &format!("user-{i}"), "one", SECRET))
                    .await
            })
        })
        .collect();
    tokio::time::timeout(Duration::from_secs(1), async {
        while entered.load(Ordering::SeqCst) != 512 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        followers.iter().all(|follower| !follower.is_finished()),
        "followers await keys instead of consuming verification admission"
    );
    assert!(tokio::time::timeout(
        Duration::from_secs(1),
        registry.try_validate(&token("healthy", "user", "one", SECRET))
    )
    .await
    .unwrap()
    .unwrap()
    .is_ok());
    keys.release.add_permits(1);
    for follower in followers {
        assert!(follower.await.unwrap().unwrap().is_ok());
    }
    assert_eq!(keys.calls.load(Ordering::SeqCst), 2);
    assert_eq!(healthy.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn fresh_known_keys_bypass_a_shared_unknown_kid_refresh() {
    let keys = KeyServer::new().await;
    let registry = Arc::new(OidcRegistry::from_config(&[keys.config("known")]).unwrap());
    let known = token("known", "user", "one", SECRET);
    assert!(registry.try_validate(&known).await.unwrap().is_ok());
    advance(2).await;
    keys.mode.store(1, Ordering::SeqCst);
    let followers: Vec<_> = (0..512)
        .map(|i| {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .try_validate(&token("known", &format!("unknown-{i}"), "missing", SECRET))
                    .await
            })
        })
        .collect();
    keys.started.notified().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), registry.try_validate(&known))
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    keys.release.add_permits(1);
    for follower in followers {
        assert!(matches!(follower.await.unwrap(), Some(Err(Error::Auth(_)))));
    }
    assert_eq!(keys.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn replacement_keys_and_expiry_override_signature_memoization_and_outages_back_off() {
    let keys = KeyServer::new().await;
    let registry = OidcRegistry::from_config(&[keys.config("rotation")]).unwrap();
    let old = token("rotation", "user", "one", SECRET);
    let new = token("rotation", "user", "two", "signing-secret-two");
    assert!(registry.try_validate(&old).await.unwrap().is_ok());
    *keys.keys.write().unwrap() = jwks("two", "signing-secret-two");
    assert!(matches!(
        registry.try_validate(&new).await,
        Some(Err(Error::Auth(_)))
    ));
    assert_eq!(
        keys.calls.load(Ordering::SeqCst),
        1,
        "a newly fetched set is briefly authoritative"
    );
    advance(2).await;
    assert!(registry.try_validate(&new).await.unwrap().is_ok());
    assert!(
        matches!(registry.try_validate(&old).await, Some(Err(Error::Auth(_)))),
        "removed keys are authoritative"
    );
    keys.mode.store(503, Ordering::SeqCst);
    advance(301).await;
    assert!(
        matches!(
            registry.try_validate(&new).await,
            Some(Err(Error::Unavailable(_)))
        ),
        "expired keys are not reused during outages"
    );
    assert!(matches!(
        registry.try_validate(&new).await,
        Some(Err(Error::Unavailable(_)))
    ));
    assert_eq!(
        keys.calls.load(Ordering::SeqCst),
        3,
        "actual endpoint failures back off"
    );
    keys.mode.store(0, Ordering::SeqCst);
    advance(1).await;
    assert!(registry.try_validate(&new).await.unwrap().is_ok());
}

#[tokio::test]
async fn caller_deadline_does_not_cancel_or_poison_shared_discovery_and_keys() {
    let keys = KeyServer::new().await;
    keys.mode.store(1, Ordering::SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    let discovery = Server::new(Router::new().route(
        "/.well-known/openid-configuration",
        get({
            let (calls, url) = (calls.clone(), keys.server.url.clone());
            move || {
                let (calls, url) = (calls.clone(), url.clone());
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(1400)).await;
                    Json(json!({"issuer":"deadline", "jwks_uri":url}))
                }
            }
        }),
    ))
    .await;
    let registry = OidcRegistry::from_config(&[IssuerConfig {
        discovery_url: Some(discovery.url.clone()),
        ..IssuerConfig::discovery("deadline")
    }])
    .unwrap();
    let token = token("deadline", "user", "one", SECRET);
    assert!(matches!(
        registry.try_validate(&token).await,
        Some(Err(Error::Unavailable(_)))
    ));
    assert_eq!(keys.calls.load(Ordering::SeqCst), 1);
    keys.release.add_permits(1);
    assert!(registry.try_validate(&token).await.unwrap().is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(keys.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_replaced_key_with_the_same_kid_cannot_reuse_a_previous_signature_result() {
    let keys = KeyServer::new().await;
    let registry = OidcRegistry::from_config(&[keys.config("same-kid")]).unwrap();
    let old = token("same-kid", "user", "one", SECRET);
    assert!(registry.try_validate(&old).await.unwrap().is_ok());
    advance(2).await;
    // Repopulate signature memoization immediately before a rotation fetch.
    assert!(registry.try_validate(&old).await.unwrap().is_ok());
    let mut replacement = jwks("one", "replacement-secret");
    replacement["keys"]
        .as_array_mut()
        .unwrap()
        .push(jwks("two", "replacement-secret")["keys"][0].clone());
    *keys.keys.write().unwrap() = replacement;
    let new = token("same-kid", "user", "two", "replacement-secret");
    assert!(registry.try_validate(&new).await.unwrap().is_ok());
    assert!(
        matches!(registry.try_validate(&old).await, Some(Err(Error::Auth(_)))),
        "keyset revision must invalidate the successful check for the exact old token"
    );
    assert_eq!(keys.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn invalid_identity_responses_are_unavailable_and_share_failure_backoff() {
    for (discovery, status, body) in [
        (true, StatusCode::OK, "{}"),
        (true, StatusCode::SERVICE_UNAVAILABLE, "offline"),
        (false, StatusCode::OK, "invalid JSON"),
        (false, StatusCode::SERVICE_UNAVAILABLE, "offline"),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let path = if discovery {
            "/.well-known/openid-configuration"
        } else {
            "/"
        };
        let server = Server::new(Router::new().route(
            path,
            get({
                let calls = calls.clone();
                move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        (status, body)
                    }
                }
            }),
        ))
        .await;
        let mut config = IssuerConfig::discovery("invalid-response");
        if discovery {
            config.discovery_url = Some(server.url.clone());
        } else {
            config.jwks_uri = Some(server.url.clone());
        }
        let registry = OidcRegistry::from_config(&[config]).unwrap();
        let token = token("invalid-response", "user", "one", SECRET);
        for _ in 0..2 {
            assert!(matches!(
                registry.try_validate(&token).await,
                Some(Err(Error::Unavailable(_)))
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn a_key_missing_from_a_fresh_keyset_is_rejected_until_the_cooldown_allows_a_refresh() {
    let keys = KeyServer::new().await;
    let registry = OidcRegistry::from_config(&[keys.config("publish")]).unwrap();
    assert!(registry
        .try_validate(&token("publish", "user", "one", SECRET))
        .await
        .unwrap()
        .is_ok());
    // The issuer starts signing with a key published after our fetch.
    *keys.keys.write().unwrap() = jwks("two", "signing-secret-two");
    let new = token("publish", "user", "two", "signing-secret-two");
    for _ in 0..3 {
        assert!(matches!(
            registry.try_validate(&new).await,
            Some(Err(Error::Auth(_)))
        ));
    }
    assert_eq!(
        keys.calls.load(Ordering::SeqCst),
        1,
        "the one-second cooldown absorbs repeated unknown kids"
    );
    advance(2).await;
    assert!(registry.try_validate(&new).await.unwrap().is_ok());
    assert_eq!(keys.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn registries_sharing_limits_share_refresh_capacity() {
    let busy = KeyServer::new().await;
    let other = KeyServer::new().await;
    busy.mode.store(1, Ordering::SeqCst);
    let limits = SharedLimits::new(1, 1).unwrap();
    let options = || {
        let mut options = RegistryOptions::default();
        options.limits = limits.clone();
        options
    };
    let first = Arc::new(OidcRegistry::with_options(&[busy.config("busy")], options()).unwrap());
    let second = OidcRegistry::with_options(&[other.config("other")], options()).unwrap();
    let pending = tokio::spawn({
        let first = first.clone();
        async move {
            first
                .try_validate(&token("busy", "user", "one", SECRET))
                .await
        }
    });
    busy.started.notified().await;
    assert!(
        matches!(
            second
                .try_validate(&token("other", "user", "one", SECRET))
                .await,
            Some(Err(Error::Unavailable(_)))
        ),
        "the only refresh slot belongs to the other registry"
    );
    busy.release.add_permits(1);
    assert!(pending.await.unwrap().unwrap().is_ok());
    assert!(second
        .try_validate(&token("other", "user", "one", SECRET))
        .await
        .unwrap()
        .is_ok());
    assert_eq!(other.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_full_result_cache_never_rejects_valid_tokens() {
    let keys = KeyServer::new().await;
    let mut options = RegistryOptions::default();
    options.result_cache_capacity = 1;
    let registry = Arc::new(OidcRegistry::with_options(&[keys.config("full")], options).unwrap());
    let checks: Vec<_> = (0..64)
        .map(|i| {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .try_validate(&token("full", &format!("user-{i}"), "one", SECRET))
                    .await
            })
        })
        .collect();
    for check in checks {
        assert!(check.await.unwrap().unwrap().is_ok());
    }
}

#[test]
fn inconsistent_options_are_rejected_at_construction() {
    let issuers = [
        IssuerConfig {
            jwks_uri: Some("https://a.example/jwks".into()),
            ..IssuerConfig::discovery("a")
        },
        IssuerConfig::discovery("https://b.example"),
    ];
    type Change = fn(&mut RegistryOptions);
    let invalid: [(&str, Change); 7] = [
        ("zero http timeout", |o| o.http_timeout = Duration::ZERO),
        ("refresh deadline within the http timeout", |o| {
            o.refresh_deadline = o.http_timeout
        }),
        ("zero validate deadline", |o| {
            o.validate_deadline = Some(Duration::ZERO)
        }),
        ("keys shorter-lived than the authoritative window", |o| {
            o.jwks_ttl = Duration::from_secs(1)
        }),
        ("keys trusted for over a day", |o| {
            o.jwks_ttl = Duration::from_secs(86_401)
        }),
        ("cooldown outlasting the keys", |o| {
            o.failure_cooldown = o.jwks_ttl
        }),
        ("result reuse beyond a minute", |o| {
            o.result_cache_ttl = Duration::from_secs(61)
        }),
    ];
    for (case, change) in invalid {
        let mut options = RegistryOptions::default();
        change(&mut options);
        assert!(
            matches!(
                OidcRegistry::with_options(&issuers, options),
                Err(Error::Config(_))
            ),
            "{case}"
        );
    }
    let mut custom = RegistryOptions::default();
    custom.http_timeout = Duration::from_millis(500);
    custom.refresh_deadline = Duration::from_secs(1);
    custom.validate_deadline = None;
    custom.failure_cooldown = Duration::ZERO;
    custom.result_cache_capacity = 0;
    custom.limits = SharedLimits::new(4, 8).unwrap();
    assert!(OidcRegistry::with_options(&issuers, custom).is_ok());
    assert!(matches!(SharedLimits::new(0, 1), Err(Error::Config(_))));
    assert!(matches!(SharedLimits::new(2, 1), Err(Error::Config(_))));
}

#[tokio::test]
async fn an_unknown_kid_with_an_extreme_iat_is_rejected_without_panicking() {
    let keys = KeyServer::new().await;
    let registry = OidcRegistry::from_config(&[keys.config("overflow")]).unwrap();
    assert!(registry
        .try_validate(&token("overflow", "user", "one", SECRET))
        .await
        .unwrap()
        .is_ok());
    // Forged: unknown kid, so validation stops at key lookup, before the signature.
    let forged = token_issued_at("overflow", u64::MAX, "forged-kid", "attacker-secret");
    assert!(matches!(
        registry.try_validate(&forged).await,
        Some(Err(Error::Auth(_)))
    ));
}
