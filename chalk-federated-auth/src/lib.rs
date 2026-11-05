//! Federated JWT validation against trusted external issuers.
//!
//! Extracted from chalk-mcp-gateway's `src/auth/oidc.rs` so that any Chalk
//! service (mcp-gateway, chalk-router, ...) can accept JWTs minted by Chalk's
//! metadata API server — or any other configured issuer — without sharing a
//! secret with it.
//!
//! The flow:
//! 1. Peek at the (unverified) `iss` claim of an incoming token.
//! 2. If it matches a configured [`IssuerConfig`], resolve that issuer's
//!    signing key — a shared secret from an env var (HS256), a static JWKS
//!    URI, or OIDC discovery (`{issuer}/.well-known/openid-configuration`) —
//!    and fully validate the token (signature, `exp`, optional `aud`).
//! 3. Return normalized [`Claims`]; the caller decides what the identity may
//!    do. A non-matching `iss` returns `None` so the caller can fall back to
//!    its own auth scheme (gateway JWT secret, admin key, API keys, ...).
//!
//! Chalk's metadata API serves OIDC discovery and a JWKS endpoint, so
//! federating with it only requires `IssuerConfig::discovery("https://api.chalk.ai")`
//! (signing keys rotate; never pin them).

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use base64::Engine;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
mod endpoint_cache;
mod options;
mod verification;
use endpoint_cache::{EndpointCache, Policy};
use options::AUTHORITATIVE_WINDOW;
pub use options::{RegistryOptions, SharedLimits};
use verification::ResultCache;

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Misconfiguration detected while building the registry.
    #[error("config error: {0}")]
    Config(String),
    /// Trusted identity infrastructure could not be reached or read.
    #[error("authentication temporarily unavailable: {0}")]
    Unavailable(String),
    /// Token failed validation (bad signature, claims, or key resolution).
    #[error("auth error: {0}")]
    Auth(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Identity normalized from a validated federated token.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject of the token, mapped from the issuer's configured subject
    /// claim (default `sub`; Chalk tokens carry the user id there).
    pub sub: String,
    /// Expiry as a unix timestamp; `0` when the issuer does not require one.
    pub exp: usize,
    /// Scopes/permissions, mapped from the issuer's configured scopes claim.
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Trusted external JWT issuer. Tokens whose `iss` claim matches `issuer` are
/// validated against the issuer's keys (JWKS or shared secret).
///
/// The serde shape is kept identical to chalk-mcp-gateway's historical
/// `[[oidc_issuers]]` TOML sections so existing gateway configs keep parsing.
#[derive(Debug, Clone, Deserialize)]
pub struct IssuerConfig {
    /// The `iss` claim value to match in incoming JWTs.
    pub issuer: String,
    /// JWKS endpoint for asymmetric key validation (RS256, ES256, etc.).
    /// Mutually exclusive with `secret_env`.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// OIDC discovery URL. When set, `{discovery_url}/.well-known/openid-configuration`
    /// is fetched to find `jwks_uri`. When omitted and `jwks_uri` is also
    /// omitted, auto-discovery uses the issuer itself if it is a URL.
    #[serde(default)]
    pub discovery_url: Option<String>,
    /// Environment variable holding the shared secret for HS256 validation.
    /// Mutually exclusive with `jwks_uri`.
    #[serde(default)]
    pub secret_env: Option<String>,
    /// Optional `aud` claim validation.
    #[serde(default)]
    pub audience: Option<String>,
    /// Maps normalized claim names to token claim names. Supported keys:
    ///   - `sub`    — which token claim becomes the identity (default: "sub")
    ///   - `scopes` — which token claim supplies scopes (default: "scopes")
    #[serde(default)]
    pub claims_map: HashMap<String, String>,
    /// Whether to require the `exp` claim. Defaults to true.
    #[serde(default = "default_true")]
    pub require_exp: bool,
}

fn default_true() -> bool {
    true
}

impl IssuerConfig {
    /// Issuer validated via OIDC discovery on the issuer URL itself — the
    /// right constructor for Chalk's metadata API server.
    pub fn discovery(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            jwks_uri: None,
            discovery_url: None,
            secret_env: None,
            audience: None,
            claims_map: HashMap::new(),
            require_exp: true,
        }
    }

    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }
}

enum KeySource {
    Secret(String),
    Jwks { uri: String },
    Discovery { issuer_url: String },
}

struct ResolvedIssuer {
    key_source: KeySource,
    audience: Option<String>,
    subject_claim: String,
    scopes_claim: String,
    require_exp: bool,
}

/// Registry of trusted issuers with endpoint-owned discovery/JWKS refreshes.
/// Construct once at startup and share; rebuilding defeats the key cache.
pub struct OidcRegistry {
    issuers: HashMap<String, ResolvedIssuer>,
    jwks: EndpointCache<jsonwebtoken::jwk::JwkSet>,
    discovery: EndpointCache<String>,
    http: reqwest::Client,
    verifications: ResultCache,
    jwks_ttl: Duration,
    validate_deadline: Option<Duration>,
}

impl OidcRegistry {
    /// Registry that trusts no issuers; `try_validate` always returns `None`.
    pub fn empty() -> Self {
        Self::from_config(&[]).expect("empty registry cannot fail")
    }

    /// Registry with [`RegistryOptions::default`].
    pub fn from_config(configs: &[IssuerConfig]) -> Result<Self> {
        Self::with_options(configs, RegistryOptions::default())
    }

    /// Registry with explicit deadlines, cache sizes, and refresh budgets.
    /// Inconsistent options are rejected with [`Error::Config`].
    pub fn with_options(configs: &[IssuerConfig], options: RegistryOptions) -> Result<Self> {
        let mut issuers = HashMap::new();
        for c in configs {
            let key_source = if let Some(ref env_name) = c.secret_env {
                let secret = std::env::var(env_name).map_err(|_| {
                    Error::Config(format!(
                        "issuer '{}': env var '{env_name}' not set",
                        c.issuer
                    ))
                })?;
                KeySource::Secret(secret)
            } else if let Some(ref uri) = c.jwks_uri {
                KeySource::Jwks { uri: uri.clone() }
            } else if let Some(ref url) = c.discovery_url {
                KeySource::Discovery {
                    issuer_url: url.clone(),
                }
            } else if c.issuer.starts_with("http://") || c.issuer.starts_with("https://") {
                KeySource::Discovery {
                    issuer_url: c.issuer.clone(),
                }
            } else {
                return Err(Error::Config(format!(
                    "issuer '{}': set jwks_uri, secret_env, or discovery_url \
                     (or use an https:// issuer for auto-discovery)",
                    c.issuer
                )));
            };

            let subject_claim = c
                .claims_map
                .get("sub")
                .cloned()
                .unwrap_or_else(|| "sub".to_string());
            let scopes_claim = c
                .claims_map
                .get("scopes")
                .cloned()
                .unwrap_or_else(|| "scopes".to_string());

            issuers.insert(
                c.issuer.clone(),
                ResolvedIssuer {
                    key_source,
                    audience: c.audience.clone(),
                    subject_claim,
                    scopes_claim,
                    require_exp: c.require_exp,
                },
            );
        }
        // Discovery issuers need one discovery entry and one JWKS entry each.
        let endpoints: HashSet<&str> = issuers
            .values()
            .filter_map(|issuer| match &issuer.key_source {
                KeySource::Secret(_) => None,
                KeySource::Jwks { uri } => Some(uri.as_str()),
                KeySource::Discovery { issuer_url } => Some(issuer_url.as_str()),
            })
            .collect();
        options.validate(endpoints.len())?;
        let policy = Policy {
            capacity: options.endpoint_capacity,
            deadline: options.refresh_deadline,
            cooldown: options.failure_cooldown,
        };
        Ok(Self {
            issuers,
            verifications: ResultCache::new(
                options.result_cache_capacity,
                options.result_cache_ttl,
            ),
            jwks: EndpointCache::new(options.limits.clone(), policy),
            discovery: EndpointCache::new(options.limits, policy),
            http: reqwest::Client::builder()
                .timeout(options.http_timeout)
                .build()
                .map_err(|e| Error::Config(e.to_string()))?,
            jwks_ttl: options.jwks_ttl,
            validate_deadline: options.validate_deadline,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.issuers.is_empty()
    }

    /// Try to validate a token against configured federated issuers.
    /// Returns `None` if the token's `iss` claim doesn't match any configured
    /// issuer — the caller should fall back to its own auth scheme.
    pub async fn try_validate(&self, token: &str) -> Option<Result<Claims>> {
        if self.issuers.is_empty() {
            return None;
        }
        let iss = peek_issuer(token)?;
        let issuer = self.issuers.get(&iss)?;
        let validation = self.validate_with_issuer(token, &iss, issuer);
        Some(match self.validate_deadline {
            Some(deadline) => tokio::time::timeout(deadline, validation)
                .await
                .unwrap_or_else(|_| Err(Error::Unavailable("token verification timed out".into()))),
            None => validation.await,
        })
    }

    async fn validate_with_issuer(
        &self,
        token: &str,
        iss: &str,
        issuer: &ResolvedIssuer,
    ) -> Result<Claims> {
        let header =
            decode_header(token).map_err(|e| Error::Auth(format!("invalid token header: {e}")))?;

        let (key, revision) = self.resolve_key(issuer, &header).await?;

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = issuer.require_exp;
        if !issuer.require_exp {
            // jsonwebtoken's default `required_spec_claims` demands that `exp`
            // be *present* even when expiry checking is off; drop it so
            // `require_exp = false` genuinely permits tokens without one.
            validation.required_spec_claims.remove("exp");
        }
        if let Some(ref aud) = issuer.audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }
        validation.set_issuer(&[iss]);

        let subject_claim = &issuer.subject_claim;
        let scopes_claim = &issuer.scopes_claim;
        self.verifications
            .verify(token, revision, issuer.require_exp, || {
                let token_data = decode::<serde_json::Value>(token, &key, &validation)
                    .map_err(|e| Error::Auth(format!("federated token invalid: {e}")))?;

                let sub = token_data
                    .claims
                    .get(subject_claim)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        Error::Auth(format!(
                            "token missing '{}' claim (mapped from sub)",
                            subject_claim
                        ))
                    })?
                    .to_string();

                let exp = token_data
                    .claims
                    .get("exp")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;

                let scopes = token_data
                    .claims
                    .get(scopes_claim)
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                Ok(Claims { sub, exp, scopes })
            })
    }

    async fn resolve_key(
        &self,
        issuer: &ResolvedIssuer,
        header: &jsonwebtoken::Header,
    ) -> Result<(DecodingKey, u64)> {
        match &issuer.key_source {
            KeySource::Secret(secret) => Ok((DecodingKey::from_secret(secret.as_bytes()), 0)),
            KeySource::Jwks { uri } => self.resolve_jwks_key(uri, header).await,
            KeySource::Discovery { issuer_url } => {
                let jwks_uri = self.discover_jwks_uri(issuer_url).await?;
                self.resolve_jwks_key(&jwks_uri, header).await
            }
        }
    }

    async fn resolve_jwks_key(
        &self,
        jwks_uri: &str,
        header: &jsonwebtoken::Header,
    ) -> Result<(DecodingKey, u64)> {
        let kid = header.kid.as_deref();
        let http = self.http.clone();
        let uri = jwks_uri.to_owned();
        let ttl = self.jwks_ttl;
        let cached = self
            .jwks
            .get(
                jwks_uri,
                |cached| {
                    let age = cached.fetched_at.elapsed();
                    // A newly fetched set is authoritative even for absent kids.
                    age < AUTHORITATIVE_WINDOW
                        || (age < ttl && find_jwk(&cached.value, kid).is_some())
                },
                move || async move { fetch_json(&http, &uri).await },
            )
            .await?;
        // A missing key is authoritative: the keyset was fetched within the
        // last second or was just refreshed for this request. Issuers must
        // publish a key before signing with it.
        let key = find_jwk(&cached.value, kid).ok_or_else(|| {
            Error::Auth(format!("no matching JWK found (kid={kid:?}) at {jwks_uri}"))
        })?;
        DecodingKey::from_jwk(key)
            .map(|key| (key, cached.revision))
            .map_err(|e| Error::Auth(format!("invalid JWK: {e}")))
    }

    async fn discover_jwks_uri(&self, issuer_url: &str) -> Result<String> {
        let http = self.http.clone();
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let cached = self
            .discovery
            .get(
                issuer_url,
                |_| true,
                move || async move {
                    let doc: serde_json::Value = fetch_json(&http, &url).await?;
                    let jwks_uri = doc
                        .get("jwks_uri")
                        .and_then(|value| value.as_str())
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            Error::Unavailable(format!("OIDC discovery at {url} has no jwks_uri"))
                        })?;
                    tracing::info!(discovery_url = %url, %jwks_uri, "discovered JWKS endpoint");
                    Ok(jwks_uri)
                },
            )
            .await?;
        Ok(cached.value.clone())
    }
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
) -> Result<T> {
    let response = http
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| {
            Error::Unavailable(format!("identity fetch from {url} failed: {error}"))
        })?;
    response.json().await.map_err(|error| {
        Error::Unavailable(format!("identity response from {url} is invalid: {error}"))
    })
}

/// Extract the `iss` claim from a JWT without validating it. Used to route a
/// token to the right issuer before signature verification; never treat the
/// result as authenticated.
pub fn peek_issuer(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let unpadded = payload_b64.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(unpadded)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("iss")?.as_str().map(String::from)
}

fn find_jwk<'a>(
    jwks: &'a jsonwebtoken::jwk::JwkSet,
    kid: Option<&str>,
) -> Option<&'a jsonwebtoken::jwk::Jwk> {
    match kid {
        Some(kid) => jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid)),
        // Single-key JWKS — common with Kubernetes API servers.
        None if jwks.keys.len() == 1 => jwks.keys.first(),
        None => None,
    }
}
