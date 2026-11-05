# chalk-federated-auth

Rust crates for accepting Chalk-issued JWTs outside the Chalk API server:

- [`chalk-federated-auth`](chalk-federated-auth/): validates tokens from trusted issuers.
- [`chalk-permission-claims`](chalk-permission-claims/): decodes a validated token's
  permission claims.

Depend on either through git; Cargo finds each crate by name:

```toml
chalk-federated-auth = { git = "https://github.com/chalk-ai/chalk-federated-auth", branch = "main" }
chalk-permission-claims = { git = "https://github.com/chalk-ai/chalk-federated-auth", branch = "main" }
```

## chalk-federated-auth

Federated JWT validation against trusted external issuers — most importantly
Chalk's metadata API server, which signs RS256 user/service JWTs and serves
OIDC discovery (`/.well-known/openid-configuration`) plus a JWKS endpoint
(`/.well-known/jwks.json`).

Extracted from `chalk-mcp-gateway/src/auth/oidc.rs` so any Chalk service
(chalk-mcp-gateway, chalk-router, ...) can accept Chalk-issued JWTs without
sharing a secret with the API server.

### Usage

```rust
use chalk_federated_auth::{IssuerConfig, OidcRegistry};

// At startup. The registry caches JWKS (5 min TTL) and discovery results,
// so construct it once and share it.
let registry = OidcRegistry::from_config(&[
    IssuerConfig::discovery("https://api.chalk.ai"),
])?;

// Per request:
match registry.try_validate(bearer_token).await {
    None => { /* token's `iss` is not a trusted issuer — fall back to your own auth */ }
    Some(Ok(claims)) => { /* authenticated; claims.sub is the Chalk user id */ }
    Some(Err(chalk_federated_auth::Error::Unavailable(e))) => { /* retryable identity infrastructure/overload error; e.g. HTTP 503 */ }
    Some(Err(e)) => { /* invalid credentials — reject */ }
}
```

Issuers can alternatively be configured with an explicit `jwks_uri`, or with
`secret_env` for HS256 shared-secret validation. `claims_map` remaps which
token claims populate `Claims::sub` / `Claims::scopes` (Chalk user tokens
carry the user id in `sub`; service tokens carry permissions in
`permissions`). The serde shape of `IssuerConfig` matches the gateway's
historical `[[oidc_issuers]]` TOML sections.

### Security notes

- `peek_issuer` reads the **unverified** `iss` claim purely to route the token
  to the right key material; trust is only established by `try_validate`.
- The signing algorithm is taken from the token header but the key is fixed by
  issuer config, so an attacker cannot downgrade an RS256 issuer to HS256:
  `DecodingKey::from_jwk` keys only verify the JWK's key family.
- Unknown `kid`s trigger a shared JWKS refetch for key rotation. A newly fetched
  keyset is authoritative for one second for keys it lacks: a token with such a
  `kid` is rejected with `Error::Auth`, unless its `iat` is within 30 seconds
  before the fetch or later, in which case the issuer may have published the key
  since and the result is a retryable `Error::Unavailable`. `iat` is unverified,
  so a forged token can only choose a 503 over a 401.

### Refreshes and verification

Construct one registry and share it. Discovery and JWKS loads coalesce by trusted
endpoint and continue in the background if a caller disconnects or times out.
Callers that join a load do not consume admission slots. By default each registry
tracks up to 1,024 endpoints, and the process allows 256 active or queued endpoint
loads and 16 concurrent HTTP requests with FIFO admission. HTTP requests time out
after two seconds; each endpoint load and each `try_validate` call have a
three-second deadline. Failed HTTP calls, and loads that time out after HTTP
admission, back off for one second. Queue-only timeouts and local admission
failures do not mark an endpoint failed.

Fresh known signing keys bypass refresh, even while a rotation fetch is running
or failing. Keysets expire after 300 seconds and then require a successful
refresh; expired keys are not reused during outages. A successful refresh
replaces the keyset, including removing keys the issuer no longer publishes. A
refresh that returns the same keyset keeps its revision.

Signature checks run inline once keys are resolved. Successful results are reused
for one second, keyed by token digest and keyset revision, with expiry checked on
every reuse; failures are not cached. Key resolution always runs first, so reuse
cannot bypass expired or replaced keys. Each registry caches at most 4,096
results; when full, new results are simply not cached, and requests are never
rejected for cache capacity. The library logs no tokens or unverified claims;
error messages name the requested `kid` and JWKS URL.

`Error::Auth` means credential validation failed. `Error::Unavailable` means the
caller should retry: identity infrastructure, local capacity, or a deadline
prevented validation. `Error` is `#[non_exhaustive]`, so matches need a wildcard
arm. Structured tracing events report refresh admission, completion, queue/fetch
durations, and failure cooldown once per load, rather than once per waiting token.

### Options

`OidcRegistry::with_options` takes a `RegistryOptions`; `from_config` uses the
defaults above. Start from `RegistryOptions::default()` and assign the fields to
change:

```rust
use chalk_federated_auth::{OidcRegistry, RegistryOptions, SharedLimits};

let mut options = RegistryOptions::default();
options.validate_deadline = None; // the service applies its own request deadline
options.limits = SharedLimits::new(8, 128)?; // share this handle across registries
let registry = OidcRegistry::with_options(&issuers, options)?;
```

| Field | Default | Rule |
|---|---|---|
| `http_timeout` | 2s | positive |
| `refresh_deadline` | 3s | greater than `http_timeout` |
| `validate_deadline` | `Some(3s)` | positive; `None` leaves it to the caller |
| `failure_cooldown` | 1s | less than `jwks_ttl`; zero disables backoff |
| `jwks_ttl` | 300s | greater than the 1s authoritative window |
| `endpoint_capacity` | 1,024 | at least the configured JWKS/discovery endpoints |
| `result_cache_capacity` | 4,096 | zero disables result reuse |
| `result_cache_ttl` | 1s | at most 60s; zero disables result reuse |
| `limits` | `SharedLimits::global()` | `SharedLimits::new(http_calls, refresh_owners)` requires `1 <= http_calls <= refresh_owners` |

Registries holding the same `SharedLimits` handle share its HTTP and refresh
budgets; the global handle is shared by every registry that does not set one.
Invalid combinations fail with `Error::Config` when the registry is built.

## chalk-permission-claims

Decodes a token's permission claims in either format Chalk mints:

- **V1:** permission slugs in `env_permissions` (environment id to slugs),
  `team_permissions`, `permissions` and `requestable_perms`.
- **V2:** `v: 2` and the same grants in `p` as unpadded base64url bitsets, in which
  permission n is bit `n % 8` of byte `n / 8`.
- **Dual:** `v: 1` with both; the V1 claims are authoritative.

It only reads claims. Verify the token's signature first, for example with
`chalk-federated-auth`.

```rust
use chalk_permission_claims::{PermissionIndex, PermissionTable};

// Once, at startup, from the reader's own `chalk.auth.v1.Permission` enum: (enum number, V1 slug).
// Keep it in the struct that owns your auth and borrow it per request.
let table = PermissionTable::new([(3, "query.online"), (11, "deploy.read")])?;

// Per request, on the verified claims, with `environment_id: &str`:
let decoded = table.decode(&claims)?;
let can_query = decoded
    .env
    .as_ref()
    .and_then(|envs| envs.get(environment_id))
    .is_some_and(|set| set.contains(PermissionIndex::new(3)));
```

Permissions missing from the table are dropped in either format, so a reader never grants
a permission it cannot name. Decoding does not allowlist `kind`: an unrecognized kind decodes
with every field `None`, so accept only the kinds you serve, and never read `agent: None` as
unrestricted; only `AgentGrant::Unrestricted` is. Errors carry the reason codes of the shared fixture corpus in
`chalk-permission-claims/testdata/jwt_v2`, which is generated alongside the token issuer and
keeps this decoder in agreement with Chalk's Go, C++ and Python decoders. The corpus copy here is
payload-only: no signed tokens and no keys.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```
