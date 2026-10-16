# chalk-federated-auth

Federated JWT validation against trusted external issuers — most importantly
Chalk's metadata API server, which signs RS256 user/service JWTs and serves
OIDC discovery (`/.well-known/openid-configuration`) plus a JWKS endpoint
(`/.well-known/jwks.json`).

Extracted from `chalk-mcp-gateway/src/auth/oidc.rs` so any Chalk service
(chalk-mcp-gateway, chalk-router, ...) can accept Chalk-issued JWTs without
sharing a secret with the API server.

## Usage

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
    Some(Ok(claims)) => {
        /* authenticated; claims.sub is the Chalk user id and the optional
           claims.team_id / claims.environment_id identify its Chalk tenant */
    }
    Some(Err(e)) => { /* token claimed a trusted issuer but failed validation — reject */ }
}
```

Issuers can alternatively be configured with an explicit `jwks_uri`, or with
`secret_env` for HS256 shared-secret validation. `claims_map` remaps which
token claims populate `Claims::sub`, `Claims::scopes`, `Claims::team_id`, and
`Claims::environment_id` (Chalk user tokens carry the user id in `sub`; service
tokens carry permissions in `permissions`). Team and environment identities
default to the Chalk-standard `team_id` and `environment_id` claim names and
remain optional for generic OIDC issuers; tenant-aware services should require
the identities they use for isolation. The serde shape of `IssuerConfig`
matches the gateway's historical `[[oidc_issuers]]` TOML sections.

Applications that map additional claims (for example a CI repository to an
agent name) should use `try_validate_with_payload` instead. Its `VerifiedToken`
returns `claims()` for normalized identity, `issuer()` for the validated
issuer, and `payload()` for the original, verified JSON. Do not decode the JWT
again or use raw payload fields in place of mapped subject/team/environment
claims. The existing `try_validate` API retains its return type and fallback
behavior.

Absent tenant claims remain compatible with generic OIDC and existing
environment-dedicated tokens. Present null, non-string, empty, or surrounding-
whitespace identifiers are rejected, as are blank subjects and duplicate
issuer configurations. A dedicated service may bind a credential without
tenant claims to its configured environment; a hosted service must require
an authenticated tenant binding and check the environment's canonical team
ownership against trusted metadata before using it. Claim normalization alone
does not prove that relationship or authorize an operation. Interactive Chalk
tokens may carry `env_permissions` instead of a single `environment_id`;
use the tenant-binding API below to resolve those grants. `VerifiedToken`
alone is a verified claim container, not an authorized tenant context.

## Chalk tenant binding

For platform-configured Chalk issuers, call `verified.chalk_principal()?`, then
`principal.select_environment(request_selector)?`. Look up that environment's
canonical owner in trusted metadata or a platform-provisioned inventory and
call `principal.bind_environment(environment_id, owner_team_id)?`. Never pass
a caller's team header or the JWT's own team claim as the owner. Bind on every
request, even when signature verification is cached.

The resulting immutable `TenantContext` contains issuer, subject, principal
kind, canonical team, and environment. Check `tenant.permits(operation_permission)`
before invoking the operation, and clone the context into asynchronous work.
An environment selector cannot override a scoped credential, grant a user an
unlisted environment, or cross a team boundary. Impersonation is restricted to
the effective team. Exchange credentials, absent/unknown kinds, and malformed
grant claims are rejected. User and service-account tokens must name a team;
internal engine/metadata credentials may derive their missing team from trusted
environment ownership. These rules operate on normalized mapped tenant fields.

Tenant-managed third-party issuers must not be interpreted as Chalk identity
authorities. Legacy dedicated deployments can retain their existing verifier
without opting into this stricter contract. This library does not fetch metadata;
the caller supplies canonical ownership and handles lookup failures by denying
access. Provisioning and refreshing that inventory remain platform responsibilities.

## Security notes

- `peek_issuer` reads the **unverified** `iss` claim purely to route the token
  to the right key material; trust is only established by `try_validate`.
- The signing algorithm is taken from the token header but the key is fixed by
  issuer config, so an attacker cannot downgrade an RS256 issuer to HS256:
  `DecodingKey::from_jwk` keys only verify the JWK's key family.
- Unknown `kid`s trigger one JWKS refetch (key rotation) before rejecting.

## Development

```bash
cargo test
cargo clippy --all-targets -- -Dwarnings
cargo fmt
```
