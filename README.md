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
    Some(Err(e)) => { /* token claimed a trusted issuer but failed validation — reject */ }
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
- Unknown `kid`s trigger one JWKS refetch (key rotation) before rejecting.

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

// Per request, on the verified claims:
let decoded = table.decode(&claims)?;
let can_query = decoded
    .env
    .as_ref()
    .and_then(|envs| envs.get(&environment_id))
    .is_some_and(|set| set.contains(PermissionIndex::new(3)));
```

Permissions missing from the table are dropped in either format, so a reader never grants
a permission it cannot name. Errors carry the reason codes of the shared fixture corpus in
`chalk-permission-claims/testdata/jwt_v2`, which is generated alongside the token issuer and
keeps this decoder in agreement with Chalk's Go, C++ and Python decoders. The corpus copy here is
payload-only: no signed tokens and no keys.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```
