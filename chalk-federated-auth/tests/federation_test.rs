use std::collections::HashMap;

use base64::Engine;
use chalk_federated_auth::{peek_issuer, IssuerConfig, OidcRegistry};
use jsonwebtoken::{encode, EncodingKey, Header};
use rsa::traits::PublicKeyParts;

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hs256_token(secret: &str, claims: &serde_json::Value) -> String {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("encode HS256 token")
}

fn future_exp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
        + 600
}

fn secret_issuer(issuer: &str, env_name: &str, secret: &str) -> IssuerConfig {
    // SAFETY-of-tests note: each test uses a unique env var name, so parallel
    // test threads never race on the same variable.
    std::env::set_var(env_name, secret);
    IssuerConfig {
        issuer: issuer.to_string(),
        jwks_uri: None,
        discovery_url: None,
        secret_env: Some(env_name.to_string()),
        audience: None,
        claims_map: HashMap::new(),
        require_exp: true,
    }
}

#[tokio::test]
async fn hs256_roundtrip_and_claim_mapping() {
    let mut config = secret_issuer("chalk-test-hs256", "FED_TEST_SECRET_A", "s3cret");
    config.claims_map = HashMap::from([
        ("sub".to_string(), "email".to_string()),
        ("scopes".to_string(), "permissions".to_string()),
    ]);
    let registry = OidcRegistry::from_config(&[config]).expect("registry");

    let token = hs256_token(
        "s3cret",
        &serde_json::json!({
            "iss": "chalk-test-hs256",
            "email": "andy@chalk.ai",
            "permissions": ["team:admin"],
            "exp": future_exp(),
        }),
    );

    let claims = registry
        .try_validate(&token)
        .await
        .expect("issuer should match")
        .expect("token should validate");
    assert_eq!(claims.sub, "andy@chalk.ai");
    assert_eq!(claims.scopes, vec!["team:admin".to_string()]);
}

#[tokio::test]
async fn unknown_issuer_returns_none() {
    let config = secret_issuer("chalk-test-known", "FED_TEST_SECRET_B", "s3cret");
    let registry = OidcRegistry::from_config(&[config]).expect("registry");

    let token = hs256_token(
        "s3cret",
        &serde_json::json!({ "iss": "someone-else", "sub": "u", "exp": future_exp() }),
    );
    assert!(registry.try_validate(&token).await.is_none());

    // Tokens with no iss at all also fall through to the caller.
    let token = hs256_token("s3cret", &serde_json::json!({ "sub": "u" }));
    assert!(registry.try_validate(&token).await.is_none());
}

#[tokio::test]
async fn empty_registry_matches_nothing() {
    let registry = OidcRegistry::empty();
    assert!(registry.is_empty());
    let token = hs256_token(
        "whatever",
        &serde_json::json!({ "iss": "x", "sub": "u", "exp": future_exp() }),
    );
    assert!(registry.try_validate(&token).await.is_none());
}

#[tokio::test]
async fn wrong_secret_rejected() {
    let config = secret_issuer("chalk-test-wrong-secret", "FED_TEST_SECRET_C", "right");
    let registry = OidcRegistry::from_config(&[config]).expect("registry");

    let token = hs256_token(
        "wrong",
        &serde_json::json!({ "iss": "chalk-test-wrong-secret", "sub": "u", "exp": future_exp() }),
    );
    let result = registry
        .try_validate(&token)
        .await
        .expect("issuer should match");
    assert!(result.is_err());
}

#[tokio::test]
async fn verification_results_are_isolated_between_registries() {
    let trusted = OidcRegistry::from_config(&[secret_issuer(
        "shared-issuer",
        "FED_TEST_ISOLATION_TRUSTED",
        "right",
    )])
    .unwrap();
    let other = OidcRegistry::from_config(&[secret_issuer(
        "shared-issuer",
        "FED_TEST_ISOLATION_OTHER",
        "wrong",
    )])
    .unwrap();
    let token = hs256_token(
        "right",
        &serde_json::json!({
            "iss": "shared-issuer", "sub": "user", "exp": future_exp(),
        }),
    );
    assert!(trusted.try_validate(&token).await.unwrap().is_ok());
    assert!(matches!(
        other.try_validate(&token).await,
        Some(Err(chalk_federated_auth::Error::Auth(_)))
    ));
    assert!(trusted.try_validate(&token).await.unwrap().is_ok());
}

#[tokio::test]
async fn expired_token_rejected() {
    let config = secret_issuer("chalk-test-expired", "FED_TEST_SECRET_D", "s3cret");
    let registry = OidcRegistry::from_config(&[config]).expect("registry");

    let token = hs256_token(
        "s3cret",
        &serde_json::json!({ "iss": "chalk-test-expired", "sub": "u", "exp": 1 }),
    );
    let result = registry
        .try_validate(&token)
        .await
        .expect("issuer should match");
    assert!(result.is_err());
}

#[tokio::test]
async fn require_exp_false_allows_missing_exp() {
    let mut config = secret_issuer("chalk-test-noexp", "FED_TEST_SECRET_E", "s3cret");
    config.require_exp = false;
    let registry = OidcRegistry::from_config(&[config]).expect("registry");

    let token = hs256_token(
        "s3cret",
        &serde_json::json!({ "iss": "chalk-test-noexp", "sub": "u" }),
    );
    let claims = registry
        .try_validate(&token)
        .await
        .expect("issuer should match")
        .expect("token without exp should validate when require_exp = false");
    assert_eq!(claims.sub, "u");
    assert_eq!(claims.exp, 0);
}

#[tokio::test]
async fn audience_validation() {
    let mut config = secret_issuer("chalk-test-aud", "FED_TEST_SECRET_F", "s3cret");
    config.audience = Some("chalk-router".to_string());
    let registry = OidcRegistry::from_config(&[config]).expect("registry");

    let good = hs256_token(
        "s3cret",
        &serde_json::json!({
            "iss": "chalk-test-aud", "sub": "u", "aud": "chalk-router", "exp": future_exp(),
        }),
    );
    assert!(registry.try_validate(&good).await.expect("match").is_ok());

    let bad = hs256_token(
        "s3cret",
        &serde_json::json!({
            "iss": "chalk-test-aud", "sub": "u", "aud": "other", "exp": future_exp(),
        }),
    );
    assert!(registry.try_validate(&bad).await.expect("match").is_err());
}

#[tokio::test]
async fn missing_secret_env_is_config_error() {
    let config = IssuerConfig {
        issuer: "chalk-test-missing-env".to_string(),
        jwks_uri: None,
        discovery_url: None,
        secret_env: Some("FED_TEST_SECRET_DOES_NOT_EXIST".to_string()),
        audience: None,
        claims_map: HashMap::new(),
        require_exp: true,
    };
    assert!(OidcRegistry::from_config(&[config]).is_err());
}

#[tokio::test]
async fn non_url_issuer_without_keys_is_config_error() {
    let config = IssuerConfig {
        issuer: "not-a-url".to_string(),
        jwks_uri: None,
        discovery_url: None,
        secret_env: None,
        audience: None,
        claims_map: HashMap::new(),
        require_exp: true,
    };
    assert!(OidcRegistry::from_config(&[config]).is_err());
}

#[test]
fn peek_issuer_reads_unverified_iss() {
    let token = hs256_token(
        "any",
        &serde_json::json!({ "iss": "https://api.chalk.ai", "sub": "u" }),
    );
    assert_eq!(peek_issuer(&token).as_deref(), Some("https://api.chalk.ai"));
    assert_eq!(peek_issuer("not-a-jwt"), None);
}

/// Spin up a local OIDC issuer (discovery + JWKS over HTTP) and validate an
/// RS256 token end-to-end — the exact shape of federation with Chalk's
/// metadata API server, which signs RS256 with a `kid` header and serves
/// `/.well-known/openid-configuration` + `/.well-known/jwks.json`.
#[tokio::test]
async fn rs256_via_oidc_discovery() {
    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
    let public_key = private_key.to_public_key();

    let pem =
        rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_pem(&private_key, rsa::pkcs8::LineEnding::LF)
            .expect("encode private key PEM");
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("private key");

    let jwk = serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "test-key-1",
        "n": b64url(&public_key.n().to_bytes_be()),
        "e": b64url(&public_key.e().to_bytes_be()),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let issuer = format!("http://{addr}");

    let jwks_uri = format!("{issuer}/.well-known/jwks.json");
    let discovery_doc = serde_json::json!({ "issuer": issuer, "jwks_uri": jwks_uri });
    let jwks_doc = serde_json::json!({ "keys": [jwk] });
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let doc = discovery_doc.clone();
                async move { axum::Json(doc) }
            }),
        )
        .route(
            "/.well-known/jwks.json",
            axum::routing::get(move || {
                let doc = jwks_doc.clone();
                async move { axum::Json(doc) }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let registry =
        OidcRegistry::from_config(&[IssuerConfig::discovery(issuer.clone())]).expect("registry");

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    let token = encode(
        &header,
        &serde_json::json!({
            "iss": issuer,
            "sub": "user_123",
            "kind": "user",
            "team_id": "team_456",
            "exp": future_exp(),
        }),
        &encoding_key,
    )
    .expect("encode RS256 token");

    let claims = registry
        .try_validate(&token)
        .await
        .expect("issuer should match")
        .expect("token should validate");
    assert_eq!(claims.sub, "user_123");

    // A token signed by a different key but claiming the same kid/issuer must
    // be rejected — JWKS lookup succeeds, signature verification fails.
    let attacker_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate attacker key");
    let attacker_pem =
        rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_pem(&attacker_key, rsa::pkcs8::LineEnding::LF)
            .expect("encode attacker PEM");
    let forged = encode(
        &header,
        &serde_json::json!({ "iss": issuer, "sub": "user_123", "exp": future_exp() }),
        &EncodingKey::from_rsa_pem(attacker_pem.as_bytes()).expect("attacker key"),
    )
    .expect("encode forged token");
    let result = registry
        .try_validate(&forged)
        .await
        .expect("issuer should match");
    assert!(result.is_err(), "forged signature must be rejected");
}

#[tokio::test]
async fn future_nbf_rejected() {
    let config = secret_issuer("chalk-test-nbf", "FED_TEST_SECRET_G", "s3cret");
    let registry = OidcRegistry::from_config(&[config]).expect("registry");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs();
    let premature = hs256_token(
        "s3cret",
        &serde_json::json!({
            "iss": "chalk-test-nbf", "sub": "u", "exp": future_exp(), "nbf": now + 600,
        }),
    );
    let result = registry
        .try_validate(&premature)
        .await
        .expect("issuer should match");
    assert!(result.is_err(), "token with future nbf must be rejected");

    // nbf in the past is fine (absence is covered by the other tests).
    let mature = hs256_token(
        "s3cret",
        &serde_json::json!({
            "iss": "chalk-test-nbf", "sub": "u", "exp": future_exp(), "nbf": now - 600,
        }),
    );
    assert!(registry.try_validate(&mature).await.expect("match").is_ok());
}

#[tokio::test]
async fn fractional_exp_is_normalized_not_dropped() {
    let config = secret_issuer("chalk-test-floatexp", "FED_TEST_SECRET_H", "s3cret");
    let registry = OidcRegistry::from_config(&[config]).expect("registry");

    // Some issuers emit `exp` as a JSON float; jsonwebtoken validates it
    // (rounding), so the normalized claims must not report 0 ("no expiry").
    let exp = future_exp();
    for (fraction, expected) in [(0.25, exp), (0.75, exp + 1)] {
        let token = hs256_token(
            "s3cret",
            &serde_json::json!({
                "iss": "chalk-test-floatexp", "sub": "u", "exp": (exp as f64) + fraction,
            }),
        );
        let claims = registry
            .try_validate(&token)
            .await
            .expect("issuer should match")
            .expect("float exp in the future should validate");
        assert_eq!(claims.exp, expected as usize);
    }
}

fn gen_rsa_jwk(kid: &str) -> (EncodingKey, serde_json::Value) {
    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
    let public_key = private_key.to_public_key();

    let pem =
        rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_pem(&private_key, rsa::pkcs8::LineEnding::LF)
            .expect("encode private key PEM");
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("private key");

    let jwk = serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": b64url(&public_key.n().to_bytes_be()),
        "e": b64url(&public_key.e().to_bytes_be()),
    });
    (encoding_key, jwk)
}

async fn serve_local(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

fn jwks_only_issuer(issuer: &str, jwks_uri: String) -> IssuerConfig {
    IssuerConfig {
        issuer: issuer.to_string(),
        jwks_uri: Some(jwks_uri),
        discovery_url: None,
        secret_env: None,
        audience: None,
        claims_map: HashMap::new(),
        require_exp: true,
    }
}

#[tokio::test]
async fn symmetric_jwks_keys_are_never_trusted() {
    let k: &[u8] = b"public-by-construction";
    let jwks_doc = serde_json::json!({
        "keys": [{ "kty": "oct", "kid": "sym-1", "k": b64url(k) }]
    });
    let app = axum::Router::new().route(
        "/jwks.json",
        axum::routing::get(move || {
            let doc = jwks_doc.clone();
            async move { axum::Json(doc) }
        }),
    );
    let base = serve_local(app).await;

    let config = jwks_only_issuer("chalk-test-oct", format!("{base}/jwks.json"));
    let registry = OidcRegistry::from_config(&[config]).expect("registry");

    let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("sym-1".to_string());
    let forged = encode(
        &header,
        &serde_json::json!({ "iss": "chalk-test-oct", "sub": "attacker", "exp": future_exp() }),
        &EncodingKey::from_secret(k),
    )
    .expect("encode forged token");
    let result = registry
        .try_validate(&forged)
        .await
        .expect("issuer should match");
    assert!(result.is_err(), "oct JWKS key must not validate tokens");

    // Nor may an oct key be selected via the single-key no-`kid` fallback.
    let unkidded = encode(
        &Header::default(),
        &serde_json::json!({ "iss": "chalk-test-oct", "sub": "attacker", "exp": future_exp() }),
        &EncodingKey::from_secret(k),
    )
    .expect("encode forged token");
    let result = registry
        .try_validate(&unkidded)
        .await
        .expect("issuer should match");
    assert!(result.is_err(), "oct JWKS key must not validate tokens");
}

#[tokio::test]
async fn discovery_issuer_mismatch_rejected() {
    let (encoding_key, jwk) = gen_rsa_jwk("test-key-1");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let issuer = format!("http://{addr}");

    let discovery_doc = serde_json::json!({
        "issuer": "https://attacker.example.com",
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
    });
    let jwks_doc = serde_json::json!({ "keys": [jwk] });
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let doc = discovery_doc.clone();
                async move { axum::Json(doc) }
            }),
        )
        .route(
            "/.well-known/jwks.json",
            axum::routing::get(move || {
                let doc = jwks_doc.clone();
                async move { axum::Json(doc) }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let registry =
        OidcRegistry::from_config(&[IssuerConfig::discovery(issuer.clone())]).expect("registry");

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    let token = encode(
        &header,
        &serde_json::json!({ "iss": issuer, "sub": "u", "exp": future_exp() }),
        &encoding_key,
    )
    .expect("encode token");

    let result = registry
        .try_validate(&token)
        .await
        .expect("issuer should match");
    let err = result.expect_err("mismatched discovery issuer must be rejected");
    assert!(
        err.to_string().contains("reports issuer"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn malformed_nbf_cannot_bypass_optional_claim_validation() {
    let registry = OidcRegistry::from_config(&[secret_issuer(
        "chalk-test-malformed-nbf",
        "FED_TEST_SECRET_MALFORMED_NBF",
        "s3cret",
    )])
    .unwrap();
    for nbf in [
        serde_json::json!("99999999999"),
        serde_json::json!(true),
        serde_json::json!({}),
    ] {
        let token = hs256_token(
            "s3cret",
            &serde_json::json!({
                "iss":"chalk-test-malformed-nbf", "sub":"u", "exp":future_exp(), "nbf":nbf,
            }),
        );
        assert!(matches!(
            registry.try_validate(&token).await,
            Some(Err(chalk_federated_auth::Error::Auth(_)))
        ));
    }
}

#[tokio::test]
async fn jwks_selection_counts_only_eligible_signature_keys() {
    let (signing, mut signature_key) = gen_rsa_jwk("key-1");
    // An absent use is eligible, too.
    signature_key.as_object_mut().unwrap().remove("use");
    let mut encryption_key = signature_key.clone();
    encryption_key["use"] = serde_json::json!("enc");
    let public_secret = b"public-by-construction";
    let symmetric_key = serde_json::json!({"kty":"oct", "kid":"key-1", "k":b64url(public_secret)});
    let mut second_signature_key = signature_key.clone();
    second_signature_key["kid"] = serde_json::json!("key-2");
    for (keys, with_kid, without_kid) in [
        (
            serde_json::json!([encryption_key, symmetric_key, signature_key]),
            true,
            true,
        ),
        (serde_json::json!([encryption_key]), false, false),
        (
            serde_json::json!([signature_key, second_signature_key]),
            true,
            false,
        ),
    ] {
        let doc = serde_json::json!({"keys":keys});
        let url = serve_local(axum::Router::new().route(
            "/",
            axum::routing::get(move || std::future::ready(axum::Json(doc.clone()))),
        ))
        .await;
        let registry = OidcRegistry::from_config(&[jwks_only_issuer("selection", url)]).unwrap();
        for (kid, expected) in [(Some("key-1"), with_kid), (None, without_kid)] {
            let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = kid.map(String::from);
            let token = encode(
                &header,
                &serde_json::json!({
                    "iss":"selection", "sub":"u", "exp":future_exp(),
                }),
                &signing,
            )
            .unwrap();
            assert_eq!(
                registry.try_validate(&token).await.unwrap().is_ok(),
                expected
            );
        }
    }
}

#[tokio::test]
async fn cached_discovery_is_checked_against_each_configured_issuer() {
    let (signing, jwk) = gen_rsa_jwk("key-1");
    let keys = serde_json::json!({"keys":[jwk]});
    let jwks_url = serve_local(axum::Router::new().route(
        "/",
        axum::routing::get(move || std::future::ready(axum::Json(keys.clone()))),
    ))
    .await;
    let doc = serde_json::json!({"issuer":"issuer-a/", "jwks_uri":jwks_url});
    let discovery_url = serve_local(axum::Router::new().route(
        "/.well-known/openid-configuration",
        axum::routing::get(move || std::future::ready(axum::Json(doc.clone()))),
    ))
    .await;
    let configs: Vec<_> = ["issuer-a", "issuer-b"]
        .into_iter()
        .map(|issuer| IssuerConfig {
            discovery_url: Some(discovery_url.clone()),
            ..IssuerConfig::discovery(issuer)
        })
        .collect();
    let registry = OidcRegistry::from_config(&configs).unwrap();
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("key-1".into());
    for (issuer, expected) in [("issuer-a", true), ("issuer-b", false)] {
        let token = encode(
            &header,
            &serde_json::json!({
                "iss":issuer, "sub":"u", "exp":future_exp(),
            }),
            &signing,
        )
        .unwrap();
        assert_eq!(
            registry.try_validate(&token).await.unwrap().is_ok(),
            expected
        );
    }
}

#[tokio::test]
async fn discovery_without_an_issuer_is_rejected_before_fetching_keys() {
    let doc = serde_json::json!({"jwks_uri":"http://127.0.0.1:1/must-not-fetch"});
    let discovery_url = serve_local(axum::Router::new().route(
        "/.well-known/openid-configuration",
        axum::routing::get(move || std::future::ready(axum::Json(doc.clone()))),
    ))
    .await;
    let registry = OidcRegistry::from_config(&[IssuerConfig {
        discovery_url: Some(discovery_url),
        ..IssuerConfig::discovery("missing-discovery-issuer")
    }])
    .unwrap();
    let token = hs256_token(
        "unused",
        &serde_json::json!({
            "iss":"missing-discovery-issuer", "sub":"u", "exp":future_exp(),
        }),
    );
    assert!(matches!(
        registry.try_validate(&token).await,
        Some(Err(chalk_federated_auth::Error::Auth(_)))
    ));
}
