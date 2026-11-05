//! Manual throughput check for the validation path; not run by default.
//!
//! cargo test --release -p chalk-federated-auth --test throughput_test -- --ignored --nocapture
//!
//! Compare the printed rates against the same test on the base branch. The
//! numbers depend on the machine, so nothing here asserts a rate.
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{routing::get, Json, Router};
use base64::Engine;
use chalk_federated_auth::{IssuerConfig, OidcRegistry};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::traits::PublicKeyParts;
use serde_json::json;

fn exp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600
}

async fn run(label: &str, registry: &Arc<OidcRegistry>, tokens: &Arc<Vec<String>>, workers: usize) {
    let next = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let tasks: Vec<_> = (0..workers)
        .map(|_| {
            let (registry, tokens, next) = (registry.clone(), tokens.clone(), next.clone());
            tokio::spawn(async move {
                let mut failures = 0;
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(token) = tokens.get(i) else { break };
                    if !matches!(registry.try_validate(token).await, Some(Ok(_))) {
                        failures += 1;
                    }
                }
                failures
            })
        })
        .collect();
    let mut failures = 0;
    for task in tasks {
        failures += task.await.unwrap();
    }
    let elapsed = started.elapsed();
    println!(
        "{label:<16} concurrency={workers:<5} {:>7.0}/s",
        tokens.len() as f64 / elapsed.as_secs_f64()
    );
    assert_eq!(failures, 0, "{label} at concurrency {workers}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual benchmark"]
async fn validation_throughput() {
    std::env::set_var("THROUGHPUT_TEST_SECRET", "s3cret");
    let hs = Arc::new(
        OidcRegistry::from_config(&[IssuerConfig {
            secret_env: Some("THROUGHPUT_TEST_SECRET".into()),
            ..IssuerConfig::discovery("hs")
        }])
        .unwrap(),
    );
    let hs_tokens: Arc<Vec<_>> = Arc::new(
        (0..100_000)
            .map(|i| {
                encode(
                    &Header::default(),
                    &json!({"iss": "hs", "sub": format!("u{i}"), "exp": exp()}),
                    &EncodingKey::from_secret(b"s3cret"),
                )
                .unwrap()
            })
            .collect(),
    );

    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pem =
        rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_pem(&key, rsa::pkcs8::LineEnding::LF).unwrap();
    let signing = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    let b64 = |bytes: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let jwks = json!({"keys": [{"kty": "RSA", "alg": "RS256", "kid": "k1",
        "n": b64(key.n().to_bytes_be()), "e": b64(key.e().to_bytes_be())}]});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route("/", get(move || std::future::ready(Json(jwks.clone()))));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let rs = Arc::new(
        OidcRegistry::from_config(&[IssuerConfig {
            jwks_uri: Some(url),
            ..IssuerConfig::discovery("rs")
        }])
        .unwrap(),
    );
    let header = Header {
        alg: Algorithm::RS256,
        kid: Some("k1".into()),
        ..Header::default()
    };
    let rs_tokens: Arc<Vec<_>> = Arc::new(
        (0..20_000)
            .map(|i| {
                encode(
                    &header,
                    &json!({"iss": "rs", "sub": format!("u{i}"), "exp": exp()}),
                    &signing,
                )
                .unwrap()
            })
            .collect(),
    );
    assert!(matches!(rs.try_validate(&rs_tokens[0]).await, Some(Ok(_))));

    for workers in [64, 1024, 8192] {
        run("HS256 distinct", &hs, &hs_tokens, workers).await;
        run("RS256 distinct", &rs, &rs_tokens, workers).await;
    }
    // Let earlier results expire so the identical burst starts cold.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let identical = Arc::new(vec![rs_tokens[1].clone(); 20_000]);
    run("RS256 identical", &rs, &identical, 1024).await;
}
