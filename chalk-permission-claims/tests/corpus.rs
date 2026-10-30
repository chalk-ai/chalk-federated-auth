//! Checks the decoder against the shared JWT Permissions V2 fixture corpus, which is generated
//! alongside the token issuer.

use chalk_permission_claims::{
    AgentGrant, DecodedPermissionClaims, PermissionIndex, PermissionSet, PermissionTable,
};
use serde_json::{json, Map, Value};

const CORPUS: &str = include_str!("../testdata/jwt_v2/cases.json");
/// This reader's name in the corpus's `readers` and `reader_overrides`.
const READER: &str = "rust-permission-claims";

fn corpus() -> Value {
    serde_json::from_str(CORPUS).expect("corpus is valid JSON")
}

/// The table the corpus was generated with: every permission it knows, by V1 slug.
fn table(corpus: &Value) -> PermissionTable {
    let entries = corpus["permissions"]
        .as_object()
        .expect("corpus has a permissions map")
        .iter()
        .map(|(slug, index)| {
            let index = index.as_u64().and_then(|n| u32::try_from(n).ok());
            (index.expect("permission index is a u32"), slug.clone())
        });
    PermissionTable::new(entries).expect("corpus permissions form a valid table")
}

fn indexes(set: &PermissionSet) -> Value {
    json!(set.iter().map(PermissionIndex::get).collect::<Vec<_>>())
}

/// Renders a decode result in the corpus's `expected` shape.
fn grants(decoded: &DecodedPermissionClaims) -> Value {
    json!({
        "env": decoded.env.as_ref().map(|envs| {
            envs.iter().map(|(env, set)| (env.as_str().to_string(), indexes(set))).collect::<Map<_, _>>()
        }),
        "team": decoded.team.as_ref().map(indexes),
        "agent": decoded.agent.map(|grant| match grant {
            AgentGrant::Unrestricted => json!({"unrestricted": true, "permissions": []}),
            AgentGrant::Restricted(set) => json!({"unrestricted": false, "permissions": indexes(&set)}),
        }),
        "requestable": decoded.requestable.as_ref().map(indexes),
    })
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

#[test]
fn decodes_every_valid_case() {
    let corpus = corpus();
    let table = table(&corpus);
    let cases = corpus["valid"].as_array().cloned().unwrap_or_default();
    assert!(!cases.is_empty(), "corpus has no valid cases");
    for case in &cases {
        let name = case["name"].as_str().unwrap_or_default();
        for (variant, payload) in object(&case["payloads"]) {
            let decoded = table.decode(&object(&payload));
            if let Some(reason) = case["reader_overrides"][READER]["reject"].as_str() {
                assert_eq!(
                    decoded.map_err(|e| e.reason()),
                    Err(reason),
                    "{name}/{variant}"
                );
                continue;
            }
            assert_eq!(
                decoded.map(|d| (d.format.as_str().to_string(), grants(&d))),
                Ok((variant.clone(), case["expected"].clone())),
                "{name}/{variant}"
            );
        }
    }
}

#[test]
fn rejects_every_applicable_case() {
    let corpus = corpus();
    let table = table(&corpus);
    let cases = corpus["reject"].as_array().cloned().unwrap_or_default();
    assert!(!cases.is_empty(), "corpus has no reject cases");
    for case in &cases {
        let readers = case["readers"].as_array().cloned().unwrap_or_default();
        if !readers.iter().any(|r| r == "all" || r == READER) {
            continue;
        }
        let name = case["name"].as_str().unwrap_or_default();
        assert_eq!(
            table
                .decode(&object(&case["payload"]))
                .map_err(|e| e.reason()),
            Err(case["reason"].as_str().unwrap_or_default()),
            "{name}"
        );
    }
}

/// This repository is public, so its corpus copy must hold claims only: no signed tokens and no
/// signing metadata.
#[test]
fn corpus_is_payload_only() {
    let corpus = corpus();
    for field in ["issuer", "key_id"] {
        assert!(corpus.get(field).is_none(), "corpus carries {field}");
    }
    for case in corpus["valid"].as_array().into_iter().flatten() {
        assert!(
            case.get("variants").is_none(),
            "{} carries tokens",
            case["name"]
        );
    }
    for case in corpus["reject"].as_array().into_iter().flatten() {
        assert!(
            case.get("token").is_none(),
            "{} carries a token",
            case["name"]
        );
    }
    assert!(
        !CORPUS.contains("eyJ"),
        "corpus contains a JWT-shaped string"
    );
    assert!(
        !CORPUS.contains("-----BEGIN"),
        "corpus contains a PEM block"
    );
}
