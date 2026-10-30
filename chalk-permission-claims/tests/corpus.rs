//! Checks the decoder against the shared JWT Permissions V2 fixture corpus, which is generated
//! alongside the token issuer.

use std::collections::BTreeMap;

use chalk_permission_claims::{
    AgentGrant, DecodedPermissionClaims, PermissionIndex, PermissionSet, PermissionTable,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

const CORPUS: &str = include_str!("../testdata/jwt_v2/cases.json");
/// This reader's name in the corpus's `readers` and `reader_overrides`.
const READER: &str = "rust-permission-claims";

// `deny_unknown_fields` allowlists every field, so the corpus cannot carry tokens, keys or
// signing metadata, and a renamed field fails to parse instead of skipping assertions.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    generated_by: String,
    permissions: BTreeMap<String, u32>,
    valid: Vec<ValidCase>,
    reject: Vec<RejectCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidCase {
    name: String,
    #[allow(dead_code)]
    kind: String,
    payloads: BTreeMap<String, Map<String, Value>>,
    expected: Value,
    #[serde(default)]
    reader_overrides: BTreeMap<String, ReaderOverride>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderOverride {
    reject: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectCase {
    name: String,
    #[allow(dead_code)]
    kind: Option<String>,
    payload: Map<String, Value>,
    reason: String,
    readers: Vec<String>,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("corpus matches the payload-only schema")
}

/// The table the corpus was generated with: every permission it knows, by V1 slug.
fn table(corpus: &Corpus) -> PermissionTable {
    PermissionTable::new(
        corpus
            .permissions
            .iter()
            .map(|(slug, index)| (*index, slug.clone())),
    )
    .expect("corpus permissions form a valid table")
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

#[test]
fn decodes_every_valid_case() {
    let corpus = corpus();
    let table = table(&corpus);
    assert!(!corpus.valid.is_empty(), "corpus has no valid cases");
    for case in &corpus.valid {
        let name = &case.name;
        assert!(!case.payloads.is_empty(), "{name} has no payloads");
        for (variant, payload) in &case.payloads {
            let decoded = table.decode(payload);
            if let Some(ReaderOverride { reject }) = case.reader_overrides.get(READER) {
                assert_eq!(
                    decoded.map_err(|e| e.reason()),
                    Err(reject.as_str()),
                    "{name}/{variant}"
                );
                continue;
            }
            assert_eq!(
                decoded.map(|d| (d.format.as_str().to_string(), grants(&d))),
                Ok((variant.clone(), case.expected.clone())),
                "{name}/{variant}"
            );
        }
    }
}

#[test]
fn rejects_every_applicable_case() {
    let corpus = corpus();
    let table = table(&corpus);
    assert!(!corpus.reject.is_empty(), "corpus has no reject cases");
    for case in &corpus.reject {
        assert!(!case.readers.is_empty(), "{} lists no readers", case.name);
        if !case.readers.iter().any(|r| r == "all" || r == READER) {
            continue;
        }
        assert_eq!(
            table.decode(&case.payload).map_err(|e| e.reason()),
            Err(case.reason.as_str()),
            "{}",
            case.name
        );
    }
}

/// This repository is public, so its corpus copy must hold claims only. The schema's field
/// allowlist rejects token and key fields; these checks also catch one nested in a payload.
#[test]
fn corpus_is_payload_only() {
    let corpus = corpus();
    assert!(
        corpus.generated_by.contains('@'),
        "generated_by names no source commit: {}",
        corpus.generated_by
    );
    for needle in ["eyJ", "-----BEGIN", "\"kty\""] {
        assert!(!CORPUS.contains(needle), "corpus contains {needle}");
    }
}

#[test]
fn schema_rejects_token_and_key_fields() {
    let base: Value = serde_json::from_str(CORPUS).expect("corpus is valid JSON");
    // (JSON pointer to an object, field the payload-only schema must refuse there)
    for (parent, field) in [
        ("", "key_id"),
        ("/valid/0", "variants"),
        ("/reject/0", "token"),
    ] {
        let mut corpus = base.clone();
        corpus
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .expect("parent is an object")
            .insert(field.to_string(), json!("x"));
        assert!(
            serde_json::from_value::<Corpus>(corpus).is_err(),
            "{parent}/{field} should be rejected"
        );
    }
}
