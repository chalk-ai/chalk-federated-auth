//! Shapes mirror go-api-server/auth/auth.go's working-token issuers and
//! connectutil/token.go's ChalkJWTClaims (including omitempty tenant fields).
use chalk_federated_auth::{IssuerConfig, OidcRegistry};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};

fn registry() -> OidcRegistry {
    std::env::set_var("FED_TENANT_CONFORMANCE_SECRET", "conformance-only-secret");
    let mut issuer = IssuerConfig::discovery("https://chalk.example.test");
    issuer.secret_env = Some("FED_TENANT_CONFORMANCE_SECRET".into());
    OidcRegistry::from_config(&[issuer]).unwrap()
}

fn token(mut claims: Value) -> String {
    claims["iss"] = "https://chalk.example.test".into();
    claims["exp"] = json!(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600
    );
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"conformance-only-secret"),
    )
    .unwrap()
}

#[tokio::test]
async fn chalk_working_credentials_conform_to_one_tenant_contract() {
    let registry = registry();
    let fixtures = [
        json!({"kind":"user", "sub":"user-a", "team_id":"team-a",
            "env_permissions":{"env-a":["query.online"], "env-a2":["logs.list"]},
            "fpts":{}, "uccs":{}, "dfps":{}}),
        json!({"kind":"service-account", "sub":"sa-a", "client_id":"client-a",
            "team_id":"team-a", "environment_id":"env-a", "permissions":["query.online"],
            "custom_claims":{}, "fpt":{}, "dfp":1}),
        json!({"kind":"sandbox", "sub":"sandbox-a", "sandbox_id":"sandbox-a",
            "team_id":"team-a", "environment_id":"env-a", "permissions":["query.online"]}),
    ];
    for fixture in fixtures {
        let signed = token(fixture.clone());
        let verified = registry
            .try_validate_with_payload(&signed)
            .await
            .unwrap()
            .unwrap();
        let principal = verified.chalk_principal().unwrap();
        let tenant = principal.bind_environment("env-a", "team-a").unwrap();
        assert_eq!(tenant.subject(), fixture["sub"].as_str().unwrap());
        assert_eq!(tenant.issuer(), "https://chalk.example.test");
        assert_eq!(tenant.team_id(), "team-a");
        assert_eq!(tenant.environment_id(), "env-a");
        assert!(tenant.permits("query.online"));
        assert!(!tenant.permits("tokens.write"));
        // Check canonical ownership even when the token names an environment
        // directly or has an explicit environment grant.
        assert!(principal.bind_environment("env-a", "team-b").is_err());
        assert!(principal.bind_environment("env-b", "team-b").is_err());
        assert!(principal.select_environment(Some(" env-a")).is_err());
        let task = tokio::spawn(async move {
            (
                tenant.team_id().to_owned(),
                tenant.environment_id().to_owned(),
            )
        });
        assert_eq!(task.await.unwrap(), ("team-a".into(), "env-a".into()));
    }

    let cases = [
        // User requires a grant, not merely a signed environment/team claim.
        (
            json!({"kind":"user","sub":"u","team_id":"team-a","environment_id":"env-a"}),
            false,
            false,
        ),
        (
            json!({"kind":"user","sub":"u","team_id":"team-a","env_permissions":{"env-b":["query.online"]}}),
            false,
            false,
        ),
        (
            json!({"kind":"user","sub":"u","team_id":"team-a","env_permissions":{"env-a":[]}}),
            true,
            false,
        ),
        (
            json!({"kind":"user","sub":"u","team_id":"team-a","team_permissions":["query.online"]}),
            true,
            true,
        ),
        // Team-scoped service tokens bind only to that team's environments.
        (
            json!({"kind":"service-account","sub":"sa","team_id":"team-a","team_permissions":["query.online"]}),
            true,
            true,
        ),
        (
            json!({"kind":"service-account","sub":"sa","team_id":"team-a","permissions":["query.online"]}),
            true,
            false,
        ),
        // Platform internal credentials may obtain a missing team from metadata.
        (
            json!({"kind":"engine","sub":"engine","environment_id":"env-a"}),
            true,
            true,
        ),
        (
            json!({"kind":"metadata-service-agent","sub":"metadata","environment_id":"env-a"}),
            true,
            true,
        ),
        // Impersonated users are constrained to the effective team, never to
        // the real user's previous environment grants.
        (
            json!({"kind":"user","sub":"admin","team_id":"original-team","impersonated_team_id":"team-a","env_permissions":{"env-b":["query.online"]}}),
            true,
            true,
        ),
        (
            json!({"kind":"user","sub":"admin","team_id":"team-a","impersonated_team_id":"team-b","env_permissions":{"env-a":["query.online"]}}),
            false,
            false,
        ),
    ];
    for (fixture, binds, permits) in cases {
        let signed = token(fixture.clone());
        let principal = registry
            .try_validate_with_payload(&signed)
            .await
            .unwrap()
            .unwrap()
            .chalk_principal()
            .unwrap();
        let result = principal.bind_environment("env-a", "team-a");
        assert_eq!(result.is_ok(), binds, "{fixture}");
        if let Ok(tenant) = result {
            assert_eq!(tenant.permits("query.online"), permits, "{fixture}");
        }
    }

    for fixture in [
        json!({"kind":"exchange","sub":"exchange","team_id":"team-a","environment_id":"env-a"}),
        json!({"sub":"no-kind","team_id":"team-a","environment_id":"env-a"}),
        json!({"kind":"service-account","sub":"no-team","environment_id":"env-a"}),
        json!({"kind":"sandbox","sub":"no-environment","team_id":"team-a"}),
        json!({"kind":"service-account","sub":"sa","team_id":"team-a","impersonated":true}),
        json!({"kind":"user","sub":"u","team_id":"team-a","env_permissions":{"env-a":"query.online"}}),
        json!({"kind":"user","sub":"u","team_id":"team-a","env_permissions":{"env-a": [42]}}),
        json!({"kind":"user","sub":"u","team_id":"team-a","impersonated_team_id":""}),
        json!({"kind":"user","sub":"u","team_id":"team-a","team_permissions":null}),
    ] {
        let signed = token(fixture.clone());
        let verified = registry
            .try_validate_with_payload(&signed)
            .await
            .unwrap()
            .unwrap();
        assert!(verified.chalk_principal().is_err(), "{fixture}");
    }

    let signed = token(
        json!({"kind":"user","sub":"u","team_id":"team-a","env_permissions":{"env-a":["query.online"],"env-a2":["logs.list"]}}),
    );
    let principal = registry
        .try_validate_with_payload(&signed)
        .await
        .unwrap()
        .unwrap()
        .chalk_principal()
        .unwrap();
    assert!(principal.select_environment(None).is_err());
    assert_eq!(
        principal.select_environment(Some("env-a2")).unwrap(),
        "env-a2"
    );
    let tenant = principal.bind_environment("env-a2", "team-a").unwrap();
    assert!(tenant.permits("logs.list"));
    assert!(!tenant.permits("query.online"));
    assert!(principal.bind_environment("env-a", "").is_err());
}
