use std::borrow::Borrow;
use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::permission_set::PermissionSet;
use crate::permission_table::PermissionTable;

/// The permission claim encoding a token uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    V1,
    V1V2,
    V2,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V1V2 => "v1_v2",
            Self::V2 => "v2",
        }
    }
}

/// Why a token's permission claims could not be decoded. Every variant but `InvalidV1Claim` is a
/// fixture corpus reject reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PermissionClaimsError {
    #[error("token has no kind")]
    NoKind,
    #[error("unsupported permission claims version {0}")]
    UnknownV(String),
    #[error("V2 token carries V1 permission claim {0}")]
    MixedFormat(&'static str),
    #[error("malformed V2 permission claims: {0}")]
    MalformedP(String),
    #[error("V2 tenant token has no restriction")]
    TenantMissingRestriction,
    #[error("V1 permission claim {0} is not a list of permission slugs")]
    InvalidV1Claim(String),
}

impl PermissionClaimsError {
    /// The error's name in the fixture corpus.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NoKind => "no_kind",
            Self::UnknownV(_) => "unknown_v",
            Self::MixedFormat(_) => "mixed_format",
            Self::MalformedP(_) => "malformed_p",
            Self::TenantMissingRestriction => "tenant_missing_restriction",
            Self::InvalidV1Claim(_) => "invalid_v1_claim",
        }
    }
}

/// An environment id, the key of a token's environment permissions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvironmentId(String);

impl EnvironmentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Sound because the derived Eq, Ord and Hash compare the inner `String` exactly as `str` does.
impl Borrow<str> for EnvironmentId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// A token's agent-level restriction. Only tenant tokens are ever unrestricted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentGrant {
    Unrestricted,
    Restricted(PermissionSet),
}

/// A token's permissions independently of their encoding. `None` means the token does not carry
/// that claim, or its kind does not use it; an unrecognized kind leaves every field `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedPermissionClaims {
    pub format: Format,
    pub env: Option<BTreeMap<EnvironmentId, PermissionSet>>,
    pub team: Option<PermissionSet>,
    pub agent: Option<AgentGrant>,
    pub requestable: Option<PermissionSet>,
}

/// The permission fields a kind uses, by `p` field: `e` (env_permissions), `t` (team_permissions),
/// `a` (permissions), `r` (requestable_perms). Fields a kind does not use are ignored in either
/// format, as V1 decoding always has.
#[derive(Clone, Copy)]
struct KindFields {
    env: bool,
    team: bool,
    agent: bool,
    requestable: bool,
}

const TENANT: &str = "tenant";
const V1_CLAIMS: [&str; 4] = [
    "env_permissions",
    "team_permissions",
    "permissions",
    "requestable_perms",
];

fn kind_fields(kind: &str) -> KindFields {
    let fields = |env, team, agent, requestable| KindFields {
        env,
        team,
        agent,
        requestable,
    };
    match kind {
        "user" => fields(true, true, false, false),
        "service-account" => fields(false, true, true, false),
        "sandbox" | TENANT => fields(false, false, true, false),
        "exchange" | "user-exchange" | "service-token-exchange" | "sandbox-exchange" => {
            fields(false, false, true, true)
        }
        _ => fields(false, false, false, false),
    }
}

impl PermissionTable {
    /// Reads a token's permission claims in the format its `v` claim selects: absent or 1 reads
    /// the V1 claims, 2 reads `p`. Permissions this table does not know are dropped. `kind` is not
    /// allowlisted; see the crate docs.
    pub fn decode(
        &self,
        claims: &Map<String, Value>,
    ) -> Result<DecodedPermissionClaims, PermissionClaimsError> {
        let kind = match claims.get("kind") {
            Some(Value::String(kind)) if !kind.is_empty() => kind.as_str(),
            _ => return Err(PermissionClaimsError::NoKind),
        };
        let format = format_of(claims)?;
        if format != Format::V2 {
            // A dual token's V1 claims are authoritative, so `p` is not read at all.
            return decode_v1(self, claims, kind, format);
        }
        if let Some(name) = V1_CLAIMS.into_iter().find(|name| present(claims, name)) {
            return Err(PermissionClaimsError::MixedFormat(name));
        }
        decode_v2(self, claims, kind)
    }
}

/// A null claim counts as absent, matching how Go decodes it into nil.
fn present(claims: &Map<String, Value>, name: &str) -> bool {
    claims.get(name).is_some_and(|value| !value.is_null())
}

fn format_of(claims: &Map<String, Value>) -> Result<Format, PermissionClaimsError> {
    let Some(v) = claims.get("v") else {
        return Ok(Format::V1);
    };
    // `as_i64` is `None` for floats, booleans, and null, all of which are unknown versions.
    match v.as_i64() {
        Some(1) => Ok(Format::V1V2),
        Some(2) => Ok(Format::V2),
        _ => Err(PermissionClaimsError::UnknownV(v.to_string())),
    }
}

fn slug_list<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>, PermissionClaimsError> {
    value
        .as_array()
        .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
        .ok_or_else(|| PermissionClaimsError::InvalidV1Claim(field.to_string()))
}

fn slug_set(
    table: &PermissionTable,
    value: &Value,
    field: &str,
) -> Result<PermissionSet, PermissionClaimsError> {
    Ok(PermissionSet::from_slugs(table, slug_list(value, field)?))
}

fn v1_set(
    table: &PermissionTable,
    claims: &Map<String, Value>,
    name: &str,
) -> Result<Option<PermissionSet>, PermissionClaimsError> {
    match claims.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => slug_set(table, value, name).map(Some),
    }
}

fn decode_v1(
    table: &PermissionTable,
    claims: &Map<String, Value>,
    kind: &str,
    format: Format,
) -> Result<DecodedPermissionClaims, PermissionClaimsError> {
    let uses = kind_fields(kind);
    let env = match claims.get("env_permissions") {
        Some(Value::Object(envs)) if uses.env => Some(
            envs.iter()
                .map(|(env, slugs)| {
                    Ok((
                        EnvironmentId::new(env.clone()),
                        slug_set(table, slugs, &format!("env_permissions.{env}"))?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?,
        ),
        Some(value) if uses.env && !value.is_null() => {
            return Err(PermissionClaimsError::InvalidV1Claim(
                "env_permissions".to_string(),
            ));
        }
        _ => None,
    };
    let team = if uses.team {
        v1_set(table, claims, "team_permissions")?
    } else {
        None
    };
    let agent = if uses.agent {
        let slugs = match claims.get("permissions") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => slug_list(value, "permissions")?,
        };
        // A V1 tenant token without permissions is unrestricted.
        if kind == TENANT && slugs.is_empty() {
            Some(AgentGrant::Unrestricted)
        } else {
            Some(AgentGrant::Restricted(PermissionSet::from_slugs(
                table, slugs,
            )))
        }
    } else {
        None
    };
    let requestable = if uses.requestable {
        v1_set(table, claims, "requestable_perms")?
    } else {
        None
    };
    Ok(DecodedPermissionClaims {
        format,
        env,
        team,
        agent,
        requestable,
    })
}

fn bitset(
    table: &PermissionTable,
    value: &Value,
    field: &str,
) -> Result<PermissionSet, PermissionClaimsError> {
    // A null bitset decodes as empty, matching Go's string unmarshaling.
    match value {
        Value::Null => bitset_str(table, "", field),
        Value::String(encoded) => bitset_str(table, encoded, field),
        _ => Err(PermissionClaimsError::MalformedP(format!(
            "{field} is not a string"
        ))),
    }
}

fn bitset_str(
    table: &PermissionTable,
    encoded: &str,
    field: &str,
) -> Result<PermissionSet, PermissionClaimsError> {
    PermissionSet::from_base64url(table, encoded)
        .map_err(|e| PermissionClaimsError::MalformedP(format!("{field}: {e}")))
}

fn decode_v2(
    table: &PermissionTable,
    claims: &Map<String, Value>,
    kind: &str,
) -> Result<DecodedPermissionClaims, PermissionClaimsError> {
    let empty = Map::new();
    let p = match claims.get("p") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(p)) => p,
        Some(_) => {
            return Err(PermissionClaimsError::MalformedP(
                "p is not an object".to_string(),
            ));
        }
    };
    let uses = kind_fields(kind);
    let env = match p.get("e") {
        Some(raw) if uses.env => {
            let envs = match raw {
                Value::Null => &empty,
                Value::Object(envs) => envs,
                _ => {
                    return Err(PermissionClaimsError::MalformedP(
                        "p.e is not an object of bitsets".to_string(),
                    ));
                }
            };
            Some(
                envs.iter()
                    .map(|(env, value)| {
                        Ok((
                            EnvironmentId::new(env.clone()),
                            bitset(table, value, &format!("p.e.{env}"))?,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?,
            )
        }
        _ => None,
    };
    let team = match p.get("t") {
        Some(value) if uses.team => Some(bitset(table, value, "p.t")?),
        _ => None,
    };
    let requestable = match p.get("r") {
        Some(value) if uses.requestable => Some(bitset(table, value, "p.r")?),
        _ => None,
    };
    let agent = if uses.agent {
        Some(decode_agent(table, kind, p)?)
    } else {
        None
    };
    Ok(DecodedPermissionClaims {
        format: Format::V2,
        env,
        team,
        agent,
        requestable,
    })
}

fn decode_agent(
    table: &PermissionTable,
    kind: &str,
    p: &Map<String, Value>,
) -> Result<AgentGrant, PermissionClaimsError> {
    let encoded = match p.get("a") {
        None | Some(Value::Null) => "",
        Some(Value::String(encoded)) => encoded.as_str(),
        Some(_) => {
            return Err(PermissionClaimsError::MalformedP(
                "p.a is not a string".to_string(),
            ));
        }
    };
    if kind == TENANT {
        // "*" is not base64url, so on any other kind it falls through to a malformed bitset.
        if encoded == "*" {
            return Ok(AgentGrant::Unrestricted);
        }
        // An empty restriction means unrestricted on the agent, so a tenant must state "*".
        if encoded.is_empty() {
            return Err(PermissionClaimsError::TenantMissingRestriction);
        }
    }
    Ok(AgentGrant::Restricted(bitset_str(table, encoded, "p.a")?))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::PermissionIndex;

    #[test]
    fn env_grants_look_up_by_str() {
        let table = PermissionTable::new([(3, "query.online")]).expect("valid table");
        let claims = json!({"kind": "user", "env_permissions": {"env_a": ["query.online"]}});
        let decoded = table
            .decode(claims.as_object().expect("object"))
            .expect("decodes");
        let envs = decoded.env.expect("user tokens carry env grants");
        assert!(envs["env_a"].contains(PermissionIndex::new(3)));
        assert!(!envs.contains_key("env_b"));
    }

    #[test]
    fn unknown_kind_decodes_without_grants() {
        let table = PermissionTable::new([(3, "query.online")]).expect("valid table");
        let claims = json!({"kind": "not-a-kind", "permissions": ["query.online"]});
        let decoded = table
            .decode(claims.as_object().expect("object"))
            .expect("decodes");
        assert_eq!(
            (
                decoded.env,
                decoded.team,
                decoded.agent,
                decoded.requestable
            ),
            (None, None, None, None)
        );
    }
}
