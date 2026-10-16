//! Chalk working credentials and their binding to trusted environment ownership.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{Error, Result, VerifiedToken};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalKind {
    User,
    ServiceAccount,
    Sandbox,
    Engine,
    MetadataServiceAgent,
    Tenant,
}

/// Parsed only from a federation-verified token. It is not yet bound to an
/// environment; use `bind_environment` with ownership from trusted metadata.
#[derive(Debug, Clone)]
pub struct ChalkPrincipal {
    issuer: String,
    subject: String,
    team_id: Option<String>,
    environment_id: Option<String>,
    grants: Grants,
}

#[derive(Debug, Clone, Deserialize)]
struct Grants {
    kind: PrincipalKind,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    team_permissions: Vec<String>,
    #[serde(default)]
    env_permissions: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    impersonated: bool,
    impersonated_team_id: Option<String>,
}

/// An immutable identity qualified by a canonical team and environment. Clone
/// this context into asynchronous work; never reconstruct it from headers.
#[derive(Debug, Clone)]
pub struct TenantContext {
    principal: ChalkPrincipal,
    team_id: String,
    environment_id: String,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.trim() == id && !id.chars().any(char::is_control)
}

fn denied() -> Error {
    // Do not disclose which environments exist or which teams own them.
    Error::Auth("credential does not grant access to the requested tenant".into())
}

impl VerifiedToken {
    /// Interpret a token from a platform-configured Chalk issuer. Do not call
    /// this on tokens from tenant-managed issuers: a tenant's IdP is not an
    /// authority for Chalk teams or permissions.
    pub fn chalk_principal(&self) -> Result<ChalkPrincipal> {
        let grants = Grants::deserialize(self.payload())
            .map_err(|_| Error::Auth("invalid Chalk working credential claims".into()))?;
        let claims = self.claims();
        if !valid_id(&claims.sub)
            || claims.team_id.as_deref().is_some_and(|id| !valid_id(id))
            || claims
                .environment_id
                .as_deref()
                .is_some_and(|id| !valid_id(id))
            || grants
                .impersonated_team_id
                .as_deref()
                .is_some_and(|id| !valid_id(id))
            || grants.env_permissions.keys().any(|id| !valid_id(id))
        {
            return Err(denied());
        }
        if grants.kind != PrincipalKind::User
            && (grants.impersonated || grants.impersonated_team_id.is_some())
        {
            return Err(denied());
        }
        // Go's customer working credentials always carry a team. Internal
        // engine/metadata credentials may carry only an environment.
        if !matches!(
            grants.kind,
            PrincipalKind::Engine | PrincipalKind::MetadataServiceAgent
        ) && claims.team_id.is_none()
            && grants.impersonated_team_id.is_none()
        {
            return Err(denied());
        }
        if grants.kind == PrincipalKind::Sandbox && claims.environment_id.is_none() {
            return Err(denied());
        }
        Ok(ChalkPrincipal {
            issuer: self.issuer().into(),
            subject: claims.sub.clone(),
            team_id: claims.team_id.clone(),
            environment_id: claims.environment_id.clone(),
            grants,
        })
    }
}

impl ChalkPrincipal {
    /// A request selector only chooses a target; it never establishes access.
    /// Scoped credentials cannot override their environment with a selector.
    pub fn select_environment<'a>(&'a self, selector: Option<&'a str>) -> Result<&'a str> {
        if selector.is_some_and(|id| !valid_id(id)) {
            return Err(denied());
        }
        match self.environment_id.as_deref() {
            Some(id) if selector.is_none_or(|selected| selected == id) => Ok(id),
            Some(_) => Err(denied()),
            None => selector.ok_or_else(denied),
        }
    }

    /// Bind to an environment and its canonical owner, supplied by trusted
    /// metadata or a platform-provisioned inventory. Never supply `owner_team`
    /// from a request header or from this token's team claim. Re-run this check
    /// per request, even if signature verification is cached.
    pub fn bind_environment(&self, environment: &str, owner_team: &str) -> Result<TenantContext> {
        if !valid_id(environment) || !valid_id(owner_team) {
            return Err(denied());
        }
        self.select_environment(Some(environment))?;
        let impersonated = self.grants.kind == PrincipalKind::User
            && (self.grants.impersonated || self.grants.impersonated_team_id.is_some());
        let team = if impersonated {
            self.grants
                .impersonated_team_id
                .as_deref()
                .or(self.team_id.as_deref())
        } else {
            self.team_id.as_deref()
        };
        if team.is_some_and(|team| team != owner_team) {
            return Err(denied());
        }
        if self.grants.kind == PrincipalKind::User
            && !impersonated
            && !self.grants.env_permissions.contains_key(environment)
            && self.grants.team_permissions.is_empty()
        {
            return Err(denied());
        }
        if self.environment_id.is_none() && team.is_none() {
            return Err(denied());
        }
        Ok(TenantContext {
            principal: self.clone(),
            team_id: owner_team.into(),
            environment_id: environment.into(),
        })
    }
}

impl TenantContext {
    pub fn issuer(&self) -> &str {
        &self.principal.issuer
    }
    pub fn subject(&self) -> &str {
        &self.principal.subject
    }
    pub fn kind(&self) -> PrincipalKind {
        self.principal.grants.kind
    }
    pub fn team_id(&self) -> &str {
        &self.team_id
    }
    pub fn environment_id(&self) -> &str {
        &self.environment_id
    }

    /// Existing Chalk working-token permission semantics. Binding establishes
    /// tenant identity; callers must also check the operation's permission.
    pub fn permits(&self, permission: &str) -> bool {
        let grants = &self.principal.grants;
        let contains = |values: &[String]| values.iter().any(|value| value == permission);
        match grants.kind {
            PrincipalKind::Engine | PrincipalKind::MetadataServiceAgent => true,
            PrincipalKind::User => {
                grants.impersonated
                    || grants.impersonated_team_id.is_some()
                    || contains(&grants.team_permissions)
                    || grants
                        .env_permissions
                        .get(&self.environment_id)
                        .is_some_and(|values| contains(values))
            }
            PrincipalKind::ServiceAccount => {
                contains(&grants.team_permissions)
                    || (self.principal.environment_id.as_deref() == Some(&self.environment_id)
                        && contains(&grants.permissions))
                    || (!grants.team_permissions.is_empty()
                        && matches!(
                            permission,
                            "deploy.read"
                                | "logs.list"
                                | "tokens.list"
                                | "secrets.list"
                                | "monitoring.read"
                        ))
            }
            PrincipalKind::Sandbox => contains(&grants.permissions),
            PrincipalKind::Tenant => grants.permissions.is_empty() || contains(&grants.permissions),
        }
    }
}
