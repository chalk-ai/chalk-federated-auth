//! Decodes Chalk JWT permission claims in either the V1 slug format or the V2 compact bitset
//! format.
//!
//! V1 tokens carry permission slugs: `env_permissions` (environment id to slugs),
//! `team_permissions`, `permissions` and `requestable_perms`. V2 tokens set `v` to 2 and carry
//! the same grants in `p` as unpadded base64url bitsets, in which permission n is bit `n % 8` of
//! byte `n / 8`: `p.e` (environment id to bitset), `p.t`, `p.a` and `p.r`. A token with `v` 1
//! carries both, and its V1 claims are authoritative.
//!
//! Decoding runs on claims whose signature has already been verified. It does not verify
//! anything itself.
//!
//! Each reader supplies a [`PermissionTable`] built from its own `chalk.auth.v1.Permission` enum,
//! so permissions newer than the reader are dropped in either format. The fixture corpus in
//! `testdata/jwt_v2`, generated alongside the token issuer, keeps this decoder in agreement with the Go,
//! C++ and Python decoders.

mod decode;
mod permission_set;
mod permission_table;

pub use decode::{
    AgentGrant, DecodedPermissionClaims, EnvironmentId, Format, PermissionClaimsError,
};
pub use permission_set::{BitsetError, PermissionSet, CAPACITY};
pub use permission_table::{PermissionIndex, PermissionTable, PermissionTableError};
