# JWT Permissions V2 fixtures (payload-only)

Generated alongside the token issuer. Do not edit; regenerate instead.

- `cases.json`: decoded token payloads and the expected decode result. It carries no signed
  tokens and no keys: decoding permission claims happens after signature verification and
  needs neither.

`permissions` maps each V1 slug to its `Permission` enum number. `valid` cases carry the
`v1`, `v1_v2` and/or `v2` payloads of one set of permissions under `payloads`; every payload
must decode to `expected`. Permissions are enum numbers. In `expected`, `null` means the
field does not apply to the kind (or, for `team`, that no team grants are present). `agent`
is `{"unrestricted", "permissions"}`, where `unrestricted` is a tenant whose restriction is
`*` and `permissions` is then empty. Unknown slugs and bits are ignored, so they never
appear in `expected`. Bit 0 (`unspecified`) is never a grant: a bitset with it set is
malformed. Bitsets must be canonical: nonzero unused bits in the final base64url character
are malformed. A permission field the token's kind does not use is ignored, in either format.

`reject` cases are single payloads a reader must refuse with `reason`. `readers` lists the
readers that validate that rule, or is `["all"]`. `reader_overrides` on a valid case names
readers that intentionally decide differently.
