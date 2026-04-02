# Fixture Policy

## What Must Be Redacted (Manual)
- Real email addresses → `user@example.com`
- Raw NameID values that identify real users
- Tokens, secrets, session IDs
- Customer-specific org IDs

## What Must Be Preserved (Protocol-Critical)
- SAML XML element structure and names
- Attribute positions and naming
- RelayState URL format
- Issuer/audience structure (can generalize domains)
- NameID Format values
- Timing relationships between events
- All normalized event fields the engine expects (protocol, kind, binding, etc.)

## Naming Convention
- `{vendor}-{descriptor}.json`
- Examples: `zoho-successful-late-capture.json`, `okta-broken-signature.json`

## Important
- **Manual sanitization is required before adding fixtures**
- The automatic validator is a smoke test only - not a substitute for manual review
- Passing validator does not guarantee fixture is safe

## Fixture Shape
Fixtures must use the exact TypeScript model from `src/shared/models.ts`:
- `NormalizedSamlEvent` for SAML events: `protocol: "SAML"`, `binding: "post"|"redirect"|"unknown"`
- `BaseNormalizedEvent` for other events: `protocol: "network"|"unknown"`, `kind` is a string

See `src/shared/models.ts` for the canonical types.