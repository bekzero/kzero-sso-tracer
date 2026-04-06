export interface RuleDoc {
  ruleId: string;
  protocol: "SAML" | "OIDC" | "network" | "unknown";
  short: string;
  why: string;
  kzeroChecks: string[];
  vendorChecks: string[];
}

export const RULE_CATALOG: RuleDoc[] = [
  {
    ruleId: "OIDC_REDIRECT_URI_MISMATCH",
    protocol: "OIDC",
    short: "Callback URL does not match configured redirect URI.",
    why: "Most vendors require exact redirect URI match including path and slash.",
    kzeroChecks: ["Redirect URL", "Client ID"],
    vendorChecks: ["Redirect URI / Callback URL"]
  },
  {
    ruleId: "OIDC_DISCOVERY_ISSUER_MISMATCH",
    protocol: "OIDC",
    short: "Discovery issuer does not match expected tenant issuer.",
    why: "Issuer mismatch breaks token validation and can indicate wrong tenant or case.",
    kzeroChecks: ["Use discovery endpoint", "Discovery Endpoint", "Issuer"],
    vendorChecks: ["Issuer URL"]
  },
  {
    ruleId: "OIDC_INVALID_CLIENT",
    protocol: "OIDC",
    short: "Client authentication failed.",
    why: "Client ID/secret or auth method likely does not match token endpoint expectations.",
    kzeroChecks: ["Client ID", "Client Secret", "Client authentication"],
    vendorChecks: ["Client credentials", "Token auth method"]
  },
  {
    ruleId: "OIDC_STATE_MISSING_OR_MISMATCH",
    protocol: "OIDC",
    short: "State missing or changed between authorize and callback.",
    why: "State mismatch can indicate CSRF protection failure or redirect handling bug.",
    kzeroChecks: ["Redirect URL"],
    vendorChecks: ["State handling in callback"]
  },
  {
    ruleId: "SAML_AUDIENCE_MISMATCH",
    protocol: "SAML",
    short: "Assertion audience does not match SP Entity ID.",
    why: "SP validates audience strictly and rejects assertions for other entity IDs.",
    kzeroChecks: ["Service provider Entity ID"],
    vendorChecks: ["SP Entity ID", "Audience URI"]
  },
  {
    ruleId: "SAML_ACS_RECIPIENT_MISMATCH",
    protocol: "SAML",
    short: "Assertion recipient does not match ACS URL.",
    why: "Recipient/ACS mismatch commonly causes generic SSO failure at SP endpoint.",
    kzeroChecks: ["Assertion Consumer Service URL"],
    vendorChecks: ["ACS URL"]
  },
  {
    ruleId: "SAML_AUTHNREQUEST_REJECTED_BY_KZERO",
    protocol: "SAML",
    short: "KZero rejected AuthnRequest before SAMLResponse was produced.",
    why: "A captured AuthnRequest reached KZero and KZero returned HTTP 4xx before any SAMLResponse was generated.",
    kzeroChecks: ["Valid Redirect URIs", "Assertion Consumer Service POST Binding URL"],
    vendorChecks: ["Assertion Consumer Service URL (ACS)", "SP Entity ID"]
  },
  {
    ruleId: "SAML_DESTINATION_MISMATCH",
    protocol: "SAML",
    short: "SAML destination does not match receiving URL.",
    why: "Destination mismatch is treated as replay/tampering protection by many SPs.",
    kzeroChecks: ["Single Sign-On service url"],
    vendorChecks: ["Destination URL"]
  },
  {
    ruleId: "SAML_MISSING_NAMEID",
    protocol: "SAML",
    short: "NameID was not found in assertion.",
    why: "Without NameID, SP cannot map user identity.",
    kzeroChecks: ["Principal type", "Pass subject", "NameID Policy Format"],
    vendorChecks: ["NameID mapping"]
  },
  {
    ruleId: "SAML_CLOCK_SKEW",
    protocol: "SAML",
    short: "Assertion appears expired.",
    why: "Clock skew or stale response invalidates assertion conditions.",
    kzeroChecks: ["Allow clock skew"],
    vendorChecks: ["Allowed skew", "System time"]
  },
  {
    ruleId: "TENANT_CASE_MISMATCH",
    protocol: "unknown",
    short: "Tenant casing differs across endpoints.",
    why: "KZero tenant names are case-sensitive and mismatches break issuer/endpoints.",
    kzeroChecks: ["Alias", "Discovery Endpoint", "Identity provider entity ID"],
    vendorChecks: ["Issuer", "Metadata URL"]
  }
];

export const getRuleDoc = (ruleId: string): RuleDoc | undefined =>
  RULE_CATALOG.find((rule) => rule.ruleId === ruleId);
