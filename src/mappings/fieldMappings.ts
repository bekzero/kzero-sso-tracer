export interface FieldMap {
  kzeroFields: string[];
  vendorFields: string[];
}

const map: Record<string, FieldMap> = {
  OIDC_REDIRECT_URI_MISMATCH: {
    kzeroFields: ["Redirect URL", "Client ID"],
    vendorFields: ["Redirect URI / Callback URL", "Client ID"]
  },
  OIDC_DISCOVERY_ISSUER_MISMATCH: {
    kzeroFields: ["Use discovery endpoint", "Discovery Endpoint", "Issuer"],
    vendorFields: ["Issuer URL"]
  },
  OIDC_INVALID_CLIENT: {
    kzeroFields: ["Client ID", "Client Secret", "Client authentication"],
    vendorFields: ["Client ID", "Client Secret", "Token Auth Method"]
  },
  OIDC_INVALID_SCOPE: {
    kzeroFields: ["Client ID"],
    vendorFields: ["Scope", "OIDC Application Permissions"]
  },
  OIDC_PKCE_INCONSISTENT: {
    kzeroFields: ["Use PKCE", "Client authentication"],
    vendorFields: ["PKCE Required", "Code Challenge Method"]
  },
  OIDC_TOKEN_AUTH_METHOD_MISMATCH_CLUE: {
    kzeroFields: ["Client authentication", "Client ID", "Client Secret"],
    vendorFields: ["Token endpoint auth method", "Client credentials"]
  },
  OIDC_LOGOUT_REDIRECT_MISMATCH_CLUE: {
    kzeroFields: ["Logout URL", "Redirect URL"],
    vendorFields: ["Post logout redirect URI"]
  },
  SAML_AUDIENCE_MISMATCH: {
    kzeroFields: ["Service provider Entity ID", "Identity provider entity ID"],
    vendorFields: ["SP Entity ID", "Audience URI"]
  },
  SAML_ACS_RECIPIENT_MISMATCH: {
    kzeroFields: ["Assertion Consumer Service URL", "Single Sign-On service url"],
    vendorFields: ["ACS URL"]
  },
  SAML_DESTINATION_MISMATCH: {
    kzeroFields: ["Single Sign-On service url"],
    vendorFields: ["Destination URL"]
  },
  SAML_ISSUER_MISMATCH: {
    kzeroFields: ["Identity provider entity ID"],
    vendorFields: ["Expected IdP Issuer", "Entity ID"]
  },
  SAML_MISSING_NAMEID: {
    kzeroFields: ["Principal type", "Pass subject", "NameID Policy Format"],
    vendorFields: ["NameID format", "Subject mapping"]
  },
  SAML_CLOCK_SKEW: {
    kzeroFields: ["Allow clock skew"],
    vendorFields: ["Allowed Clock Skew", "System Time"]
  },
  SAML_NAMEID_FORMAT_MISMATCH: {
    kzeroFields: ["NameID Policy Format", "Principal type", "Pass subject"],
    vendorFields: ["NameID format", "User identifier mapping"]
  },
  SAML_CERT_SIGNATURE_VALIDATION_CLUE: {
    kzeroFields: ["Tenant certificate", "Tenant XML data", "Validate signatures"],
    vendorFields: ["Signature certificate", "Certificate fingerprint"]
  },
  TENANT_CASE_MISMATCH: {
    kzeroFields: ["Alias", "Discovery Endpoint", "Identity provider entity ID"],
    vendorFields: ["Issuer", "Metadata URL"]
  }
};

export const getFieldMapping = (ruleId: string): FieldMap =>
  map[ruleId] ?? { kzeroFields: ["Alias", "Display name"], vendorFields: ["App config values"] };
