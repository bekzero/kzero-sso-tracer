export interface RuleDoc {
  ruleId: string;
  protocol: 'SAML' | 'OIDC' | 'network' | 'unknown';
  short: string;
  why: string;
  kzeroChecks: string[];
  vendorChecks: string[];
}

export const RULE_CATALOG: RuleDoc[] = [
  // OIDC Rules
  {
    ruleId: 'OIDC_REDIRECT_URI_MISMATCH',
    protocol: 'OIDC',
    short: 'Callback URL does not match configured redirect URI.',
    why: 'Most vendors require exact redirect URI match including path and slash.',
    kzeroChecks: ['Redirect URL', 'Client ID'],
    vendorChecks: ['Redirect URI / Callback URL']
  },
  {
    ruleId: 'OIDC_DISCOVERY_ISSUER_MISMATCH',
    protocol: 'OIDC',
    short: 'Discovery issuer does not match expected tenant issuer.',
    why: 'Issuer mismatch breaks token validation and can indicate wrong tenant or case.',
    kzeroChecks: ['Use discovery endpoint', 'Discovery Endpoint', 'Issuer'],
    vendorChecks: ['Issuer URL']
  },
  {
    ruleId: 'OIDC_INVALID_CLIENT',
    protocol: 'OIDC',
    short: 'Client authentication failed.',
    why: 'Client ID/secret or auth method likely does not match token endpoint expectations.',
    kzeroChecks: ['Client ID', 'Client Secret', 'Client authentication'],
    vendorChecks: ['Client credentials', 'Token auth method']
  },
  {
    ruleId: 'OIDC_STATE_MISSING_OR_MISMATCH',
    protocol: 'OIDC',
    short: 'State missing or changed between authorize and callback.',
    why: 'State mismatch can indicate CSRF protection failure or redirect handling bug.',
    kzeroChecks: ['Redirect URL'],
    vendorChecks: ['State handling in callback']
  },
  {
    ruleId: 'OIDC_DISCOVERY_UNREACHABLE',
    protocol: 'OIDC',
    short: 'OIDC discovery endpoint could not be reached.',
    why: 'If the discovery document is unreachable, the vendor cannot start OIDC flow.',
    kzeroChecks: ['Discovery Endpoint URL'],
    vendorChecks: ['Discovery URL configuration']
  },
  {
    ruleId: 'OIDC_DISCOVERY_MALFORMED',
    protocol: 'OIDC',
    short: 'OIDC discovery document is invalid or incomplete.',
    why: 'Malformed discovery response prevents proper OIDC client configuration.',
    kzeroChecks: ['Discovery Endpoint URL'],
    vendorChecks: ['Discovery endpoint configuration']
  },
  {
    ruleId: 'OIDC_DISCOVERY_PUBLIC_REACHABILITY_CLUE',
    protocol: 'OIDC',
    short: 'Discovery endpoint may not be publicly reachable.',
    why: 'If KZero cannot fetch discovery document, OIDC flows will fail.',
    kzeroChecks: ['Discovery Endpoint URL', 'Tenant status'],
    vendorChecks: ['Network/firewall settings']
  },
  {
    ruleId: 'OIDC_DISCOVERY_ENDPOINT_HOST_SUSPICIOUS',
    protocol: 'OIDC',
    short: 'Discovery endpoint host does not match expected KZero tenant.',
    why: 'Wrong host in discovery URL indicates wrong environment or configuration.',
    kzeroChecks: ['Discovery Endpoint URL', 'Tenant alias'],
    vendorChecks: ['Discovery URL setting']
  },
  {
    ruleId: 'OIDC_MISSING_OPENID_SCOPE',
    protocol: 'OIDC',
    short: 'Required "openid" scope is missing.',
    why: 'Without openid scope, the server will not return an ID token.',
    kzeroChecks: ['Client scopes', 'Default scopes'],
    vendorChecks: ['OIDC scope configuration', 'Requested scopes']
  },
  {
    ruleId: 'OIDC_NONCE_MISSING',
    protocol: 'OIDC',
    short: 'Nonce parameter is missing from authorize request.',
    why: 'Nonce is required for replay protection in OIDC implicit/hybrid flows.',
    kzeroChecks: ['Require nonce', 'Client settings'],
    vendorChecks: ['Nonce generation setting']
  },
  {
    ruleId: 'OIDC_PKCE_INCONSISTENT',
    protocol: 'OIDC',
    short: 'PKCE code_verifier or code_challenge is inconsistent.',
    why: 'PKCE protects authorization code flow; inconsistent values cause token exchange to fail.',
    kzeroChecks: ['PKCE settings', 'Client authentication'],
    vendorChecks: ['PKCE configuration', 'Code challenge method']
  },
  {
    ruleId: 'OIDC_PKCE_MISSING_WHEN_CODE_FLOW',
    protocol: 'OIDC',
    short: 'PKCE missing for authorization code flow.',
    why: 'PKCE is recommended for all code flows to prevent authorization code interception.',
    kzeroChecks: ['PKCE settings'],
    vendorChecks: ['PKCE settings', 'Enable PKCE']
  },
  {
    ruleId: 'OIDC_PKCE_METHOD_WEAK_OR_UNEXPECTED',
    protocol: 'OIDC',
    short: 'PKCE code challenge method is weak or unexpected.',
    why: 'S256 is recommended; plain is deprecated and may be rejected.',
    kzeroChecks: ['PKCE settings', 'Allowed challenge methods'],
    vendorChecks: ['PKCE method setting']
  },
  {
    ruleId: 'OIDC_JWKS_FETCH_FAILURE',
    protocol: 'OIDC',
    short: 'JWKS endpoint could not be fetched.',
    why: 'If KZero cannot fetch vendor JWKS, token signature validation will fail.',
    kzeroChecks: ['JWKS URL', 'Tenant configuration'],
    vendorChecks: ['JWKS endpoint URL', 'TLS/certificate settings']
  },
  {
    ruleId: 'OIDC_REACHABILITY_WAF_TLS_SUSPECTED',
    protocol: 'OIDC',
    short: 'OIDC endpoint may be blocked by WAF or TLS issue.',
    why: 'WAF rules or TLS mismatches can block OIDC flows.',
    kzeroChecks: ['Tenant status', 'Endpoint URL'],
    vendorChecks: ['WAF settings', 'TLS version', 'Certificate validity']
  },
  {
    ruleId: 'OIDC_TOKEN_ISSUER_MISMATCH',
    protocol: 'OIDC',
    short: 'Token issuer does not match expected issuer.',
    why: 'Issuer mismatch causes token validation failure at the vendor.',
    kzeroChecks: ['Issuer', 'Discovery Endpoint'],
    vendorChecks: ['Issuer validation setting']
  },
  {
    ruleId: 'OIDC_CALLBACK_TOKEN_EXCHANGE_BROKEN',
    protocol: 'OIDC',
    short: 'Token exchange at callback failed.',
    why: 'Authorization code could not be exchanged for tokens at the token endpoint.',
    kzeroChecks: ['Client secret', 'Token endpoint URL', 'Client auth method'],
    vendorChecks: ['Token endpoint configuration', 'Client credentials']
  },
  {
    ruleId: 'OIDC_TOKEN_AUTH_METHOD_MISMATCH_CLUE',
    protocol: 'OIDC',
    short: 'Token endpoint auth method may not match.',
    why: 'Client auth method (secret, JWT, none) must match token endpoint expectations.',
    kzeroChecks: ['Client authentication method', 'Token endpoint settings'],
    vendorChecks: ['Token endpoint auth method']
  },
  {
    ruleId: 'OIDC_LOGOUT_REDIRECT_MISMATCH_CLUE',
    protocol: 'OIDC',
    short: 'Logout redirect URI may not match configured URI.',
    why: 'Post-logout redirect must be whitelisted in client configuration.',
    kzeroChecks: ['Post-logout redirect URIs', 'Client settings'],
    vendorChecks: ['Logout redirect URI setting']
  },
  {
    ruleId: 'OIDC_ACCESS_TOKEN_OPAQUE',
    protocol: 'OIDC',
    short: 'Access token is opaque (not a JWT).',
    why: 'Opaque tokens cannot be introspected by the vendor; this is expected for some configurations.',
    kzeroChecks: ['Token type setting', 'Client settings'],
    vendorChecks: ['Token type expectation']
  },
  {
    ruleId: 'OIDC_LATE_CAPTURE_CLUE',
    protocol: 'OIDC',
    short: 'Capture may have started after the authorize request.',
    why: 'Late capture means some OIDC flow steps may be missing from the trace.',
    kzeroChecks: [],
    vendorChecks: []
  },
  {
    ruleId: 'OIDC_MISSING_AUTHORIZE_REQUEST_CLUE',
    protocol: 'OIDC',
    short: 'No OIDC authorize request was captured.',
    why: 'If authorize request is missing, the trace may be incomplete or capture started late.',
    kzeroChecks: [],
    vendorChecks: []
  },
  {
    ruleId: 'OIDC_MISSING_CALLBACK',
    protocol: 'OIDC',
    short: 'No OIDC callback was captured after authorize request.',
    why: 'Missing callback suggests the flow was interrupted or vendor did not redirect back.',
    kzeroChecks: ['Redirect URI', 'Client status'],
    vendorChecks: ['Redirect URI', 'Application status']
  },
  {
    ruleId: 'OIDC_USERINFO_FAILED',
    protocol: 'OIDC',
    short: 'UserInfo endpoint request failed.',
    why: 'If UserInfo fails, the vendor cannot retrieve user claims after login.',
    kzeroChecks: ['UserInfo endpoint URL', 'Client scopes'],
    vendorChecks: ['UserInfo endpoint', 'Required scopes']
  },
  {
    ruleId: 'OIDC_BROWSER_STORAGE_OR_COOKIE_BLOCKING_CLUE',
    protocol: 'OIDC',
    short: 'Browser may be blocking storage or cookies needed for OIDC.',
    why: 'OIDC flows often require cookies or session storage; blocking these breaks the flow.',
    kzeroChecks: [],
    vendorChecks: ['Browser settings', 'Cookie policy']
  },
  {
    ruleId: 'OIDC_CALLBACK_SEEN_BUT_NO_APP_LANDING_CLUE',
    protocol: 'OIDC',
    short: 'Callback succeeded but application did not complete login.',
    why: 'Token exchange succeeded but the app did not complete the login sequence.',
    kzeroChecks: ['Client settings', 'Redirect URI'],
    vendorChecks: ['Application login handler', 'Post-login redirect']
  },
  {
    ruleId: 'OIDC_DISCOVERY_ENDPOINT_INCONSISTENT',
    protocol: 'OIDC',
    short: 'Discovery endpoint values are inconsistent.',
    why: 'Inconsistent values in discovery document (issuer, endpoints) cause validation failures.',
    kzeroChecks: ['Discovery Endpoint', 'Issuer', 'Tenant alias'],
    vendorChecks: ['Discovery endpoint configuration']
  },
  {
    ruleId: 'OIDC_INVALID_SCOPE',
    protocol: 'OIDC',
    short: 'Requested scope is invalid or not supported.',
    why: 'Invalid scopes cause the authorization server to reject the request.',
    kzeroChecks: ['Client scopes', 'Allowed scopes'],
    vendorChecks: ['Scope configuration', 'Supported scopes']
  },

  // SAML Rules
  {
    ruleId: 'SAML_AUDIENCE_MISMATCH',
    protocol: 'SAML',
    short: 'Assertion audience does not match SP Entity ID.',
    why: 'SP validates audience strictly and rejects assertions for other entity IDs.',
    kzeroChecks: ['Service provider Entity ID'],
    vendorChecks: ['SP Entity ID', 'Audience URI']
  },
  {
    ruleId: 'SAML_ACS_RECIPIENT_MISMATCH',
    protocol: 'SAML',
    short: 'The requested ACS URL did not match the configured reply URL.',
    why: 'The ACS URL is the reply URL where the service provider receives the SAML response from KZero. This value must match exactly on both sides.',
    kzeroChecks: ['Assertion Consumer Service URL'],
    vendorChecks: ['ACS URL']
  },
  {
    ruleId: 'SAML_AUTHNREQUEST_REJECTED_BY_KZERO',
    protocol: 'SAML',
    short: 'KZero rejected AuthnRequest before SAMLResponse was produced.',
    why: 'A captured AuthnRequest reached KZero and KZero returned HTTP 4xx before any SAMLResponse was generated.',
    kzeroChecks: ['Valid Redirect URIs', 'Assertion Consumer Service POST Binding URL'],
    vendorChecks: ['Assertion Consumer Service URL (ACS)', 'SP Entity ID']
  },
  {
    ruleId: 'SAML_PREAUTHN_CONFIG_ISSUE',
    protocol: 'SAML',
    short: 'Pre-response configuration issue detected.',
    why: 'KZero returned an error before generating a SAMLResponse, indicating a client configuration problem (Client ID, Entity ID, ACS URL).',
    kzeroChecks: ['Client ID', 'Entity ID', 'ACS URL', 'Valid Redirect URIs'],
    vendorChecks: ['SP Entity ID', 'ACS URL', 'Client configuration']
  },
  {
    ruleId: 'SAML_MISSING_RESPONSE',
    protocol: 'SAML',
    short: 'No SAML Response was captured after AuthnRequest.',
    why: 'If no SAMLResponse is captured, the flow may have failed before generating a response, or capture started late.',
    kzeroChecks: ['SSO endpoint URL', 'Client status'],
    vendorChecks: ['ACS URL', 'Application status']
  },
  {
    ruleId: 'SAML_MISSING_REQUEST',
    protocol: 'SAML',
    short: 'No SAML AuthnRequest was captured.',
    why: 'Missing AuthnRequest suggests the flow is IdP-initiated or capture started after the request.',
    kzeroChecks: [],
    vendorChecks: []
  },
  {
    ruleId: 'SAML_DESTINATION_MISMATCH',
    protocol: 'SAML',
    short: 'SAML destination does not match receiving URL.',
    why: 'Destination mismatch is treated as replay/tampering protection by many SPs.',
    kzeroChecks: ['Single Sign-On service url'],
    vendorChecks: ['Destination URL']
  },
  {
    ruleId: 'SAML_ISSUER_MISMATCH',
    protocol: 'SAML',
    short: 'SAML Issuer does not match expected Entity ID.',
    why: 'Issuer mismatch causes the SP or IdP to reject the SAML message.',
    kzeroChecks: ['Identity provider entity ID', 'Service provider Entity ID'],
    vendorChecks: ['Entity ID', 'Issuer setting']
  },
  {
    ruleId: 'SAML_MISSING_NAMEID',
    protocol: 'SAML',
    short: 'NameID was not found in assertion.',
    why: 'Without NameID, SP cannot map user identity.',
    kzeroChecks: ['Principal type', 'Pass subject', 'NameID Policy Format'],
    vendorChecks: ['NameID mapping']
  },
  {
    ruleId: 'SAML_NAMEID_FORMAT_MISMATCH',
    protocol: 'SAML',
    short: 'NameID format does not match SP expectation.',
    why: 'NameID format mismatch can cause SP to reject the assertion.',
    kzeroChecks: ['NameID Policy Format', 'Principal type'],
    vendorChecks: ['NameID format setting']
  },
  {
    ruleId: 'SAML_RELAYSTATE_UNEXPECTED',
    protocol: 'SAML',
    short: 'RelayState is present but not expected, or missing when expected.',
    why: 'RelayState mismatch can cause SP to lose context or reject the response.',
    kzeroChecks: ['Pass RelayState', 'Client settings'],
    vendorChecks: ['RelayState handling']
  },
  {
    ruleId: 'SAML_ASSERTION_SIGNATURE_MISSING',
    protocol: 'SAML',
    short: 'Assertion is not signed.',
    why: 'Many SPs require the SAML assertion to be digitally signed.',
    kzeroChecks: ['Want Assertions Signed', 'Signing settings'],
    vendorChecks: ['Require assertion signature']
  },
  {
    ruleId: 'SAML_DOCUMENT_SIGNATURE_MISSING',
    protocol: 'SAML',
    short: 'SAML document (response) is not signed.',
    why: 'Some SPs require the entire SAML Response document to be signed.',
    kzeroChecks: ['Want Response Signed', 'Signing settings'],
    vendorChecks: ['Require response signature']
  },
  {
    ruleId: 'SAML_CLOCK_SKEW',
    protocol: 'SAML',
    short: 'Assertion appears expired or not yet valid.',
    why: 'Clock skew or stale response invalidates assertion conditions.',
    kzeroChecks: ['Allow clock skew'],
    vendorChecks: ['Allowed skew', 'System time']
  },
  {
    ruleId: 'SAML_CLOCK_SKEW_NOT_BEFORE',
    protocol: 'SAML',
    short: 'Assertion is not yet valid (NotBefore in the future).',
    why: 'Clock skew can cause "NotBefore" condition to fail.',
    kzeroChecks: ['Allow clock skew'],
    vendorChecks: ['Allowed skew', 'System time']
  },
  {
    ruleId: 'SAML_INRESPONSETO_MISSING',
    protocol: 'SAML',
    short: 'InResponseTo attribute is missing in SAML Response.',
    why: 'Missing InResponseTo can indicate IdP-initiated flow or request/response mismatch.',
    kzeroChecks: ['SP-initiated flow settings'],
    vendorChecks: ['Flow type configuration']
  },
  {
    ruleId: 'SAML_ASSERTION_ENCRYPTED',
    protocol: 'SAML',
    short: 'Assertion is encrypted but SP may not expect it.',
    why: 'Encryption mismatch can cause SP to fail reading the assertion.',
    kzeroChecks: ['Encrypt assertion', 'Encryption certificate'],
    vendorChecks: ['Encryption support', 'Certificate configuration']
  },
  {
    ruleId: 'SAML_UNPARSEABLE_ARTIFACT',
    protocol: 'SAML',
    short: 'SAML artifact could not be parsed or decoded.',
    why: 'Malformed or corrupted SAML messages cause parsing failures.',
    kzeroChecks: ['SSO endpoint', 'Client configuration'],
    vendorChecks: ['SAML endpoint configuration']
  },
  {
    ruleId: 'SAML_CAPTURE_STARTED_LATE',
    protocol: 'SAML',
    short: 'Capture appears to have started after the AuthnRequest.',
    why: 'Late capture means some SAML flow steps may be missing from the trace.',
    kzeroChecks: [],
    vendorChecks: []
  },
  {
    ruleId: 'SAML_IDP_SP_INIT_MISMATCH_CLUE',
    protocol: 'SAML',
    short: 'Flow may be IdP-initiated but SP configuration expects SP-initiated.',
    why: 'Mismatch in expected flow initiation can cause issues.',
    kzeroChecks: ['Flow type settings'],
    vendorChecks: ['Flow initiation setting']
  },
  {
    ruleId: 'SAML_WRONG_BINDING_CLUE',
    protocol: 'SAML',
    short: 'SAML binding (POST vs Redirect) may not match expectation.',
    why: 'Binding mismatch can cause the SP or IdP to reject the message.',
    kzeroChecks: ['Protocol binding settings'],
    vendorChecks: ['SAML binding setting']
  },
  {
    ruleId: 'SAML_CERT_SIGNATURE_VALIDATION_CLUE',
    protocol: 'SAML',
    short: 'Certificate or signature validation may have failed.',
    why: 'Certificate expiration, mismatch, or signature validation failure can cause SAML rejection.',
    kzeroChecks: ['Signing certificate', 'Certificate expiry'],
    vendorChecks: ['Certificate configuration', 'Certificate validity']
  },
  {
    ruleId: 'SAML_POLICY_MISMATCH_CLUE',
    protocol: 'SAML',
    short: 'SAML policy or authentication context mismatch.',
    why: 'Requested authentication policies may not be supported or configured.',
    kzeroChecks: ['Authentication policies', 'NameID Policy Format'],
    vendorChecks: ['Authentication policy settings']
  },
  {
    ruleId: 'SAML_AUTHNREQUEST_SIGN_EXPECTATION_MISMATCH',
    protocol: 'SAML',
    short: 'AuthnRequest signing expectation mismatch.',
    why: 'If KZero expects signed AuthnRequest but SP does not sign, or vice versa, the request may be rejected.',
    kzeroChecks: ['Want AuthnRequests Signed', 'Client settings'],
    vendorChecks: ['Sign AuthnRequest setting']
  },

  // Cross-Protocol Rules
  {
    ruleId: 'TENANT_CASE_MISMATCH',
    protocol: 'unknown',
    short: 'Tenant casing differs across endpoints.',
    why: 'KZero tenant names are case-sensitive and mismatches break issuer/endpoints.',
    kzeroChecks: ['Alias', 'Discovery Endpoint', 'Identity provider entity ID'],
    vendorChecks: ['Issuer', 'Metadata URL']
  },
  {
    ruleId: 'WRONG_HOST_OR_ENVIRONMENT',
    protocol: 'unknown',
    short: 'URL points to wrong host or environment.',
    why: 'Using wrong tenant environment (prod vs staging) or wrong host breaks federation.',
    kzeroChecks: ['Tenant alias', 'Endpoint URLs'],
    vendorChecks: ['Endpoint configuration', 'Environment setting']
  },
  {
    ruleId: 'WRONG_REALM_ENDPOINT_FAMILY',
    protocol: 'unknown',
    short: 'Endpoint does not match expected realm/tenant family.',
    why: 'Using endpoints from a different realm breaks token validation and discovery.',
    kzeroChecks: ['Realm settings', 'Endpoint URLs'],
    vendorChecks: ['Endpoint configuration']
  },
  {
    ruleId: 'METADATA_COPY_PASTE_TRUNCATION',
    protocol: 'unknown',
    short: 'Metadata may have been truncated during copy-paste.',
    why: 'Truncated metadata causes parsing failures or missing configuration values.',
    kzeroChecks: ['Metadata URL', 'Entity ID'],
    vendorChecks: ['Metadata integrity', 'Copy-paste process']
  },
  {
    ruleId: 'VENDOR_VALIDATION_REJECTING_METADATA_CLUE',
    protocol: 'unknown',
    short: 'Vendor may be rejecting metadata due to validation rules.',
    why: 'Strict vendor validation can reject valid metadata if format differs.',
    kzeroChecks: ['Metadata URL', 'Tenant configuration'],
    vendorChecks: ['Metadata validation settings']
  },
  {
    ruleId: 'CLIENT_SIDE_VS_BACKEND_VALIDATION_DISTINCTION',
    protocol: 'unknown',
    short: 'Validation error may be client-side (browser) vs backend.',
    why: 'Distinguishing where validation fails helps focus troubleshooting.',
    kzeroChecks: ['Client settings', 'Tenant configuration'],
    vendorChecks: ['Validation configuration']
  },
  {
    ruleId: 'NETWORK_TLS_REACHABILITY_SUSPECTED',
    protocol: 'unknown',
    short: 'Network, TLS, or reachability issue suspected.',
    why: 'Connection failures often indicate network blocks, TLS mismatches, or endpoint unavailability.',
    kzeroChecks: ['Tenant status', 'Endpoint URLs'],
    vendorChecks: ['Firewall', 'TLS version', 'Endpoint availability']
  },
  {
    ruleId: 'STALE_VALUES_FROM_ANOTHER_ENVIRONMENT',
    protocol: 'unknown',
    short: 'Configuration values may be from a different environment.',
    why: 'Using values from production in staging (or vice versa) causes endpoint and issuer mismatches.',
    kzeroChecks: ['Tenant alias', 'Endpoint URLs', 'Issuer'],
    vendorChecks: ['Environment configuration', 'Endpoint URLs']
  }
];

export const getRuleDoc = (ruleId: string): RuleDoc | undefined =>
  RULE_CATALOG.find((rule) => rule.ruleId === ruleId);
