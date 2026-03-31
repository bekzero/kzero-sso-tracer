import type { Finding } from "../shared/models";
import { getFieldMapping } from "../mappings/fieldMappings";
import type { TraceContext } from "./context";
import type { FixRecipe } from "./types";
import { 
  buildOidcNavigationSteps, 
  buildRedirectUriFix, 
  buildClientIdFix,
  buildDiscoveryUrlFix,
  buildIssuerFix,
  buildClientAuthFix,
  detectOidcVendor,
  getOidcFieldTooltip
} from "./guidance/oidc";
import {
  buildSamlNavigationSteps,
  buildAcsUrlFix,
  buildEntityIdFix,
  buildIssuerFix as buildSamlIssuerFix,
  buildNameIdFix,
  buildSigningFix,
  buildBindingFix,
  detectSamlVendor,
  getSamlFieldTooltip
} from "./guidance/saml";
import { detectVendor, getDocUrl, formatVendorNotice } from "./guidance";

const urlExactMatchNote = "⚠️ Exact match matters: scheme, host, path, query (if used), and trailing slash.";

const baseVerify = [
  "Start capture, run login once, stop capture.",
  "Confirm the finding no longer appears and the flow progresses past the failing step.",
  "Export sanitized trace + attach to ticket if escalation is needed."
];

const formatStep = (step: { text: string; important?: boolean; warning?: boolean; field?: string }): string => {
  let prefix = "";
  if (step.important && step.warning) prefix = "⚠️ ";
  else if (step.important) prefix = "→ ";
  else if (step.warning) prefix = "⚠️ ";
  return `${prefix}${step.text}`;
};

export const buildFixRecipe = (finding: Finding, ctx: TraceContext): FixRecipe => {
  const map = getFieldMapping(finding.ruleId);
  const kzeroTenantHint = ctx.tenants[0] ? `Tenant: ${ctx.tenants[0]} (case-sensitive)` : "Tenant name is case-sensitive";

  const getVendorName = (): string | undefined => {
    if (ctx.oidc.authorize?.redirectUri) {
      const detected = detectOidcVendor(ctx.oidc.authorize.redirectUri);
      if (detected) return detected;
    }
    if (ctx.oidc.authorize?.clientId) {
      const detected = detectOidcVendor(undefined, ctx.oidc.authorize.clientId);
      if (detected) return detected;
    }
    if (ctx.saml?.ssoUrl) {
      const detected = detectSamlVendor(ctx.saml.ssoUrl);
      if (detected) return detected;
    }
    if (ctx.saml?.issuer) {
      const detected = detectSamlVendor(ctx.saml.issuer);
      if (detected) return detected;
    }
    return undefined;
  };

  const vendorName = getVendorName();
  const vendorNotice = vendorName ? formatVendorNotice(vendorName, "both") : "";
  const docLink = getDocUrl("samlClients");
  const oidcDocLink = getDocUrl("oidcClients");

  switch (finding.ruleId) {
    case "OIDC_REDIRECT_URI_MISMATCH": {
      const expected = finding.expected;
      const observed = finding.observed;
      const clientId = ctx.oidc.authorize?.clientId ?? ctx.oidc.token?.clientId;
      const navSteps = buildOidcNavigationSteps(true);
      const fixSteps = buildRedirectUriFix(observed, expected, vendorName);
      
      return {
        title: "Redirect URI mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in KZero",
            owner: "KZero",
            bullets: fixSteps.map(formatStep),
            kzeroFields: map.kzeroFields,
            fieldExpectations: [{ field: "Valid Redirect URIs", expected }],
            copySnippets: [{ label: "Expected Redirect URL", value: expected }],
            tooltip: "The Redirect URI (or callback URL) is where the vendor app tells KZero to send the user after login. It must match exactly or the login fails."
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              `Update vendor \"Redirect URI / Callback URL\" to exactly: ${expected}`,
              urlExactMatchNote,
              "If the vendor supports multiple redirect URIs, remove stale ones from other environments.",
              "Retry login after saving changes."
            ],
            vendorFields: map.vendorFields,
            copySnippets: [{ label: "Vendor Redirect URI", value: expected }],
            tooltip: "The vendor app needs to tell KZero where to send the user after they log in. This must match exactly."
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [`Expected redirect_uri: ${expected}`, `Browser callback reached: ${observed}`]
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[OIDC Client Configuration](${oidcDocLink})`
            ]
          }
        ],
        verify: [
          ...baseVerify,
          "In the new trace, ensure authorize request redirect_uri equals the callback URL that is reached."
        ],
        nextEvidence: ["Authorize request URL", "Callback URL", "Configured redirect/callback URI on vendor side"]
      };
    }
    case "OIDC_DISCOVERY_ISSUER_MISMATCH": {
      const discoveryUrl = ctx.oidc.discovery?.url;
      const issuerObserved = ctx.oidc.discovery?.issuer ?? finding.observed;
      const issuerExpected = finding.expected;
      const fixSteps = buildDiscoveryUrlFix(issuerExpected);
      
      return {
        title: "Discovery issuer mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in KZero",
            owner: "KZero",
            bullets: [
              ...fixSteps.map(formatStep),
              "",
              "⚠️ The issuer URL is CASE SENSITIVE - check for any uppercase/lowercase mismatches",
              `Tenant name must match exactly: ${kzeroTenantHint}`
            ],
            kzeroFields: map.kzeroFields,
            fieldExpectations: [
              { field: "OIDC Discovery URL", expected: ctx.oidc.discovery?.url ?? "" },
              { field: "Issuer", expected: issuerExpected }
            ].filter((e) => e.expected.length > 0),
            copySnippets: discoveryUrl ? [{ label: "Discovery URL used", value: discoveryUrl }] : undefined,
            tooltip: "The Issuer is the unique identifier for your KZero tenant. Both KZero and the vendor must agree on exactly the same issuer value (case-sensitive)."
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              `Set vendor "Issuer" / "Authority" to exactly: ${issuerExpected}`,
              "If vendor uses discovery, configure it to the same Discovery Endpoint you used in KZero.",
              "⚠️ Verify the exact casing - 'ABCMSP' is not the same as 'abcmasp'"
            ],
            vendorFields: map.vendorFields,
            copySnippets: [{ label: "Expected Issuer", value: issuerExpected }],
            tooltip: "The vendor app needs to know exactly who issued the tokens. The issuer must match exactly (case-sensitive)."
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [
              discoveryUrl ? `Discovery URL: ${discoveryUrl}` : "Discovery URL captured",
              `Issuer in discovery: ${issuerObserved}`,
              `Expected issuer: ${issuerExpected}`
            ]
          },
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[OIDC Discovery Document](${getDocUrl("oidcOverview")})`,
              `[Realm Settings](${getDocUrl("realmSettings")})`
            ]
          }
        ],
        verify: [
          ...baseVerify,
          "In the new trace, discovery issuer equals the tenant base URL and matches token iss when JWT is present."
        ],
        nextEvidence: ["Discovery URL", "Discovery response issuer", "Tenant name and casing"]
      };
    }
    case "OIDC_INVALID_CLIENT": {
      const clientId = ctx.oidc.authorize?.clientId ?? ctx.oidc.token?.clientId;
      const fixSteps = buildClientIdFix(finding.observed, clientId || finding.expected, vendorName);
      
      return {
        title: "Client authentication failed (invalid_client)",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in KZero",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard → Select your tenant",
              "Navigate to: Integrations → Applications → [Select your OIDC app]",
              "Click 'Advanced Console'",
              "Select 'Client' and search for your app",
              "Go to 'General settings' section",
              `Confirm 'Client ID' is: ${clientId || finding.expected}`,
              "",
              "Go to 'Capability Config' section → verify 'Client Authentication' is set correctly",
              "Go to 'Credentials' tab → check/regenerate 'Client Secret' if needed"
            ],
            kzeroFields: map.kzeroFields,
            tooltip: "The Client ID and Client Secret are like a username and password for your app. Both KZero and the vendor must use the same values."
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Confirm vendor has the same Client ID as configured in KZero",
              `Expected Client ID: ${clientId || finding.expected}`,
              "Confirm the Client Secret matches exactly (check for leading/trailing spaces)",
              "Verify the authentication method matches:",
              "  - 'Client secret basic' (default) or",
              "  - 'Client secret post' or",
              "  - 'None' (for public/SPA clients)"
            ],
            vendorFields: map.vendorFields,
            tooltip: "The vendor app needs to authenticate itself to KZero using the same Client ID and Client Secret."
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[OIDC Client Configuration](${oidcDocLink})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, token endpoint returns HTTP 200 and no invalid_client error."],
        nextEvidence: ["Token endpoint response error_description", "Client auth method configured on both sides"]
      };
    }
    case "SAML_AUDIENCE_MISMATCH": {
      const fixSteps = buildEntityIdFix(finding.observed, finding.expected, vendorName);
      
      return {
        title: "Audience / Entity ID mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in KZero",
            owner: "KZero",
            bullets: [
              ...fixSteps.map(formatStep),
              "",
              "⚠️ The Entity ID must match exactly - this is case-sensitive"
            ],
            kzeroFields: map.kzeroFields,
            fieldExpectations: [{ field: "Client ID", expected: finding.expected }],
            copySnippets: [{ label: "Expected SP Entity ID", value: finding.expected }],
            tooltip: "The Entity ID is like a company name on a business card - both KZero and the vendor app need to agree on exactly who each other are. Case-sensitive!"
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              `Set vendor \"Entity ID\" / \"Audience URI\" / \"SP Entity ID\" to exactly: ${finding.expected}`,
              "If vendor imported metadata, re-import to avoid truncation or stale values.",
              "⚠️ Entity IDs are case-sensitive - verify exact casing"
            ],
            vendorFields: map.vendorFields,
            tooltip: "The vendor app needs to identify itself with the same Entity ID that KZero expects. Both sides must match exactly."
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [`Observed Entity ID: ${finding.observed}`, `Expected Entity ID: ${finding.expected}`]
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[SAML Client Configuration](${docLink})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, assertion Audience matches SP Entity ID exactly."],
        nextEvidence: ["Vendor SP Entity ID", "KZero Service provider Entity ID", "Assertion AudienceRestriction"]
      };
    }
    case "SAML_ACS_RECIPIENT_MISMATCH": {
      const acs = finding.expected;
      const fixSteps = buildAcsUrlFix(finding.observed, acs, vendorName);
      
      return {
        title: "ACS / Recipient mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in KZero",
            owner: "KZero",
            bullets: fixSteps.map(formatStep),
            kzeroFields: map.kzeroFields,
            fieldExpectations: [{ field: "Master SAML Processing URL", expected: acs }],
            copySnippets: [{ label: "Expected ACS URL", value: acs }],
            tooltip: "The ACS URL (Assertion Consumer Service URL) is the 'delivery address' where the vendor app receives the login confirmation from KZero. It must be exact."
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              `Set vendor \"ACS URL\" / \"Assertion Consumer Service URL\" to exactly: ${acs}`,
              urlExactMatchNote,
              "If vendor has multiple ACS entries, ensure the active/default one matches.",
              "Verify the vendor is using HTTPS (not HTTP) for the ACS URL."
            ],
            vendorFields: map.vendorFields,
            tooltip: "The vendor app needs to tell KZero where to send the SAML response. This URL must match exactly on both sides."
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[SAML Client Configuration](${docLink})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, Recipient equals the posted ACS URL."],
        nextEvidence: ["Vendor ACS URL setting", "Assertion SubjectConfirmationData Recipient"]
      };
    }
    case "SAML_DESTINATION_MISMATCH": {
      const destination = finding.observed;
      const postedTo = finding.expected;
      
      return {
        title: "SAML Destination mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in KZero",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard → Select your tenant",
              "Navigate to: Integrations → Applications → [Select your SAML app]",
              "Click 'Advanced Console'",
              "Select 'Client' and search for your app",
              "Go to 'Access settings' section",
              "Find 'Master SAML Processing URL' (ACS URL)",
              "",
              `Confirm the ACS URL is set to: ${postedTo}`,
              "⚠️ The URL must match exactly - including https:// and trailing slash"
            ],
            kzeroFields: map.kzeroFields,
            tooltip: "The Destination tells the vendor app where the SAML response is being sent. It must match what the vendor expects."
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              `Ensure vendor is configured to receive the SAML response at: ${postedTo}`,
              `Current vendor destination: ${destination}`,
              "Check if vendor has multiple ACS URLs and ensure the correct one is active.",
              "Verify the vendor is using HTTPS (not HTTP) for receiving SAML."
            ],
            vendorFields: map.vendorFields,
            copySnippets: [{ label: "Expected ACS URL", value: postedTo }],
            tooltip: "The vendor app needs to be listening at the same URL where KZero is sending the SAML response."
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [`Destination in SAMLResponse: ${destination}`, `Browser posted to: ${postedTo}`]
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[SAML Client Configuration](${docLink})`,
              `[SAML Bindings](${getDocUrl("samlBindings")})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, Destination equals the receiving ACS URL."],
        nextEvidence: ["SAMLResponse Destination", "Actual POST target URL"]
      };
    }
    case "SAML_MISSING_NAMEID": {
      const fixSteps = buildNameIdFix("emailAddress", vendorName);
      
      return {
        title: "Missing NameID",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in KZero",
            owner: "KZero",
            bullets: fixSteps.map(formatStep),
            kzeroFields: map.kzeroFields,
            tooltip: "The NameID is how KZero identifies the user to the vendor app. It must match what the vendor expects."
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Check what identifier the vendor expects (usually email or a persistent ID)",
              "Configure vendor to use the NameID (or specific attribute) as the user identifier",
              "Common NameID formats: emailAddress, persistent, transient"
            ],
            vendorFields: map.vendorFields,
            tooltip: "The vendor app needs to know which field identifies the user. Most vendors expect the user's email as the identifier."
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[SAML Client Configuration](${docLink})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, SAMLResponse contains a populated NameID and vendor accepts it."],
        nextEvidence: ["Vendor expected identifier field", "KZero Principal type / Pass subject values"]
      };
    }
    case "SAML_CLOCK_SKEW":
    case "SAML_CLOCK_SKEW_NOT_BEFORE": {
      const windowValue = finding.observed;
      return {
        title: "SAML assertion time window problem",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Check KZero time settings",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard → Select your tenant",
              "Navigate to: Configure → Realm settings",
              "Click on 'Tokens' tab",
              "",
              "Find 'Allow clock skew' setting",
              "This allows a time difference between KZero and the vendor servers",
              "",
              "Recommended: Set to 30 seconds to 5 minutes to handle minor time drift",
              "⚠️ Don't set too high (hours) as this is a security risk"
            ],
            kzeroFields: ["Allow clock skew"],
            tooltip: "Servers can have slightly different times due to clock drift. The clock skew setting allows a tolerance for this difference. Too much skew is a security risk."
          },
          {
            title: "Check server times",
            owner: "network",
            bullets: [
              "Verify KZero server time is accurate (check via 'Realm settings → General')",
              "Ask vendor to verify their server time is accurate and using NTP",
              "Time difference between servers can cause 'expired' or 'not yet valid' errors"
            ]
          },
          {
            title: "Check vendor settings",
            owner: "vendor SP",
            bullets: [
              "Ask the vendor if they have a clock skew tolerance setting",
              "If so, increase it slightly to match KZero's 'Allow clock skew'",
              "Ensure both servers are using NTP for accurate time"
            ],
            vendorFields: ["Allowed clock skew", "System time"]
          },
          {
            title: "What we observed",
            owner: "network",
            bullets: [
              `Assertion time window: ${windowValue}`,
              "This suggests a time mismatch between KZero and the vendor"
            ]
          },
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[Realm Settings - Timeouts](${getDocUrl("realmSettings")})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, NotBefore/NotOnOrAfter window covers the current time."],
        nextEvidence: ["NotBefore", "NotOnOrAfter", "System time on both ends"]
      };
    }
    case "REALM_CASE_MISMATCH": {
      return {
        title: "Realm/Tenant casing mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in KZero",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard → Select your tenant",
              "Note the exact casing of your tenant name (e.g., 'ABCMSP' not 'abcmasp')",
              "",
              "Navigate to: Configure → Realm settings → General tab",
              "Scroll to the 'Endpoints' section",
              "Verify all KZero URLs use the exact same tenant casing",
              "",
              "⚠️ IMPORTANT: Tenant names are CASE SENSITIVE",
              "  - 'ABCMSP' ≠ 'abcmasp'",
              "  - 'MyCompany' ≠ 'mycompany'"
            ],
            kzeroFields: map.kzeroFields,
            tooltip: "The tenant name in your KZero URL must be exactly right. URLs are case-sensitive - 'MyTenant' and 'mytenant' are treated as different tenants."
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Check all KZero-related URLs in the vendor configuration:",
              "  - Discovery/Metadata URL",
              "  - Issuer URL",
              "  - SSO/Login URL",
              "  - Entity ID",
              "",
              "⚠️ Ensure the tenant name in vendor config matches exactly:",
              finding.observed
            ],
            vendorFields: map.vendorFields,
            tooltip: "Every URL that mentions your KZero tenant must have the exact same casing. Mixed casing is a common cause of SSO failures."
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [
              `Different casing variants found: ${finding.observed}`,
              "One of these is correct, but they must all match exactly"
            ]
          },
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[Realm Settings](${getDocUrl("realmSettings")})`,
              `[OIDC Overview](${getDocUrl("oidcOverview")})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, only one tenant value appears and issuer values match exactly."],
        nextEvidence: ["Discovery URL", "Issuer", "SAML IdP Entity ID", "Tenant name casing"]
      };
    }
    case "OIDC_MISSING_OPENID_SCOPE": {
      return {
        title: "Missing openid scope",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "The vendor app's SSO configuration is missing the required 'openid' scope",
              "",
              "→ Check the vendor's SSO/OAuth configuration",
              "→ Look for a 'Scopes' or 'Permissions' field",
              "→ Add 'openid' to the list of requested scopes",
              "",
              "What is 'openid'? It's the minimum required scope for OIDC - without it, you won't get an ID token",
              "",
              "Common scope combinations:",
              "  - openid (required)",
              "  - openid profile (includes name and picture)",
              "  - openid email (includes email address)",
              "  - openid profile email (all user info)"
            ],
            vendorFields: ["Scope"],
            tooltip: "The 'openid' scope tells OIDC that this is an authentication request. Without it, the server doesn't know you want to log in - it just gives you an access token."
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[OIDC Auth Flows](${getDocUrl("oidcOverview")})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, authorize request scope includes openid."],
        nextEvidence: ["Authorize request URL with scope"]
      };
    }
    case "OIDC_INVALID_SCOPE": {
      return {
        title: "Invalid scope",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "The vendor is requesting a scope that KZero doesn't recognize or allow",
              "",
              "→ Check the vendor's SSO/OAuth configuration",
              "→ Look for 'Scopes' or 'Permissions' settings",
              "→ Remove any scopes that aren't standard OIDC:",
              "",
              "Standard OIDC scopes (usually supported):",
              "  ✅ openid - Required for OIDC",
              "  ✅ profile - User's name and picture",
              "  ✅ email - User's email address",
              "  ✅ offline_access - Access tokens without user present",
              "",
              "Scopes to remove (vendor-specific):",
              "  ❌ Any custom/vendor-specific scopes not configured in KZero"
            ],
            vendorFields: map.vendorFields,
            tooltip: "Scopes control what information you get back from login. Each scope must be both requested AND allowed by KZero. If a scope isn't configured, it will be rejected."
          },
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "If KZero is acting as OIDC client to vendor, confirm requested scopes match vendor supported set.",
              "Check 'Client Scopes' in the advanced console to see which scopes are allowed for this client.",
              "Avoid assuming every vendor supports generic OIDC scopes beyond openid/profile/email."
            ],
            kzeroFields: ["Client ID", "Client Scopes"],
            tooltip: "In KZero, you can control which scopes a client can request through 'Client Scopes'. Check if the requested scope is assigned to this client."
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[OIDC Client Configuration](${oidcDocLink})`,
              `[Client Scopes](${getDocUrl("samlClients")})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, the flow returns no invalid_scope error."],
        nextEvidence: ["Authorize request scope", "Vendor allowed scopes"]
      };
    }
    case "OIDC_CALLBACK_TOKEN_EXCHANGE_BROKEN": {
      return {
        title: "Callback reached but token exchange failed",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Check vendor app (SP) backend",
            owner: "vendor SP",
            bullets: [
              "The login page loaded, but the vendor's backend couldn't exchange the auth code for tokens",
              "",
              "→ Check vendor's backend/server logs for the actual error",
              "→ Verify the vendor backend can reach KZero's token endpoint:",
              `   https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/openid-connect/token`,
              "",
              "→ Check these common issues:",
              "   1. Network/Firewall: Can the vendor server reach KZero?",
              "   2. Client ID/Secret: Do they match exactly?",
              "   3. PKCE: If KZero requires PKCE, does vendor send code_verifier?",
              "   4. Redirect URI: Does it match exactly what was used in the auth request?"
            ],
            vendorFields: ["Token URL", "Client credentials", "Outbound connectivity"],
            tooltip: "After login, the vendor's server needs to exchange an 'authorization code' for actual tokens (ID token, access token). If this exchange fails, the user won't be logged in."
          },
          {
            title: "Check KZero configuration",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard → Select your tenant",
              "Navigate to: Integrations → Applications → [Select your OIDC app]",
              "Click 'Advanced Console' → Select 'Client' → search for app",
              "",
              "→ Go to 'Capability Config' section:",
              "   - Verify 'Client Authentication' is set correctly",
              "   - If using PKCE, ensure it's configured properly",
              "",
              "→ Go to 'Credentials' tab:",
              "   - Verify Client Secret is correct and hasn't expired"
            ],
            kzeroFields: ["Token URL", "Use PKCE", "Client authentication", "Client Secret"],
            tooltip: "The Client ID and Client Secret are like a username and password. If they don't match exactly, KZero will reject the token exchange."
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[OIDC Client Configuration](${oidcDocLink})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, token endpoint call exists and returns HTTP 200."],
        nextEvidence: ["Callback URL with code", "Token request/response status", "Vendor backend logs"]
      };
    }
    case "OIDC_JWKS_FETCH_FAILURE":
    case "OIDC_REACHABILITY_WAF_TLS_SUSPECTED": {
      return {
        title: "JWKS/cert fetch failed",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Network connectivity check",
            owner: "network",
            bullets: [
              "The vendor app couldn't reach KZero's JWKS endpoint to verify tokens",
              "",
              "→ Test if KZero is reachable from the vendor's server:",
              "   1. Open a browser and try:",
              `      https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/openid-connect/certs`,
              "   2. If using SAML:",
              `      https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/saml/descriptor`,
              "",
              "→ Check if the URL is blocked by:",
              "   - Firewall (port 443)",
              "   - WAF (Web Application Firewall)",
              "   - VPN (must be public, not private network)",
              "   - Geo-blocking",
              "",
              "→ Verify TLS certificate is valid (no expired certs)"
            ],
            tooltip: "JWKS is a set of public keys that vendors use to verify that tokens really came from KZero. If they can't fetch these keys, they can't verify the tokens."
          },
          {
            title: "Check KZero configuration",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard → Select your tenant",
              "Navigate to: Configure → Realm settings → General tab",
              "Scroll to the 'Endpoints' section at the bottom",
              "",
              "Verify these URLs are accessible from the internet:",
              "   - OpenID Endpoint Configuration",
              "   - SAML 2.0 Identity Provider Metadata",
              "",
              "⚠️ Endpoints must be publicly accessible - not behind a firewall or VPN"
            ],
            kzeroFields: ["Issuer", "Discovery Endpoint"],
            tooltip: "KZero's endpoints must be publicly accessible for vendors to fetch the public keys needed to verify tokens."
          },
          {
            title: "Check vendor configuration",
            owner: "vendor SP",
            bullets: [
              "Ask the vendor to check their network connectivity to KZero",
              "Request their server's outbound IPs if you need to whitelist them",
              "Verify they're using the correct tenant name in the JWKS URL",
              "",
              "Expected JWKS URL format:",
              `   https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/openid-connect/certs`
            ],
            vendorFields: ["JWKS URL", "Outbound connectivity"]
          },
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[Realm Settings](${getDocUrl("realmSettings")})`,
              `[OIDC Endpoints](${getDocUrl("oidcOverview")})`
            ]
          }
        ],
        verify: [...baseVerify, "In the new trace, JWKS returns HTTP 200 and token validation proceeds."],
        nextEvidence: ["JWKS URL", "HTTP status and error text", "WAF logs if available"]
      };
    }
    default: {
      const steps: string[] = [];
      if (map.kzeroFields.length) {
        steps.push(`→ Check these KZero Passwordless fields: ${map.kzeroFields.join(", ")}.`);
      }
      if (map.vendorFields.length) {
        steps.push(`→ Check these vendor app fields: ${map.vendorFields.join(", ")}.`);
      }
      steps.push(`Expected: ${finding.expected}.`);
      steps.push(`Observed: ${finding.observed}.`);

      const isOidcRelated = finding.ruleId.startsWith("OIDC_");
      const docLink = isOidcRelated ? oidcDocLink : docLink;

      return {
        title: finding.title,
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "What happened",
            owner: "browser",
            bullets: [finding.explanation],
            tooltip: finding.explanation
          },
          {
            title: "🔧 What to check",
            owner: finding.likelyOwner,
            bullets: steps,
            kzeroFields: map.kzeroFields,
            vendorFields: map.vendorFields
          },
          ...(vendorNotice ? [{
            title: "📖 Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "📚 Documentation",
            owner: "docs",
            bullets: [
              `[${isOidcRelated ? "OIDC" : "SAML"} Client Configuration](${docLink})`
            ]
          }
        ],
        verify: baseVerify,
        nextEvidence: finding.evidence
      };
    }
  }
};
