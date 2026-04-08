import type { Finding, Owner } from "../shared/models";
import { getFieldMapping } from "../mappings/fieldMappings";
import type { TraceContext } from "./context";
import type { FixRecipe } from "./types";
import type { FixLink } from "./types"; // eslint-disable-line @typescript-eslint/no-unused-vars
import { 
  buildOidcNavigationSteps, 
  buildRedirectUriFix, 
  buildClientIdFix,
  buildDiscoveryUrlFix,
  buildIssuerFix, // eslint-disable-line @typescript-eslint/no-unused-vars
  buildClientAuthFix, // eslint-disable-line @typescript-eslint/no-unused-vars
  detectOidcVendor,
  getOidcFieldTooltip // eslint-disable-line @typescript-eslint/no-unused-vars
} from "./guidance/oidc";
import {
  buildSamlNavigationSteps, // eslint-disable-line @typescript-eslint/no-unused-vars
  buildAcsUrlFix,
  buildEntityIdFix,
  buildIssuerFix as buildSamlIssuerFix, // eslint-disable-line @typescript-eslint/no-unused-vars
  buildNameIdFix,
  buildSigningFix, // eslint-disable-line @typescript-eslint/no-unused-vars
  buildBindingFix, // eslint-disable-line @typescript-eslint/no-unused-vars
  detectSamlVendor,
  getSamlFieldTooltip // eslint-disable-line @typescript-eslint/no-unused-vars
} from "./guidance/saml";
import { getDocUrl, formatVendorNotice } from "./guidance";

const urlExactMatchNote = "⚠️ Exact match matters: scheme, host, path, query (if used), and trailing slash.";

const baseVerify = [
  "Start capture, run login once, stop capture.",
  "Confirm the finding no longer appears and the flow progresses past the failing step.",
  "Export sanitized trace + attach to ticket if escalation is needed."
];

const formatStep = (step: { text: string; important?: boolean; warning?: boolean; field?: string }): string => {
  let prefix = "";
  if (step.important && step.warning) prefix = "⚠️ ";
  else if (step.important) prefix = "";
  else if (step.warning) prefix = "⚠️ ";
  return `${prefix}${step.text}`;
};

const docLinks = {
  samlClients: { label: "SAML Client Configuration", url: getDocUrl("samlClients") },
  oidcClients: { label: "OIDC Client Configuration", url: getDocUrl("oidcClients") },
  samlBindings: { label: "SAML Bindings", url: getDocUrl("samlBindings") },
  realmSettings: { label: "Realm Settings", url: getDocUrl("realmSettings") },
  oidcOverview: { label: "OIDC Overview", url: getDocUrl("oidcOverview") },
  samlOverview: { label: "SAML Overview", url: getDocUrl("samlOverview") },
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
    if (ctx.saml?.request?.url) {
      const detected = detectSamlVendor(ctx.saml.request.url);
      if (detected) return detected;
    }
    if (ctx.saml?.response?.url) {
      const detected = detectSamlVendor(ctx.saml.response.url);
      if (detected) return detected;
    }
    if (ctx.saml?.response?.samlResponse?.issuer) {
      const detected = detectSamlVendor(ctx.saml.response.samlResponse.issuer);
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
      const _clientId = ctx.oidc.authorize?.clientId ?? ctx.oidc.token?.clientId;
      const _navSteps = buildOidcNavigationSteps(true);
      const fixSteps = buildRedirectUriFix(observed, expected, vendorName);
      
      return {
        title: "Redirect URI mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "Fix in KZero",
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
              `Update vendor "Redirect URI / Callback URL" to exactly: ${expected}`,
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
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.oidcClients]
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
            title: "Fix in KZero",
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
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.oidcOverview, docLinks.realmSettings]
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
      const _fixSteps = buildClientIdFix(finding.observed, clientId || finding.expected, vendorName);
      
      return {
        title: "Client authentication failed (invalid_client)",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard, select your tenant",
              "Click 'Advanced Console', select 'Clients', search for your app",
              "Go to 'General settings' section",
              `Confirm 'Client ID' is: ${clientId || finding.expected}`,
              "",
              "Go to 'Capability Config' section, verify 'Client Authentication' is set correctly",
              "Go to 'Credentials' tab, check/regenerate 'Client Secret' if needed"
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
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.oidcClients]
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
            title: "Fix in KZero",
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
              `Set vendor "Entity ID" / "Audience URI" / "SP Entity ID" to exactly: ${finding.expected}`,
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
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients]
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
            title: "Fix in KZero",
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
              `Set vendor "ACS URL" / "Assertion Consumer Service URL" to exactly: ${acs}`,
              urlExactMatchNote,
              "If vendor has multiple ACS entries, ensure the active/default one matches.",
              "Verify the vendor is using HTTPS (not HTTP) for the ACS URL."
            ],
            vendorFields: map.vendorFields,
            tooltip: "The vendor app needs to tell KZero where to send the SAML response. This URL must match exactly on both sides."
          },
          ...(vendorNotice ? [{
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients]
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
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard, select your tenant",
              "Click 'Advanced Console', select 'Clients', search for your app",
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
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients, docLinks.samlBindings]
          }
        ],
        verify: [...baseVerify, "In the new trace, Destination equals the receiving ACS URL."],
        nextEvidence: ["SAMLResponse Destination", "Actual POST target URL"]
      };
    }
    case "SAML_AUTHNREQUEST_REJECTED_BY_KZERO": {
      const requestedAcs = finding.likelyFix.action.match(/Requested ACS URL from the trace: (.*?), \(2\)/)?.[1] ?? "(not captured)";
      return {
        title: "KZero rejected the sign-in request",
        owner: "KZero",
        confidence: finding.confidence,
        sections: [
          {
            title: "What happened",
            owner: "browser",
            bullets: [
              "The service provider sent a SAML AuthnRequest to KZero.",
              finding.observed,
              "No SAMLResponse was generated after that error."
            ]
          },
          {
            title: "What to check in KZero",
            owner: "KZero",
            bullets: [
              "Open the KZero integration Advanced settings for this app.",
              "Compare these values side by side:",
              `Requested ACS URL from trace: ${requestedAcs}`,
              "KZero Valid Redirect URIs",
              "KZero Assertion Consumer Service POST Binding URL",
              "These values must match exactly. Check hostname, tenant, environment, and trailing slash."
            ],
            kzeroFields: ["Valid Redirect URIs", "Assertion Consumer Service POST Binding URL"],
            copySnippets: [{ label: "Requested ACS URL from trace", value: requestedAcs }],
            tooltip: "When KZero rejects AuthnRequest before login, ACS/redirect URL mismatch is a common cause."
          },
          {
            title: "What to check in the service provider",
            owner: "vendor SP",
            bullets: [
              "Open the service provider SAML settings.",
              "Verify Assertion Consumer Service URL (ACS) exactly matches KZero values.",
              "If environment was copied (test/prod), replace outdated URLs."
            ],
            vendorFields: ["Assertion Consumer Service URL (ACS)", "SP Entity ID"]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [...baseVerify, "In the new trace, KZero SAML endpoint returns 2xx/3xx and a SAMLResponse is captured."],
        nextEvidence: ["AuthnRequest AssertionConsumerServiceURL", "KZero Valid Redirect URIs", "KZero Assertion Consumer Service POST Binding URL"]
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
            title: "Fix in KZero",
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
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients]
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
            title: "Check KZero time settings",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard, select your tenant",
              "Navigate to: Configure, Realm settings",
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
              "Verify KZero server time is accurate (check via 'Realm settings, General')",
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
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.realmSettings]
          }
        ],
        verify: [...baseVerify, "In the new trace, NotBefore/NotOnOrAfter window covers the current time."],
        nextEvidence: ["NotBefore", "NotOnOrAfter", "System time on both ends"]
      };
    }
    case "TENANT_CASE_MISMATCH": {
      const uniqueTenants = [...new Set(finding.evidence as string[])];
      return {
        title: "Tenant name casing mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "What Happened",
            owner: "analysis",
            bullets: [
              "Tenant names are case-sensitive in KZero URLs.",
              "We detected different casing variants in your authentication flow:",
              uniqueTenants.map(t => `  • ${t}`).join("\n"),
              "",
              "Mixed casing causes the Identity Provider to reject the request because the issuer doesn't match exactly."
            ]
          },
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "1. Go to your KZero dashboard, select your tenant",
              "2. Navigate to Configure, Realm settings, General",
              "3. Note the exact casing of your tenant name",
              "4. Scroll to Endpoints section and verify all URLs use the same casing",
              "",
              "⚠️ Tenant names are case-sensitive: 'ABCMSP' ≠ 'abcmasp'"
            ],
            kzeroFields: map.kzeroFields,
            tooltip: "The tenant name in your KZero URLs must be exactly correct. URL casing matters."
          },
          {
            title: "Fix in your application (SP)",
            owner: "vendor SP",
            bullets: [
              "Check all KZero-related URLs in your application settings:",
              "  • Discovery/Metadata URL",
              "  • Issuer URL",
              "  • SSO Login URL",
              "  • Entity ID",
              "",
              "Ensure the tenant name matches exactly with KZero.",
              `Expected: ${uniqueTenants[0]}`
            ],
            vendorFields: map.vendorFields,
            tooltip: "Every URL pointing to KZero must use the exact same tenant casing."
          },
          {
            title: "How to verify",
            owner: "verification",
            bullets: [
              "After making changes:",
              "1. Clear your browser cache",
              "2. Start a new trace",
              "3. Attempt login again",
              "4. Confirm only one tenant variant appears"
            ]
          },
          {
            title: "Learn more",
            owner: "docs" as Owner,
            bullets: [],
            links: [docLinks.realmSettings, docLinks.oidcOverview]
          }
        ],
        verify: [
          "In a new trace, only one tenant value appears",
          "All issuer/endpoints use consistent casing",
          "Login completes successfully"
        ],
        nextEvidence: ["Discovery URL", "Issuer URL", "SAML Entity ID", "Tenant casing"]
      };
    }

    // ============ PHASE 3: SIGNATURE/CERTIFICATE ISSUES ============
    case "SAML_ASSERTION_SIGNATURE_MISSING": {
      return {
        title: "Assertion signature not detected",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Check KZero signing settings",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard > Select your tenant",
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              "",
              "Go to 'Signature & Encryption' section",
              "",
              "> Check 'Sign Assertions':",
              "   - Turn ON if vendor requires signed assertions",
              "   - This adds a digital signature to prove KZero sent the assertion",
              "",
              "What is assertion signing?",
              "   Like a wax seal on a letter - proves the assertion really came from KZero",
              "   Many vendors require this for security"
            ],
            kzeroFields: ["Sign Assertions"],
            tooltip: "Assertion signing proves to the vendor that the assertion really came from KZero and wasn't tampered with."
          },
          {
            title: "Check vendor requirements",
            owner: "vendor SP",
            bullets: [
              "> Check what the vendor expects:",
              "   - Some vendors REQUIRE signed assertions",
              "   - Some vendors don't need signing",
              "   - Check vendor docs for 'Want Assertions Signed' or similar",
              "",
              "> If vendor requires signing, make sure KZero is configured to sign",
              "> If vendor doesn't need signing, you can leave it OFF"
            ],
            vendorFields: ["Want Assertions Signed", "Require signed assertions"]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [...baseVerify, "In the new trace, assertion signature is detected if vendor requires it."],
        nextEvidence: ["Assertion XML signature element", "Vendor signature requirements"]
      };
    }
    case "SAML_DOCUMENT_SIGNATURE_MISSING": {
      return {
        title: "Document signature not detected",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Understanding document vs assertion signing",
            owner: "KZero",
            bullets: [
              "There are TWO types of signing in SAML:",
              "",
              "1️⃣ Document Signing (Sign Documents):",
              "   - Signs the entire SAML response envelope",
              "   - Rarely needed by vendors",
              "   - Can cause compatibility issues",
              "",
              "2️⃣ Assertion Signing (Sign Assertions):",
              "   - Signs the actual user identity information",
              "   - What most vendors actually need",
              "   - Enable this instead"
            ],
            kzeroFields: ["Sign Documents", "Sign Assertions"],
            tooltip: "Document signing is usually unnecessary - assertion signing is what vendors typically require."
          },
          {
            title: "Recommendation",
            owner: "KZero",
            bullets: [
              "> Keep 'Sign Documents' OFF unless vendor specifically requires it",
              "> Enable 'Sign Assertions' ON if vendor requires signed assertions",
              "",
              "Most modern vendors only need assertion signing, not document signing"
            ]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [...baseVerify, "In the new trace, document signature is detected if required by vendor."],
        nextEvidence: ["Response XML signature element", "Vendor document signing requirement"]
      };
    }
    case "SAML_CERT_SIGNATURE_VALIDATION_CLUE": {
      return {
        title: "Certificate signature validation issue",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Check certificate configuration",
            owner: "KZero",
            bullets: [
              "The certificate used to sign assertions may need attention",
              "",
              "> Go to: Configure > Realm settings",
              "> Click on 'Keys' tab",
              "",
              "Check the signing keys:",
              "   - Are there active keys with 'Enabled' status?",
              "   - Has any key expired?",
              "   - Has a key been rotated recently?",
              "",
              "If key was rotated:",
              "   - Vendor may have cached old public key",
              "   - Ask vendor to refresh/re-download metadata"
            ],
            kzeroFields: ["Realm Keys"],
            tooltip: "The signing certificate proves KZero's identity. If it's expired or was recently rotated, vendors need to update their copy."
          },
          {
            title: "For the vendor app",
            owner: "vendor SP",
            bullets: [
              "> Ask vendor to:",
              "   1. Refresh/re-download KZero metadata",
              "   2. Update the IdP certificate if it was changed",
              "   3. Clear any certificate cache",
              "",
              "> Common certificate issues:",
              "   - Expired certificate",
              "   - Certificate was rotated but vendor still has old one",
              "   - Wrong certificate format (missing BEGIN/END markers)"
            ],
            vendorFields: ["IdP Certificate", "Signing Certificate"]
          },
          {
            title: "How to get KZero's certificate",
            owner: "KZero",
            bullets: [
              "> Go to: Configure > Realm settings > General tab",
              "> Scroll to 'Endpoints' section",
              "> Click 'SAML 2.0 Identity Provider Metadata'",
              "> Download the XML file",
              "> Share with vendor to update their configuration"
            ]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.realmSettings]
          }
        ],
        verify: [...baseVerify, "In the new trace, certificate validation succeeds."],
        nextEvidence: ["Certificate expiration date", "Metadata XML", "Vendor certificate cache"]
      };
    }

    // ============ PHASE 4: FLOW-SPECIFIC ISSUES ============
    case "SAML_WRONG_BINDING_CLUE": {
      return {
        title: "Unexpected SAML response binding",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Understanding SAML bindings",
            owner: "KZero",
            bullets: [
              "SAML responses can be sent two ways:",
              "",
              "1️⃣ POST Binding (recommended for most vendors):",
              "   - Sends response as form data",
              "   - More reliable, works with most vendors",
              "   - User clicks and data is submitted",
              "",
              "2️⃣ Redirect Binding:",
              "   - Sends response as URL parameters",
              "   - Can have issues with large responses",
              "   - Some vendors don't support this"
            ],
            tooltip: "SAML binding is how the login response gets delivered. POST is more reliable for most vendors."
          },
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard > Select your tenant",
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              "",
              "Go to 'SAML Capabilities' section",
              "",
              "> Enable 'Force POST Binding' if vendor requires POST",
              "> Disable if vendor accepts redirect"
            ],
            kzeroFields: ["Force POST Binding"],
            tooltip: "Force POST Binding tells KZero to always use the POST method. Enable this if the vendor expects form-based responses."
          },
          {
            title: "Check vendor requirements",
            owner: "vendor SP",
            bullets: [
              "> Ask the vendor what binding they support:",
              "   - POST binding: Most vendors support this",
              "   - Redirect binding: Some vendors only accept this",
              "",
              "> If vendor requires POST, ensure KZero has 'Force POST Binding' ON",
              "> If vendor accepts either, either setting should work"
            ],
            vendorFields: ["SAML Binding", "Response Binding"]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlBindings]
          }
        ],
        verify: [...baseVerify, "In the new trace, response binding matches vendor requirements."],
        nextEvidence: ["Response binding type", "Vendor binding requirements"]
      };
    }
    case "OIDC_STATE_MISSING_OR_MISMATCH": {
      return {
        title: "State parameter missing or mismatched",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Understanding the state parameter",
            owner: "browser",
            bullets: [
              "The 'state' parameter is a security feature that:",
              "   - Prevents CSRF (Cross-Site Request Forgery) attacks",
              "   - Links your login request to the response",
              "   - Must be the same on both sides",
              "",
              "Why it fails:",
              "   - Browser extensions sometimes strip URL parameters",
              "   - Vendor app may not be preserving state through redirects",
              "   - State was never generated in the first place"
            ],
            tooltip: "The state parameter is like a receipt number - it proves this login response goes with your original request."
          },
          {
            title: "Fix in vendor app",
            owner: "vendor SP",
            bullets: [
              "> Check vendor SSO configuration:",
              "   - Is state generation enabled?",
              "   - Is state being preserved through the login flow?",
              "",
              "> Check for issues:",
              "   - Browser extensions blocking parameters",
              "   - Redirect chain dropping state",
              "   - State stored in wrong place (session vs cookie)",
              "",
              "> Test in incognito/private browser to rule out extensions"
            ],
            vendorFields: ["State parameter", "CSRF protection"]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, "In the new trace, state parameter matches between authorize and callback."],
        nextEvidence: ["Authorize request state", "Callback state value"]
      };
    }
    case "OIDC_NONCE_MISSING": {
      return {
        title: "Nonce missing for ID token response",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Understanding the nonce parameter",
            owner: "vendor SP",
            bullets: [
              "A nonce is a unique, random value that:",
              "   - Prevents replay attacks",
              "   - Proves the ID token is for THIS login request",
              "   - Should be unique for each login attempt",
              "",
              "When is it required?",
              "   - Required when using 'Hybrid Flow' (response includes id_token)",
              "   - Optional for pure Authorization Code flow",
              "",
              "What happens without it?",
              "   - Security vulnerability to token replay attacks",
              "   - May cause login failures with strict vendors"
            ],
            tooltip: "A nonce is like a one-time scratch card - each login has a unique code to prevent someone from replaying an old stolen token."
          },
          {
            title: "Fix in vendor app",
            owner: "vendor SP",
            bullets: [
              "> Enable nonce generation in vendor OIDC settings",
              "> Make sure the nonce:",
              "   - Is generated fresh for each login",
              "   - Is included in the authorization request",
              "   - Is validated against the ID token on callback"
            ],
            vendorFields: ["Nonce", "Hybrid Flow settings"]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, "In the new trace, nonce is present in authorize and matches ID token."],
        nextEvidence: ["Authorize request nonce", "ID token nonce claim"]
      };
    }
    case "OIDC_PKCE_INCONSISTENT": {
      return {
        title: "PKCE code_verifier missing",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Understanding PKCE",
            owner: "KZero",
            bullets: [
              "PKCE (Proof Key for Code Exchange) is an extra security layer:",
              "   - Generates a random 'code verifier' before login",
              "   - Sends a hash 'code challenge' with the request",
              "   - Proves the same client is exchanging the code",
              "",
              "Why it matters:",
              "   - Prevents authorization code interception attacks",
              "   - Required for public clients (SPAs, mobile apps)",
              "   - Recommended for all OIDC flows"
            ],
            tooltip: "PKCE is like adding a second lock - even if someone steals the authorization code, they can't use it without the verifier."
          },
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard > Select your tenant",
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              "",
              "Go to 'Capability Config' section",
              "",
              "> Check 'PKCE Method':",
              "   - S256 (recommended) - Uses SHA-256 hash",
              "   - Plain - Uses plain text (less secure)",
              "   - None - PKCE disabled"
            ],
            kzeroFields: ["PKCE Method"],
            tooltip: "PKCE Method determines how the code verifier is hashed. S256 is the recommended secure option."
          },
          {
            title: "Fix in vendor app",
            owner: "vendor SP",
            bullets: [
              "> Vendor MUST use PKCE consistently:",
              "   - If KZero requires PKCE, vendor must send code_verifier",
              "   - If KZero doesn't require PKCE, vendor shouldn't send challenge",
              "",
              "> Check vendor OIDC settings:",
              "   - Enable/disable PKCE to match KZero",
              "   - Ensure code_verifier is sent at token endpoint"
            ],
            vendorFields: ["PKCE", "Code Challenge Method"]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [...baseVerify, "In the new trace, PKCE is consistent between authorize and token exchange."],
        nextEvidence: ["code_challenge in authorize", "code_verifier in token request"]
      };
    }
    case "SAML_INRESPONSETO_MISSING": {
      return {
        title: "InResponseTo missing",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Understanding SP-initiated vs IdP-initiated SSO",
            owner: "vendor SP",
            bullets: [
              "There are two ways SAML SSO can work:",
              "",
              "1️⃣ SP-Initiated (most common):",
              "   - User goes to vendor app first",
              "   - App sends AuthnRequest to KZero",
              "   - Response includes InResponseTo (references the request)",
              "",
              "2️⃣ IdP-Initiated:",
              "   - User goes to KZero first",
              "   - KZero sends response without InResponseTo",
              "   - Vendor must accept responses without InResponseTo"
            ],
            tooltip: "InResponseTo links the response to the original request. Missing InResponseTo means it's an IdP-initiated login."
          },
          {
            title: "Fix the issue",
            owner: "vendor SP",
            bullets: [
              "> If vendor expects SP-initiated:",
              "   - Ensure the login flow starts from vendor app",
              "   - Check vendor isn't stripping the AuthnRequest",
              "",
              "> If vendor accepts IdP-initiated:",
              "   - Vendor must be configured to accept responses without InResponseTo",
              "   - Some vendors require this setting to be enabled"
            ],
            vendorFields: ["Accept IdP-Initiated", "Allow unsolicited responses"]
          },
          {
            title: "KZero configuration",
            owner: "KZero",
            bullets: [
              "For IdP-initiated login, KZero provides:",
              "   - 'IDP-Initiated SSO URL Name' field in Access settings",
              "   - Creates a direct login URL:",
              `      https://ca.auth.kzero.com/realms/<TENANT>/protocol/saml/clients/<CLIENT_ID>`
            ],
            kzeroFields: ["IDP-Initiated SSO URL Name"]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [...baseVerify, "In the new trace, InResponseTo is present for SP-initiated, or vendor accepts IdP-initiated."],
        nextEvidence: ["AuthnRequest ID", "InResponseTo value", "Vendor initated login setting"]
      };
    }
    case "SAML_IDP_SP_INIT_MISMATCH_CLUE": {
      return {
        title: "IdP vs SP initiated flow mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 SSO Flow Types Explained",
            owner: "vendor SP",
            bullets: [
              "Your trace shows a mismatch between login flows:",
              "",
              "The SAML response has InResponseTo (SP-initiated marker)",
              "but no AuthnRequest was captured (IdP-initiated marker)",
              "",
              "This can happen if:",
              "   - Login started before trace capture",
              "   - AuthnRequest happened on a different device",
              "   - Vendor is doing something unusual"
            ],
            tooltip: "The trace captured the response but not the request. This is usually a timing issue, not a configuration error."
          },
          {
            title: "What to check",
            owner: "vendor SP",
            bullets: [
              "> Verify vendor supports the flow you're testing:",
              "   - SP-initiated: Login starts from vendor app",
              "   - IdP-initiated: Login starts from KZero dashboard",
              "",
              "> Make sure trace captures the FULL login flow:",
              "   - Start trace BEFORE clicking any login button",
              "   - Include the entire redirect chain",
              "",
              "> If this was just a capture timing issue, re-test with full capture"
            ],
            vendorFields: ["SSO Flow Type", "IdP-Initiated supported"]
          },
          {
            title: "Recommendation",
            owner: "vendor SP",
            bullets: [
              "> For testing, use SP-initiated flow:",
              "   1. Start trace capture",
              "   2. Go to vendor app login page",
              "   3. Click SSO/login button",
              "   4. Complete login at KZero",
              "   5. Stop trace after returning to vendor app"
            ]
          }
        ],
        verify: [...baseVerify, "In a new trace, capture the full login flow from start to finish."],
        nextEvidence: ["Full redirect chain", "AuthnRequest capture", "Login flow timing"]
      };
    }
    case "SAML_ASSERTION_ENCRYPTED": {
      return {
        title: "Assertion is encrypted",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Understanding assertion encryption",
            owner: "KZero",
            bullets: [
              "Encrypted assertions contain the user data in a locked box:",
              "   - The box can only be opened with the SP's private key",
              "   - Prevents eavesdropping during transit",
              "   - Not all vendors support this",
              "",
              "Common issues:",
              "   - Vendor doesn't have the decryption key",
              "   - Wrong encryption algorithm",
              "   - Vendor expects unsigned + unencrypted"
            ],
            tooltip: "Encrypted assertions keep the user data secret during transmission. But not all vendors can handle encryption."
          },
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard > Select your tenant",
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              "",
              "Go to 'Keys' tab",
              "",
              "> Check 'Encryption' settings:",
              "   - 'Client signature and encryption key'",
              "   - Encryption enabled = sends encrypted assertions",
              "",
              "> If vendor can't handle encryption, disable it here"
            ],
            kzeroFields: ["Encryption", "Client encryption key"],
            tooltip: "Turn off assertion encryption if the vendor can't decrypt the assertions."
          },
          {
            title: "Check vendor requirements",
            owner: "vendor SP",
            bullets: [
              "> Ask vendor:",
              "   - Do you support encrypted SAML assertions?",
              "   - What's your encryption key/certificate?",
              "",
              "> If vendor doesn't support encryption:",
              "   - Disable encryption in KZero",
              "   - Assertions will be sent in plain text (but still signed)"
            ],
            vendorFields: ["Want Assertions Encrypted", "Decryption Certificate"]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [...baseVerify, "In the new trace, assertion encryption matches vendor capabilities."],
        nextEvidence: ["EncryptedAssertion element", "Vendor encryption support"]
      };
    }
    case "SAML_NAMEID_FORMAT_MISMATCH": {
      return {
        title: "Likely wrong NameID format",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Understanding NameID formats",
            owner: "KZero",
            bullets: [
              "NameID is how KZero identifies the user to the vendor:",
              "",
              "Common formats:",
              "   - emailAddress: user@example.com",
              "   - persistent: A unique opaque ID like 'AB123...'",
              "   - transient: A temporary anonymous ID",
              "",
              "The issue:",
              "   - Format says 'emailAddress'",
              "   - But the value doesn't look like an email!"
            ],
            tooltip: "The NameID format and value must match what the vendor expects."
          },
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard > Select your tenant",
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              "",
              "Go to 'SAML Capabilities' section",
              "",
              "> Check 'Name ID format':",
              "   - If vendor expects email, make sure user principal IS an email",
              "   - If vendor expects persistent ID, verify the mapper sends correct format"
            ],
            kzeroFields: ["Name ID format", "Force Name ID Format"],
            tooltip: "The NameID format must match what the vendor expects. Check if the user's identity is being sent in the correct format."
          },
          {
            title: "Fix in vendor app",
            owner: "vendor SP",
            bullets: [
              "> Check what format the vendor expects:",
              "   - Most modern apps expect emailAddress",
              "   - Some legacy apps expect persistent (unique user ID)",
              "",
              "> If vendor shows email format but you use username:",
              "   - Map 'username' to the email attribute OR",
              "   - Change vendor to accept your format"
            ],
            vendorFields: ["NameID Format", "User Identifier"]
          },
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [...baseVerify, "In the new trace, NameID format and value match vendor expectations."],
        nextEvidence: ["NameID format value", "Vendor expected format"]
      };
    }
    case "SAML_RELAYSTATE_UNEXPECTED": {
      return {
        title: "RelayState mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "🔧 Understanding RelayState",
            owner: "vendor SP",
            bullets: [
              "RelayState is where the user should go after login:",
              "   - Embedded in the login URL",
              "   - Passed through KZero unchanged",
              "   - Vendor uses it to redirect after SSO",
              "",
              "Common issues:",
              "   - RelayState gets lost in redirect chain",
              "   - Vendor encodes/decodes differently",
              "   - Too much data for RelayState limit"
            ],
            tooltip: "RelayState tells the vendor where to send the user after login - like a 'forwarding address' on an envelope."
          },
          {
            title: "What to check",
            owner: "vendor SP",
            bullets: [
              "> Verify vendor supports RelayState:",
              "   - Some vendors ignore it entirely",
              "   - Some have character limits",
              "   - Some require specific encoding",
              "",
              "> Check the RelayState value:",
              "   - Is it URL-encoded properly?",
              "   - Is it too long? (RelayState has size limits)",
              "   - Does vendor expect base64 encoding?"
            ],
            vendorFields: ["RelayState", "Post-login redirect"]
          }
        ],
        verify: [...baseVerify, "In the new trace, RelayState is preserved and vendor accepts it."],
        nextEvidence: ["RelayState in request", "RelayState in response", "Post-login redirect"]
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
              "> Check the vendor's SSO/OAuth configuration",
              "> Look for a 'Scopes' or 'Permissions' field",
              "> Add 'openid' to the list of requested scopes",
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
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.oidcOverview]
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
              "> Check the vendor's SSO/OAuth configuration",
              "> Look for 'Scopes' or 'Permissions' settings",
              "> Remove any scopes that aren't standard OIDC:",
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
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.oidcClients, docLinks.samlClients]
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
              "> Check vendor's backend/server logs for the actual error",
              "> Verify the vendor backend can reach KZero's token endpoint:",
              `   https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/openid-connect/token`,
              "",
              "> Check these common issues:",
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
              "Go to your KZero dashboard > Select your tenant",
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              "",
              "> Go to 'Capability Config' section:",
              "   - Verify 'Client Authentication' is set correctly",
              "   - If using PKCE, ensure it's configured properly",
              "",
              "> Go to 'Credentials' tab:",
              "   - Verify Client Secret is correct and hasn't expired"
            ],
            kzeroFields: ["Token URL", "Use PKCE", "Client authentication", "Client Secret"],
            tooltip: "The Client ID and Client Secret are like a username and password. If they don't match exactly, KZero will reject the token exchange."
          },
          ...(vendorNotice ? [{
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.oidcClients]
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
              "> Test if KZero is reachable from the vendor's server:",
              "   1. Open a browser and try:",
              `      https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/openid-connect/certs`,
              "   2. If using SAML:",
              `      https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/saml/descriptor`,
              "",
              "> Check if the URL is blocked by:",
              "   - Firewall (port 443)",
              "   - WAF (Web Application Firewall)",
              "   - VPN (must be public, not private network)",
              "   - Geo-blocking",
              "",
              "> Verify TLS certificate is valid (no expired certs)"
            ],
            tooltip: "JWKS is a set of public keys that vendors use to verify that tokens really came from KZero. If they can't fetch these keys, they can't verify the tokens."
          },
          {
            title: "Check KZero configuration",
            owner: "KZero",
            bullets: [
              "Go to your KZero dashboard > Select your tenant",
              "Navigate to: Configure > Realm settings > General tab",
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
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [docLinks.realmSettings, docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, "In the new trace, JWKS returns HTTP 200 and token validation proceeds."],
        nextEvidence: ["JWKS URL", "HTTP status and error text", "WAF logs if available"]
      };
    }
    default: {
      const steps: string[] = [];
      if (map.kzeroFields.length) {
        steps.push(`Check these KZero Passwordless fields: ${map.kzeroFields.join(", ")}.`);
      }
      if (map.vendorFields.length) {
        steps.push(`Check these vendor app fields: ${map.vendorFields.join(", ")}.`);
      }
      steps.push(`Expected: ${finding.expected}.`);
      steps.push(`Observed: ${finding.observed}.`);

      const isOidcRelated = finding.ruleId.startsWith("OIDC_");
      const _defaultDocLink = isOidcRelated ? oidcDocLink : docLink;

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
            title: "What to check",
            owner: finding.likelyOwner,
            bullets: steps,
            kzeroFields: map.kzeroFields,
            vendorFields: map.vendorFields
          },
          ...(vendorNotice ? [{
            title: "Vendor Guide",
            owner: "docs",
            bullets: [vendorNotice]
          }] : []),
          {
            title: "Documentation",
            owner: "docs",
            bullets: [],
            links: [isOidcRelated ? docLinks.oidcClients : docLinks.samlClients]
          }
        ],
        verify: baseVerify,
        nextEvidence: finding.evidence
      };
    }
  }
};
