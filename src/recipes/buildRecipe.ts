import type { Finding } from "../shared/models";
import { getFieldMapping } from "../mappings/fieldMappings";
import type { TraceContext } from "./context";
import type { FixRecipe } from "./types";

const urlExactMatchNote = "Exact match matters: scheme, host, path, query (if used), and trailing slash.";

const baseVerify = [
  "Start capture, run login once, stop capture.",
  "Confirm the finding no longer appears and the flow progresses past the failing step.",
  "Export sanitized trace + attach to ticket if escalation is needed."
];

export const buildFixRecipe = (finding: Finding, ctx: TraceContext): FixRecipe => {
  const map = getFieldMapping(finding.ruleId);
  const kzeroTenantHint = ctx.tenants[0] ? `Tenant: ${ctx.tenants[0]} (case-sensitive)` : "Tenant name is case-sensitive";

  switch (finding.ruleId) {
    case "OIDC_REDIRECT_URI_MISMATCH": {
      const expected = finding.expected;
      const observed = finding.observed;
      const clientId = ctx.oidc.authorize?.clientId ?? ctx.oidc.token?.clientId;
      return {
        title: "Redirect URI mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              `Open the OIDC Identity Provider config used for this integration (${kzeroTenantHint}).`,
              `Set \"Redirect URL\" to exactly the vendor callback URL. ${urlExactMatchNote}`,
              clientId ? `Confirm \"Client ID\" is ${clientId}.` : "Confirm \"Client ID\" matches the vendor app.",
              "If \"Use discovery endpoint\" is enabled, confirm \"Discovery Endpoint\" points to the correct tenant."
            ],
            kzeroFields: map.kzeroFields,
            fieldExpectations: [{ field: "Redirect URL", expected }],
            copySnippets: [{ label: "Expected Redirect URL", value: expected }]
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
            copySnippets: [{ label: "Vendor Redirect URI", value: expected }]
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [`Requested redirect_uri: ${expected}`, `Browser callback reached: ${observed}`]
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
      return {
        title: "Discovery issuer mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              `Confirm the tenant name is correct and case-sensitive. ${kzeroTenantHint}.`,
              `If \"Use discovery endpoint\" is enabled, set \"Discovery Endpoint\" to the correct tenant discovery URL.`,
              `Set \"Issuer\" to exactly: ${issuerExpected}`,
              "Avoid mixing values across environments (prod vs staging)."
            ],
            kzeroFields: map.kzeroFields,
            fieldExpectations: [
              { field: "Discovery Endpoint", expected: ctx.oidc.discovery?.url ?? "" },
              { field: "Issuer", expected: issuerExpected }
            ].filter((e) => e.expected.length > 0),
            copySnippets: discoveryUrl ? [{ label: "Discovery URL used", value: discoveryUrl }] : undefined
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              `Set vendor \"Issuer\" / \"Authority\" to exactly: ${issuerExpected}`,
              "If vendor uses discovery, configure it to the same Discovery Endpoint you used in KZero."
            ],
            vendorFields: map.vendorFields,
            copySnippets: [{ label: "Expected Issuer", value: issuerExpected }]
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [
              discoveryUrl ? `Discovery URL: ${discoveryUrl}` : "Discovery URL captured",
              `issuer in discovery: ${issuerObserved}`,
              `expected issuer: ${issuerExpected}`
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
      return {
        title: "Client authentication failed (invalid_client)",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              clientId ? `Confirm \"Client ID\" is ${clientId}.` : "Confirm \"Client ID\" matches vendor configuration.",
              "Re-enter \"Client Secret\" (do not paste leading/trailing spaces).",
              "Verify \"Client authentication\" matches what the vendor uses (basic vs post vs private_key_jwt)."
            ],
            kzeroFields: map.kzeroFields
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Confirm vendor has the same Client ID and Client Secret as configured in KZero.",
              "Confirm token endpoint auth method matches (client_secret_basic vs client_secret_post).",
              "If vendor rotates secrets, generate a new secret and update both sides."
            ],
            vendorFields: map.vendorFields
          }
        ],
        verify: [...baseVerify, "In the new trace, token endpoint returns HTTP 200 and no invalid_client error."],
        nextEvidence: ["Token endpoint response error_description", "Client auth method configured on both sides"]
      };
    }
    case "SAML_AUDIENCE_MISMATCH": {
      return {
        title: "Audience / Entity ID mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Open the SAML Identity Provider / Application SAML settings for this integration.",
              `Set \"Service provider Entity ID\" to the vendor SP Entity ID / Audience URI expected by the vendor.`,
              kzeroTenantHint
            ],
            kzeroFields: map.kzeroFields,
            fieldExpectations: [{ field: "Service provider Entity ID", expected: finding.expected }],
            copySnippets: [{ label: "Expected SP Entity ID", value: finding.expected }]
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              `Set vendor \"SP Entity ID\" / \"Audience URI\" to exactly match the value KZero uses.`,
              "If vendor imported metadata, re-import to avoid truncation or stale values."
            ],
            vendorFields: map.vendorFields
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [`Observed audience: ${finding.observed}`, `Expected audience: ${finding.expected}`]
          }
        ],
        verify: [...baseVerify, "In the new trace, assertion Audience matches SP Entity ID exactly."],
        nextEvidence: ["Vendor SP Entity ID", "KZero Service provider Entity ID", "Assertion AudienceRestriction"]
      };
    }
    case "SAML_ACS_RECIPIENT_MISMATCH": {
      const acs = finding.expected;
      return {
        title: "ACS / Recipient mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Open the SAML application/client used for this vendor.",
              `Set \"Assertion Consumer Service URL\" to exactly: ${acs}`, 
              "If using IdP config screen, confirm \"Single Sign-On service url\" is the correct KZero SSO endpoint."
            ],
            kzeroFields: map.kzeroFields,
            fieldExpectations: [{ field: "Assertion Consumer Service URL", expected: acs }],
            copySnippets: [{ label: "Expected ACS URL", value: acs }]
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              `Set vendor \"ACS URL\" to exactly: ${acs}`,
              urlExactMatchNote,
              "If vendor has multiple ACS entries, ensure the active/default one matches."
            ],
            vendorFields: map.vendorFields
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
              "Confirm the vendor ACS URL configured in KZero is correct.",
              "If this is SP-initiated, ensure vendor metadata is up to date in KZero.",
              kzeroTenantHint
            ],
            kzeroFields: map.kzeroFields
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              `Ensure vendor posts the SAMLResponse to the same URL referenced by Destination (${destination}).`,
              `If vendor expects a different Destination/ACS URL, update it to: ${postedTo}`
            ],
            vendorFields: map.vendorFields,
            copySnippets: [{ label: "Posted-to URL", value: postedTo }]
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [`Destination in SAMLResponse: ${destination}`, `Browser posted to: ${postedTo}`]
          }
        ],
        verify: [...baseVerify, "In the new trace, Destination equals the receiving ACS URL."],
        nextEvidence: ["SAMLResponse Destination", "Actual POST target URL"]
      };
    }
    case "SAML_MISSING_NAMEID": {
      return {
        title: "Missing NameID",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Set \"Principal type\" and \"Pass subject\" so a stable identifier is used.",
              "Set \"NameID Policy Format\" to what the vendor expects (often emailAddress or persistent).",
              "If the vendor expects email, ensure KZero is sending an email-like principal." 
            ],
            kzeroFields: map.kzeroFields
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Configure vendor to use NameID (or a specific attribute) as the user identifier.",
              "If vendor requires a specific NameID format, set it explicitly."
            ],
            vendorFields: map.vendorFields
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
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Confirm KZero tenant and browser host system time are correct.",
              "Adjust \"Allow clock skew\" to tolerate small drift (seconds/minutes, not hours).",
              "Re-run flow immediately after changing clock skew settings."
            ],
            kzeroFields: ["Allow clock skew"]
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Confirm vendor server time is correct (NTP).",
              "If vendor has allowed skew setting, increase slightly."
            ],
            vendorFields: ["Allowed clock skew", "System time"]
          },
          {
            title: "What we observed",
            owner: "network",
            bullets: [`Assertion time value: ${windowValue}`]
          }
        ],
        verify: [...baseVerify, "In the new trace, NotBefore/NotOnOrAfter window covers the current time."],
        nextEvidence: ["NotBefore", "NotOnOrAfter", "System time on both ends"]
      };
    }
    case "REALM_CASE_MISMATCH": {
      return {
        title: "Realm casing mismatch",
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Identify the correct tenant name and exact casing.",
              "Update \"Discovery Endpoint\" / \"Issuer\" / SAML entity IDs to use the exact same tenant casing.",
              "Avoid mixing tenant casing between copied URLs."
            ],
            kzeroFields: map.kzeroFields
          },
          {
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Update vendor Issuer/Metadata URLs to match the exact tenant casing.",
              "Re-import metadata if the vendor caches old issuer values."
            ],
            vendorFields: map.vendorFields
          },
          {
            title: "What we observed",
            owner: "browser",
            bullets: [
              `Realm variants seen: ${finding.observed}`
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
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Add the openid scope to the authorization request.",
              "Keep profile/email scopes only if the vendor actually needs them.",
              "Retry login and confirm authorize request includes scope=openid ..."
            ],
            vendorFields: ["Scope"]
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
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Remove scopes not supported by the vendor or not allowed for this client.",
              "Ensure openid is present.",
              "If the vendor requires offline_access, confirm it is allowed for the client."
            ],
            vendorFields: map.vendorFields
          },
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "If KZero is acting as OIDC client to vendor, confirm requested scopes match vendor supported set.",
              "Avoid assuming every vendor supports generic OIDC scopes beyond openid/profile/email."
            ],
            kzeroFields: ["Client ID"]
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
            title: "Fix in vendor app (SP)",
            owner: "vendor SP",
            bullets: [
              "Confirm backend is exchanging the code at the Token URL.",
              "Confirm backend can reach KZero token endpoint (outbound firewall/WAF).",
              "Confirm client authentication method matches the client type."
            ],
            vendorFields: ["Token URL", "Client credentials", "Outbound connectivity"]
          },
          {
            title: "Fix in KZero",
            owner: "KZero",
            bullets: [
              "Confirm Token URL is correct for the tenant.",
              "If \"Use PKCE\" is enabled, ensure vendor supplies code_verifier to token endpoint.",
              kzeroTenantHint
            ],
            kzeroFields: ["Token URL", "Use PKCE", "Client authentication"]
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
            title: "Network/TLS checks",
            owner: "network",
            bullets: [
              "Test the JWKS URL in an incognito browser session and from the vendor backend network if possible.",
              "Check DNS resolution, TLS chain validity, and any WAF rate limiting or geo-blocking.",
              "Ensure endpoints are publicly reachable (not private/VPN-only) if the vendor validates tokens server-side."
            ]
          },
          {
            title: "KZero checks",
            owner: "KZero",
            bullets: [
              "Confirm the tenant endpoints are correct and match discovery jwks_uri.",
              kzeroTenantHint
            ],
            kzeroFields: ["Issuer", "Discovery Endpoint"]
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

      return {
        title: finding.title,
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: "What happened",
            owner: "browser",
            bullets: [finding.explanation]
          },
          {
            title: "What to check",
            owner: finding.likelyOwner,
            bullets: steps,
            kzeroFields: map.kzeroFields,
            vendorFields: map.vendorFields
          }
        ],
        verify: baseVerify,
        nextEvidence: finding.evidence
      };
    }
  }
};
