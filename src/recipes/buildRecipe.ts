import type { Finding, Owner } from '../shared/models';
import { getFieldMapping } from '../mappings/fieldMappings';
import type { TraceContext } from './context';
import type { FixRecipe } from './types';
import type { FixLink } from './types'; // eslint-disable-line @typescript-eslint/no-unused-vars
import {
  buildOidcNavigationSteps,
  buildRedirectUriFix,
  buildClientIdFix,
  buildDiscoveryUrlFix,
  buildIssuerFix, // eslint-disable-line @typescript-eslint/no-unused-vars
  buildClientAuthFix, // eslint-disable-line @typescript-eslint/no-unused-vars
  detectOidcVendor,
  getOidcFieldTooltip // eslint-disable-line @typescript-eslint/no-unused-vars
} from './guidance/oidc';
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
} from './guidance/saml';
import { getDocUrl, formatVendorNotice } from './guidance';

const urlExactMatchNote =
  '⚠️ Exact match matters: scheme, host, path, query (if used), and trailing slash.';

const baseVerify = [
  'Start capture, run login once, stop capture.',
  'Confirm the finding no longer appears and the flow progresses past the failing step.',
  'Export sanitized trace + attach to ticket if escalation is needed.'
];

const formatStep = (step: {
  text: string;
  important?: boolean;
  warning?: boolean;
  field?: string;
}): string => {
  let prefix = '';
  if (step.important && step.warning) prefix = '⚠️ ';
  else if (step.important) prefix = '';
  else if (step.warning) prefix = '⚠️ ';
  return `${prefix}${step.text}`;
};

const docLinks = {
  samlClients: { label: 'SAML Client Configuration', url: getDocUrl('samlClients') },
  oidcClients: { label: 'OIDC Client Configuration', url: getDocUrl('oidcClients') },
  samlBindings: { label: 'SAML Bindings', url: getDocUrl('samlBindings') },
  realmSettings: { label: 'Realm Settings', url: getDocUrl('realmSettings') },
  oidcOverview: { label: 'OIDC Overview', url: getDocUrl('oidcOverview') },
  samlOverview: { label: 'SAML Overview', url: getDocUrl('samlOverview') }
};

export const buildFixRecipe = (finding: Finding, ctx: TraceContext): FixRecipe => {
  const map = getFieldMapping(finding.ruleId);
  const kzeroTenantHint = ctx.tenants[0]
    ? `Tenant: ${ctx.tenants[0]} (case-sensitive)`
    : 'Tenant name is case-sensitive';

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
  const vendorNotice = vendorName ? formatVendorNotice(vendorName, 'both') : '';
  const docLink = getDocUrl('samlClients');
  const oidcDocLink = getDocUrl('oidcClients');

  switch (finding.ruleId) {
    case 'OIDC_REDIRECT_URI_MISMATCH': {
      const expected = finding.expected;
      const observed = finding.observed;
      const _clientId = ctx.oidc.authorize?.clientId ?? ctx.oidc.token?.clientId;
      const _navSteps = buildOidcNavigationSteps(true);
      const fixSteps = buildRedirectUriFix(observed, expected, vendorName);

      return {
        title: 'Redirect URI mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: fixSteps.map(formatStep),
            kzeroFields: map.kzeroFields,
            fieldExpectations: [{ field: 'Valid Redirect URIs', expected }],
            copySnippets: [{ label: 'Expected Redirect URL', value: expected }],
            tooltip:
              'The Redirect URI (or callback URL) is where the vendor app tells KZero to send the user after login. It must match exactly or the login fails.'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              `Update vendor "Redirect URI / Callback URL" to exactly: ${expected}`,
              urlExactMatchNote,
              'If the vendor supports multiple redirect URIs, remove stale ones from other environments.',
              'Retry login after saving changes.'
            ],
            vendorFields: map.vendorFields,
            copySnippets: [{ label: 'Vendor Redirect URI', value: expected }],
            tooltip:
              'The vendor app needs to tell KZero where to send the user after they log in. This must match exactly.'
          },
          {
            title: 'What we observed',
            owner: 'browser',
            bullets: [`Expected redirect_uri: ${expected}`, `Browser callback reached: ${observed}`]
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, ensure authorize request redirect_uri equals the callback URL that is reached.'
        ],
        nextEvidence: [
          'Authorize request URL',
          'Callback URL',
          'Configured redirect/callback URI on vendor side'
        ]
      };
    }
    case 'OIDC_DISCOVERY_ISSUER_MISMATCH': {
      const discoveryUrl = ctx.oidc.discovery?.url;
      const issuerObserved = ctx.oidc.discovery?.issuer ?? finding.observed;
      const issuerExpected = finding.expected;
      const fixSteps = buildDiscoveryUrlFix(issuerExpected);

      return {
        title: 'Discovery issuer mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              ...fixSteps.map(formatStep),
              '',
              '⚠️ The issuer URL is CASE SENSITIVE - check for any uppercase/lowercase mismatches',
              `Tenant name must match exactly: ${kzeroTenantHint}`
            ],
            kzeroFields: map.kzeroFields,
            fieldExpectations: [
              { field: 'OIDC Discovery URL', expected: ctx.oidc.discovery?.url ?? '' },
              { field: 'Issuer', expected: issuerExpected }
            ].filter((e) => e.expected.length > 0),
            copySnippets: discoveryUrl
              ? [{ label: 'Discovery URL used', value: discoveryUrl }]
              : undefined,
            tooltip:
              'The Issuer is the unique identifier for your KZero tenant. Both KZero and the vendor must agree on exactly the same issuer value (case-sensitive).'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              `Set vendor "Issuer" / "Authority" to exactly: ${issuerExpected}`,
              'If vendor uses discovery, configure it to the same Discovery Endpoint you used in KZero.',
              "⚠️ Verify the exact casing - 'ABCMSP' is not the same as 'abcmasp'"
            ],
            vendorFields: map.vendorFields,
            copySnippets: [{ label: 'Expected Issuer', value: issuerExpected }],
            tooltip:
              'The vendor app needs to know exactly who issued the tokens. The issuer must match exactly (case-sensitive).'
          },
          {
            title: 'What we observed',
            owner: 'browser',
            bullets: [
              discoveryUrl ? `Discovery URL: ${discoveryUrl}` : 'Discovery URL captured',
              `Issuer in discovery: ${issuerObserved}`,
              `Expected issuer: ${issuerExpected}`
            ]
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcOverview, docLinks.realmSettings]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, discovery issuer equals the tenant base URL and matches token iss when JWT is present.'
        ],
        nextEvidence: ['Discovery URL', 'Discovery response issuer', 'Tenant name and casing']
      };
    }
    case 'OIDC_INVALID_CLIENT': {
      const clientId = ctx.oidc.authorize?.clientId ?? ctx.oidc.token?.clientId;
      const _fixSteps = buildClientIdFix(
        finding.observed,
        clientId || finding.expected,
        vendorName
      );

      return {
        title: 'Client authentication failed (invalid_client)',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard, select your tenant',
              "Click 'Advanced Console', select 'Clients', search for your app",
              "Go to 'General settings' section",
              `Confirm 'Client ID' is: ${clientId || finding.expected}`,
              '',
              "Go to 'Capability Config' section, verify 'Client Authentication' is set correctly",
              "Go to 'Credentials' tab, check/regenerate 'Client Secret' if needed"
            ],
            kzeroFields: map.kzeroFields,
            tooltip:
              'The Client ID and Client Secret are like a username and password for your app. Both KZero and the vendor must use the same values.'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              'Confirm vendor has the same Client ID as configured in KZero',
              `Expected Client ID: ${clientId || finding.expected}`,
              'Confirm the Client Secret matches exactly (check for leading/trailing spaces)',
              'Verify the authentication method matches:',
              "  - 'Client secret basic' (default) or",
              "  - 'Client secret post' or",
              "  - 'None' (for public/SPA clients)"
            ],
            vendorFields: map.vendorFields,
            tooltip:
              'The vendor app needs to authenticate itself to KZero using the same Client ID and Client Secret.'
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, token endpoint returns HTTP 200 and no invalid_client error.'
        ],
        nextEvidence: [
          'Token endpoint response error_description',
          'Client auth method configured on both sides'
        ]
      };
    }
    case 'SAML_AUDIENCE_MISMATCH': {
      const fixSteps = buildEntityIdFix(finding.observed, finding.expected, vendorName);

      return {
        title: 'Audience / Entity ID mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              ...fixSteps.map(formatStep),
              '',
              '⚠️ The Entity ID must match exactly - this is case-sensitive'
            ],
            kzeroFields: map.kzeroFields,
            fieldExpectations: [{ field: 'Client ID', expected: finding.expected }],
            copySnippets: [{ label: 'Expected SP Entity ID', value: finding.expected }],
            tooltip:
              'The Entity ID is like a company name on a business card - both KZero and the vendor app need to agree on exactly who each other are. Case-sensitive!'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              `Set vendor "Entity ID" / "Audience URI" / "SP Entity ID" to exactly: ${finding.expected}`,
              'If vendor imported metadata, re-import to avoid truncation or stale values.',
              '⚠️ Entity IDs are case-sensitive - verify exact casing'
            ],
            vendorFields: map.vendorFields,
            tooltip:
              'The vendor app needs to identify itself with the same Entity ID that KZero expects. Both sides must match exactly.'
          },
          {
            title: 'What we observed',
            owner: 'browser',
            bullets: [
              `Observed Entity ID: ${finding.observed}`,
              `Expected Entity ID: ${finding.expected}`
            ]
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, assertion Audience matches SP Entity ID exactly.'
        ],
        nextEvidence: [
          'Vendor SP Entity ID',
          'KZero Service provider Entity ID',
          'Assertion AudienceRestriction'
        ]
      };
    }
    case 'SAML_ACS_RECIPIENT_MISMATCH': {
      const acs = finding.expected;
      const fixSteps = buildAcsUrlFix(finding.observed, acs, vendorName);

      return {
        title: 'Check the ACS URL first',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Check these KZero settings first',
            owner: 'KZero',
            bullets: fixSteps.map(formatStep),
            kzeroFields: map.kzeroFields,
            fieldExpectations: [{ field: 'Master SAML Processing URL', expected: acs }],
            copySnippets: [{ label: 'Requested ACS URL from this sign-in attempt', value: acs }],
            tooltip:
              'The ACS URL (Assertion Consumer Service URL) is the reply URL where the service provider receives the SAML response from KZero. This should match your configured ACS URL exactly.'
          },
          {
            title: 'Then check the service provider settings',
            owner: 'vendor SP',
            bullets: [
              `Check that the service provider ACS URL matches: ${acs}`,
              'This should match your configured ACS URL exactly.',
              'Even one extra character, a wrong hostname, a path difference, an environment mismatch, or a trailing slash can break sign-in.',
              'If the provider has multiple ACS entries, ensure the active/default one matches.',
              'Verify the provider is using HTTPS (not HTTP) for the ACS URL.'
            ],
            vendorFields: map.vendorFields,
            tooltip:
              'The service provider needs to tell KZero where to send the SAML response. This URL must match exactly on both sides.'
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [...baseVerify, 'In the new trace, Recipient equals the posted ACS URL.'],
        nextEvidence: ['Vendor ACS URL setting', 'Assertion SubjectConfirmationData Recipient']
      };
    }
    case 'SAML_DESTINATION_MISMATCH': {
      const destination = finding.observed;
      const postedTo = finding.expected;

      return {
        title: 'SAML Destination mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard, select your tenant',
              "Click 'Advanced Console', select 'Clients', search for your app",
              "Go to 'Access settings' section",
              "Find 'Master SAML Processing URL' (ACS URL)",
              '',
              `Confirm the ACS URL is set to: ${postedTo}`,
              '⚠️ The URL must match exactly - including https:// and trailing slash'
            ],
            kzeroFields: map.kzeroFields,
            tooltip:
              'The Destination tells the vendor app where the SAML response is being sent. It must match what the vendor expects.'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              `Ensure vendor is configured to receive the SAML response at: ${postedTo}`,
              `Current vendor destination: ${destination}`,
              'Check if vendor has multiple ACS URLs and ensure the correct one is active.',
              'Verify the vendor is using HTTPS (not HTTP) for receiving SAML.'
            ],
            vendorFields: map.vendorFields,
            copySnippets: [{ label: 'Expected ACS URL', value: postedTo }],
            tooltip:
              'The vendor app needs to be listening at the same URL where KZero is sending the SAML response.'
          },
          {
            title: 'What we observed',
            owner: 'browser',
            bullets: [
              `Destination in SAMLResponse: ${destination}`,
              `Browser posted to: ${postedTo}`
            ]
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients, docLinks.samlBindings]
          }
        ],
        verify: [...baseVerify, 'In the new trace, Destination equals the receiving ACS URL.'],
        nextEvidence: ['SAMLResponse Destination', 'Actual POST target URL']
      };
    }
    case 'SAML_AUTHNREQUEST_REJECTED_BY_KZERO': {
      const requestedAcs =
        finding.likelyFix.action.match(/Requested ACS URL from the trace: (.*?), \(2\)/)?.[1] ??
        '(not captured)';
      return {
        title: 'KZero rejected the sign-in request',
        owner: 'KZero',
        confidence: finding.confidence,
        sections: [
          {
            title: 'What happened',
            owner: 'browser',
            bullets: [
              'The service provider sent a SAML AuthnRequest to KZero.',
              finding.observed,
              'No SAMLResponse was generated after that error.'
            ]
          },
          {
            title: 'What to check in KZero',
            owner: 'KZero',
            bullets: [
              'Open the KZero integration Advanced settings for this app.',
              'Compare these values side by side:',
              `Requested ACS URL from trace: ${requestedAcs}`,
              'KZero Valid Redirect URIs',
              'KZero Assertion Consumer Service POST Binding URL',
              'These values must match exactly. Check hostname, tenant, environment, and trailing slash.'
            ],
            kzeroFields: ['Valid Redirect URIs', 'Assertion Consumer Service POST Binding URL'],
            copySnippets: [{ label: 'Requested ACS URL from trace', value: requestedAcs }],
            tooltip:
              'When KZero rejects AuthnRequest before login, ACS/redirect URL mismatch is a common cause.'
          },
          {
            title: 'What to check in the service provider',
            owner: 'vendor SP',
            bullets: [
              'Open the service provider SAML settings.',
              'Verify Assertion Consumer Service URL (ACS) exactly matches KZero values.',
              'If environment was copied (test/prod), replace outdated URLs.'
            ],
            vendorFields: ['Assertion Consumer Service URL (ACS)', 'SP Entity ID']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, KZero SAML endpoint returns 2xx/3xx and a SAMLResponse is captured.'
        ],
        nextEvidence: [
          'AuthnRequest AssertionConsumerServiceURL',
          'KZero Valid Redirect URIs',
          'KZero Assertion Consumer Service POST Binding URL'
        ]
      };
    }
    case 'SAML_MISSING_NAMEID': {
      const fixSteps = buildNameIdFix('emailAddress', vendorName);

      return {
        title: 'Missing NameID',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: fixSteps.map(formatStep),
            kzeroFields: map.kzeroFields,
            tooltip:
              'The NameID is how KZero identifies the user to the vendor app. It must match what the vendor expects.'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              'Check what identifier the vendor expects (usually email or a persistent ID)',
              'Configure vendor to use the NameID (or specific attribute) as the user identifier',
              'Common NameID formats: emailAddress, persistent, transient'
            ],
            vendorFields: map.vendorFields,
            tooltip:
              "The vendor app needs to know which field identifies the user. Most vendors expect the user's email as the identifier."
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, SAMLResponse contains a populated NameID and vendor accepts it.'
        ],
        nextEvidence: [
          'Vendor expected identifier field',
          'KZero Principal type / Pass subject values'
        ]
      };
    }
    case 'SAML_CLOCK_SKEW':
    case 'SAML_CLOCK_SKEW_NOT_BEFORE': {
      const windowValue = finding.observed;
      return {
        title: 'SAML assertion time window problem',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Check KZero time settings',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard, select your tenant',
              'Navigate to: Configure, Realm settings',
              "Click on 'Tokens' tab",
              '',
              "Find 'Allow clock skew' setting",
              'This allows a time difference between KZero and the vendor servers',
              '',
              'Recommended: Set to 30 seconds to 5 minutes to handle minor time drift',
              "⚠️ Don't set too high (hours) as this is a security risk"
            ],
            kzeroFields: ['Allow clock skew'],
            tooltip:
              'Servers can have slightly different times due to clock drift. The clock skew setting allows a tolerance for this difference. Too much skew is a security risk.'
          },
          {
            title: 'Check server times',
            owner: 'network',
            bullets: [
              "Verify KZero server time is accurate (check via 'Realm settings, General')",
              'Ask vendor to verify their server time is accurate and using NTP',
              "Time difference between servers can cause 'expired' or 'not yet valid' errors"
            ]
          },
          {
            title: 'Check vendor settings',
            owner: 'vendor SP',
            bullets: [
              'Ask the vendor if they have a clock skew tolerance setting',
              "If so, increase it slightly to match KZero's 'Allow clock skew'",
              'Ensure both servers are using NTP for accurate time'
            ],
            vendorFields: ['Allowed clock skew', 'System time']
          },
          {
            title: 'What we observed',
            owner: 'network',
            bullets: [
              `Assertion time window: ${windowValue}`,
              'This suggests a time mismatch between KZero and the vendor'
            ]
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.realmSettings]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, NotBefore/NotOnOrAfter window covers the current time.'
        ],
        nextEvidence: ['NotBefore', 'NotOnOrAfter', 'System time on both ends']
      };
    }
    case 'TENANT_CASE_MISMATCH': {
      const uniqueTenants = [...new Set(finding.evidence as string[])];
      return {
        title: 'Tenant name casing mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'What Happened',
            owner: 'analysis',
            bullets: [
              'Tenant names are case-sensitive in KZero URLs.',
              'We detected different casing variants in your authentication flow:',
              uniqueTenants.map((t) => `  • ${t}`).join('\n'),
              '',
              "Mixed casing causes the Identity Provider to reject the request because the issuer doesn't match exactly."
            ]
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              '1. Go to your KZero dashboard, select your tenant',
              '2. Navigate to Configure, Realm settings, General',
              '3. Note the exact casing of your tenant name',
              '4. Scroll to Endpoints section and verify all URLs use the same casing',
              '',
              "⚠️ Tenant names are case-sensitive: 'ABCMSP' ≠ 'abcmasp'"
            ],
            kzeroFields: map.kzeroFields,
            tooltip:
              'The tenant name in your KZero URLs must be exactly correct. URL casing matters.'
          },
          {
            title: 'Fix in your application (SP)',
            owner: 'vendor SP',
            bullets: [
              'Check all KZero-related URLs in your application settings:',
              '  • Discovery/Metadata URL',
              '  • Issuer URL',
              '  • SSO Login URL',
              '  • Entity ID',
              '',
              'Ensure the tenant name matches exactly with KZero.',
              `Expected: ${uniqueTenants[0]}`
            ],
            vendorFields: map.vendorFields,
            tooltip: 'Every URL pointing to KZero must use the exact same tenant casing.'
          },
          {
            title: 'How to verify',
            owner: 'verification',
            bullets: [
              'After making changes:',
              '1. Clear your browser cache',
              '2. Start a new trace',
              '3. Attempt login again',
              '4. Confirm only one tenant variant appears'
            ]
          },
          {
            title: 'Learn more',
            owner: 'docs' as Owner,
            bullets: [],
            links: [docLinks.realmSettings, docLinks.oidcOverview]
          }
        ],
        verify: [
          'In a new trace, only one tenant value appears',
          'All issuer/endpoints use consistent casing',
          'Login completes successfully'
        ],
        nextEvidence: ['Discovery URL', 'Issuer URL', 'SAML Entity ID', 'Tenant casing']
      };
    }

    // ============ PHASE 3: SIGNATURE/CERTIFICATE ISSUES ============
    case 'SAML_ASSERTION_SIGNATURE_MISSING': {
      return {
        title: 'Assertion signature not detected',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Check KZero signing settings',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              '',
              "Go to 'Signature & Encryption' section",
              '',
              "> Check 'Sign Assertions':",
              '   - Turn ON if vendor requires signed assertions',
              '   - This adds a digital signature to prove KZero sent the assertion',
              '',
              'What is assertion signing?',
              '   Like a wax seal on a letter - proves the assertion really came from KZero',
              '   Many vendors require this for security'
            ],
            kzeroFields: ['Sign Assertions'],
            tooltip:
              "Assertion signing proves to the vendor that the assertion really came from KZero and wasn't tampered with."
          },
          {
            title: 'Check vendor requirements',
            owner: 'vendor SP',
            bullets: [
              '> Check what the vendor expects:',
              '   - Some vendors REQUIRE signed assertions',
              "   - Some vendors don't need signing",
              "   - Check vendor docs for 'Want Assertions Signed' or similar",
              '',
              '> If vendor requires signing, make sure KZero is configured to sign',
              "> If vendor doesn't need signing, you can leave it OFF"
            ],
            vendorFields: ['Want Assertions Signed', 'Require signed assertions']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, assertion signature is detected if vendor requires it.'
        ],
        nextEvidence: ['Assertion XML signature element', 'Vendor signature requirements']
      };
    }
    case 'SAML_DOCUMENT_SIGNATURE_MISSING': {
      return {
        title: 'Document signature not detected',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding document vs assertion signing',
            owner: 'KZero',
            bullets: [
              'There are TWO types of signing in SAML:',
              '',
              '1️⃣ Document Signing (Sign Documents):',
              '   - Signs the entire SAML response envelope',
              '   - Rarely needed by vendors',
              '   - Can cause compatibility issues',
              '',
              '2️⃣ Assertion Signing (Sign Assertions):',
              '   - Signs the actual user identity information',
              '   - What most vendors actually need',
              '   - Enable this instead'
            ],
            kzeroFields: ['Sign Documents', 'Sign Assertions'],
            tooltip:
              'Document signing is usually unnecessary - assertion signing is what vendors typically require.'
          },
          {
            title: 'Recommendation',
            owner: 'KZero',
            bullets: [
              "> Keep 'Sign Documents' OFF unless vendor specifically requires it",
              "> Enable 'Sign Assertions' ON if vendor requires signed assertions",
              '',
              'Most modern vendors only need assertion signing, not document signing'
            ]
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, document signature is detected if required by vendor.'
        ],
        nextEvidence: ['Response XML signature element', 'Vendor document signing requirement']
      };
    }
    case 'SAML_CERT_SIGNATURE_VALIDATION_CLUE': {
      return {
        title: 'Certificate signature validation issue',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Check certificate configuration',
            owner: 'KZero',
            bullets: [
              'The certificate used to sign assertions may need attention',
              '',
              '> Go to: Configure > Realm settings',
              "> Click on 'Keys' tab",
              '',
              'Check the signing keys:',
              "   - Are there active keys with 'Enabled' status?",
              '   - Has any key expired?',
              '   - Has a key been rotated recently?',
              '',
              'If key was rotated:',
              '   - Vendor may have cached old public key',
              '   - Ask vendor to refresh/re-download metadata'
            ],
            kzeroFields: ['Realm Keys'],
            tooltip:
              "The signing certificate proves KZero's identity. If it's expired or was recently rotated, vendors need to update their copy."
          },
          {
            title: 'For the vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Ask vendor to:',
              '   1. Refresh/re-download KZero metadata',
              '   2. Update the IdP certificate if it was changed',
              '   3. Clear any certificate cache',
              '',
              '> Common certificate issues:',
              '   - Expired certificate',
              '   - Certificate was rotated but vendor still has old one',
              '   - Wrong certificate format (missing BEGIN/END markers)'
            ],
            vendorFields: ['IdP Certificate', 'Signing Certificate']
          },
          {
            title: "How to get KZero's certificate",
            owner: 'KZero',
            bullets: [
              '> Go to: Configure > Realm settings > General tab',
              "> Scroll to 'Endpoints' section",
              "> Click 'SAML 2.0 Identity Provider Metadata'",
              '> Download the XML file',
              '> Share with vendor to update their configuration'
            ]
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.realmSettings]
          }
        ],
        verify: [...baseVerify, 'In the new trace, certificate validation succeeds.'],
        nextEvidence: ['Certificate expiration date', 'Metadata XML', 'Vendor certificate cache']
      };
    }

    // ============ PHASE 4: FLOW-SPECIFIC ISSUES ============
    case 'SAML_WRONG_BINDING_CLUE': {
      return {
        title: 'Unexpected SAML response binding',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding SAML bindings',
            owner: 'KZero',
            bullets: [
              'SAML responses can be sent two ways:',
              '',
              '1️⃣ POST Binding (recommended for most vendors):',
              '   - Sends response as form data',
              '   - More reliable, works with most vendors',
              '   - User clicks and data is submitted',
              '',
              '2️⃣ Redirect Binding:',
              '   - Sends response as URL parameters',
              '   - Can have issues with large responses',
              "   - Some vendors don't support this"
            ],
            tooltip:
              'SAML binding is how the login response gets delivered. POST is more reliable for most vendors.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              '',
              "Go to 'SAML Capabilities' section",
              '',
              "> Enable 'Force POST Binding' if vendor requires POST",
              '> Disable if vendor accepts redirect'
            ],
            kzeroFields: ['Force POST Binding'],
            tooltip:
              'Force POST Binding tells KZero to always use the POST method. Enable this if the vendor expects form-based responses.'
          },
          {
            title: 'Check vendor requirements',
            owner: 'vendor SP',
            bullets: [
              '> Ask the vendor what binding they support:',
              '   - POST binding: Most vendors support this',
              '   - Redirect binding: Some vendors only accept this',
              '',
              "> If vendor requires POST, ensure KZero has 'Force POST Binding' ON",
              '> If vendor accepts either, either setting should work'
            ],
            vendorFields: ['SAML Binding', 'Response Binding']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlBindings]
          }
        ],
        verify: [...baseVerify, 'In the new trace, response binding matches vendor requirements.'],
        nextEvidence: ['Response binding type', 'Vendor binding requirements']
      };
    }
    case 'OIDC_STATE_MISSING_OR_MISMATCH': {
      return {
        title: 'State parameter missing or mismatched',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding the state parameter',
            owner: 'browser',
            bullets: [
              "The 'state' parameter is a security feature that:",
              '   - Prevents CSRF (Cross-Site Request Forgery) attacks',
              '   - Links your login request to the response',
              '   - Must be the same on both sides',
              '',
              'Why it fails:',
              '   - Browser extensions sometimes strip URL parameters',
              '   - Vendor app may not be preserving state through redirects',
              '   - State was never generated in the first place'
            ],
            tooltip:
              'The state parameter is like a receipt number - it proves this login response goes with your original request.'
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Check vendor SSO configuration:',
              '   - Is state generation enabled?',
              '   - Is state being preserved through the login flow?',
              '',
              '> Check for issues:',
              '   - Browser extensions blocking parameters',
              '   - Redirect chain dropping state',
              '   - State stored in wrong place (session vs cookie)',
              '',
              '> Test in incognito/private browser to rule out extensions'
            ],
            vendorFields: ['State parameter', 'CSRF protection']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcOverview]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, state parameter matches between authorize and callback.'
        ],
        nextEvidence: ['Authorize request state', 'Callback state value']
      };
    }
    case 'OIDC_NONCE_MISSING': {
      return {
        title: 'Nonce missing for ID token response',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding the nonce parameter',
            owner: 'vendor SP',
            bullets: [
              'A nonce is a unique, random value that:',
              '   - Prevents replay attacks',
              '   - Proves the ID token is for THIS login request',
              '   - Should be unique for each login attempt',
              '',
              'When is it required?',
              "   - Required when using 'Hybrid Flow' (response includes id_token)",
              '   - Optional for pure Authorization Code flow',
              '',
              'What happens without it?',
              '   - Security vulnerability to token replay attacks',
              '   - May cause login failures with strict vendors'
            ],
            tooltip:
              'A nonce is like a one-time scratch card - each login has a unique code to prevent someone from replaying an old stolen token.'
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Enable nonce generation in vendor OIDC settings',
              '> Make sure the nonce:',
              '   - Is generated fresh for each login',
              '   - Is included in the authorization request',
              '   - Is validated against the ID token on callback'
            ],
            vendorFields: ['Nonce', 'Hybrid Flow settings']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcOverview]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, nonce is present in authorize and matches ID token.'
        ],
        nextEvidence: ['Authorize request nonce', 'ID token nonce claim']
      };
    }
    case 'OIDC_PKCE_INCONSISTENT': {
      return {
        title: 'PKCE code_verifier missing',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding PKCE',
            owner: 'KZero',
            bullets: [
              'PKCE (Proof Key for Code Exchange) is an extra security layer:',
              "   - Generates a random 'code verifier' before login",
              "   - Sends a hash 'code challenge' with the request",
              '   - Proves the same client is exchanging the code',
              '',
              'Why it matters:',
              '   - Prevents authorization code interception attacks',
              '   - Required for public clients (SPAs, mobile apps)',
              '   - Recommended for all OIDC flows'
            ],
            tooltip:
              "PKCE is like adding a second lock - even if someone steals the authorization code, they can't use it without the verifier."
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              '',
              "Go to 'Capability Config' section",
              '',
              "> Check 'PKCE Method':",
              '   - S256 (recommended) - Uses SHA-256 hash',
              '   - Plain - Uses plain text (less secure)',
              '   - None - PKCE disabled'
            ],
            kzeroFields: ['PKCE Method'],
            tooltip:
              'PKCE Method determines how the code verifier is hashed. S256 is the recommended secure option.'
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Vendor MUST use PKCE consistently:',
              '   - If KZero requires PKCE, vendor must send code_verifier',
              "   - If KZero doesn't require PKCE, vendor shouldn't send challenge",
              '',
              '> Check vendor OIDC settings:',
              '   - Enable/disable PKCE to match KZero',
              '   - Ensure code_verifier is sent at token endpoint'
            ],
            vendorFields: ['PKCE', 'Code Challenge Method']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, PKCE is consistent between authorize and token exchange.'
        ],
        nextEvidence: ['code_challenge in authorize', 'code_verifier in token request']
      };
    }
    case 'SAML_INRESPONSETO_MISSING': {
      return {
        title: 'InResponseTo missing',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding SP-initiated vs IdP-initiated SSO',
            owner: 'vendor SP',
            bullets: [
              'There are two ways SAML SSO can work:',
              '',
              '1️⃣ SP-Initiated (most common):',
              '   - User goes to vendor app first',
              '   - App sends AuthnRequest to KZero',
              '   - Response includes InResponseTo (references the request)',
              '',
              '2️⃣ IdP-Initiated:',
              '   - User goes to KZero first',
              '   - KZero sends response without InResponseTo',
              '   - Vendor must accept responses without InResponseTo'
            ],
            tooltip:
              "InResponseTo links the response to the original request. Missing InResponseTo means it's an IdP-initiated login."
          },
          {
            title: 'Fix the issue',
            owner: 'vendor SP',
            bullets: [
              '> If vendor expects SP-initiated:',
              '   - Ensure the login flow starts from vendor app',
              "   - Check vendor isn't stripping the AuthnRequest",
              '',
              '> If vendor accepts IdP-initiated:',
              '   - Vendor must be configured to accept responses without InResponseTo',
              '   - Some vendors require this setting to be enabled'
            ],
            vendorFields: ['Accept IdP-Initiated', 'Allow unsolicited responses']
          },
          {
            title: 'KZero configuration',
            owner: 'KZero',
            bullets: [
              'For IdP-initiated login, KZero provides:',
              "   - 'IDP-Initiated SSO URL Name' field in Access settings",
              '   - Creates a direct login URL:',
              `      https://ca.auth.kzero.com/realms/<TENANT>/protocol/saml/clients/<CLIENT_ID>`
            ],
            kzeroFields: ['IDP-Initiated SSO URL Name']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, InResponseTo is present for SP-initiated, or vendor accepts IdP-initiated.'
        ],
        nextEvidence: ['AuthnRequest ID', 'InResponseTo value', 'Vendor initated login setting']
      };
    }
    case 'SAML_IDP_SP_INIT_MISMATCH_CLUE': {
      return {
        title: 'IdP vs SP initiated flow mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 SSO Flow Types Explained',
            owner: 'vendor SP',
            bullets: [
              'Your trace shows a mismatch between login flows:',
              '',
              'The SAML response has InResponseTo (SP-initiated marker)',
              'but no AuthnRequest was captured (IdP-initiated marker)',
              '',
              'This can happen if:',
              '   - Login started before trace capture',
              '   - AuthnRequest happened on a different device',
              '   - Vendor is doing something unusual'
            ],
            tooltip:
              'The trace captured the response but not the request. This is usually a timing issue, not a configuration error.'
          },
          {
            title: 'What to check',
            owner: 'vendor SP',
            bullets: [
              "> Verify vendor supports the flow you're testing:",
              '   - SP-initiated: Login starts from vendor app',
              '   - IdP-initiated: Login starts from KZero dashboard',
              '',
              '> Make sure trace captures the FULL login flow:',
              '   - Start trace BEFORE clicking any login button',
              '   - Include the entire redirect chain',
              '',
              '> If this was just a capture timing issue, re-test with full capture'
            ],
            vendorFields: ['SSO Flow Type', 'IdP-Initiated supported']
          },
          {
            title: 'Recommendation',
            owner: 'vendor SP',
            bullets: [
              '> For testing, use SP-initiated flow:',
              '   1. Start trace capture',
              '   2. Go to vendor app login page',
              '   3. Click SSO/login button',
              '   4. Complete login at KZero',
              '   5. Stop trace after returning to vendor app'
            ]
          }
        ],
        verify: [
          ...baseVerify,
          'In a new trace, capture the full login flow from start to finish.'
        ],
        nextEvidence: ['Full redirect chain', 'AuthnRequest capture', 'Login flow timing']
      };
    }
    case 'SAML_ASSERTION_ENCRYPTED': {
      return {
        title: 'Assertion is encrypted',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding assertion encryption',
            owner: 'KZero',
            bullets: [
              'Encrypted assertions contain the user data in a locked box:',
              "   - The box can only be opened with the SP's private key",
              '   - Prevents eavesdropping during transit',
              '   - Not all vendors support this',
              '',
              'Common issues:',
              "   - Vendor doesn't have the decryption key",
              '   - Wrong encryption algorithm',
              '   - Vendor expects unsigned + unencrypted'
            ],
            tooltip:
              'Encrypted assertions keep the user data secret during transmission. But not all vendors can handle encryption.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              '',
              "Go to 'Keys' tab",
              '',
              "> Check 'Encryption' settings:",
              "   - 'Client signature and encryption key'",
              '   - Encryption enabled = sends encrypted assertions',
              '',
              "> If vendor can't handle encryption, disable it here"
            ],
            kzeroFields: ['Encryption', 'Client encryption key'],
            tooltip: "Turn off assertion encryption if the vendor can't decrypt the assertions."
          },
          {
            title: 'Check vendor requirements',
            owner: 'vendor SP',
            bullets: [
              '> Ask vendor:',
              '   - Do you support encrypted SAML assertions?',
              "   - What's your encryption key/certificate?",
              '',
              "> If vendor doesn't support encryption:",
              '   - Disable encryption in KZero',
              '   - Assertions will be sent in plain text (but still signed)'
            ],
            vendorFields: ['Want Assertions Encrypted', 'Decryption Certificate']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, assertion encryption matches vendor capabilities.'
        ],
        nextEvidence: ['EncryptedAssertion element', 'Vendor encryption support']
      };
    }
    case 'SAML_NAMEID_FORMAT_MISMATCH': {
      return {
        title: 'Likely wrong NameID format',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding NameID formats',
            owner: 'KZero',
            bullets: [
              'NameID is how KZero identifies the user to the vendor:',
              '',
              'Common formats:',
              '   - emailAddress: user@example.com',
              "   - persistent: A unique opaque ID like 'AB123...'",
              '   - transient: A temporary anonymous ID',
              '',
              'The issue:',
              "   - Format says 'emailAddress'",
              "   - But the value doesn't look like an email!"
            ],
            tooltip: 'The NameID format and value must match what the vendor expects.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              '',
              "Go to 'SAML Capabilities' section",
              '',
              "> Check 'Name ID format':",
              '   - If vendor expects email, make sure user principal IS an email',
              '   - If vendor expects persistent ID, verify the mapper sends correct format'
            ],
            kzeroFields: ['Name ID format', 'Force Name ID Format'],
            tooltip:
              "The NameID format must match what the vendor expects. Check if the user's identity is being sent in the correct format."
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Check what format the vendor expects:',
              '   - Most modern apps expect emailAddress',
              '   - Some legacy apps expect persistent (unique user ID)',
              '',
              '> If vendor shows email format but you use username:',
              "   - Map 'username' to the email attribute OR",
              '   - Change vendor to accept your format'
            ],
            vendorFields: ['NameID Format', 'User Identifier']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, NameID format and value match vendor expectations.'
        ],
        nextEvidence: ['NameID format value', 'Vendor expected format']
      };
    }
    case 'SAML_RELAYSTATE_UNEXPECTED': {
      return {
        title: 'RelayState mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding RelayState',
            owner: 'vendor SP',
            bullets: [
              'RelayState is where the user should go after login:',
              '   - Embedded in the login URL',
              '   - Passed through KZero unchanged',
              '   - Vendor uses it to redirect after SSO',
              '',
              'Common issues:',
              '   - RelayState gets lost in redirect chain',
              '   - Vendor encodes/decodes differently',
              '   - Too much data for RelayState limit'
            ],
            tooltip:
              "RelayState tells the vendor where to send the user after login - like a 'forwarding address' on an envelope."
          },
          {
            title: 'What to check',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor supports RelayState:',
              '   - Some vendors ignore it entirely',
              '   - Some have character limits',
              '   - Some require specific encoding',
              '',
              '> Check the RelayState value:',
              '   - Is it URL-encoded properly?',
              '   - Is it too long? (RelayState has size limits)',
              '   - Does vendor expect base64 encoding?'
            ],
            vendorFields: ['RelayState', 'Post-login redirect']
          }
        ],
        verify: [...baseVerify, 'In the new trace, RelayState is preserved and vendor accepts it.'],
        nextEvidence: ['RelayState in request', 'RelayState in response', 'Post-login redirect']
      };
    }
    case 'SAML_PREAUTHN_CONFIG_ISSUE': {
      return {
        title: 'Configuration issue before login',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'KZero returned an error before generating a SAMLResponse.',
              'This typically indicates a client configuration issue in one of these areas:',
              '',
              '1️⃣ Client ID / SP Entity ID mismatch',
              "   - The Entity ID in the AuthnRequest doesn't match KZero",
              '',
              '2️⃣ ACS URL mismatch',
              "   - The callback URL doesn't match KZero configuration",
              '',
              '3️⃣ Client configuration issue',
              '   - Wrong client settings, disabled client, etc.'
            ],
            kzeroFields: map.kzeroFields,
            tooltip:
              "When KZero rejects before login, it's usually a configuration mismatch between the vendor app and KZero."
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              '',
              'Verify these three values match exactly:',
              '   1. Client ID / SP Entity ID',
              '   2. ACS URL / Valid Redirect URIs',
              '   3. Client is enabled and configured correctly'
            ],
            kzeroFields: ['Client ID', 'Valid Redirect URIs', 'Entity ID']
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              'Open the SAML settings in your vendor app',
              'Verify these match your KZero configuration:',
              '   - SP Entity ID / Client ID (exact match, case-sensitive)',
              '   - ACS URL / Reply URL (exact match, including https:// and trailing slash)',
              "   - Ensure you're using the correct KZero tenant (not test vs prod)"
            ],
            vendorFields: ['SP Entity ID', 'ACS URL', 'Reply URL']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, KZero returns 2xx/3xx and generates a SAMLResponse.'
        ],
        nextEvidence: ['AuthnRequest Entity ID', 'ACS URL', 'KZero client configuration']
      };
    }
    case 'SAML_MISSING_RESPONSE': {
      return {
        title: 'No SAML Response captured',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'browser',
            bullets: [
              'No SAML Response was captured after the AuthnRequest.',
              'This could mean:',
              '   - The flow failed before generating a response',
              '   - The response was sent but not captured (late capture)',
              '   - The flow is IdP-initiated (no AuthnRequest expected)'
            ],
            tooltip: 'Missing SAML Response can indicate a failed login or a capture timing issue.'
          },
          {
            title: 'What to check',
            owner: 'KZero',
            bullets: [
              'Check if KZero generated a SAMLResponse:',
              '   - Look for successful HTTP status (200/302) at SAML endpoint',
              '   - Check KZero logs for SAMLResponse generation',
              '',
              'If using IdP-initiated flow:',
              '   - No AuthnRequest is expected',
              '   - Response should still be captured'
            ],
            kzeroFields: ['SSO endpoint', 'Client status']
          },
          {
            title: 'Fix capture timing',
            owner: 'browser',
            bullets: [
              '> For next test:',
              '   1. Clear browser cache and cookies',
              '   2. Start capture BEFORE clicking login',
              '   3. Capture the ENTIRE flow from start to finish',
              '   4. Include all redirects in the trace'
            ]
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, a SAMLResponse is captured after the AuthnRequest.'
        ],
        nextEvidence: ['SAMLResponse in trace', 'KZero SSO endpoint status', 'Full redirect chain']
      };
    }
    case 'SAML_MISSING_REQUEST': {
      return {
        title: 'No SAML AuthnRequest captured',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'browser',
            bullets: [
              'No SAML AuthnRequest was captured in the trace.',
              'This usually means one of these:',
              '',
              '1️⃣ IdP-initiated flow (expected - no request)',
              '   - User starts at KZero, not vendor app',
              '   - This is normal for IdP-initiated SSO',
              '',
              '2️⃣ Capture started late',
              '   - AuthnRequest happened before trace started',
              '   - Need to recapture from the beginning'
            ],
            tooltip:
              'Missing AuthnRequest is normal for IdP-initiated flows, or indicates late capture.'
          },
          {
            title: 'If this should be SP-initiated',
            owner: 'vendor SP',
            bullets: [
              '> The flow should start from the vendor app:',
              '   1. Go to vendor app login page',
              '   2. Click SSO/Login button',
              '   3. Vendor sends AuthnRequest to KZero',
              '',
              '> For testing:',
              '   - Start trace BEFORE going to vendor app',
              '   - Capture the full flow from vendor app to KZero'
            ],
            vendorFields: ['SSO initiation', 'IdP-Initiated settings']
          },
          {
            title: 'If this is IdP-initiated',
            owner: 'KZero',
            bullets: [
              '> This is normal - no AuthnRequest expected',
              '> KZero sends response directly to vendor ACS',
              '> Verify vendor ACS URL is configured correctly in KZero'
            ],
            kzeroFields: ['IDP-Initiated SSO URL Name', 'ACS URL']
          }
        ],
        verify: [...baseVerify, 'In the new trace, capture the full flow from beginning.'],
        nextEvidence: ['AuthnRequest in trace', 'Flow initiation type', 'Vendor app login page']
      };
    }
    case 'SAML_UNPARSEABLE_ARTIFACT': {
      return {
        title: 'SAML artifact could not be parsed',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'browser',
            bullets: [
              'The SAML message could not be decoded or parsed.',
              'This usually indicates:',
              '   - Corrupted or truncated SAML message',
              '   - Wrong encoding (not base64)',
              '   - Not actually SAML (could be other protocol)',
              '   - Malformed XML in the SAML message'
            ],
            tooltip:
              'Unparseable SAML usually means the message is corrupted or using the wrong format.'
          },
          {
            title: 'What to check',
            owner: 'KZero',
            bullets: [
              '> Check KZero SAML settings:',
              '   - Is the SAML endpoint correct?',
              '   - Is the binding correct (POST vs Redirect)?',
              '   - Are there any special characters in the config?',
              '',
              '> Try re-exporting metadata:',
              '   - Go to Realm Settings > General > Endpoints',
              '   - Download fresh SAML metadata',
              '   - Share with vendor'
            ],
            kzeroFields: ['SAML endpoint', 'Client configuration']
          },
          {
            title: 'What to check in vendor',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor SAML configuration:',
              '   - Using correct KZero metadata/endpoint',
              '   - SAML binding matches KZero (POST/Redirect)',
              '   - No proxy/firewall modifying the SAML message'
            ],
            vendorFields: ['SAML endpoint', 'SAML binding', 'Metadata URL']
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, SAML message is properly encoded and parseable.'
        ],
        nextEvidence: ['SAMLRequest/Response value', 'Encoding format', 'XML structure']
      };
    }
    case 'SAML_CAPTURE_STARTED_LATE': {
      return {
        title: 'Trace capture started after flow began',
        owner: 'browser',
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'browser',
            bullets: [
              'The trace capture appears to have started after the SAML flow began.',
              'This means some SAML messages may be missing from the trace.',
              '',
              'Impact:',
              '   - May be missing AuthnRequest',
              '   - May be missing parts of the redirect chain',
              '   - Harder to diagnose the full flow'
            ],
            tooltip:
              'Late capture means you started tracing after the login flow began. This is a timing issue, not a configuration error.'
          },
          {
            title: 'How to fix for next test',
            owner: 'browser',
            bullets: [
              '> Proper capture sequence:',
              '   1. Open a NEW incognito/private browser window',
              '   2. Start trace capture FIRST',
              '   3. THEN go to vendor app and click login',
              '   4. Capture the ENTIRE flow including all redirects',
              '   5. Stop capture only after returning to vendor app',
              '',
              '> Tips:',
              '   - Clear cache/cookies before starting',
              '   - Make sure all redirects are captured',
              '   - Include the final landing page too'
            ]
          }
        ],
        verify: [...baseVerify, 'In the new trace, capture from BEFORE the login flow starts.'],
        nextEvidence: ['Full redirect chain', 'AuthnRequest timing', 'Capture start time']
      };
    }
    case 'SAML_ISSUER_MISMATCH': {
      const fixSteps = buildSamlIssuerFix(finding.observed, finding.expected);
      return {
        title: 'Issuer mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              ...fixSteps.map(formatStep),
              '',
              '⚠️ The Issuer/Entity ID must match exactly - this is case-sensitive'
            ],
            kzeroFields: map.kzeroFields,
            fieldExpectations: [
              { field: 'Identity provider entity ID', expected: finding.expected }
            ],
            copySnippets: [{ label: 'Expected Issuer', value: finding.expected }],
            tooltip:
              'The Issuer identifies KZero to the vendor. Both sides must agree on the exact Issuer value (case-sensitive).'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              `Set vendor "Issuer" / "IdP Entity ID" to exactly: ${finding.expected}`,
              'If vendor imported metadata, re-import to avoid stale values.',
              '⚠️ Issuer values are case-sensitive - verify exact casing'
            ],
            vendorFields: map.vendorFields,
            copySnippets: [{ label: 'Expected Issuer', value: finding.expected }],
            tooltip:
              'The vendor app needs to know the exact Issuer of KZero. This must match exactly on both sides.'
          },
          {
            title: 'What we observed',
            owner: 'browser',
            bullets: [
              `Observed Issuer: ${finding.observed}`,
              `Expected Issuer: ${finding.expected}`
            ]
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.samlClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, Issuer matches exactly between request and response.'
        ],
        nextEvidence: ['SAMLRequest Issuer', 'SAMLResponse Issuer', 'KZero Entity ID setting']
      };
    }
    case 'SAML_POLICY_MISMATCH_CLUE': {
      return {
        title: 'Authentication policy mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding SAML policies',
            owner: 'KZero',
            bullets: [
              'The AuthnRequest may request specific authentication policies:',
              '   - Password authentication',
              '   - Multi-factor authentication (MFA)',
              '   - Specific authentication context classes',
              '',
              'The issue:',
              '   - KZero may not support the requested policy',
              '   - Vendor may require MFA but KZero is not configured for it',
              '   - Policy format may not be supported'
            ],
            kzeroFields: ['Authentication policies', 'Required actions'],
            tooltip:
              'SAML policies tell KZero what type of authentication is required. Mismatch can cause auth failures.'
          },
          {
            title: 'What to check in KZero',
            owner: 'KZero',
            bullets: [
              '> Check authentication requirements:',
              '   - Go to Authentication > Required Actions',
              '   - Verify MFA/policies are properly configured',
              '   - Check if specific context classes are supported',
              '',
              '> Check client settings:',
              '   - Force MFA for this client if needed',
              '   - Configure authentication flow correctly'
            ],
            kzeroFields: ['Authentication flows', 'Required actions', 'MFA settings']
          },
          {
            title: 'What to check in vendor',
            owner: 'vendor SP',
            bullets: [
              '> Check what policies vendor requests:',
              '   - Look for "RequestedAuthnContext" in SAML Request',
              "   - Verify vendor's policy requirements",
              '',
              '> Common fixes:',
              '   - Disable specific policy requirements if not needed',
              '   - Configure KZero to support the requested policies'
            ],
            vendorFields: ['Requested Authentication Context', 'Authn policies']
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, authentication policies match between KZero and vendor.'
        ],
        nextEvidence: ['AuthnRequest RequestedAuthnContext', 'KZero authentication flows']
      };
    }
    case 'SAML_AUTHNREQUEST_SIGN_EXPECTATION_MISMATCH': {
      return {
        title: 'AuthnRequest signing expectation mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding AuthnRequest signing',
            owner: 'KZero',
            bullets: [
              'KZero can be configured to require signed AuthnRequests:',
              '   - If ON: Vendor MUST sign the SAML request',
              '   - If OFF: Vendor should NOT sign (or KZero ignores signature)',
              '',
              'The issue:',
              "   - KZero expects signed request but vendor doesn't sign",
              "   - KZero doesn't expect signed request but vendor signs",
              '   - Both sides need to agree on signing'
            ],
            kzeroFields: ['Want AuthnRequests Signed'],
            tooltip:
              'AuthnRequest signing proves the request really came from the vendor. Both sides must agree on whether to sign.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              '',
              "Go to 'Signature & Encryption' section",
              '',
              "> Check 'Want AuthnRequests Signed':",
              '   - Turn ON if vendor signs requests',
              "   - Turn OFF if vendor doesn't sign",
              '',
              '⚠️ This must match what the vendor actually does'
            ],
            kzeroFields: ['Want AuthnRequests Signed']
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Check if vendor signs AuthnRequests:',
              '   - Look for "Sign AuthnRequest" setting',
              '   - Check if vendor has a signing certificate configured',
              '',
              '> Match KZero setting:',
              '   - If KZero expects signed: Enable signing in vendor',
              "   - If KZero doesn't expect signed: Disable signing in vendor"
            ],
            vendorFields: ['Sign AuthnRequest', 'Request signing certificate']
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, signing settings match between KZero and vendor.'
        ],
        nextEvidence: ['AuthnRequest Signature', 'Want AuthnRequests Signed setting']
      };
    }

    // ============ OIDC Discovery Issues ============
    case 'OIDC_DISCOVERY_UNREACHABLE': {
      return {
        title: 'OIDC discovery endpoint unreachable',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Network connectivity check',
            owner: 'network',
            bullets: [
              'The OIDC discovery endpoint could not be reached.',
              '',
              '> Test if the URL is accessible:',
              '   1. Open a browser and try the discovery URL:',
              `      https://ca.auth.kzero.com/realms/<TENANT_NAME>/.well-known/openid-configuration`,
              '',
              '> Check if blocked by:',
              '   - Firewall (port 443)',
              '   - WAF (Web Application Firewall)',
              '   - VPN (must be public, not private network)',
              '   - DNS resolution issues'
            ],
            tooltip: 'The discovery endpoint must be publicly accessible for OIDC flows to work.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              'Navigate to: Configure > Realm settings > General tab',
              "Scroll to the 'Endpoints' section at the bottom",
              '',
              'Verify these URLs are accessible from the internet:',
              '   - OpenID Endpoint Configuration (discovery document)',
              '   - ⚠️ Endpoints must be publicly accessible'
            ],
            kzeroFields: ['Discovery Endpoint', 'Issuer'],
            tooltip:
              'KZero discovery endpoint must be publicly accessible for vendors to fetch OIDC configuration.'
          },
          {
            title: 'Check vendor configuration',
            owner: 'vendor SP',
            bullets: [
              'Ask the vendor to check their network connectivity to KZero',
              "Request their server's outbound IPs if you need to whitelist them",
              "Verify they're using the correct tenant name in the discovery URL"
            ],
            vendorFields: ['Discovery URL', 'Outbound connectivity']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.realmSettings, docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, 'In the new trace, discovery endpoint returns HTTP 200.'],
        nextEvidence: ['Discovery URL', 'HTTP status', 'Network/firewall logs']
      };
    }
    case 'OIDC_DISCOVERY_MALFORMED': {
      return {
        title: 'OIDC discovery document malformed',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'The OIDC discovery document is invalid or incomplete.',
              'This prevents vendors from properly configuring OIDC clients.',
              '',
              'Common issues:',
              '   - Truncated JSON response',
              '   - Invalid JSON syntax',
              '   - Missing required fields (issuer, endpoints)'
            ],
            kzeroFields: ['Discovery Endpoint'],
            tooltip: 'A malformed discovery document breaks OIDC client configuration for vendors.'
          },
          {
            title: 'What to check in KZero',
            owner: 'KZero',
            bullets: [
              '> Verify the discovery endpoint returns valid JSON:',
              '   1. Open browser to discovery URL',
              '   2. Validate JSON structure',
              '   3. Check for required fields: issuer, authorization_endpoint, token_endpoint',
              '',
              '> If malformed, try:',
              '   - Refresh realm settings',
              '   - Re-check realm configuration',
              '   - Contact KZero support if persists'
            ],
            kzeroFields: ['Discovery Endpoint', 'Realm settings']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.realmSettings, docLinks.oidcOverview]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, discovery document is valid JSON with all required fields.'
        ],
        nextEvidence: ['Discovery document JSON', 'Missing required fields']
      };
    }
    case 'OIDC_DISCOVERY_PUBLIC_REACHABILITY_CLUE': {
      return {
        title: 'Discovery endpoint may not be publicly reachable',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Public reachability check',
            owner: 'network',
            bullets: [
              'KZero discovery endpoint should be publicly accessible.',
              '',
              '> Test from different networks:',
              '   - Try from vendor server',
              '   - Try from mobile network (not corporate)',
              '   - Use online HTTP tester tools',
              '',
              '> If not reachable:',
              '   - Check firewall rules',
              '   - Verify DNS resolution',
              '   - Check if endpoint is behind VPN'
            ]
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Verify tenant is active and not in maintenance mode.',
              'Check if any IP restrictions are configured.',
              'Ensure endpoints are not restricted to specific networks.'
            ],
            kzeroFields: ['Tenant status', 'Discovery Endpoint']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.realmSettings]
          }
        ],
        verify: [...baseVerify, 'In the new trace, discovery endpoint is publicly reachable.'],
        nextEvidence: ['Discovery URL', 'Network test results', 'Firewall logs']
      };
    }
    case 'OIDC_DISCOVERY_ENDPOINT_HOST_SUSPICIOUS': {
      return {
        title: 'Discovery endpoint host mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'The discovery endpoint host does not match expected KZero tenant host.',
              '',
              'Expected host: ca.auth.kzero.com',
              'Check if vendor is using:',
              '   - Wrong environment (test vs prod)',
              '   - Wrong tenant name',
              '   - Old/cached discovery URL'
            ],
            kzeroFields: ['Discovery Endpoint', 'Tenant alias'],
            tooltip: 'Using wrong host in discovery URL indicates wrong environment or tenant.'
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor is using correct discovery URL:',
              '   - Correct tenant name in URL',
              '   - Correct environment (prod vs test)',
              '   - Re-import metadata if needed',
              '',
              '> Expected format:',
              '   https://ca.auth.kzero.com/realms/<TENANT_NAME>/.well-known/openid-configuration'
            ],
            vendorFields: ['Discovery URL', 'OIDC configuration']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, 'In the new trace, discovery host matches expected KZero host.'],
        nextEvidence: ['Discovery URL', 'Tenant name', 'Expected host']
      };
    }
    case 'OIDC_DISCOVERY_ENDPOINT_INCONSISTENT': {
      return {
        title: 'Discovery endpoint values inconsistent',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding the issue',
            owner: 'KZero',
            bullets: [
              'Values in the discovery document are inconsistent.',
              '',
              'Common inconsistencies:',
              '   - issuer does not match discovery URL host',
              '   - endpoints use different hosts',
              '   - tenant casing differs across fields',
              '',
              'This breaks token validation and causes auth failures.'
            ],
            kzeroFields: ['Discovery Endpoint', 'Issuer', 'Tenant alias'],
            tooltip: 'Inconsistent discovery values cause validation failures in OIDC flows.'
          },
          {
            title: 'What to check in KZero',
            owner: 'KZero',
            bullets: [
              '> Verify these match across discovery document:',
              '   1. issuer URL',
              '   2. discovery URL host',
              '   3. All endpoint URLs host',
              '',
              '> Check tenant casing:',
              '   - All references should use same casing',
              "   - 'ABCMSP' ≠ 'abcmasp'"
            ],
            kzeroFields: ['Issuer', 'Discovery Endpoint', 'Realm settings']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.realmSettings, docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, 'In the new trace, all discovery values are consistent.'],
        nextEvidence: ['Discovery document', 'issuer', 'endpoint URLs']
      };
    }

    // ============ OIDC PKCE Issues ============
    case 'OIDC_PKCE_MISSING_WHEN_CODE_FLOW': {
      return {
        title: 'PKCE missing for authorization code flow',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding PKCE',
            owner: 'KZero',
            bullets: [
              'PKCE (Proof Key for Code Exchange) is recommended for all code flows.',
              '',
              'Why it matters:',
              '   - Prevents authorization code interception attacks',
              '   - Required for public clients (SPAs, mobile apps)',
              '   - Adds an extra layer of security'
            ],
            kzeroFields: ['PKCE Method'],
            tooltip:
              'PKCE is recommended for all authorization code flows to prevent code interception attacks.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              '',
              "Go to 'Capability Config' section",
              '',
              "> Enable PKCE by setting 'PKCE Method' to S256",
              '> S256 is the recommended secure option'
            ],
            kzeroFields: ['PKCE Method'],
            tooltip:
              'Enabling PKCE in KZero requires the vendor to send code_verifier with token exchange.'
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Enable PKCE in vendor OIDC settings:',
              '   - Generate code_verifier before login',
              '   - Send code_challenge (S256 hash) with authorize request',
              '   - Send code_verifier with token exchange',
              '',
              '> PKCE is required for:',
              '   - Single Page Applications (SPAs)',
              '   - Mobile applications',
              '   - Any public client'
            ],
            vendorFields: ['PKCE', 'Code Challenge Method']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [...baseVerify, 'In the new trace, PKCE is used for authorization code flow.'],
        nextEvidence: ['code_challenge in authorize', 'PKCE method setting']
      };
    }
    case 'OIDC_PKCE_METHOD_WEAK_OR_UNEXPECTED': {
      return {
        title: 'PKCE method weak or unexpected',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding PKCE methods',
            owner: 'KZero',
            bullets: [
              'PKCE supports two challenge methods:',
              '',
              '1️⃣ S256 (recommended):',
              '   - Uses SHA-256 hash',
              '   - Secure and widely supported',
              '',
              '2️⃣ Plain (deprecated):',
              '   - Uses plain text challenge',
              '   - Less secure, may be rejected'
            ],
            kzeroFields: ['PKCE Method'],
            tooltip: 'S256 is the recommended PKCE method. Plain is deprecated and less secure.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              "Set 'PKCE Method' to S256 in client Capability Config.",
              'S256 is the industry standard and most secure option.'
            ],
            kzeroFields: ['PKCE Method']
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Use S256 for code_challenge_method:',
              '   - Generate SHA-256 hash of code_verifier',
              '   - Send method=S256 with authorize request',
              '',
              '> If vendor only supports plain:',
              '   - Consider upgrading vendor OIDC library',
              '   - Plain is less secure but may work temporarily'
            ],
            vendorFields: ['PKCE Method', 'Code Challenge Method']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [...baseVerify, 'In the new trace, PKCE method is S256.'],
        nextEvidence: ['code_challenge_method', 'PKCE method setting']
      };
    }

    // ============ OIDC Token Issues ============
    case 'OIDC_TOKEN_ISSUER_MISMATCH': {
      return {
        title: 'Token issuer mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'The issuer in the token does not match what the vendor expects.',
              '',
              'This causes token validation to fail at the vendor.',
              '',
              'Common causes:',
              '   - Wrong tenant in token issuer',
              '   - Vendor configured with wrong issuer URL',
              '   - Tenant casing mismatch'
            ],
            kzeroFields: ['Issuer', 'Discovery Endpoint'],
            tooltip:
              'Token issuer must match exactly what the vendor expects for validation to succeed.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Verify the issuer in Realm Settings > General:',
              '   - Should be: https://ca.auth.kzero.com/realms/<TENANT_NAME>',
              '   - Check for correct casing',
              '',
              'Verify discovery endpoint returns same issuer.'
            ],
            kzeroFields: ['Issuer', 'Discovery Endpoint']
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Set vendor issuer to exactly match KZero:',
              '   - Check vendor OIDC configuration',
              '   - Update issuer URL if needed',
              '   - Re-import discovery document if available'
            ],
            vendorFields: ['Issuer', 'Discovery URL']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcOverview, docLinks.realmSettings]
          }
        ],
        verify: [...baseVerify, 'In the new trace, token iss matches expected issuer exactly.'],
        nextEvidence: ['Token iss claim', 'Expected issuer', 'Discovery document issuer']
      };
    }
    case 'OIDC_TOKEN_AUTH_METHOD_MISMATCH_CLUE': {
      return {
        title: 'Token endpoint auth method may not match',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding token endpoint auth',
            owner: 'KZero',
            bullets: [
              'The client authentication method at token endpoint may not match.',
              '',
              'Common methods:',
              '   - client_secret_basic (default, in Authorization header)',
              '   - client_secret_post (in POST body)',
              '   - none (for public clients)',
              '   - private_key_jwt (for advanced scenarios)'
            ],
            kzeroFields: ['Client authentication', 'Token endpoint'],
            tooltip:
              'Client auth method must match between KZero and vendor for token exchange to succeed.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              '',
              "Go to 'Capability Config' section",
              '',
              '> Check "Client Authentication" setting:',
              '   - Should match what vendor sends',
              '   - Most vendors use client_secret_basic'
            ],
            kzeroFields: ['Client authentication']
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Check vendor token endpoint configuration:',
              '   - What auth method does vendor use?',
              '   - Does it match KZero setting?',
              '',
              '> Common fixes:',
              '   - Set vendor to use client_secret_basic',
              '   - Or update KZero to match vendor method'
            ],
            vendorFields: ['Token endpoint auth method', 'Client credentials']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [...baseVerify, 'In the new trace, token endpoint auth method matches.'],
        nextEvidence: ['Token request auth method', 'KZero client auth setting']
      };
    }
    case 'OIDC_LOGOUT_REDIRECT_MISMATCH_CLUE': {
      return {
        title: 'Logout redirect URI may not match',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'The post-logout redirect URI may not be whitelisted.',
              '',
              'After logout, KZero redirects to this URI.',
              'It must be whitelisted in client configuration.'
            ],
            kzeroFields: ['Post-logout redirect URIs', 'Client settings'],
            tooltip:
              'Post-logout redirect URIs must be whitelisted for logout to complete successfully.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              '',
              "Go to 'Settings' or 'Access settings' section",
              '',
              '> Add post-logout redirect URI to whitelist:',
              '   - Must match exactly what vendor sends',
              '   - Include https:// and trailing slash if used'
            ],
            kzeroFields: ['Post-logout redirect URIs']
          },
          {
            title: 'Check vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor logout configuration:',
              '   - What URI does vendor send for post-logout?',
              '   - Is it whitelisted in KZero?',
              '',
              '> If vendor does not use post-logout redirect:',
              '   - That is OK, this is just a clue'
            ],
            vendorFields: ['Post-logout redirect URI', 'Logout settings']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [...baseVerify, 'In the new trace, post-logout redirect works correctly.'],
        nextEvidence: ['Logout request post_logout_redirect_uri', 'Whitelisted URIs']
      };
    }
    case 'OIDC_ACCESS_TOKEN_OPAQUE': {
      return {
        title: 'Access token is opaque (not JWT)',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'The access token is opaque (not a JWT that can be decoded).',
              '',
              'This is normal for some configurations:',
              '   - Opaque tokens cannot be introspected by vendor',
              '   - Vendor should use /userinfo endpoint to get claims',
              '   - Or use the ID token for user information'
            ],
            kzeroFields: ['Token type setting', 'Client settings'],
            tooltip:
              'Opaque access tokens are normal for some configurations. They cannot be decoded like JWTs.'
          },
          {
            title: 'What to check',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor expectations:',
              '   - Does vendor need to decode access token?',
              '   - If yes, vendor should use /userinfo endpoint',
              '   - Or switch to JWT access tokens if supported',
              '',
              '> This is usually NOT an error, just informational'
            ],
            vendorFields: ['Access token type', 'UserInfo endpoint usage']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, 'In the new trace, vendor handles opaque token correctly.'],
        nextEvidence: ['Access token format', 'Vendor token handling']
      };
    }

    // ============ OIDC Capture/Flow Issues ============
    case 'OIDC_LATE_CAPTURE_CLUE': {
      return {
        title: 'Capture may have started after authorize request',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'browser',
            bullets: [
              'The trace capture appears to have started after the OIDC authorize request.',
              '',
              'Impact:',
              '   - Authorize request may be missing from trace',
              '   - Harder to diagnose the full flow',
              '   - Some OIDC parameters may be missing'
            ],
            tooltip:
              'Late capture means you started tracing after the login flow began. This is a timing issue.'
          },
          {
            title: 'How to fix for next test',
            owner: 'browser',
            bullets: [
              '> Proper capture sequence:',
              '   1. Open a NEW incognito/private browser window',
              '   2. Start trace capture FIRST',
              '   3. THEN go to vendor app and click login',
              '   4. Capture the ENTIRE flow including all redirects',
              '   5. Stop capture only after returning to vendor app'
            ]
          }
        ],
        verify: [...baseVerify, 'In the new trace, capture from BEFORE the login flow starts.'],
        nextEvidence: ['Full redirect chain', 'Authorize request', 'Capture start time']
      };
    }
    case 'OIDC_MISSING_AUTHORIZE_REQUEST_CLUE': {
      return {
        title: 'No OIDC authorize request captured',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'browser',
            bullets: [
              'No OIDC authorize request was captured in the trace.',
              '',
              'This usually means:',
              '   - Capture started after the authorize request',
              '   - The flow may be using a different protocol (SAML)',
              '   - Vendor may not be using OIDC for this login'
            ],
            tooltip:
              'Missing authorize request is usually a capture timing issue or wrong protocol.'
          },
          {
            title: 'What to check',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor is using OIDC (not SAML):',
              '   - Check vendor SSO configuration',
              '   - Look for OIDC/OAuth2 settings',
              '',
              '> If using OIDC, recapture with proper timing:',
              '   1. Start trace BEFORE going to vendor app',
              '   2. Capture the full login flow',
              '   3. Include all redirects'
            ],
            vendorFields: ['SSO protocol', 'OIDC settings']
          }
        ],
        verify: [...baseVerify, 'In the new trace, OIDC authorize request is captured.'],
        nextEvidence: ['Authorize request URL', 'Vendor SSO protocol', 'Full redirect chain']
      };
    }
    case 'OIDC_MISSING_CALLBACK': {
      return {
        title: 'No OIDC callback captured',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'browser',
            bullets: [
              'No OIDC callback was captured after the authorize request.',
              '',
              'This suggests:',
              '   - The flow was interrupted before callback',
              '   - Vendor did not redirect back to callback URI',
              '   - Possible error occurred at KZero'
            ],
            tooltip:
              'Missing callback suggests the flow failed before reaching the vendor callback.'
          },
          {
            title: 'What to check in KZero',
            owner: 'KZero',
            bullets: [
              '> Check KZero logs for errors:',
              '   - Did the authorize request succeed?',
              '   - Was there an error at KZero?',
              '   - Is the client enabled?',
              '',
              '> Verify client configuration:',
              '   - Client is enabled',
              '   - Redirect URI is whitelisted'
            ],
            kzeroFields: ['Client status', 'Redirect URIs']
          },
          {
            title: 'What to check in vendor',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor callback handling:',
              '   - Does vendor have a callback endpoint?',
              '   - Is it correctly configured?',
              '   - Check vendor logs for errors'
            ],
            vendorFields: ['Callback endpoint', 'Redirect URI']
          }
        ],
        verify: [...baseVerify, 'In the new trace, OIDC callback is captured after authorize.'],
        nextEvidence: ['Callback request', 'KZero logs', 'Vendor logs']
      };
    }
    case 'OIDC_USERINFO_FAILED': {
      return {
        title: 'UserInfo endpoint request failed',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'network',
            bullets: [
              'The OIDC UserInfo endpoint request failed.',
              '',
              'Impact:',
              '   - Vendor cannot retrieve user claims after login',
              '   - User profile information may be missing',
              '',
              'Common causes:',
              '   - Invalid or expired access token',
              '   - UserInfo endpoint not accessible',
              '   - Missing required scopes (openid, profile)'
            ],
            tooltip:
              'UserInfo endpoint failure prevents vendor from getting user profile information.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              '> Verify UserInfo endpoint is accessible:',
              '   - Test URL: https://ca.auth.kzero.com/realms/<TENANT>/protocol/openid-connect/userinfo',
              '   - Should return 200 with valid access token',
              '',
              '> Check client scopes:',
              '   - Ensure "openid" and "profile" scopes are allowed',
              '   - Vendor must request these scopes'
            ],
            kzeroFields: ['Client Scopes', 'UserInfo endpoint']
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor uses correct access token:',
              '   - Token must be valid and not expired',
              '   - Include "Bearer" prefix in Authorization header',
              '',
              '> Check vendor scopes:',
              '   - Request "openid" and "profile" scopes',
              '   - Handle missing claims gracefully'
            ],
            vendorFields: ['UserInfo endpoint', 'Required scopes', 'Access token usage']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients, docLinks.oidcOverview]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, UserInfo endpoint returns HTTP 200 with user claims.'
        ],
        nextEvidence: ['UserInfo request/response', 'Access token', 'Requested scopes']
      };
    }
    case 'OIDC_BROWSER_STORAGE_OR_COOKIE_BLOCKING_CLUE': {
      return {
        title: 'Browser may be blocking storage or cookies',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'browser',
            bullets: [
              'OIDC flows often require cookies or session storage.',
              '',
              'Browser blocking can cause:',
              '   - Login session not maintained',
              '   - State/nonce parameters lost',
              '   - Redirect loops or failures'
            ],
            tooltip: 'Blocking cookies or storage breaks OIDC flows that rely on session state.'
          },
          {
            title: 'What to check',
            owner: 'browser',
            bullets: [
              '> Test in a clean browser environment:',
              '   1. Use incognito/private window',
              '   2. Disable extensions that block cookies/trackers',
              '   3. Allow third-party cookies temporarily',
              '',
              '> Check vendor requirements:',
              '   - Does vendor require cookies?',
              '   - Does vendor use localStorage or sessionStorage?',
              '   - Any CSP (Content Security Policy) restrictions?'
            ],
            vendorFields: ['Cookie policy', 'Storage requirements', 'CSP settings']
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, OIDC flow completes without storage/cookie issues.'
        ],
        nextEvidence: ['Browser console errors', 'Cookie/Storage API access', 'CSP headers']
      };
    }
    case 'OIDC_CALLBACK_SEEN_BUT_NO_APP_LANDING_CLUE': {
      return {
        title: 'Callback succeeded but app did not complete login',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'vendor SP',
            bullets: [
              'Token exchange succeeded but the app did not complete login.',
              '',
              'This suggests:',
              '   - Vendor app failed to process the tokens',
              '   - App may have crashed or encountered an error',
              '   - Redirect after login may have failed'
            ],
            tooltip: 'Tokens were received but the vendor app did not complete the login sequence.'
          },
          {
            title: 'What to check in vendor',
            owner: 'vendor SP',
            bullets: [
              '> Check vendor app logs:',
              '   - Any errors after token exchange?',
              '   - Did app validate tokens correctly?',
              '   - Was user session created?',
              '',
              '> Verify post-login flow:',
              '   - App should redirect after successful login',
              '   - Check for JavaScript errors on the page',
              '   - Verify app handles token response correctly'
            ],
            vendorFields: ['Post-login redirect', 'Token validation', 'App logs']
          },
          {
            title: 'Check KZero configuration',
            owner: 'KZero',
            bullets: [
              'Verify client configuration is correct.',
              'Check that tokens contain required claims.',
              'Ensure redirect URIs are correctly configured.'
            ],
            kzeroFields: ['Client settings', 'Redirect URIs', 'Token claims']
          }
        ],
        verify: [...baseVerify, 'In the new trace, app completes login after callback.'],
        nextEvidence: ['App landing page', 'Vendor logs', 'Token validation result']
      };
    }
    case 'OIDC_UNAUTHORIZED_CLIENT': {
      return {
        title: 'Client is not authorized for this request',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'The client is not authorized to use this flow or grant type.',
              '',
              'Common causes:',
              '   - Client is disabled',
              '   - Grant type not enabled for this client',
              '   - Client authentication failed (wrong secret)',
              '   - Client not allowed to use this response_type'
            ],
            kzeroFields: ['Client authentication', 'Grant types', 'Client status'],
            tooltip: 'The client is not authorized to use this specific flow or grant type.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              '',
              '> Check client status:',
              '   - Ensure client is enabled',
              '   - Check "Capability Config" for enabled grant types',
              '',
              '> Verify client authentication:',
              '   - Check client secret is correct',
              '   - Verify authentication method matches vendor'
            ],
            kzeroFields: ['Client status', 'Grant types', 'Client authentication']
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor is using correct grant type:',
              '   - Authorization code flow: response_type=code',
              '   - Implicit flow: response_type=id_token token',
              '   - Hybrid flow: response_type=code id_token',
              '',
              '> Check vendor credentials:',
              '   - Client ID matches KZero',
              '   - Client secret is correct and not expired'
            ],
            vendorFields: ['Grant type', 'Response type', 'Client credentials']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [...baseVerify, 'In the new trace, client is authorized and grant type matches.'],
        nextEvidence: ['Token endpoint response', 'Client status', 'Enabled grant types']
      };
    }
    case 'OIDC_UNSUPPORTED_RESPONSE_TYPE': {
      return {
        title: 'Response type is not supported',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'The requested response_type is not enabled for this client.',
              '',
              'Common response types:',
              '   - code (authorization code flow)',
              '   - id_token (implicit flow)',
              '   - token (implicit flow)',
              '   - code id_token (hybrid flow)',
              '',
              'KZero must have this response_type enabled for the client.'
            ],
            kzeroFields: ['Response types', 'Grant types'],
            tooltip: 'The response_type parameter is not supported by this client configuration.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              '',
              "> Go to 'Capability Config' section",
              '',
              '> Enable the required response types:',
              '   - For authorization code: Enable "Standard Flow"',
              '   - For implicit: Enable "Implicit Flow"',
              '   - For hybrid: Enable both'
            ],
            kzeroFields: ['Response types', 'Standard Flow', 'Implicit Flow']
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Check what response_type vendor is using:',
              '   - Look at the authorize request URL',
              '   - Common: response_type=code',
              '',
              '> If vendor uses unsupported type:',
              '   - Either enable it in KZero, or',
              '   - Change vendor to use supported response_type'
            ],
            vendorFields: ['Response type', 'OIDC settings']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients, docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, 'In the new trace, response_type is supported by client.'],
        nextEvidence: ['Authorize request response_type', 'Client enabled response types']
      };
    }
    case 'OIDC_UNSUPPORTED_RESPONSE_MODE': {
      return {
        title: 'Response mode is not supported',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'The requested response_mode is not supported.',
              '',
              'Common response modes:',
              '   - query (parameters in URL query string)',
              '   - fragment (parameters in URL fragment)',
              '   - form_post (parameters in POST body)',
              '',
              'KZero may not support the requested response_mode.'
            ],
            kzeroFields: ['Response modes', 'Client settings'],
            tooltip: 'The response_mode parameter is not supported by the authorization server.'
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              '',
              "> Check 'Capability Config' for response mode settings",
              '',
              '> If response_mode is required:',
              '   - Ensure KZero supports the mode',
              '   - Consider using default mode (based on response_type)'
            ],
            kzeroFields: ['Response modes', 'Capability Config']
          },
          {
            title: 'Fix in vendor app',
            owner: 'vendor SP',
            bullets: [
              '> Check if vendor specifies response_mode:',
              '   - Look for response_mode in authorize request',
              '   - Common modes: query, fragment, form_post',
              '',
              '> If KZero does not support the mode:',
              '   - Remove response_mode parameter from vendor config',
              '   - Let KZero use default mode based on response_type'
            ],
            vendorFields: ['Response mode', 'OIDC settings']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients, docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, 'In the new trace, response_mode is supported or not specified.'],
        nextEvidence: ['Authorize request response_mode', 'Client response mode settings']
      };
    }
    case 'OIDC_CALLBACK_ERROR': {
      return {
        title: `OIDC error: ${finding.observed}`,
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'vendor SP',
            bullets: [
              'The authorization or token endpoint returned an OAuth/OIDC error.',
              '',
              'Common errors:',
              '   - invalid_request: Missing or invalid parameter',
              '   - unauthorized_client: Client not authorized',
              '   - access_denied: User or authorization server denied request',
              '   - unsupported_response_type: Response type not supported',
              '   - invalid_scope: Scope invalid or not supported',
              '',
              `Error details: ${finding.observed}`
            ],
            tooltip:
              'An OAuth/OIDC error parameter was returned. This indicates a problem with the request.'
          },
          {
            title: 'What to check in vendor',
            owner: 'vendor SP',
            bullets: [
              '> Check the exact error returned:',
              `   - Error: ${finding.observed}`,
              '',
              '> Common fixes:',
              '   - Verify all required parameters are present',
              '   - Check client ID and secret are correct',
              '   - Ensure scopes are valid and allowed',
              '   - Verify redirect URI matches exactly'
            ],
            vendorFields: ['OIDC error handling', 'Authorization parameters']
          },
          {
            title: 'Check KZero configuration',
            owner: 'KZero',
            bullets: [
              'Verify client configuration is correct.',
              'Check that requested scopes are allowed for this client.',
              'Ensure client is enabled and credentials are valid.'
            ],
            kzeroFields: ['Client settings', 'Client scopes', 'Client status']
          }
        ],
        verify: [...baseVerify, 'In the new trace, no OAuth/OIDC error is returned.'],
        nextEvidence: ['OAuth error parameter', 'Error description', 'Request parameters']
      };
    }

    // ============ Cross-Protocol Rules ============
    case 'WRONG_HOST_OR_ENVIRONMENT': {
      return {
        title: 'Wrong host or environment detected',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding the issue',
            owner: 'KZero',
            bullets: [
              'URL points to wrong host or environment.',
              '',
              'Common scenarios:',
              '   - Using production tenant URL in test environment',
              '   - Using test tenant URL in production',
              '   - Wrong KZero region/host',
              '',
              'This causes endpoint and issuer mismatches.'
            ],
            kzeroFields: ['Tenant alias', 'Endpoint URLs'],
            tooltip: 'Using URLs from wrong environment causes tenant/issuer mismatches.'
          },
          {
            title: 'What to check in KZero',
            owner: 'KZero',
            bullets: [
              '> Verify correct environment:',
              '   - Production: ca.auth.kzero.com',
              '   - Test: Check your test tenant URL',
              '',
              '> Check tenant name in URLs:',
              '   - Should match your actual tenant',
              '   - Case-sensitive!'
            ],
            kzeroFields: ['Tenant alias', 'Endpoint URLs', 'Issuer']
          },
          {
            title: 'What to check in vendor',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor is using correct KZero URLs:',
              '   - Discovery URL',
              '   - SSO URL / SAML endpoint',
              '   - All KZero-related endpoints',
              '',
              '> Check for copied values from wrong environment:',
              '   - Production vs test tenant',
              '   - Old/stale configuration values'
            ],
            vendorFields: ['KZero endpoints', 'Environment configuration']
          }
        ],
        verify: [...baseVerify, 'In the new trace, all URLs point to correct environment.'],
        nextEvidence: ['Tenant URL', 'Environment setting', 'Endpoint host']
      };
    }
    case 'WRONG_REALM_ENDPOINT_FAMILY': {
      return {
        title: 'Endpoint does not match realm/tenant family',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'KZero',
            bullets: [
              'Endpoint does not match expected realm/tenant family.',
              '',
              'This indicates:',
              '   - Using endpoints from a different tenant',
              '   - Realm configuration may be wrong',
              '   - Token validation will fail'
            ],
            kzeroFields: ['Realm settings', 'Endpoint URLs'],
            tooltip: 'Using endpoints from wrong realm breaks token validation and discovery.'
          },
          {
            title: 'What to check in KZero',
            owner: 'KZero',
            bullets: [
              '> Verify realm/tenant configuration:',
              '   - All endpoints should use same tenant name',
              '   - Check realm settings > General > Endpoints',
              '',
              '> Common mistake:',
              '   - Copying endpoints from different tenant',
              '   - Mixing production and test endpoints'
            ],
            kzeroFields: ['Realm settings', 'Endpoint URLs', 'Tenant alias']
          },
          {
            title: 'What to check in vendor',
            owner: 'vendor SP',
            bullets: [
              '> Verify vendor uses consistent endpoints:',
              '   - All KZero URLs should reference same tenant',
              '   - Discovery URL, SSO URL, etc.',
              '',
              '> Re-import metadata if needed:',
              '   - Fresh metadata ensures consistency'
            ],
            vendorFields: ['KZero endpoints', 'Metadata URL']
          }
        ],
        verify: [...baseVerify, 'In the new trace, all endpoints belong to same realm/tenant.'],
        nextEvidence: ['Endpoint URLs', 'Tenant name', 'Discovery document']
      };
    }
    case 'METADATA_COPY_PASTE_TRUNCATION': {
      return {
        title: 'Metadata may have been truncated during copy-paste',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'vendor SP',
            bullets: [
              'Metadata may have been truncated when copying from browser.',
              '',
              'Common issues:',
              '   - Copying from browser address bar truncates long URLs',
              '   - Copying from PDF or Word document may add line breaks',
              '   - Special characters may be lost',
              '',
              'Result: Incomplete or corrupted metadata'
            ],
            vendorFields: ['Metadata URL', 'Entity ID'],
            tooltip: 'Truncated metadata causes parsing failures and missing configuration values.'
          },
          {
            title: 'How to fix',
            owner: 'vendor SP',
            bullets: [
              '> Proper way to copy metadata:',
              '   1. Download XML file from KZero (do not copy-paste)',
              '   2. Or use "View Source" and save complete file',
              '   3. Avoid copying from rendered browser view',
              '',
              '> Re-import metadata:',
              '   - Delete old configuration',
              '   - Import fresh metadata XML from KZero'
            ],
            vendorFields: ['Metadata import', 'Entity ID', 'Endpoints']
          },
          {
            title: 'Get fresh metadata from KZero',
            owner: 'KZero',
            bullets: [
              '> Go to: Configure > Realm settings > General tab',
              "> Scroll to 'Endpoints' section",
              "> Click 'SAML 2.0 Identity Provider Metadata'",
              '> Download the XML file',
              '> Share with vendor to re-import'
            ],
            kzeroFields: ['Metadata endpoint', 'Realm settings']
          }
        ],
        verify: [...baseVerify, 'In the new trace, metadata is complete and valid.'],
        nextEvidence: ['Metadata XML', 'Entity ID', 'Truncation indicators']
      };
    }
    case 'VENDOR_VALIDATION_REJECTING_METADATA_CLUE': {
      return {
        title: 'Vendor may be rejecting metadata due to validation rules',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'vendor SP',
            bullets: [
              'Vendor may have strict metadata validation rules.',
              '',
              'This can cause rejection of valid metadata if:',
              '   - Format differs slightly from vendor expectation',
              '   - Vendor expects specific XML structure',
              '   - Vendor does not support all SAML/OIDC features',
              '',
              'Result: Metadata import fails or is rejected'
            ],
            vendorFields: ['Metadata validation', 'Import settings'],
            tooltip: 'Strict vendor validation can reject valid metadata if format differs.'
          },
          {
            title: 'What to check in vendor',
            owner: 'vendor SP',
            bullets: [
              '> Check vendor metadata requirements:',
              '   - What format does vendor expect?',
              '   - Any specific XML elements required?',
              '   - Does vendor support the full SAML/OIDC spec?',
              '',
              '> Try manual configuration:',
              '   - Instead of metadata import, configure manually',
              '   - Copy individual values (Entity ID, endpoints, etc.)'
            ],
            vendorFields: ['Metadata format', 'Manual configuration']
          },
          {
            title: 'Check KZero metadata',
            owner: 'KZero',
            bullets: [
              'Verify KZero metadata is standards-compliant.',
              'Download fresh metadata and validate against vendor requirements.',
              'Contact KZero support if metadata format needs adjustment.'
            ],
            kzeroFields: ['Metadata endpoint', 'Realm settings']
          }
        ],
        verify: [...baseVerify, 'In the new trace, metadata is accepted by vendor.'],
        nextEvidence: ['Vendor validation errors', 'Metadata XML', 'Vendor documentation']
      };
    }
    case 'CLIENT_SIDE_VS_BACKEND_VALIDATION_DISTINCTION': {
      return {
        title: 'Validation error may be client-side vs backend',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Understanding the distinction',
            owner: 'analysis',
            bullets: [
              'Validation errors can happen at different levels:',
              '',
              '1️⃣ Client-side (browser):',
              '   - Form validation before submit',
              '   - JavaScript validation errors',
              '   - Browser extension interference',
              '',
              '2️⃣ Backend (KZero or vendor server):',
              '   - Server-side validation of SAML/OIDC messages',
              '   - Configuration validation',
              '   - Token/certificate validation'
            ],
            tooltip: 'Distinguishing where validation fails helps focus troubleshooting efforts.'
          },
          {
            title: 'What to check',
            owner: 'vendor SP',
            bullets: [
              '> Check browser console for client-side errors:',
              '   - JavaScript errors',
              '   - Form validation messages',
              '   - Network errors',
              '',
              '> Check server logs for backend errors:',
              '   - KZero logs (if accessible)',
              '   - Vendor server logs',
              '   - Token validation errors'
            ],
            vendorFields: ['Client-side validation', 'Server logs']
          },
          {
            title: 'Check KZero configuration',
            owner: 'KZero',
            bullets: [
              'Verify all KZero settings are correct.',
              'Check that client configuration matches vendor requirements.',
              'Look for validation errors in KZero admin console.'
            ],
            kzeroFields: ['Client settings', 'Validation rules']
          }
        ],
        verify: [...baseVerify, 'In the new trace, identify where validation is failing.'],
        nextEvidence: ['Browser console', 'Server logs', 'Validation error messages']
      };
    }
    case 'NETWORK_TLS_REACHABILITY_SUSPECTED': {
      return {
        title: 'Network, TLS, or reachability issue suspected',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Network connectivity check',
            owner: 'network',
            bullets: [
              'Connection failures often indicate network issues:',
              '',
              'Common causes:',
              '   - Firewall blocking connections',
              '   - TLS version mismatch',
              '   - Certificate validation failure',
              '   - Endpoint not accessible (wrong URL, down)',
              '',
              'Result: OIDC/OIDC flows cannot complete'
            ],
            tooltip: 'Network, TLS, or reachability issues prevent successful authentication flows.'
          },
          {
            title: 'What to check',
            owner: 'network',
            bullets: [
              '> Test endpoint accessibility:',
              '   - Try reaching URLs from different networks',
              '   - Check TLS version (should be TLS 1.2+)',
              '   - Verify certificate is valid and trusted',
              '',
              '> Check firewall/proxy settings:',
              '   - Ensure outbound HTTPS (443) is allowed',
              '   - Check for proxy interference',
              '   - Whitelist KZero IPs if needed'
            ],
            vendorFields: ['Firewall settings', 'TLS version', 'Proxy configuration']
          },
          {
            title: 'Check KZero status',
            owner: 'KZero',
            bullets: [
              'Verify KZero tenant is active and endpoints are up.',
              'Check KZero status page or contact support if outages.'
            ],
            kzeroFields: ['Tenant status', 'Endpoint URLs']
          }
        ],
        verify: [...baseVerify, 'In the new trace, all endpoints are reachable with valid TLS.'],
        nextEvidence: ['HTTP status codes', 'TLS handshake', 'Network logs']
      };
    }
    case 'STALE_VALUES_FROM_ANOTHER_ENVIRONMENT': {
      return {
        title: 'Configuration values may be from different environment',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 What this means',
            owner: 'vendor SP',
            bullets: [
              'Configuration values may be from a different environment.',
              '',
              'Common scenario:',
              '   - Copied production values to test environment',
              '   - Or vice versa',
              '   - Using wrong tenant URLs',
              '',
              'Result: Endpoint, issuer, and tenant mismatches'
            ],
            vendorFields: ['Environment configuration', 'Endpoint URLs'],
            tooltip: 'Using values from wrong environment causes tenant and endpoint mismatches.'
          },
          {
            title: 'What to check in vendor',
            owner: 'vendor SP',
            bullets: [
              '> Verify environment consistency:',
              '   - Production app → Production KZero tenant',
              '   - Test app → Test KZero tenant',
              '   - Do NOT mix environments!',
              '',
              '> Check all KZero-related values:',
              '   - Discovery URL',
              '   - Entity ID / Issuer',
              '   - All endpoint URLs',
              '   - Should all reference same environment'
            ],
            vendorFields: ['Environment', 'KZero endpoints', 'Tenant name']
          },
          {
            title: 'What to check in KZero',
            owner: 'KZero',
            bullets: [
              'Verify you are configuring the correct tenant.',
              'Double-check tenant name and environment.',
              'Ensure you are not in the wrong tenant dashboard.'
            ],
            kzeroFields: ['Tenant alias', 'Endpoint URLs', 'Issuer']
          }
        ],
        verify: [...baseVerify, 'In the new trace, all values belong to same environment.'],
        nextEvidence: ['Tenant name', 'Endpoint URLs', 'Environment indicators']
      };
    }

    case 'OIDC_MISSING_OPENID_SCOPE': {
      return {
        title: 'Missing openid scope',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              "The vendor app's SSO configuration is missing the required 'openid' scope",
              '',
              "> Check the vendor's SSO/OAuth configuration",
              "> Look for a 'Scopes' or 'Permissions' field",
              "> Add 'openid' to the list of requested scopes",
              '',
              "What is 'openid'? It's the minimum required scope for OIDC - without it, you won't get an ID token",
              '',
              'Common scope combinations:',
              '  - openid (required)',
              '  - openid profile (includes name and picture)',
              '  - openid email (includes email address)',
              '  - openid profile email (all user info)'
            ],
            vendorFields: ['Scope'],
            tooltip:
              "The 'openid' scope tells OIDC that this is an authentication request. Without it, the server doesn't know you want to log in - it just gives you an access token."
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcOverview]
          }
        ],
        verify: [...baseVerify, 'In the new trace, authorize request scope includes openid.'],
        nextEvidence: ['Authorize request URL with scope']
      };
    }
    case 'OIDC_INVALID_SCOPE': {
      return {
        title: 'Invalid scope',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              "The vendor is requesting a scope that KZero doesn't recognize or allow",
              '',
              "> Check the vendor's SSO/OAuth configuration",
              "> Look for 'Scopes' or 'Permissions' settings",
              "> Remove any scopes that aren't standard OIDC:",
              '',
              'Standard OIDC scopes (usually supported):',
              '  ✅ openid - Required for OIDC',
              "  ✅ profile - User's name and picture",
              "  ✅ email - User's email address",
              '  ✅ offline_access - Access tokens without user present',
              '',
              'Scopes to remove (vendor-specific):',
              '  ❌ Any custom/vendor-specific scopes not configured in KZero'
            ],
            vendorFields: map.vendorFields,
            tooltip:
              "Scopes control what information you get back from login. Each scope must be both requested AND allowed by KZero. If a scope isn't configured, it will be rejected."
          },
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'If KZero is acting as OIDC client to vendor, confirm requested scopes match vendor supported set.',
              "Check 'Client Scopes' in the advanced console to see which scopes are allowed for this client.",
              'Avoid assuming every vendor supports generic OIDC scopes beyond openid/profile/email.'
            ],
            kzeroFields: ['Client ID', 'Client Scopes'],
            tooltip:
              "In KZero, you can control which scopes a client can request through 'Client Scopes'. Check if the requested scope is assigned to this client."
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients, docLinks.samlClients]
          }
        ],
        verify: [...baseVerify, 'In the new trace, the flow returns no invalid_scope error.'],
        nextEvidence: ['Authorize request scope', 'Vendor allowed scopes']
      };
    }
    case 'OIDC_CALLBACK_TOKEN_EXCHANGE_BROKEN': {
      return {
        title: 'Callback reached but token exchange failed',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Check vendor app (SP) backend',
            owner: 'vendor SP',
            bullets: [
              "The login page loaded, but the vendor's backend couldn't exchange the auth code for tokens",
              '',
              "> Check vendor's backend/server logs for the actual error",
              "> Verify the vendor backend can reach KZero's token endpoint:",
              `   https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/openid-connect/token`,
              '',
              '> Check these common issues:',
              '   1. Network/Firewall: Can the vendor server reach KZero?',
              '   2. Client ID/Secret: Do they match exactly?',
              '   3. PKCE: If KZero requires PKCE, does vendor send code_verifier?',
              '   4. Redirect URI: Does it match exactly what was used in the auth request?'
            ],
            vendorFields: ['Token URL', 'Client credentials', 'Outbound connectivity'],
            tooltip:
              "After login, the vendor's server needs to exchange an 'authorization code' for actual tokens (ID token, access token). If this exchange fails, the user won't be logged in."
          },
          {
            title: 'Check KZero configuration',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              "Click 'Advanced Console' > Select 'Clients' > Search for your app",
              "Click 'Advanced Console' > Select 'Client' > search for app",
              '',
              "> Go to 'Capability Config' section:",
              "   - Verify 'Client Authentication' is set correctly",
              "   - If using PKCE, ensure it's configured properly",
              '',
              "> Go to 'Credentials' tab:",
              "   - Verify Client Secret is correct and hasn't expired"
            ],
            kzeroFields: ['Token URL', 'Use PKCE', 'Client authentication', 'Client Secret'],
            tooltip:
              "The Client ID and Client Secret are like a username and password. If they don't match exactly, KZero will reject the token exchange."
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.oidcClients]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, token endpoint call exists and returns HTTP 200.'
        ],
        nextEvidence: [
          'Callback URL with code',
          'Token request/response status',
          'Vendor backend logs'
        ]
      };
    }
    case 'OIDC_JWKS_FETCH_FAILURE':
    case 'OIDC_REACHABILITY_WAF_TLS_SUSPECTED': {
      return {
        title: 'JWKS/cert fetch failed',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: '🔧 Network connectivity check',
            owner: 'network',
            bullets: [
              "The vendor app couldn't reach KZero's JWKS endpoint to verify tokens",
              '',
              "> Test if KZero is reachable from the vendor's server:",
              '   1. Open a browser and try:',
              `      https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/openid-connect/certs`,
              '   2. If using SAML:',
              `      https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/saml/descriptor`,
              '',
              '> Check if the URL is blocked by:',
              '   - Firewall (port 443)',
              '   - WAF (Web Application Firewall)',
              '   - VPN (must be public, not private network)',
              '   - Geo-blocking',
              '',
              '> Verify TLS certificate is valid (no expired certs)'
            ],
            tooltip:
              "JWKS is a set of public keys that vendors use to verify that tokens really came from KZero. If they can't fetch these keys, they can't verify the tokens."
          },
          {
            title: 'Check KZero configuration',
            owner: 'KZero',
            bullets: [
              'Go to your KZero dashboard > Select your tenant',
              'Navigate to: Configure > Realm settings > General tab',
              "Scroll to the 'Endpoints' section at the bottom",
              '',
              'Verify these URLs are accessible from the internet:',
              '   - OpenID Endpoint Configuration',
              '   - SAML 2.0 Identity Provider Metadata',
              '',
              '⚠️ Endpoints must be publicly accessible - not behind a firewall or VPN'
            ],
            kzeroFields: ['Issuer', 'Discovery Endpoint'],
            tooltip:
              "KZero's endpoints must be publicly accessible for vendors to fetch the public keys needed to verify tokens."
          },
          {
            title: 'Check vendor configuration',
            owner: 'vendor SP',
            bullets: [
              'Ask the vendor to check their network connectivity to KZero',
              "Request their server's outbound IPs if you need to whitelist them",
              "Verify they're using the correct tenant name in the JWKS URL",
              '',
              'Expected JWKS URL format:',
              `   https://ca.auth.kzero.com/realms/<TENANT_NAME>/protocol/openid-connect/certs`
            ],
            vendorFields: ['JWKS URL', 'Outbound connectivity']
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [docLinks.realmSettings, docLinks.oidcOverview]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, JWKS returns HTTP 200 and token validation proceeds.'
        ],
        nextEvidence: ['JWKS URL', 'HTTP status and error text', 'WAF logs if available']
      };
    }
    default: {
      const steps: string[] = [];
      if (map.kzeroFields.length) {
        steps.push(`Check these KZero Passwordless fields: ${map.kzeroFields.join(', ')}.`);
      }
      if (map.vendorFields.length) {
        steps.push(`Check these vendor app fields: ${map.vendorFields.join(', ')}.`);
      }
      steps.push(`Expected: ${finding.expected}.`);
      steps.push(`Observed: ${finding.observed}.`);

      const isOidcRelated = finding.ruleId.startsWith('OIDC_');
      const _defaultDocLink = isOidcRelated ? oidcDocLink : docLink;

      return {
        title: finding.title,
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'What happened',
            owner: 'browser',
            bullets: [finding.explanation],
            tooltip: finding.explanation
          },
          {
            title: 'What to check',
            owner: finding.likelyOwner,
            bullets: steps,
            kzeroFields: map.kzeroFields,
            vendorFields: map.vendorFields
          },
          ...(vendorNotice
            ? [
                {
                  title: 'Vendor Guide',
                  owner: 'docs',
                  bullets: [vendorNotice]
                }
              ]
            : []),
          {
            title: 'Documentation',
            owner: 'docs',
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
