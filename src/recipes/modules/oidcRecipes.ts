import type { Finding } from '../../shared/models';
import type { TraceContext } from '../context';
import type { FixRecipe } from '../types';
import { buildRedirectUriFix, detectOidcVendor } from '../guidance/oidc';
import { formatVendorNotice } from '../guidance';
import { getFieldMapping } from '../../mappings/fieldMappings';

const baseVerify = [
  'Start capture, run login once, stop capture.',
  'Confirm the finding no longer appears and the flow progresses past the failing step.',
  'Export sanitized trace + attach to ticket if escalation is needed.'
];

export const getOidcRecipe = (finding: Finding, ctx: TraceContext): FixRecipe | null => {
  const map = getFieldMapping(finding.ruleId);

  const getVendorName = (): string | undefined => {
    if (ctx.oidc.authorize?.redirectUri) {
      const detected = detectOidcVendor(ctx.oidc.authorize.redirectUri);
      if (detected) return detected;
    }
    if (ctx.oidc.authorize?.clientId) {
      const detected = detectOidcVendor(undefined, ctx.oidc.authorize.clientId);
      if (detected) return detected;
    }
    return undefined;
  };

  const vendorName = getVendorName();
  const vendorNotice = vendorName ? formatVendorNotice(vendorName, 'oidc') : '';

  switch (finding.ruleId) {
    case 'OIDC_REDIRECT_URI_MISMATCH': {
      const expected = finding.expected;
      const observed = finding.observed;
      const fixSteps = buildRedirectUriFix(observed, expected, vendorName);
      const fixBullets = fixSteps.map((s) => s.text);

      return {
        title: 'Redirect URI mismatch',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: fixBullets,
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
              'Exact match matters: scheme, host, path, query (if used), and trailing slash.',
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
            links: [
              { label: 'OIDC Client Configuration', url: 'https://docs.kzero.com/oidc-clients' }
            ]
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
    default:
      return null;
  }
};
