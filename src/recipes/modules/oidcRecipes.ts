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
    if (ctx.oidc?.authorize?.redirectUri) {
      const detected = detectOidcVendor(ctx.oidc.authorize.redirectUri);
      if (detected) return detected;
    }
    if (ctx.oidc?.authorize?.clientId) {
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
    case 'OIDC_UNAUTHORIZED_CLIENT': {
      return {
        title: 'Unauthorized client',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Check if the client ID is correct and active in KZero.',
              'Verify the client secret has not expired or been revoked.',
              'Ensure the client is enabled for the OIDC flow being used.'
            ],
            kzeroFields: map.kzeroFields,
            tooltip:
              'The client ID may be incorrect, disabled, or not configured for this OIDC flow.'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              `Verify the client ID matches: ${finding.expected ?? 'check KZero configuration'}`,
              'Check that the client secret is correct and up to date.',
              'Ensure the app is registered with the correct issuer/tenant.'
            ],
            vendorFields: map.vendorFields,
            tooltip: 'The vendor app may be using an incorrect or expired client ID/secret.'
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
          'In the new trace, ensure the authorize request includes a valid client_id that is active in KZero.'
        ],
        nextEvidence: [
          'Authorize request client_id',
          'KZero client configuration',
          'Vendor app client settings'
        ]
      };
    }

    case 'OIDC_UNSUPPORTED_RESPONSE_TYPE': {
      return {
        title: 'Unsupported response type',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Check which response types are enabled for this client in KZero.',
              `Ensure the response_type "${finding.observed}" is allowed.`,
              'Common valid types: code, token, id_token, code token, code id_token.'
            ],
            kzeroFields: map.kzeroFields,
            tooltip: 'The OIDC client in KZero may not have this response type enabled.'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              'Check the vendor app is requesting a supported response_type.',
              'Common options: code (authorization code), token (implicit), id_token (implicit with OIDC).',
              'Update the app configuration if it is using an unsupported type.'
            ],
            vendorFields: map.vendorFields,
            tooltip:
              'The vendor app may be requesting a response_type that is not enabled in KZero.'
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [
              { label: 'OIDC Response Types', url: 'https://docs.kzero.com/oidc-response-types' }
            ]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, ensure the authorize request response_type is allowed in KZero.'
        ],
        nextEvidence: [
          'Authorize request response_type',
          'KZero allowed response types',
          'Vendor app OIDC settings'
        ]
      };
    }

    case 'OIDC_UNSUPPORTED_RESPONSE_MODE': {
      return {
        title: 'Unsupported response mode',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'Fix in KZero',
            owner: 'KZero',
            bullets: [
              'Check which response modes are supported for this client.',
              `Ensure the response_mode "${finding.observed}" is allowed.`,
              'Common modes: query, fragment, form_post.'
            ],
            kzeroFields: map.kzeroFields,
            tooltip: 'The response_mode may not be supported or configured correctly in KZero.'
          },
          {
            title: 'Fix in vendor app (SP)',
            owner: 'vendor SP',
            bullets: [
              'Check if the vendor app specifies response_mode in the authorize request.',
              'If not specified, the mode is inferred from response_type (query for code, fragment for implicit).',
              'Update the app to use a supported response_mode or remove the parameter to use default.'
            ],
            vendorFields: map.vendorFields,
            tooltip: 'The vendor app may be requesting a response_mode that KZero does not support.'
          },
          {
            title: 'Documentation',
            owner: 'docs',
            bullets: [],
            links: [
              { label: 'OIDC Response Modes', url: 'https://docs.kzero.com/oidc-response-modes' }
            ]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, ensure the authorize request uses a supported response_mode.'
        ],
        nextEvidence: [
          'Authorize request response_mode',
          'KZero supported response modes',
          'Vendor app OIDC settings'
        ]
      };
    }

    case 'OIDC_CALLBACK_ERROR': {
      return {
        title: 'OIDC callback error',
        owner: finding.likelyOwner,
        confidence: finding.confidence,
        sections: [
          {
            title: 'What happened',
            owner: 'browser',
            bullets: [
              `The authorization server returned an error at the callback: ${finding.observed}`,
              'This prevented the login from completing.'
            ],
            tooltip: 'An error occurred during the OIDC authorization callback.'
          },
          {
            title: 'What to check',
            owner: finding.likelyOwner,
            bullets: [
              'Check the full error details in the callback URL parameters.',
              'Common errors: invalid_scope, access_denied, server_error.',
              'Review the authorization request for incorrect parameters.'
            ],
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
            links: [{ label: 'OIDC Errors', url: 'https://docs.kzero.com/oidc-errors' }]
          }
        ],
        verify: [
          ...baseVerify,
          'In the new trace, ensure the callback does not contain error parameters.'
        ],
        nextEvidence: [
          'Callback URL with error parameters',
          'Authorize request details',
          'KZero client configuration'
        ]
      };
    }

    default:
      return null;
  }
};
