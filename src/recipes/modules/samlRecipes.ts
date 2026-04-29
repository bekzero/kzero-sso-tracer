import type { Finding, Owner } from '../../shared/models';
import type { TraceContext } from '../context';
import type { FixRecipe } from '../types';
import type { FixLink } from '../types';
import {
  buildSamlNavigationSteps,
  buildAcsUrlFix,
  buildEntityIdFix,
  buildNameIdFix,
  buildSigningFix,
  buildBindingFix,
  detectSamlVendor,
  getSamlFieldTooltip
} from '../guidance/saml';
import { getDocUrl, formatVendorNotice } from '../guidance';
import { getFieldMapping } from '../../mappings/fieldMappings';

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
  samlBindings: { label: 'SAML Bindings', url: getDocUrl('samlBindings') },
  realmSettings: { label: 'Realm Settings', url: getDocUrl('realmSettings') },
  samlOverview: { label: 'SAML Overview', url: getDocUrl('samlOverview') }
};

export const getSamlRecipe = (finding: Finding, ctx: TraceContext): FixRecipe | null => {
  const map = getFieldMapping(finding.ruleId);
  const vendorName = ctx.saml?.request?.url
    ? (detectSamlVendor(ctx.saml.request.url) ?? undefined)
    : undefined;
  const vendorNotice = vendorName ? formatVendorNotice(vendorName, 'saml') : '';
  const docLink = getDocUrl('samlClients');

  switch (finding.ruleId) {
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
    default:
      return null;
  }
};
