import type { Finding, Owner } from '../shared/models';
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
import { getSamlRecipe } from './modules/samlRecipes';
import { getOidcRecipe } from './modules/oidcRecipes';

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
  // Try SAML recipes first
  if (finding.ruleId.startsWith('SAML_')) {
    const recipe = getSamlRecipe(finding, ctx);
    if (recipe) return recipe;
  }

  // Try OIDC recipes
  if (finding.ruleId.startsWith('OIDC_')) {
    const recipe = getOidcRecipe(finding, ctx);
    if (recipe) return recipe;
  }

  // Default case for cross-protocol rules or unhandled rules
  const map = { kzeroFields: [], vendorFields: [] };
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
  const _defaultDocLink = isOidcRelated ? docLinks.oidcClients : docLinks.samlClients;

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
};
