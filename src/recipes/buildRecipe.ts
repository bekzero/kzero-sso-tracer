import type { Finding } from '../shared/models';
import type { TraceContext } from './context';
import type { FixRecipe } from './types';

const baseVerify = [
  'Start capture, run login once, stop capture.',
  'Confirm the finding no longer appears and the flow progresses past the failing step.',
  'Export sanitized trace + attach to ticket if escalation is needed.'
];

export const buildFixRecipe = (finding: Finding, ctx: TraceContext): FixRecipe => {
  // Try SAML recipes first (lazy-loaded)
  if (finding.ruleId.startsWith('SAML_')) {
    const { getSamlRecipe } = require('./modules/samlRecipes');
    const recipe = getSamlRecipe(finding, ctx);
    if (recipe) return recipe;
  }

  // Try OIDC recipes (lazy-loaded)
  if (finding.ruleId.startsWith('OIDC_')) {
    const { getOidcRecipe } = require('./modules/oidcRecipes');
    const recipe = getOidcRecipe(finding, ctx);
    if (recipe) return recipe;
  }

  // Default case for cross-protocol rules or unhandled rules
  const steps: string[] = [];
  steps.push(`Expected: ${finding.expected}.`);
  steps.push(`Observed: ${finding.observed}.`);

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
        bullets: steps
      }
    ],
    verify: baseVerify,
    nextEvidence: finding.evidence
  };
};
