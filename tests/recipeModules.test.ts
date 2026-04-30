import { describe, expect, it, vi, beforeEach } from 'vitest';
import { getSamlRecipe } from '../src/recipes/modules/samlRecipes';
import { getOidcRecipe } from '../src/recipes/modules/oidcRecipes';
import type { Finding } from '../src/shared/models';
import type { TraceContext } from '../src/recipes/context';

describe('SAML Recipe Module', () => {
  let mockFinding: Finding;
  let mockCtx: TraceContext;

  beforeEach(() => {
    mockFinding = {
      id: 'f1',
      ruleId: 'SAML_AUDIENCE_MISMATCH',
      severity: 'error' as const,
      protocol: 'SAML' as const,
      likelyOwner: 'KZero' as const,
      title: 'Audience / Entity ID mismatch',
      explanation: 'The audience in the SAML assertion does not match the expected entity ID.',
      observed: 'sp-entity-id',
      expected: 'kzero-entity-id',
      evidence: ['Audience: sp-entity-id', 'Expected: kzero-entity-id'],
      likelyFix: {
        kzeroFields: ['Entity ID'],
        vendorFields: ['Entity ID / Audience URI'],
        action: 'Update Entity ID to match'
      },
      confidence: 0.9,
      confidenceLevel: 'high' as const,
      plainEnglishExplanation: 'Entity ID mismatch'
    } as Finding;

    mockCtx = {
      saml: {
        request: { url: 'https://adfs.contoso.com/adfs/ls' }
      }
    } as TraceContext;
  });

  describe('getSamlRecipe', () => {
    it('returns recipe for SAML_AUDIENCE_MISMATCH', () => {
      const recipe = getSamlRecipe(mockFinding, mockCtx);

      expect(recipe).not.toBeNull();
      expect(recipe!.title).toBe('Audience / Entity ID mismatch');
      expect(recipe!.owner).toBe('KZero');
      expect(recipe!.confidence).toBe(0.9);
      expect(recipe!.sections.length).toBeGreaterThan(0);
    });

    it('includes KZero fields in recipe sections', () => {
      const recipe = getSamlRecipe(mockFinding, mockCtx);

      const kzeroSection = recipe!.sections.find((s) => s.owner === 'KZero');
      expect(kzeroSection).toBeDefined();
      expect(kzeroSection!.kzeroFields).toBeDefined();
      expect(kzeroSection!.fieldExpectations).toBeDefined();
    });

    it('includes vendor fields in recipe sections', () => {
      const recipe = getSamlRecipe(mockFinding, mockCtx);

      const vendorSection = recipe!.sections.find((s) => s.owner === 'vendor SP');
      expect(vendorSection).toBeDefined();
      expect(vendorSection!.vendorFields).toBeDefined();
    });

    it('returns recipe for SAML_ACS_RECIPIENT_MISMATCH', () => {
      mockFinding.ruleId = 'SAML_ACS_RECIPIENT_MISMATCH';
      mockFinding.observed = 'https://app.com/acs';
      mockFinding.expected = 'https://kzero.com/acs';

      const recipe = getSamlRecipe(mockFinding, mockCtx);

      expect(recipe).not.toBeNull();
      expect(recipe!.title).toBe('Check the ACS URL first');
      expect(recipe!.sections.length).toBeGreaterThan(0);
    });

    it('returns null for unknown rule ID', () => {
      mockFinding.ruleId = 'UNKNOWN_RULE' as any;

      const recipe = getSamlRecipe(mockFinding, mockCtx);

      expect(recipe).toBeNull();
    });

    it('handles missing saml context gracefully', () => {
      mockCtx.saml = undefined as any;

      const recipe = getSamlRecipe(mockFinding, mockCtx);

      expect(recipe).not.toBeNull();
    });

    it('includes verify steps in recipe', () => {
      const recipe = getSamlRecipe(mockFinding, mockCtx);

      expect(recipe!.verify).toBeDefined();
      expect(recipe!.verify.length).toBeGreaterThan(0);
    });

    it('includes nextEvidence in recipe', () => {
      const recipe = getSamlRecipe(mockFinding, mockCtx);

      expect(recipe!.nextEvidence).toBeDefined();
      expect(recipe!.nextEvidence.length).toBeGreaterThan(0);
    });
  });
});

describe('OIDC Recipe Module', () => {
  let mockFinding: Finding;
  let mockCtx: TraceContext;

  beforeEach(() => {
    mockFinding = {
      id: 'f2',
      ruleId: 'OIDC_REDIRECT_URI_MISMATCH',
      severity: 'error' as const,
      protocol: 'OIDC' as const,
      likelyOwner: 'KZero' as const,
      title: 'Redirect URI mismatch',
      explanation: 'The redirect URI does not match the configured callback URL.',
      observed: 'https://app.com/callback',
      expected: 'https://kzero.com/callback',
      evidence: ['redirect_uri: https://app.com/callback', 'Expected: https://kzero.com/callback'],
      likelyFix: {
        kzeroFields: ['Valid Redirect URIs'],
        vendorFields: ['Redirect URI / Callback URL'],
        action: 'Update Redirect URI to match'
      },
      confidence: 0.95,
      confidenceLevel: 'high' as const,
      plainEnglishExplanation: 'Redirect URI mismatch'
    } as Finding;

    mockCtx = {
      oidc: {
        authorize: {
          redirectUri: 'https://app.com/callback',
          clientId: 'test-client-id'
        }
      }
    } as TraceContext;
  });

  describe('getOidcRecipe', () => {
    it('returns recipe for OIDC_REDIRECT_URI_MISMATCH', () => {
      const recipe = getOidcRecipe(mockFinding, mockCtx);

      expect(recipe).not.toBeNull();
      expect(recipe!.title).toBe('Redirect URI mismatch');
      expect(recipe!.owner).toBe('KZero');
      expect(recipe!.confidence).toBe(0.95);
      expect(recipe!.sections.length).toBeGreaterThan(0);
    });

    it('includes KZero fields in recipe sections', () => {
      const recipe = getOidcRecipe(mockFinding, mockCtx);

      const kzeroSection = recipe!.sections.find((s) => s.owner === 'KZero');
      expect(kzeroSection).toBeDefined();
      expect(kzeroSection!.kzeroFields).toBeDefined();
      expect(kzeroSection!.fieldExpectations).toBeDefined();
    });

    it('includes vendor fields in recipe sections', () => {
      const recipe = getOidcRecipe(mockFinding, mockCtx);

      const vendorSection = recipe!.sections.find((s) => s.owner === 'vendor SP');
      expect(vendorSection).toBeDefined();
      expect(vendorSection!.vendorFields).toBeDefined();
    });

    it('detects vendor from redirect URI', () => {
      mockCtx.oidc.authorize!.redirectUri = 'https://login.microsoftonline.com/tenant/oauth2';

      const recipe = getOidcRecipe(mockFinding, mockCtx);

      expect(recipe).not.toBeNull();
    });

    it('detects vendor from client ID', () => {
      mockCtx.oidc.authorize!.redirectUri = undefined;
      mockCtx.oidc.authorize!.clientId = 'microsoft-client';

      const recipe = getOidcRecipe(mockFinding, mockCtx);

      expect(recipe).not.toBeNull();
    });

    it('returns null for unknown rule ID', () => {
      mockFinding.ruleId = 'UNKNOWN_RULE' as any;

      const recipe = getOidcRecipe(mockFinding, mockCtx);

      expect(recipe).toBeNull();
    });

    it('handles missing oidc context gracefully', () => {
      mockCtx.oidc = undefined as any;

      const recipe = getOidcRecipe(mockFinding, mockCtx);

      expect(recipe).not.toBeNull();
    });

    it('includes verify steps in recipe', () => {
      const recipe = getOidcRecipe(mockFinding, mockCtx);

      expect(recipe!.verify).toBeDefined();
      expect(recipe!.verify.length).toBeGreaterThan(0);
    });

    it('includes nextEvidence in recipe', () => {
      const recipe = getOidcRecipe(mockFinding, mockCtx);

      expect(recipe!.nextEvidence).toBeDefined();
      expect(recipe!.nextEvidence.length).toBeGreaterThan(0);
    });

    it('includes copy snippets with expected value', () => {
      const recipe = getOidcRecipe(mockFinding, mockCtx);

      const kzeroSection = recipe!.sections.find((s) => s.owner === 'KZero');
      expect(kzeroSection!.copySnippets).toBeDefined();
      expect(kzeroSection!.copySnippets!.length).toBeGreaterThan(0);
    });
  });
});
