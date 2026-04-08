import { describe, it, expect } from "vitest";
import {
  buildHelpContext,
  mapQueryToIntent,
  getQuickSuggestions,
  getDefaultSuggestions,
  getExplanationForIntent
} from "../src/help";
import type { CaptureSession, Finding } from "../src/shared/models";

const createEmptySession = (): CaptureSession => ({
  tabId: 1,
  active: false,
  rawEvents: [],
  normalizedEvents: [],
  findings: []
});

const createSessionWithFindings = (findings: Finding[]): CaptureSession => ({
  tabId: 1,
  active: false,
  rawEvents: [],
  normalizedEvents: [],
  findings
});

const createFinding = (ruleId: string, title: string, severity: "error" | "warning" | "info" = "error"): Finding => ({
  id: `finding-${ruleId}`,
  ruleId,
  title,
  severity,
  protocol: "OIDC",
  likelyOwner: "KZero",
  explanation: `Explanation for ${ruleId}`,
  expected: "expected value",
  observed: "observed value",
  evidence: [],
  likelyFix: { kzeroFields: [], vendorFields: [], action: "fix" },
  confidence: 0.9,
  confidenceLevel: "high"
});

describe("help routing - natural phrasing", () => {
  const ctxNoSession = buildHelpContext(null, []);

  describe("maps login-related questions to troubleshooting", () => {
    const testCases = [
      "why isn't my login working?",
      "why is my login not working?",
      "why is login failing?",
      "sign in not working",
      "can't sign in",
      "login failed"
    ];

    testCases.forEach(query => {
      it(`"${query}" maps to login-related intent`, () => {
        const intent = mapQueryToIntent(query, ctxNoSession);
        expect(intent.intent).toMatch(/troubleshooting|login_issue/);
      });
    });
  });

  describe("maps redirect-related questions to relevant rules", () => {
    const testCases = [
      { query: "why am I getting redirected back?", expectTroubleshooting: true },
      { query: "what is wrong with my callback URL?", expectRuleId: "OIDC_REDIRECT_URI_MISMATCH" },
      { query: "why does the app say invalid redirect URI?", expectRuleId: "OIDC_REDIRECT_URI_MISMATCH" },
      { query: "callback error", expectRuleId: "OIDC_REDIRECT_URI_MISMATCH" },
      { query: "invalid callback", expectRuleId: "OIDC_REDIRECT_URI_MISMATCH" }
    ];

    testCases.forEach(({ query, expectRuleId, expectTroubleshooting }) => {
      it(`"${query}" maps to expected intent`, () => {
        const intent = mapQueryToIntent(query, ctxNoSession);
        if (expectRuleId) {
          expect(intent.ruleIds).toContain(expectRuleId);
        }
        if (expectTroubleshooting) {
          expect(intent.intent).toMatch(/troubleshooting|redirect_issue/);
        }
      });
    });
  });

  describe("maps SAML questions to troubleshooting", () => {
    const testCases = [
      "why is SAML failing?",
      "SAML error",
      "SAML login failed",
      "SAML not working"
    ];

    testCases.forEach(query => {
      it(`"${query}" maps to SAML-related intent`, () => {
        const intent = mapQueryToIntent(query, ctxNoSession);
        expect(intent.intent).toMatch(/troubleshooting|saml_issue|login_issue/);
      });
    });
  });
});

describe("help routing - suggestion behavior", () => {
  it("returns general suggestions when no session", () => {
    const _ctx = buildHelpContext(null, []);
    const suggestions = getDefaultSuggestions();
    
    expect(suggestions.length).toBeGreaterThan(0);
    expect(suggestions.every(s => s.category === "concept" || s.category === "troubleshooting")).toBe(true);
  });

  it("returns contextual suggestions when session has findings", () => {
    const findings = [
      createFinding("OIDC_REDIRECT_URI_MISMATCH", "Redirect URI mismatch"),
      createFinding("OIDC_DISCOVERY_ISSUER_MISMATCH", "Issuer mismatch", "warning")
    ];
    const session = createSessionWithFindings(findings);
    const ctx = buildHelpContext(session, findings);
    const suggestions = getQuickSuggestions(ctx);
    
    const hasFindingSuggestions = suggestions.some(s => s.category === "finding");
    expect(hasFindingSuggestions).toBe(true);
  });

  it("returns explanation for troubleshooting intent with no findings", () => {
    const ctx = buildHelpContext(null, []);
    const intent = mapQueryToIntent("why isn't my login working?", ctx);
    const explanation = getExplanationForIntent(intent, ctx);
    
    expect(explanation).toBeTruthy();
    expect(explanation.length).toBeGreaterThan(10);
  });

  it("returns explanation for troubleshooting intent with findings", () => {
    const findings = [createFinding("OIDC_REDIRECT_URI_MISMATCH", "Redirect URI mismatch")];
    const session = createSessionWithFindings(findings);
    const ctx = buildHelpContext(session, findings);
    
    const intent = mapQueryToIntent("why isn't my login working?", ctx);
    const explanation = getExplanationForIntent(intent, ctx);
    
    expect(explanation).toBeTruthy();
    expect(explanation.length).toBeGreaterThan(10);
  });
});

describe("help routing - session states", () => {
  it("handles no session", () => {
    const ctx = buildHelpContext(null, []);
    
    expect(ctx.session).toBeNull();
    expect(ctx.findings).toEqual([]);
    expect(ctx.tenants).toEqual([]);
    expect(ctx.flow).toBe("unknown");
  });

  it("handles session with no findings", () => {
    const session = createEmptySession();
    const ctx = buildHelpContext(session, []);
    
    expect(ctx.session).not.toBeNull();
    expect(ctx.findings).toEqual([]);
  });

  it("handles session with many findings", () => {
    const manyFindings: Finding[] = Array.from({ length: 10 }, (_, i) => 
      createFinding(`RULE_${i}`, `Finding ${i}`, i % 2 === 0 ? "error" : "warning")
    );
    const session = createSessionWithFindings(manyFindings);
    const ctx = buildHelpContext(session, manyFindings);
    
    expect(ctx.findings.length).toBe(10);
  });
});

describe("help routing - input handling", () => {
  const ctx = buildHelpContext(null, []);

  it("handles whitespace-only input gracefully", () => {
    const intent = mapQueryToIntent("   ", ctx);
    expect(intent.confidence).toBeLessThan(0.5);
  });

  it("handles empty input gracefully", () => {
    const intent = mapQueryToIntent("", ctx);
    expect(intent.confidence).toBeLessThan(0.5);
  });

  it("handles repeated submissions", () => {
    const queries = [
      "why isn't my login working?",
      "what is redirect URI?",
      "SAML error"
    ];
    
    queries.forEach(query => {
      const intent = mapQueryToIntent(query, ctx);
      expect(intent).toBeDefined();
      expect(intent.intent).toBeTruthy();
    });
  });
});

describe("help routing - edge cases", () => {
  it("handles unknown question", () => {
    const ctx = buildHelpContext(null, []);
    const intent = mapQueryToIntent("asdfghjkl qwerty", ctx);
    
    expect(intent.confidence).toBeLessThan(0.5);
    expect(intent.ruleIds).toEqual([]);
  });

  it("provides contextual help when findings exist but query is unclear", () => {
    const findings = [createFinding("OIDC_REDIRECT_URI_MISMATCH", "Redirect URI mismatch")];
    const session = createSessionWithFindings(findings);
    const ctx = buildHelpContext(session, findings);
    
    const intent = mapQueryToIntent("something went wrong", ctx);
    const explanation = getExplanationForIntent(intent, ctx);
    
    expect(explanation).toContain("Redirect URI mismatch");
  });
});
