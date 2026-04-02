import { describe, expect, it } from "vitest";
import { runOidcRules } from "../src/rules/oidcRules";

const createOidcEvent = (overrides: any = {}) => ({
  id: "e1",
  tabId: 1,
  timestamp: 1710000000000,
  protocol: "OIDC" as const,
  kind: "authorize" as const,
  url: "https://auth.example.com/authorize",
  host: "auth.example.com",
  artifacts: {},
  rawRef: "e1",
  ...overrides
});

describe("OIDC rule: OIDC_LATE_CAPTURE_CLUE", () => {
  it("triggers when callback exists but no authorize", () => {
    const events = [
      createOidcEvent({
        id: "c1",
        kind: "callback",
        url: "https://app.example.com/callback?code=xyz&state=abc",
        host: "app.example.com",
        state: "abc",
        code: "xyz"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_LATE_CAPTURE_CLUE");
    expect(f).toBeDefined();
    expect(f!.isAmbiguous).toBe(true);
    expect(f!.confidence).toBe(0.6);
    expect(f!.severity).toBe("info");
    expect(f!.likelyOwner).toBe("unknown");
  });

  it("does NOT trigger when authorize is present", () => {
    const events = [
      createOidcEvent({ state: "abc" }),
      createOidcEvent({
        id: "c1",
        kind: "callback",
        url: "https://app.example.com/callback?code=xyz&state=abc",
        host: "app.example.com",
        state: "abc",
        code: "xyz"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_LATE_CAPTURE_CLUE");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_MISSING_AUTHORIZE_REQUEST_CLUE", () => {
  it("triggers when downstream activity (token) exists but no authorize and no callback", () => {
    const events = [
      createOidcEvent({
        id: "t1",
        kind: "token",
        url: "https://auth.example.com/token",
        host: "auth.example.com",
        code: "xyz"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_MISSING_AUTHORIZE_REQUEST_CLUE");
    expect(f).toBeDefined();
    expect(f!.isAmbiguous).toBe(true);
    expect(f!.confidence).toBe(0.58);
  });

  it("does NOT trigger when callback exists (late capture handles that)", () => {
    const events = [
      createOidcEvent({
        id: "c1",
        kind: "callback",
        url: "https://app.example.com/callback?code=xyz",
        host: "app.example.com"
      }),
      createOidcEvent({
        id: "t1",
        kind: "token",
        url: "https://auth.example.com/token",
        host: "auth.example.com"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_MISSING_AUTHORIZE_REQUEST_CLUE");
    expect(f).toBeUndefined();
  });

  it("does NOT trigger for discovery/jwks only (metadata only)", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: { issuer: "https://auth.example.com" }
      }),
      createOidcEvent({
        id: "j1",
        kind: "jwks",
        url: "https://auth.example.com/protocol/openid-connect/certs",
        host: "auth.example.com"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_MISSING_AUTHORIZE_REQUEST_CLUE");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_MISSING_CALLBACK", () => {
  it("triggers when authorize exists but no callback", () => {
    const events = [
      createOidcEvent({
        state: "abc",
        redirectUri: "https://app.example.com/callback"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_MISSING_CALLBACK");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(0.68);
    expect(f!.severity).toBe("warning");
    expect(f!.likelyOwner).toBe("vendor SP");
  });

  it("does NOT trigger when callback exists", () => {
    const events = [
      createOidcEvent({ state: "abc" }),
      createOidcEvent({
        id: "c1",
        kind: "callback",
        url: "https://app.example.com/callback?code=xyz&state=abc",
        host: "app.example.com",
        state: "abc"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_MISSING_CALLBACK");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_PKCE_MISSING_WHEN_CODE_FLOW", () => {
  it("triggers when response_type=code without code_challenge", () => {
    const events = [
      createOidcEvent({
        responseType: "code",
        codeChallenge: undefined
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_PKCE_MISSING_WHEN_CODE_FLOW");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(0.74);
    expect(f!.severity).toBe("warning");
  });

  it("does NOT trigger when code_challenge is present", () => {
    const events = [
      createOidcEvent({
        responseType: "code",
        codeChallenge: "abc123",
        codeChallengeMethod: "S256"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_PKCE_MISSING_WHEN_CODE_FLOW");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_PKCE_METHOD_WEAK_OR_UNEXPECTED", () => {
  it("triggers when code_challenge_method is plain", () => {
    const events = [
      createOidcEvent({
        codeChallenge: "abc123",
        codeChallengeMethod: "plain"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_PKCE_METHOD_WEAK_OR_UNEXPECTED");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(0.84);
    expect(f!.severity).toBe("warning");
  });

  it("does NOT trigger when code_challenge_method is S256", () => {
    const events = [
      createOidcEvent({
        codeChallenge: "abc123",
        codeChallengeMethod: "S256"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_PKCE_METHOD_WEAK_OR_UNEXPECTED");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_DISCOVERY_ENDPOINT_INCONSISTENT", () => {
  it("triggers when discovery is missing required fields", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: { issuer: "https://auth.example.com" }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_ENDPOINT_INCONSISTENT");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(0.86);
    expect(f!.severity).toBe("error");
    expect(f!.likelyOwner).toBe("user data");
  });

  it("does NOT trigger when all required fields are present", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          issuer: "https://auth.example.com",
          authorization_endpoint: "https://auth.example.com/authorize",
          token_endpoint: "https://auth.example.com/token"
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_ENDPOINT_INCONSISTENT");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_USERINFO_FAILED", () => {
  it("triggers when userinfo returns error status", () => {
    const events = [
      createOidcEvent({
        id: "u1",
        kind: "userinfo",
        url: "https://auth.example.com/userinfo",
        host: "auth.example.com",
        statusCode: 401
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_USERINFO_FAILED");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(0.76);
    expect(f!.severity).toBe("warning");
  });

  it("does NOT trigger when userinfo returns 200", () => {
    const events = [
      createOidcEvent({
        id: "u1",
        kind: "userinfo",
        url: "https://auth.example.com/userinfo",
        host: "auth.example.com",
        statusCode: 200
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_USERINFO_FAILED");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_BROWSER_STORAGE_OR_COOKIE_BLOCKING_CLUE", () => {
  it("triggers when multiple authorize requests without callback", () => {
    const events = [
      createOidcEvent({ id: "a1", timestamp: 1710000000000 }),
      createOidcEvent({ id: "a2", timestamp: 1710000001000 }),
      createOidcEvent({ id: "a3", timestamp: 1710000002000 })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_BROWSER_STORAGE_OR_COOKIE_BLOCKING_CLUE");
    expect(f).toBeDefined();
    expect(f!.isAmbiguous).toBe(true);
    expect(f!.confidence).toBe(0.52);
  });

  it("does NOT trigger with callback present", () => {
    const events = [
      createOidcEvent({ id: "a1" }),
      createOidcEvent({
        id: "c1",
        kind: "callback",
        url: "https://app.example.com/callback?code=xyz",
        host: "app.example.com"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_BROWSER_STORAGE_OR_COOKIE_BLOCKING_CLUE");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_CALLBACK_SEEN_BUT_NO_APP_LANDING_CLUE", () => {
  it("triggers when callback succeeds but no landing detected", () => {
    const events = [
      createOidcEvent({
        id: "c1",
        kind: "callback",
        url: "https://app.example.com/callback?code=xyz",
        host: "app.example.com",
        code: "xyz"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_CALLBACK_SEEN_BUT_NO_APP_LANDING_CLUE");
    expect(f).toBeDefined();
    expect(f!.isAmbiguous).toBe(true);
    expect(f!.confidence).toBe(0.64);
  });
});

describe("OIDC existing rule: OIDC_STATE_MISSING_OR_MISMATCH", () => {
  it("triggers when state is missing in authorize", () => {
    const events = [
      createOidcEvent({ state: undefined }),
      createOidcEvent({
        id: "c1",
        kind: "callback",
        url: "https://app.example.com/callback?code=xyz&state=abc",
        host: "app.example.com",
        state: "abc"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_STATE_MISSING_OR_MISMATCH");
    expect(f).toBeDefined();
  });

  it("triggers when state mismatch", () => {
    const events = [
      createOidcEvent({ state: "xyz" }),
      createOidcEvent({
        id: "c1",
        kind: "callback",
        url: "https://app.example.com/callback?code=xyz&state=abc",
        host: "app.example.com",
        state: "abc"
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_STATE_MISSING_OR_MISMATCH");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("error");
  });
});

describe("OIDC rule: OIDC_DISCOVERY_MALFORMED", () => {
  it("triggers when discovery response cannot be parsed as JSON", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: { discoveryError: "Unexpected token < at position 0" }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_MALFORMED");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(0.94);
    expect(f!.severity).toBe("error");
    expect(f!.likelyOwner).toBe("user data");
  });

  it("does NOT trigger when discovery parses as valid JSON", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: { discovery: { issuer: "https://auth.example.com" } }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_MALFORMED");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_DISCOVERY_PUBLIC_REACHABILITY_CLUE", () => {
  it("triggers when discovery contains localhost endpoint", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          discovery: {
            issuer: "https://auth.example.com",
            authorization_endpoint: "http://localhost:8080/authorize",
            token_endpoint: "http://localhost:8080/token"
          }
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_PUBLIC_REACHABILITY_CLUE");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(0.58);
    expect(f!.isAmbiguous).toBe(true);
  });

  it("triggers when discovery contains RFC1918 private IP endpoint", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          discovery: {
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://192.168.1.1/authorize",
            token_endpoint: "https://192.168.1.1/token"
          }
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_PUBLIC_REACHABILITY_CLUE");
    expect(f).toBeDefined();
  });

  it("triggers when discovery contains .internal TLD endpoint (not subdomain)", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          discovery: {
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://auth.internal/authorize"
          }
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_PUBLIC_REACHABILITY_CLUE");
    expect(f).toBeDefined();
  });

  it("does NOT trigger for public endpoints with internal subdomain", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          discovery: {
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://auth.internal.example.com/authorize"
          }
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_PUBLIC_REACHABILITY_CLUE");
    expect(f).toBeUndefined();
  });

  it("does NOT trigger for public endpoints", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          discovery: {
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://auth.example.com/authorize",
            token_endpoint: "https://auth.example.com/token"
          }
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_PUBLIC_REACHABILITY_CLUE");
    expect(f).toBeUndefined();
  });
});

describe("OIDC rule: OIDC_DISCOVERY_ENDPOINT_HOST_SUSPICIOUS", () => {
  it("triggers when endpoint host is from different family", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          discovery: {
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://login.other-vendor.net/authorize",
            token_endpoint: "https://login.other-vendor.net/token"
          }
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_ENDPOINT_HOST_SUSPICIOUS");
    expect(f).toBeDefined();
    expect(f!.confidence).toBe(0.72);
    expect(f!.isAmbiguous).toBe(true);
  });

  it("does NOT trigger when endpoints use same domain family", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          discovery: {
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://identity.example.com/authorize",
            token_endpoint: "https://identity.example.com/token"
          }
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_ENDPOINT_HOST_SUSPICIOUS");
    expect(f).toBeUndefined();
  });

  it("does NOT trigger when endpoints use same host", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          discovery: {
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://auth.example.com/authorize",
            token_endpoint: "https://auth.example.com/token"
          }
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_ENDPOINT_HOST_SUSPICIOUS");
    expect(f).toBeUndefined();
  });

  it("does NOT trigger for private endpoints (handled by reachability clue)", () => {
    const events = [
      createOidcEvent({
        id: "d1",
        kind: "discovery",
        url: "https://auth.example.com/.well-known/openid-configuration",
        host: "auth.example.com",
        artifacts: {
          discovery: {
            issuer: "https://auth.example.com",
            authorization_endpoint: "http://192.168.1.1/authorize"
          }
        }
      })
    ];
    const findings = runOidcRules(events as any);
    const f = findings.find((f) => f.ruleId === "OIDC_DISCOVERY_ENDPOINT_HOST_SUSPICIOUS");
    expect(f).toBeUndefined();
  });
});