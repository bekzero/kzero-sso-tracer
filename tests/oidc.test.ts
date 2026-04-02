import { describe, expect, it } from "vitest";
import { normalizeRawEvent } from "../src/normalizers";
import { buildTraceContext, computeOidcCorrelation } from "../src/recipes/context";
import type { CaptureSession } from "../src/shared/models";

const createMockSession = (events: any[]): CaptureSession => ({
  tabId: 1,
  active: false,
  rawEvents: [],
  normalizedEvents: events as any,
  findings: []
});

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

describe("OIDC normalization", () => {
  it("extracts session_state from callback", () => {
    const raw = {
      id: "r1",
      tabId: 1,
      timestamp: 1710000001000,
      url: "https://app.example.com/callback?code=xyz&session_state=abc123&state=abc&client_id=app",
      host: "app.example.com",
      source: "devtools-network" as const,
      method: "GET",
      queryParams: { code: "xyz", session_state: "abc123", state: "abc", client_id: "app" }
    };
    const event = normalizeRawEvent(raw as any);
    expect(event.kind).toBe("callback");
    expect((event as any).sessionState).toBe("abc123");
  });

  it("extracts prompt, maxAge, acrValues from authorize", () => {
    const raw = {
      id: "r1",
      tabId: 1,
      timestamp: 1710000000000,
      url: "https://auth.example.com/protocol/openid-connect/auth?prompt=login&max_age=3600&acr_values=mfa",
      host: "auth.example.com",
      source: "devtools-network" as const,
      method: "GET",
      queryParams: { prompt: "login", max_age: "3600", acr_values: "mfa" }
    };
    const event = normalizeRawEvent(raw as any);
    expect(event.kind).toBe("authorize");
    expect((event as any).prompt).toBe("login");
    expect((event as any).maxAge).toBe("3600");
    expect((event as any).acrValues).toBe("mfa");
  });

  it("extracts idTokenHint and postLogoutRedirectUri from logout", () => {
    const raw = {
      id: "r1",
      tabId: 1,
      timestamp: 1710000000000,
      url: "https://auth.example.com/protocol/openid-connect/logout?id_token_hint=eyJ...&post_logout_redirect_uri=https://app.example.com/after-logout",
      host: "auth.example.com",
      source: "devtools-network" as const,
      method: "GET",
      queryParams: { id_token_hint: "eyJ...", post_logout_redirect_uri: "https://app.example.com/after-logout" }
    };
    const event = normalizeRawEvent(raw as any);
    expect(event.kind).toBe("logout");
    expect((event as any).idTokenHint).toBe("eyJ...");
    expect((event as any).postLogoutRedirectUri).toBe("https://app.example.com/after-logout");
  });

  it("infers flowType as auth-code for response_type=code", () => {
    const raw = {
      id: "r1",
      tabId: 1,
      timestamp: 1710000000000,
      url: "https://auth.example.com/protocol/openid-connect/auth?response_type=code",
      host: "auth.example.com",
      source: "devtools-network" as const,
      method: "GET",
      queryParams: { response_type: "code" }
    };
    const event = normalizeRawEvent(raw as any);
    expect((event as any).flowType).toBe("auth-code");
  });

  it("infers flowType as hybrid for response_type=code id_token token", () => {
    const raw = {
      id: "r1",
      tabId: 1,
      timestamp: 1710000000000,
      url: "https://auth.example.com/protocol/openid-connect/auth?response_type=code%20id_token%20token",
      host: "auth.example.com",
      source: "devtools-network" as const,
      method: "GET",
      queryParams: { response_type: "code id_token token" }
    };
    const event = normalizeRawEvent(raw as any);
    expect((event as any).flowType).toBe("hybrid");
  });

  it("infers flowType as implicit for response_type=id_token token", () => {
    const raw = {
      id: "r1",
      tabId: 1,
      timestamp: 1710000000000,
      url: "https://auth.example.com/protocol/openid-connect/auth?response_type=id_token%20token",
      host: "auth.example.com",
      source: "devtools-network" as const,
      method: "GET",
      queryParams: { response_type: "id_token token" }
    };
    const event = normalizeRawEvent(raw as any);
    expect((event as any).flowType).toBe("implicit");
  });
});

describe("OIDC correlation", () => {
  it("detects successful auth code + PKCE correlation", () => {
    const events = [
      createOidcEvent({
        id: "e1",
        kind: "authorize",
        url: "https://auth.example.com/authorize?client_id=app&redirect_uri=https://app.example.com/callback&response_type=code&state=xyz&code_challenge=abc&code_challenge_method=S256",
        state: "xyz",
        codeChallenge: "abc",
        codeChallengeMethod: "S256",
        flowType: "auth-code"
      }),
      createOidcEvent({
        id: "e2",
        kind: "callback",
        url: "https://app.example.com/callback?code=code123&state=xyz",
        host: "app.example.com",
        state: "xyz",
        code: "code123",
        timestamp: 1710000001000
      }),
      createOidcEvent({
        id: "e3",
        kind: "token",
        url: "https://auth.example.com/token",
        host: "auth.example.com",
        codeVerifier: "verifier",
        timestamp: 1710000002000,
        artifacts: { responseBody: '{"access_token":"xyz"}' }
      })
    ];
    const session = createMockSession(events);
    const context = buildTraceContext(session);

    expect(context.oidc.correlation.stateRoundTrip).toBe(true);
    expect(context.oidc.correlation.pkcePresent).toBe(true);
    expect(context.oidc.correlation.pkceVerified).toBe(true);
    expect(context.oidc.correlation.flowType).toBe("auth-code");
    expect(context.oidc.correlation.flowCorrelated).toBe(true);
    expect(context.oidc.correlation.tokenVisible).toBe(true);
  });

  it("detects late-capture callback-only correlation", () => {
    const events = [
      createOidcEvent({
        id: "e1",
        kind: "callback",
        url: "https://app.example.com/callback?code=code123&state=xyz",
        host: "app.example.com",
        state: "xyz",
        code: "code123",
        timestamp: 1710000001000
      }),
      createOidcEvent({
        id: "e2",
        kind: "request",
        url: "https://app.example.com/dashboard",
        host: "app.example.com",
        method: "GET",
        timestamp: 1710000002000
      })
    ];
    const session = createMockSession(events);
    const context = buildTraceContext(session);

    expect(context.oidc.correlation.lateCapture).toBe(true);
    expect(context.oidc.correlation.flowCorrelated).toBe(true);
    expect(context.oidc.authorize).toBeUndefined();
    expect(context.oidc.callback).toBeDefined();
  });

  it("extracts callback error", () => {
    const events = [
      createOidcEvent({
        id: "e1",
        kind: "callback",
        url: "https://app.example.com/callback?error=access_denied&error_description=User%20denied%20access",
        host: "app.example.com",
        error: "access_denied",
        errorDescription: "User denied access",
        timestamp: 1710000001000
      })
    ];
    const session = createMockSession(events);
    const context = buildTraceContext(session);

    expect(context.oidc.correlation.callbackError).toBe("access_denied");
    expect(context.oidc.correlation.errorClue).toBe("access_denied");
  });

  it("detects state round-trip true when states match", () => {
    const correlation = computeOidcCorrelation({
      authorize: createOidcEvent({ state: "xyz" }),
      callback: createOidcEvent({ state: "xyz" })
    } as any);

    expect(correlation.stateRoundTrip).toBe(true);
  });

  it("detects state round-trip false when states differ", () => {
    const correlation = computeOidcCorrelation({
      authorize: createOidcEvent({ state: "xyz" }),
      callback: createOidcEvent({ state: "abc" })
    } as any);

    expect(correlation.stateRoundTrip).toBe(false);
  });

  it("detects redirect URI match", () => {
    const correlation = computeOidcCorrelation({
      authorize: createOidcEvent({
        redirectUri: "https://app.example.com/callback"
      }),
      callback: createOidcEvent({
        url: "https://app.example.com/callback?code=xyz"
      })
    } as any);

    expect(correlation.redirectUriMatch).toBe(true);
  });

  it("detects redirect URI mismatch", () => {
    const correlation = computeOidcCorrelation({
      authorize: createOidcEvent({
        redirectUri: "https://app.example.com/callback"
      }),
      callback: createOidcEvent({
        url: "https://app.example.com/other?code=xyz"
      })
    } as any);

    expect(correlation.redirectUriMatch).toBe(false);
  });

  it("returns undefined redirectUriMatch when redirect_uri missing", () => {
    const correlation = computeOidcCorrelation({
      authorize: createOidcEvent({}),
      callback: createOidcEvent({ url: "https://app.example.com/callback" })
    } as any);

    expect(correlation.redirectUriMatch).toBeUndefined();
  });

  it("detects discovery visible + issuer match", () => {
    const correlation = computeOidcCorrelation({
      discovery: createOidcEvent({ issuer: "https://auth.example.com", kind: "discovery" }),
      authorize: createOidcEvent({}),
      token: createOidcEvent({
        kind: "token",
        idToken: {
          header: {},
          payload: { iss: "https://auth.example.com" },
          signature: "sig"
        }
      })
    } as any);

    expect(correlation.discoveryVisible).toBe(true);
    expect(correlation.issuerMatch).toBe(true);
  });

  it("returns undefined issuerMatch when no second issuer source", () => {
    const correlation = computeOidcCorrelation({
      discovery: createOidcEvent({ issuer: "https://auth.example.com", kind: "discovery" }),
      authorize: createOidcEvent({})
    } as any);

    expect(correlation.discoveryVisible).toBe(true);
    expect(correlation.issuerMatch).toBeUndefined();
  });

  it("allows flowCorrelated when token not visible", () => {
    const correlation = computeOidcCorrelation({
      authorize: createOidcEvent({ state: "xyz", redirectUri: "https://app.example.com/callback" }),
      callback: createOidcEvent({ state: "xyz", code: "xyz" }),
      token: createOidcEvent({ kind: "token" })
    } as any);

    expect(correlation.tokenVisible).toBe(false);
    expect(correlation.flowCorrelated).toBe(true);
  });

  it("extracts logout parameters", () => {
    const events = [
      createOidcEvent({
        id: "e1",
        kind: "logout",
        url: "https://auth.example.com/logout?post_logout_redirect_uri=https://app.example.com/after&id_token_hint=eyJ...",
        postLogoutRedirectUri: "https://app.example.com/after",
        idTokenHint: "eyJ...",
        timestamp: 1710000000000
      })
    ];
    const session = createMockSession(events);
    const context = buildTraceContext(session);

    expect(context.oidc.logout).toBeDefined();
    expect(context.oidc.logout?.postLogoutRedirectUri).toBe("https://app.example.com/after");
    expect(context.oidc.logout?.idTokenHint).toBe("eyJ...");
  });
});