import { describe, expect, it, beforeEach } from "vitest";
import { classifyEvent, isNoiseHost, isAuthPath, hasAuthParams } from "../src/capture/hostClassifier";
import type { RawCaptureEvent } from "../src/shared/models";

const createRawEvent = (overrides: Partial<RawCaptureEvent> = {}): RawCaptureEvent => ({
  id: "test-1",
  tabId: 1,
  source: "webrequest",
  timestamp: Date.now(),
  url: "https://example.com/",
  host: "example.com",
  method: "GET",
  ...overrides
});

describe("classifyEvent", () => {
  it("identifies noise hosts as noise", () => {
    const event = createRawEvent({ host: "google-analytics.com", url: "https://google-analytics.com/collect" });
    const result = classifyEvent(event);
    expect(result.classification).toBe("noise");
    expect(result.isAuthRelevant).toBe(false);
  });

  it("identifies auth path patterns as auth-critical", () => {
    const event = createRawEvent({ 
      url: "https://idp.example.com/saml/sso", 
      host: "idp.example.com" 
    });
    const result = classifyEvent(event);
    expect(result.classification).toBe("auth-critical");
    expect(result.isAuthRelevant).toBe(true);
  });

  it("identifies OIDC authorize path as auth-critical", () => {
    const event = createRawEvent({
      url: "https://idp.example.com/oauth2/authorize",
      host: "idp.example.com"
    });
    const result = classifyEvent(event);
    expect(result.classification).toBe("auth-critical");
    expect(result.isAuthRelevant).toBe(true);
  });

  it("identifies callback pattern as flow-adjacent", () => {
    const event = createRawEvent({
      url: "https://app.example.com/callback?code=abc123&state=xyz",
      host: "app.example.com"
    });
    const result = classifyEvent(event);
    expect(result.classification).toBe("flow-adjacent");
    expect(result.isAuthRelevant).toBe(true);
  });

  it("identifies auth params as flow-adjacent", () => {
    const event = createRawEvent({
      url: "https://app.example.com/page?samlResponse=base64",
      host: "app.example.com"
    });
    const result = classifyEvent(event);
    expect(result.classification).toBe("flow-adjacent");
    expect(result.isAuthRelevant).toBe(true);
  });

  it("keeps unknown callback-like traffic that is not yet classified", () => {
    const event = createRawEvent({
      url: "https://app.example.com/auth/callback?code=xyz",
      host: "app.example.com"
    });
    const result = classifyEvent(event);
    expect(result.isAuthRelevant).toBe(true);
  });

  it("keeps unknown traffic in general (conservative)", () => {
    const event = createRawEvent({
      url: "https://app.example.com/dashboard",
      host: "app.example.com"
    });
    const result = classifyEvent(event);
    expect(result.classification).toBe("unknown");
    expect(result.isAuthRelevant).toBe(false);
  });

  it("identifies SAML POST body as auth-critical", () => {
    const event = createRawEvent({
      url: "https://app.example.com/acs",
      host: "app.example.com",
      method: "POST",
      postBody: "SAMLResponse=base64encoded&RelayState=/app"
    });
    const result = classifyEvent(event);
    expect(result.classification).toBe("auth-critical");
    expect(result.isAuthRelevant).toBe(true);
  });
});

describe("isNoiseHost", () => {
  it("returns true for known noise hosts", () => {
    expect(isNoiseHost("google-analytics.com")).toBe(true);
    expect(isNoiseHost("www.google-analytics.com")).toBe(true);
    expect(isNoiseHost("subdomain.google-analytics.com")).toBe(true);
  });

  it("returns false for non-noise hosts", () => {
    expect(isNoiseHost("app.example.com")).toBe(false);
    expect(isNoiseHost("idp.example.com")).toBe(false);
  });
});

describe("isAuthPath", () => {
  it("returns true for auth paths", () => {
    expect(isAuthPath("https://idp.example.com/saml/sso")).toBe(true);
    expect(isAuthPath("https://idp.example.com/oauth2/authorize")).toBe(true);
    expect(isAuthPath("https://idp.example.com/openid-connect/auth")).toBe(true);
  });

  it("returns false for non-auth paths", () => {
    expect(isAuthPath("https://app.example.com/dashboard")).toBe(false);
    expect(isAuthPath("https://app.example.com/api/users")).toBe(false);
  });
});

describe("hasAuthParams", () => {
  it("returns true for URLs with auth params", () => {
    expect(hasAuthParams("https://app.example.com?code=abc")).toBe(true);
    expect(hasAuthParams("https://app.example.com?state=xyz")).toBe(true);
    expect(hasAuthParams("https://app.example.com?SAMLResponse=base64")).toBe(true);
  });

  it("returns false for URLs without auth params", () => {
    expect(hasAuthParams("https://app.example.com?page=1")).toBe(false);
    expect(hasAuthParams("https://app.example.com?q=search")).toBe(false);
  });
});