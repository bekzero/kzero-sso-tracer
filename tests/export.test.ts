import { describe, expect, it } from "vitest";
import { buildSanitizedExport, buildRawExport, buildSummaryExport } from "../src/export";
import type { CaptureSession, NormalizedSamlEvent } from "../src/shared/models";

const createMockSession = (events: CaptureSession["normalizedEvents"]): CaptureSession => ({
  tabId: 1,
  active: false,
  startedAt: 1000000000000,
  stoppedAt: 1000000001000,
  rawEvents: [],
  normalizedEvents: events,
  findings: []
});

const createSamlResponseEvent = (overrides: Partial<NormalizedSamlEvent> = {}): NormalizedSamlEvent => ({
  id: "evt-1",
  tabId: 1,
  timestamp: 1000000000000,
  protocol: "SAML",
  kind: "saml-response",
  url: "https://idp.example.com/saml",
  host: "idp.example.com",
  method: "POST",
  statusCode: 200,
  rawRef: "raw-1",
  artifacts: {
    relayState: "https://app.example.com/",
    binding: "post"
  },
  binding: "post",
  relayState: "https://app.example.com/",
  samlResponse: {
    encoded: "base64...",
    issuer: "https://idp.example.com",
    destination: "https://app.example.com/acs",
    audience: "https://app.example.com",
    recipient: "https://app.example.com/acs",
    nameId: "user@example.com",
    nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:email"
  },
  ...overrides
} as NormalizedSamlEvent);

describe("buildSummaryExport", () => {
  it("contains auth host summary", () => {
    const session = createMockSession([
      createSamlResponseEvent()
    ]);
    const result = buildSummaryExport(session);
    expect(result).not.toBeNull();
    expect(result?.authHosts.idpHost).toBe("idp.example.com");
    expect(result?.authHosts.spAppHost).toBe("app.example.com");
    expect(result?.authHosts.protocol).toBe("SAML");
  });

  it("filters to only auth events in summary mode", () => {
    const authEvent = createSamlResponseEvent();
    const networkEvent: NormalizedSamlEvent = {
      ...authEvent,
      id: "evt-2",
      timestamp: 1000000000500,
      url: "https://app.example.com/api/users",
      host: "app.example.com",
      kind: "network"
    } as any;
    const session = createMockSession([authEvent, networkEvent]);
    const result = buildSummaryExport(session);
    expect(result).not.toBeNull();
    expect(result?.summary.eventCount).toBe(2);
  });
});

describe("buildSanitizedExport", () => {
  it("preserves issuer/audience/destination", () => {
    const session = createMockSession([
      createSamlResponseEvent()
    ]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const samlEvent = result?.events[0] as NormalizedSamlEvent;
    expect(samlEvent.samlResponse?.issuer).toBe("https://idp.example.com");
    expect(samlEvent.samlResponse?.destination).toBe("https://app.example.com/acs");
    expect(samlEvent.samlResponse?.audience).toBe("https://app.example.com");
  });

  it("redacts email-like NameID", () => {
    const session = createMockSession([
      createSamlResponseEvent()
    ]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const samlEvent = result?.events[0] as NormalizedSamlEvent;
    expect(samlEvent.samlResponse?.nameId).toBe("us...om");
  });

  it("includes aggregated redaction metadata", () => {
    const session = createMockSession([
      createSamlResponseEvent({
        artifacts: {
          ...createSamlResponseEvent().artifacts,
          client_secret: "mysecret"
        }
      } as any)
    ]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    expect(result?.metadata.redactionsApplied.length).toBeGreaterThan(0);
    expect(result?.metadata.mode).toBe("sanitized");
  });

  it("filters post-login noise with grace window", () => {
    const authEvent = createSamlResponseEvent();
    const landingEvent: NormalizedSamlEvent = {
      ...authEvent,
      id: "evt-2",
      timestamp: 1000000000200,
      url: "https://app.example.com/dashboard",
      host: "app.example.com",
      kind: "network"
    } as any;
    const noiseEvent: NormalizedSamlEvent = {
      ...authEvent,
      id: "evt-3",
      timestamp: 1000000000700,
      url: "https://www.google-analytics.com/collect",
      host: "www.google-analytics.com",
      kind: "network"
    } as any;
    const session = createMockSession([authEvent, landingEvent, noiseEvent]);
    const result = buildSanitizedExport(session, { mode: "sanitized", includePostLoginActivity: false });
    expect(result).not.toBeNull();
    expect(result?.metadata.authBoundaryDetected).toBe(true);
    expect(result?.metadata.includePostLoginActivity).toBe(false);
  });
});

describe("buildRawExport", () => {
  it("preserves complete trace", () => {
    const session = createMockSession([
      createSamlResponseEvent()
    ]);
    const result = buildRawExport(session);
    expect(result).not.toBeNull();
    expect(result?.events.length).toBe(1);
    expect(result?.events[0]).toEqual(expect.objectContaining({
      protocol: "SAML",
      kind: "saml-response"
    }));
  });

  it("includes metadata.mode = raw but no redaction metadata", () => {
    const session = createMockSession([
      createSamlResponseEvent()
    ]);
    const result = buildRawExport(session);
    expect(result).not.toBeNull();
    expect(result?.metadata.mode).toBe("raw");
    expect(result?.metadata.redactionsApplied).toEqual([]);
    expect(result?.metadata.includePostLoginActivity).toBe(true);
  });
});