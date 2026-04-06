import { describe, expect, it } from "vitest";
import { assessTrace } from "../src/tenantValidator/assessor";

describe("validator assessment", () => {
  it("surfaces ACS mismatch as top root cause when provable", () => {
    const events = [
      {
        id: "s1",
        tabId: 1,
        timestamp: 1,
        protocol: "SAML",
        kind: "saml-response",
        url: "https://vendor.example.com/acs",
        host: "vendor.example.com",
        method: "POST",
        artifacts: {},
        rawRef: "s1",
        binding: "post",
        samlResponse: {
          encoded: "x",
          destination: "https://vendor.example.com/acs-wrong",
          issuer: "https://ca.auth.kzero.com/realms/abc"
        }
      }
    ];

    const assessment = assessTrace({ events: events as any });
    expect(assessment.top).toBeDefined();
    expect(assessment.top?.id).toBe("saml-destination-mismatch");
    expect(assessment.top?.confidence).toBe("high");
  });

  it("marks KZero-initiated missing request as missing-evidence clue", () => {
    const events = [
      {
        id: "s1",
        tabId: 1,
        timestamp: 1,
        protocol: "SAML",
        kind: "saml-response",
        url: "https://vendor.example.com/acs",
        host: "vendor.example.com",
        artifacts: {},
        rawRef: "s1",
        binding: "post",
        samlResponse: {
          encoded: "x",
          issuer: "https://ca.auth.kzero.com/realms/abc"
        }
      }
    ];

    const assessment = assessTrace({ events: events as any });
    const hint = assessment.hypotheses.find((h) => h.id === "idp-initiated-missing-request");
    expect(hint).toBeDefined();
    expect(hint?.kind).toBe("missing-evidence");
  });
});
