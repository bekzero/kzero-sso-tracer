import { describe, expect, it } from "vitest";
import { classifyCaptureFlow, inferSamlDirection } from "../src/analysis/flowClassifier";

describe("flowClassifier", () => {
  it("classifies empty trace as Unknown", () => {
    expect(classifyCaptureFlow([] as any)).toBe("Unknown");
  });

  it("classifies OIDC-only trace as OIDC", () => {
    const events = [
      {
        id: "o1",
        tabId: 1,
        timestamp: 1,
        protocol: "OIDC",
        kind: "authorize",
        url: "https://ca.auth.kzero.com/realms/demo/protocol/openid-connect/auth",
        host: "ca.auth.kzero.com",
        artifacts: {},
        rawRef: "o1"
      }
    ];
    expect(classifyCaptureFlow(events as any)).toBe("OIDC");
  });

  it("classifies mixed trace as Mixed / partial capture", () => {
    const events = [
      {
        id: "o1",
        tabId: 1,
        timestamp: 1,
        protocol: "OIDC",
        kind: "authorize",
        url: "https://ca.auth.kzero.com/realms/demo/protocol/openid-connect/auth",
        host: "ca.auth.kzero.com",
        artifacts: {},
        rawRef: "o1"
      },
      {
        id: "s1",
        tabId: 1,
        timestamp: 2,
        protocol: "SAML",
        kind: "saml-response",
        url: "https://vendor.example.com/acs",
        host: "vendor.example.com",
        artifacts: {},
        rawRef: "s1",
        binding: "post",
        samlResponse: { encoded: "x" }
      }
    ];
    expect(classifyCaptureFlow(events as any)).toBe("Mixed / partial capture");
  });

  it("infers KZero -> SP for SAML response with KZero issuer", () => {
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
          issuer: "https://ca.auth.kzero.com/realms/demo"
        }
      }
    ];
    const saml = events[0] as any;
    expect(inferSamlDirection(events as any, undefined, saml)).toBe("KZero -> SP");
    expect(classifyCaptureFlow(events as any)).toBe("KZero -> SP");
  });
});
