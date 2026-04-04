import { describe, expect, it } from "vitest";
import { scanForTenantMismatches, getAllTenantsInSession, getKzeroHostsInSession } from "../src/tenantValidator/scanner";
import { parseOidcMetadata, isOidcMetadata } from "../src/tenantValidator/metadata/parser";
import { parseSamlMetadata, isSamlMetadata } from "../src/tenantValidator/metadata/samlParser";
import { analyzeError, ERROR_PATTERNS } from "../src/tenantValidator/errorPatterns";
import type { NormalizedEvent } from "../src/shared/models";

const createMockEvent = (overrides: Partial<NormalizedEvent> = {}): NormalizedEvent => ({
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

describe("Tenant Scanner", () => {
  describe("scanForTenantMismatches", () => {
    it("returns empty result for empty input", () => {
      const result = scanForTenantMismatches([], "mytenant");
      expect(result.inputTenant).toBe("mytenant");
      expect(result.hasMismatch).toBe(false);
      expect(result.totalEvents).toBe(0);
    });

    it("returns empty result for empty events", () => {
      const result = scanForTenantMismatches([], "mytenant");
      expect(result.totalEvents).toBe(0);
      expect(result.hasMismatch).toBe(false);
    });

    it("returns match when all events match tenant", () => {
      const events = [
        createMockEvent({ url: "https://auth.kzero.com/realms/mycompany/protocol/openid-connect/auth" }),
        createMockEvent({ url: "https://auth.kzero.com/realms/mycompany/protocol/openid-connect/token", protocol: "OIDC", kind: "token" }),
      ];
      const result = scanForTenantMismatches(events, "mycompany");
      expect(result.hasMismatch).toBe(false);
      expect(result.totalEvents).toBe(2);
      expect(result.mismatches).toHaveLength(0);
    });

    it("detects case-sensitive mismatch", () => {
      const events = [
        createMockEvent({ url: "https://auth.kzero.com/realms/MyCompany/protocol/openid-connect/auth" }),
      ];
      const result = scanForTenantMismatches(events, "mycompany");
      expect(result.hasMismatch).toBe(true);
      expect(result.mismatches).toHaveLength(1);
      expect(result.mismatches[0].extractedTenant).toBe("MyCompany");
      expect(result.mismatches[0].inputTenant).toBe("mycompany");
    });

    it("handles multiple events with some mismatches", () => {
      const events = [
        createMockEvent({ url: "https://auth.kzero.com/realms/tenant1/protocol/openid-connect/auth", id: "e1" }),
        createMockEvent({ url: "https://auth.kzero.com/realms/tenant2/protocol/openid-connect/auth", id: "e2" }),
        createMockEvent({ url: "https://auth.kzero.com/realms/tenant1/protocol/openid-connect/token", id: "e3", kind: "token" }),
      ];
      const result = scanForTenantMismatches(events, "tenant1");
      expect(result.hasMismatch).toBe(true);
      expect(result.mismatches).toHaveLength(1);
      expect(result.mismatches[0].eventId).toBe("e2");
    });

    it("ignores events without realm in URL", () => {
      const events = [
        createMockEvent({ url: "https://app.example.com/login" }),
        createMockEvent({ url: "https://auth.kzero.com/realms/mycompany/protocol/openid-connect/auth" }),
      ];
      const result = scanForTenantMismatches(events, "mycompany");
      expect(result.hasMismatch).toBe(false);
    });

    it("counts SAML and OIDC events separately", () => {
      const events = [
        createMockEvent({ protocol: "SAML" as const, kind: "saml-request" as const, url: "https://auth.kzero.com/realms/mycompany/protocol/saml/auth" }),
        createMockEvent({ protocol: "OIDC" as const, kind: "authorize" as const, url: "https://auth.kzero.com/realms/mycompany/protocol/openid-connect/auth" }),
      ];
      const result = scanForTenantMismatches(events, "mycompany");
      expect(result.samlEvents).toBe(1);
      expect(result.oidcEvents).toBe(1);
      expect(result.totalEvents).toBe(2);
    });

    it("handles whitespace in tenant input", () => {
      const events = [
        createMockEvent({ url: "https://auth.kzero.com/realms/mycompany/protocol/openid-connect/auth" }),
      ];
      const result = scanForTenantMismatches(events, "  mycompany  ");
      expect(result.inputTenant).toBe("mycompany");
      expect(result.hasMismatch).toBe(false);
    });
  });

  describe("getAllTenantsInSession", () => {
    it("returns empty array for no events", () => {
      const result = getAllTenantsInSession([]);
      expect(result).toHaveLength(0);
    });

    it("extracts unique tenants from events", () => {
      const events = [
        createMockEvent({ url: "https://auth.kzero.com/realms/tenant1/protocol/openid-connect/auth" }),
        createMockEvent({ url: "https://auth.kzero.com/realms/tenant2/protocol/openid-connect/auth" }),
        createMockEvent({ url: "https://auth.kzero.com/realms/tenant1/protocol/openid-connect/token" }),
      ];
      const result = getAllTenantsInSession(events);
      expect(result).toEqual(["tenant1", "tenant2"]);
    });

    it("returns sorted array", () => {
      const events = [
        createMockEvent({ url: "https://auth.kzero.com/realms/zeta/protocol/openid-connect/auth" }),
        createMockEvent({ url: "https://auth.kzero.com/realms/alpha/protocol/openid-connect/auth" }),
      ];
      const result = getAllTenantsInSession(events);
      expect(result).toEqual(["alpha", "zeta"]);
    });
  });

  describe("getKzeroHostsInSession", () => {
    it("returns empty array for no events", () => {
      const result = getKzeroHostsInSession([]);
      expect(result).toHaveLength(0);
    });

    it("extracts KZero hosts from events", () => {
      const events = [
        createMockEvent({ host: "auth.kzero.com" }),
        createMockEvent({ host: "auth.kzero.com" }),
        createMockEvent({ host: "mycompany.auth.kzero.com" }),
        createMockEvent({ host: "app.example.com" }),
      ];
      const result = getKzeroHostsInSession(events);
      expect(result).toContain("auth.kzero.com");
      expect(result).toContain("mycompany.auth.kzero.com");
      expect(result).not.toContain("app.example.com");
    });
  });
});

describe("OIDC Metadata Parser", () => {
  describe("isOidcMetadata", () => {
    it("returns true for valid OIDC discovery", () => {
      const content = JSON.stringify({
        issuer: "https://auth.example.com/realms/test",
        authorization_endpoint: "https://auth.example.com/realms/test/protocol/openid-connect/auth",
        token_endpoint: "https://auth.example.com/realms/test/protocol/openid-connect/token",
        jwks_uri: "https://auth.example.com/realms/test/protocol/openid-connect/certs"
      });
      expect(isOidcMetadata(content)).toBe(true);
    });

    it("returns false for non-OIDC content", () => {
      const content = '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">';
      expect(isOidcMetadata(content)).toBe(false);
    });

    it("returns false for invalid JSON", () => {
      expect(isOidcMetadata("not json")).toBe(false);
    });
  });

  describe("parseOidcMetadata", () => {
    it("parses valid OIDC discovery document", () => {
      const content = JSON.stringify({
        issuer: "https://auth.example.com/realms/test",
        authorization_endpoint: "https://auth.example.com/realms/test/protocol/openid-connect/auth",
        token_endpoint: "https://auth.example.com/realms/test/protocol/openid-connect/token",
        jwks_uri: "https://auth.example.com/realms/test/protocol/openid-connect/certs",
        userinfo_endpoint: "https://auth.example.com/realms/test/protocol/openid-connect/userinfo",
        scopes_supported: ["openid", "profile", "email"]
      });
      const result = parseOidcMetadata(content);
      expect(result.type).toBe("oidc");
      if (result.type === "oidc") {
        expect(result.data.issuer).toBe("https://auth.example.com/realms/test");
        expect(result.data.authorizationEndpoint).toBe("https://auth.example.com/realms/test/protocol/openid-connect/auth");
        expect(result.data.scopesSupported).toEqual(["openid", "profile", "email"]);
      }
    });

    it("returns error for missing issuer", () => {
      const content = JSON.stringify({
        authorization_endpoint: "https://auth.example.com/auth"
      });
      const result = parseOidcMetadata(content);
      expect(result.type).toBe("error");
      if (result.type === "error") {
        expect(result.error).toContain("issuer");
      }
    });

    it("handles invalid JSON", () => {
      const result = parseOidcMetadata("not json");
      expect(result.type).toBe("error");
    });
  });
});

describe("SAML Metadata Parser", () => {
  describe("isSamlMetadata", () => {
    it("returns true for SAML metadata", () => {
      const content = '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor></IDPSSODescriptor></EntityDescriptor>';
      expect(isSamlMetadata(content)).toBe(true);
    });

    it("returns false for OIDC content", () => {
      expect(isSamlMetadata('{"issuer": "test"}')).toBe(false);
    });
  });

  describe("parseSamlMetadata", () => {
    it("parses valid SAML IdP metadata", () => {
      const content = `<?xml version="1.0"?>
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://auth.example.com/realms/test">
          <md:IDPSSODescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" WantAuthnRequestsSigned="true">
            <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://auth.example.com/realms/test/protocol/saml"/>
            <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
            <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>`;
      const result = parseSamlMetadata(content);
      expect(result.type).toBe("saml");
      if (result.type === "saml") {
        expect(result.data.entityId).toBe("https://auth.example.com/realms/test");
        expect(result.data.singleSignOnServiceUrl).toBe("https://auth.example.com/realms/test/protocol/saml");
        expect(result.data.wantAuthnRequestsSigned).toBe(true);
        expect(result.data.nameIdFormats).toContain("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
      }
    });

    it("returns error for missing EntityDescriptor", () => {
      const result = parseSamlMetadata("<Invalid></Invalid>");
      expect(result.type).toBe("error");
    });

    it("returns error for missing entityID", () => {
      const content = '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor></IDPSSODescriptor></EntityDescriptor>';
      const result = parseSamlMetadata(content);
      expect(result.type).toBe("error");
    });

    it("returns error for missing IDPSSODescriptor", () => {
      const content = '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test"></EntityDescriptor>';
      const result = parseSamlMetadata(content);
      expect(result.type).toBe("error");
    });
  });
});

describe("Error Pattern Analyzer", () => {
  describe("analyzeError", () => {
    it("matches invalid_grant error", () => {
      const result = analyzeError("invalid_grant: Authorization code expired");
      expect(result.matchedPattern).toBeDefined();
      expect(result.matchedPattern?.id).toBe("invalid_grant");
      expect(result.matchedPattern?.cause).toContain("expired");
    });

    it("matches invalid_client error", () => {
      const result = analyzeError("invalid_client: Client authentication failed");
      expect(result.matchedPattern).toBeDefined();
      expect(result.matchedPattern?.id).toBe("invalid_client");
    });

    it("matches redirect_uri mismatch", () => {
      const result = analyzeError("redirect_uri mismatch");
      expect(result.matchedPattern).toBeDefined();
      expect(result.matchedPattern?.id).toBe("redirect_uri_mismatch");
    });

    it("returns suggestions for unmatched errors", () => {
      const result = analyzeError("some unknown error message");
      expect(result.matchedPattern).toBeUndefined();
      expect(result.suggestions.length).toBeGreaterThan(0);
    });

    it("returns fix suggestion for matched errors", () => {
      const result = analyzeError("invalid_grant: code expired");
      expect(result.matchedPattern).toBeDefined();
      expect(result.suggestions.length).toBeGreaterThan(0);
    });
  });

  describe("ERROR_PATTERNS", () => {
    it("contains expected patterns", () => {
      const patternIds = ERROR_PATTERNS.map(p => p.id);
      expect(patternIds).toContain("invalid_grant");
      expect(patternIds).toContain("invalid_client");
      expect(patternIds).toContain("redirect_uri_mismatch");
      expect(patternIds).toContain("saml_assertion_expired");
      expect(patternIds).toContain("saml_signature_invalid");
    });

    it("all patterns have required fields", () => {
      for (const pattern of ERROR_PATTERNS) {
        expect(pattern.id).toBeDefined();
        expect(pattern.pattern).toBeDefined();
        expect(pattern.cause).toBeDefined();
        expect(pattern.fix).toBeDefined();
        expect(pattern.severity).toMatch(/^(error|warning|info)$/);
      }
    });
  });
});