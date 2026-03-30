import { describe, expect, it } from "vitest";
import pako from "pako";
import { decodeSamlArtifact } from "../src/parsers/saml";

const toB64 = (value: string): string => Buffer.from(value, "binary").toString("base64");

describe("decodeSamlArtifact", () => {
  it("parses SAML POST XML", () => {
    const xml =
      '<samlp:Response Destination="https://vendor.example.com/acs" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://ca.auth.kzero.com/realms/ACME</saml:Issuer><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>';
    const artifact = decodeSamlArtifact(toB64(xml), "post");
    expect(artifact.parseError).toBeUndefined();
    expect(artifact.issuer).toContain("/realms/ACME");
    expect(artifact.nameId).toBe("user@example.com");
  });

  it("parses SAML Redirect deflate payload", () => {
    const xml = '<samlp:AuthnRequest ForceAuthn="true" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" />';
    const compressed = pako.deflateRaw(xml);
    const encoded = Buffer.from(compressed).toString("base64");
    const artifact = decodeSamlArtifact(encoded, "redirect");
    expect(artifact.parseError).toBeUndefined();
    expect(artifact.forceAuthn).toBe(true);
  });
});
