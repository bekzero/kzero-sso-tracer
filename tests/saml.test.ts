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

  it("parses NameID with Format attribute", () => {
    const xml =
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:email">user@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>';
    const artifact = decodeSamlArtifact(toB64(xml), "post");
    expect(artifact.nameId).toBe("user@example.com");
    expect(artifact.nameIdFormat).toBe("urn:oasis:names:tc:SAML:1.1:nameid-format:email");
  });

  it("parses NameID nested in Subject with multiple attributes elsewhere", () => {
    const xml =
      '<samlp:Response Destination="https://sp.example.com/acs" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123"><saml:Subject><saml:NameID SPNameQualifier="https://sp.example.com">user123</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotOnOrAfter="2025-12-31T23:59:59Z"/></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
    const artifact = decodeSamlArtifact(toB64(xml), "post");
    expect(artifact.nameId).toBe("user123");
    expect(artifact.destination).toBe("https://sp.example.com/acs");
    expect(artifact.issuer).toBe("https://idp.example.com");
    expect(artifact.inResponseTo).toBeUndefined();
  });

  it("parses realistic Zoho-style response with all attributes", () => {
    const xml =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_kze8f3a1b2c3d4e5f6" Version="2.0" Destination="https://accounts.zoho.com/saml/sp/acs" InResponseTo="_oasis-names:tc:SAML:2.0:status:Success">
        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://ca.auth.kzero.com/realms/kzero</saml:Issuer>
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_kze9a1b2c3d4e5f6g7" Version="2.0">
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:email">ben.eakin@kzero.com</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="2026-04-02T21:30:00Z" Recipient="https://accounts.zoho.com/saml/sp/acs" InResponseTo="_oasis-names:tc:SAML:2.0:status:Success"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="2026-04-02T21:20:00Z" NotOnOrAfter="2026-04-02T21:30:00Z">
            <saml:AudienceRestriction>
              <saml:Audience>https://accounts.zoho.com/saml/sp</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AttributeStatement>
            <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue>ben.eakin@kzero.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="firstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue>Ben</saml:AttributeValue>
            </saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
      </samlp:Response>`;
    const artifact = decodeSamlArtifact(toB64(xml), "post");
    expect(artifact.nameId).toBe("ben.eakin@kzero.com");
    expect(artifact.nameIdFormat).toBe("urn:oasis:names:tc:SAML:1.1:nameid-format:email");
    expect(artifact.issuer).toBe("https://ca.auth.kzero.com/realms/kzero");
    expect(artifact.destination).toBe("https://accounts.zoho.com/saml/sp/acs");
    expect(artifact.audience).toBe("https://accounts.zoho.com/saml/sp");
    expect(artifact.notBefore).toBe("2026-04-02T21:20:00Z");
    expect(artifact.notOnOrAfter).toBe("2026-04-02T21:30:00Z");
  });

  it("does not extract NameID from unrelated @_Format in AuthnRequest", () => {
    const xml =
      '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Format="urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported" />';
    const artifact = decodeSamlArtifact(toB64(xml), "post");
    expect(artifact.nameId).toBeUndefined();
    expect(artifact.nameIdFormat).toBeUndefined();
  });
});
