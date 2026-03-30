import pako from "pako";
import { XMLParser } from "fast-xml-parser";
import type { SamlArtifact } from "../shared/models";

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  removeNSPrefix: true,
  parseTagValue: false
});

const decodeBase64 = (raw: string): string => {
  const normalized = raw.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return atob(padded);
};

const decodeRedirectPayload = (raw: string): string => {
  const binary = decodeBase64(raw);
  const uint8 = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return pako.inflateRaw(uint8, { to: "string" });
};

const findValue = (node: unknown, key: string): string | undefined => {
  if (!node || typeof node !== "object") return undefined;
  if (Array.isArray(node)) {
    for (const child of node) {
      const value = findValue(child, key);
      if (value) return value;
    }
    return undefined;
  }
  const obj = node as Record<string, unknown>;
  const direct = obj[key];
  if (typeof direct === "string") return direct;
  for (const value of Object.values(obj)) {
    const found = findValue(value, key);
    if (found) return found;
  }
  return undefined;
};

const hasNode = (node: unknown, key: string): boolean => {
  if (!node || typeof node !== "object") return false;
  if (Array.isArray(node)) return node.some((entry) => hasNode(entry, key));
  const obj = node as Record<string, unknown>;
  if (key in obj) return true;
  return Object.values(obj).some((entry) => hasNode(entry, key));
};

export const decodeSamlArtifact = (encoded: string, binding: "redirect" | "post" | "unknown"): SamlArtifact => {
  const artifact: SamlArtifact = { encoded };
  try {
    const xml = binding === "redirect" ? decodeRedirectPayload(encoded) : decodeBase64(encoded);
    artifact.decodedXml = xml;

    const parsed = xmlParser.parse(xml) as Record<string, unknown>;
    artifact.issuer = findValue(parsed, "Issuer");
    artifact.destination = findValue(parsed, "@_Destination");
    artifact.audience = findValue(parsed, "Audience");
    artifact.recipient = findValue(parsed, "@_Recipient");
    artifact.inResponseTo = findValue(parsed, "@_InResponseTo");
    artifact.nameId = findValue(parsed, "NameID");
    artifact.nameIdFormat = findValue(parsed, "@_Format");
    artifact.notBefore = findValue(parsed, "@_NotBefore");
    artifact.notOnOrAfter = findValue(parsed, "@_NotOnOrAfter");
    artifact.assertionSigned = hasNode(parsed, "Signature") && hasNode(parsed, "Assertion");
    artifact.documentSigned = hasNode(parsed, "Signature") && hasNode(parsed, "Response");
    artifact.encryptedAssertion = hasNode(parsed, "EncryptedAssertion");
    artifact.forceAuthn = findValue(parsed, "@_ForceAuthn") === "true";
    artifact.allowCreate = findValue(parsed, "@_AllowCreate") === "true";
  } catch (error) {
    artifact.parseError = error instanceof Error ? error.message : "Failed to parse SAML artifact";
  }

  return artifact;
};
