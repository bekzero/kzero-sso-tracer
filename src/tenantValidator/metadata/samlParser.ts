import { XMLParser } from "fast-xml-parser";
import type { SamlIdpMetadata, MetadataParseResult } from "../types";

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  removeNSPrefix: true,
  parseTagValue: false
});

export const parseSamlMetadata = (content: string): MetadataParseResult => {
  try {
    const doc = xmlParser.parse(content);
    
    if (!doc.EntityDescriptor) {
      return { type: "error", error: "Invalid SAML metadata: missing EntityDescriptor" };
    }

    const entityDesc = doc.EntityDescriptor;
    const entityId = entityDesc["@_entityID"] ?? entityDesc.entityID;
    
    if (!entityId) {
      return { type: "error", error: "Missing entityID in SAML metadata" };
    }

    const idpSsoDescriptor = entityDesc.IDPSSODescriptor ?? entityDesc.IDPSSODescriptor?.[0];
    
    if (!idpSsoDescriptor) {
      return { type: "error", error: "No IDPSSODescriptor found in SAML metadata" };
    }

    const ssoServices = idpSsoDescriptor.SingleSignOnService ?? [];
    const singleSignOnService = Array.isArray(ssoServices) 
      ? ssoServices.find((s: any) => s["@_Binding"]?.includes("HTTP-Redirect") || s["@_Binding"]?.includes("HTTP-POST"))
      : ssoServices;

    const logoutServices = idpSsoDescriptor.SingleLogoutService ?? [];
    const singleLogoutService = Array.isArray(logoutServices)
      ? logoutServices[0]
      : logoutServices;

    const nameIdFormats = idpSsoDescriptor.NameIDFormat ?? [];
    const formatArray = Array.isArray(nameIdFormats) 
      ? nameIdFormats.map((n: any) => typeof n === "string" ? n : n["#text"] ?? n)
      : [typeof nameIdFormats === "string" ? nameIdFormats : nameIdFormats["#text"] ?? ""];

    const keyDescriptors = idpSsoDescriptor.KeyDescriptor ?? [];
    const signingCerts: string[] = [];
    const encryptionCerts: string[] = [];

    const keyArray = Array.isArray(keyDescriptors) ? keyDescriptors : [keyDescriptors];
    for (const kd of keyArray) {
      if (!kd) continue;
      const keyInfo = kd.KeyInfo;
      if (!keyInfo) continue;
      
      const x509Data = keyInfo.X509Data;
      if (!x509Data) continue;
      
      const certData = x509Data.X509Certificate;
      if (!certData) continue;
      
      const cert = typeof certData === "string" ? certData : certData["#text"] ?? certData;
      const use = kd["@_use"] ?? "signing";
      
      if (use === "signing" || !kd["@_use"]) {
        signingCerts.push(cert);
      }
      if (use === "encryption") {
        encryptionCerts.push(cert);
      }
    }

    const wantAuthnRequestsSigned = idpSsoDescriptor["@_WantAuthnRequestsSigned"] === "true" 
      || idpSsoDescriptor.WantAuthnRequestsSigned === "true";

    const metadata: SamlIdpMetadata = {
      entityId,
      singleSignOnServiceUrl: singleSignOnService?.["@_Location"] ?? singleSignOnService?.Location,
      singleLogoutServiceUrl: singleLogoutService?.["@_Location"] ?? singleLogoutService?.Location,
      nameIdFormats: formatArray.filter(Boolean),
      signingCertificates: signingCerts,
      encryptionCertificates: encryptionCerts,
      wantAuthnRequestsSigned,
      wantAssertionsSigned: idpSsoDescriptor["@_WantAssertionsSigned"] === "true" 
        || idpSsoDescriptor.WantAssertionsSigned === "true"
    };

    return { type: "saml", data: metadata };
  } catch (e) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return { type: "error", error: `Failed to parse SAML metadata: ${message}` };
  }
};

export const isSamlMetadata = (content: string): boolean => {
  try {
    return content.includes("EntityDescriptor") && content.includes("IDPSSODescriptor");
  } catch {
    return false;
  }
};