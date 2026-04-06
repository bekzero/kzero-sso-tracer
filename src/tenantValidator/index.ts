import type { NormalizedEvent } from "../shared/models";
import type { TenantScanResult, MetadataParseResult, ErrorAnalysisResult } from "./types";
import { scanForTenantMismatches, getAllTenantsInSession, getKzeroHostsInSession } from "./scanner";
import { parseOidcMetadata, isOidcMetadata } from "./metadata/parser";
import { parseSamlMetadata, isSamlMetadata } from "./metadata/samlParser";
import { analyzeError, ERROR_PATTERNS } from "./errorPatterns";
import { assessTrace } from "./assessor";

export * from "./types";
export { ERROR_PATTERNS };

export const parseMetadata = (content: string): MetadataParseResult => {
  if (isOidcMetadata(content)) {
    return parseOidcMetadata(content);
  }
  if (isSamlMetadata(content)) {
    return parseSamlMetadata(content);
  }
  return { type: "error", error: "Unrecognized metadata format. Expected OIDC discovery JSON or SAML IdP metadata XML." };
};

export const detectMetadataType = (content: string): "oidc" | "saml" | "unknown" => {
  if (isOidcMetadata(content)) return "oidc";
  if (isSamlMetadata(content)) return "saml";
  return "unknown";
};

export const validateTenant = (events: NormalizedEvent[], tenantName: string): TenantScanResult => {
  return scanForTenantMismatches(events, tenantName);
};

export const analyzeOidcError = (errorText: string): ErrorAnalysisResult => {
  return analyzeError(errorText);
};

export { getAllTenantsInSession, getKzeroHostsInSession };
export { assessTrace };
