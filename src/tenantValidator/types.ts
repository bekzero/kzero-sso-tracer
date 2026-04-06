export interface TenantMismatch {
  eventId: string;
  eventKind: string;
  url: string;
  host: string;
  extractedTenant: string;
  inputTenant: string;
}

export interface TenantUnknown {
  eventId: string;
  eventKind: string;
  url: string;
  host: string;
}

export interface TenantScanResult {
  inputTenant: string;
  totalEvents: number;
  samlEvents: number;
  oidcEvents: number;
  matchCount: number;
  mismatches: TenantMismatch[];
  unknownCount: number;
  unknownEvents: TenantUnknown[];
  hasMismatch: boolean;
}

export interface OidcMetadata {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint?: string;
  jwksUri: string;
  endSessionEndpoint?: string;
  grantTypesSupported?: string[];
  responseTypesSupported?: string[];
  subjectTypesSupported?: string[];
  idTokenSigningAlgValuesSupported?: string[];
  tokenEndpointAuthMethodsSupported?: string[];
  scopesSupported?: string[];
}

export interface SamlIdpMetadata {
  entityId: string;
  singleSignOnServiceUrl?: string;
  singleLogoutServiceUrl?: string;
  nameIdFormats: string[];
  signingCertificates: string[];
  encryptionCertificates: string[];
  wantAuthnRequestsSigned?: boolean;
  wantAssertionsSigned?: boolean;
}

export type MetadataParseResult = 
  | { type: "oidc"; data: OidcMetadata }
  | { type: "saml"; data: SamlIdpMetadata }
  | { type: "error"; error: string };

export interface ErrorPattern {
  id: string;
  pattern: RegExp;
  cause: string;
  fix: string;
  severity: "error" | "warning" | "info";
}

export interface ErrorAnalysisResult {
  inputError: string;
  matchedPattern?: ErrorPattern;
  suggestions: string[];
}