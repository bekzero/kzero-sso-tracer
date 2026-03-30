export type ProtocolType = "SAML" | "OIDC" | "network" | "unknown";
export type Severity = "info" | "warning" | "error";
export type Owner = "KZero" | "vendor SP" | "network" | "browser" | "user data" | "unknown";

export interface RawCaptureEvent {
  id: string;
  tabId: number;
  source: "devtools-network" | "content-form" | "webrequest-error";
  timestamp: number;
  url: string;
  method?: string;
  statusCode?: number;
  requestHeaders?: Record<string, string>;
  responseHeaders?: Record<string, string>;
  queryParams?: Record<string, string>;
  postBody?: string;
  responseBody?: string;
  redirectUrl?: string;
  errorText?: string;
  initiator?: string;
  timingMs?: number;
  host?: string;
}

export interface BaseNormalizedEvent {
  id: string;
  tabId: number;
  timestamp: number;
  protocol: ProtocolType;
  kind: string;
  url: string;
  host: string;
  method?: string;
  statusCode?: number;
  artifacts: Record<string, unknown>;
  rawRef: string;
}

export interface NormalizedSamlEvent extends BaseNormalizedEvent {
  protocol: "SAML";
  binding: "redirect" | "post" | "unknown";
  samlRequest?: SamlArtifact;
  samlResponse?: SamlArtifact;
  relayState?: string;
}

export interface SamlArtifact {
  encoded: string;
  decodedXml?: string;
  parseError?: string;
  issuer?: string;
  destination?: string;
  audience?: string;
  recipient?: string;
  inResponseTo?: string;
  nameId?: string;
  nameIdFormat?: string;
  notBefore?: string;
  notOnOrAfter?: string;
  assertionSigned?: boolean;
  documentSigned?: boolean;
  encryptedAssertion?: boolean;
  forceAuthn?: boolean;
  allowCreate?: boolean;
}

export interface JwtDecoded {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

export interface NormalizedOidcEvent extends BaseNormalizedEvent {
  protocol: "OIDC";
  kind:
    | "discovery"
    | "authorize"
    | "callback"
    | "token"
    | "userinfo"
    | "jwks"
    | "logout"
    | "unknown";
  issuer?: string;
  clientId?: string;
  redirectUri?: string;
  responseType?: string;
  responseMode?: string;
  scope?: string;
  state?: string;
  nonce?: string;
  code?: string;
  error?: string;
  errorDescription?: string;
  idToken?: JwtDecoded;
  accessTokenJwt?: JwtDecoded;
  accessTokenOpaque?: boolean;
  tokenEndpointAuthMethod?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  codeVerifier?: string;
}

export type NormalizedEvent = BaseNormalizedEvent | NormalizedSamlEvent | NormalizedOidcEvent;

export interface SuggestedFix {
  kzeroFields: string[];
  vendorFields: string[];
  action: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  protocol: ProtocolType;
  likelyOwner: Owner;
  title: string;
  explanation: string;
  observed: string;
  expected: string;
  evidence: string[];
  likelyFix: SuggestedFix;
  confidence: number;
}

export interface CaptureSession {
  tabId: number;
  active: boolean;
  startedAt?: number;
  stoppedAt?: number;
  rawEvents: RawCaptureEvent[];
  normalizedEvents: NormalizedEvent[];
  findings: Finding[];
}

export interface CaptureHistoryItem {
  id: string;
  tabId: number;
  startedAt?: number;
  stoppedAt?: number;
  protocolHints: string[];
  findingCount: number;
  session: CaptureSession;
}

export interface SanitizedExportBundle {
  generatedAt: string;
  product: string;
  notice: string;
  tabId: number;
  events: NormalizedEvent[];
  findings: Finding[];
}
