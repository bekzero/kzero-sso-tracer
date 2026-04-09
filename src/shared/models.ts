export type ProtocolType = "SAML" | "OIDC" | "network" | "unknown";
export type Severity = "info" | "warning" | "error";
export type Owner = "KZero" | "vendor SP" | "network" | "browser" | "user data" | "unknown" | "analysis" | "verification" | "docs";

export interface RawCaptureEvent {
  id: string;
  tabId: number;
  source: "devtools-network" | "content-form" | "webrequest" | "webrequest-error";
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
  sessionState?: string;
  prompt?: string;
  maxAge?: string;
  acrValues?: string;
  uiLocales?: string;
  claimsLocales?: string;
  idTokenHint?: string;
  postLogoutRedirectUri?: string;
  flowType?: "auth-code" | "implicit" | "hybrid" | "unknown";
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
  confidenceLevel: "high" | "medium" | "low";
  isAmbiguous?: boolean;
  ambiguityNote?: string;
  traceGaps?: string[];
  disqualifyingEvidence?: string[];
  eventId?: string;
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

export interface CaptureHistorySummary {
  id: string;
  tabId: number;
  startedAt?: number;
  stoppedAt?: number;
  protocolHints: string[];
  findingCount: number;
  topFindings?: Array<{ ruleId: string; title: string; severity: string }>;
  session?: CaptureSession;
}

export type CaptureHistoryItem = CaptureHistorySummary;

export type ExportMode = "summary" | "sanitized" | "raw";

export type RedactionAction = "masked" | "hashed" | "truncated" | "removed";
export type RedactionCategory = "email" | "secret" | "org_id" | "user_id" | "other";

export interface RedactionSummary {
  category: RedactionCategory;
  action: RedactionAction;
  count: number;
}

export interface ExportMetadata {
  mode: ExportMode;
  generatedAt: string;
  includePostLoginActivity: boolean;
  authBoundaryDetected: boolean;
  redactionsApplied: RedactionSummary[];
}

export interface OidcSummary {
  protocol: string;
  authorizeHost?: string;
  callbackHost?: string;
  redirectUri?: string;
  issuer?: string;
  statePresent: boolean;
  stateRoundTrip?: boolean;
  noncePresent: boolean;
  pkcePresent: boolean;
  pkceMethod?: string;
  callbackHasCode: boolean;
  callbackHasError: boolean;
  callbackError?: string;
  tokenExchangeVisible: boolean;
  tokenResponseBodyVisible?: boolean;
  authBoundaryDetected: boolean;
  landingHost?: string;
}

export interface SanitizedExportBundle {
  generatedAt: string;
  product: string;
  notice: string;
  tabId: number;
  events: SanitizedEvent[];
  findings: Finding[];
  metadata: ExportMetadata;
}

export type SanitizedEvent = SanitizedOidcEvent | SanitizedSamlEvent | SanitizedGenericEvent;

export interface SanitizedOidcEvent extends Omit<NormalizedOidcEvent, "state" | "nonce" | "code" | "idToken" | "accessTokenJwt" | "accessTokenOpaque" | "codeVerifier" | "sessionState" | "url"> {
  state?: string;
  nonce?: string;
  code?: string;
  url?: string;
}

export interface SanitizedSamlEvent extends Omit<NormalizedSamlEvent, "url" | "samlResponse"> {
  url?: string;
  samlResponse?: SamlArtifact;
}

export interface SanitizedGenericEvent {
  id: string;
  tabId: number;
  timestamp: number;
  protocol?: string;
  kind: string;
  url?: string;
  host: string;
  method?: string;
  statusCode?: number;
  artifacts: Record<string, unknown>;
  rawRef: string;
}

export interface SummaryExportBundle {
  generatedAt: string;
  product: string;
  tabId: number;
  metadata: ExportMetadata;
  summary: {
    eventCount: number;
    findingCount: number;
    problemCount: number;
    warningCount: number;
    infoCount: number;
    duration?: number;
  };
  authHosts: {
    idpHost?: string;
    spAppHost?: string;
    protocol?: string;
  };
  oidcSummary?: OidcSummary;
  findings: Array<{
    id: string;
    ruleId: string;
    severity: Severity;
    title: string;
  }>;
  postLoginTrimmed: boolean;
}
