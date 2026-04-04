import type { RedactionCategory, RedactionAction, RedactionSummary, NormalizedOidcEvent, SanitizedOidcEvent } from "./models";

const SECRET_KEYS = [
  "client_secret",
  "refresh_token",
  "access_token",
  "id_token",
  "authorization",
  "code",
  "samlresponse",
  "samlrequest",
  "assertion",
  "signedinfo",
  "private_key",
  "certificate",
  "keystore",
  "session_id",
  "sid",
  "jti",
  "at_hash"
];

const SECRET_PATTERNS = [
  /secret/i,
  /token/i,
  /password/i,
  /credential/i,
  /private/i,
  /authorization/i,
  /assertion/i,
  /certificate/i,
  /keystore/i
];

const USER_ID_FIELDS = [
  "sub",
  "user_id",
  "userid",
  "uid",
  "user-id",
  "subject",
  "userIdentifier",
  "principal"
];

const SENSITIVE_QUERY_PARAMS = [
  "token",
  "code",
  "session",
  "sessionid",
  "email",
  "user",
  "id_token",
  "access_token",
  "refresh_token",
  "jwt",
  "saml",
  "samlresponse"
];

const PROTOCOL_CRITICAL_FIELDS = [
  "issuer",
  "audience",
  "destination",
  "recipient",
  "entityId",
  "entity_id",
  "entityID",
  "redirectUri",
  "redirect_uri",
  "samlEndpoint",
  "saml_endpoint",
  "acsUrl",
  "acs_url",
  "loginUrl",
  "login_url",
  "logoutUrl",
  "logout_url",
  "issuerUrl",
  "jwksUri",
  "authorizationEndpoint",
  "authorization_endpoint",
  "tokenEndpoint",
  "token_endpoint",
  "userinfoEndpoint",
  "userinfo_endpoint",
  "endSessionEndpoint",
  "end_session_endpoint",
  "responseType",
  "response_type",
  "responseMode",
  "response_mode",
  "scope",
  "codeChallenge",
  "code_challenge",
  "codeChallengeMethod",
  "code_challenge_method"
];

const OIDC_SENSITIVE_URL_PARAMS = [
  "access_token",
  "refresh_token",
  "id_token",
  "code_verifier",
  "client_secret",
  "session_state"
];

const OIDC_HASH_PARAMS = ["state", "nonce", "code"];

const NESTED_URL_KEYS = ["url", "callbackurl", "finalurl", "redirecturl", "requesturl", "responseurl", "location", "href"];

type UrlParamAction = { type: "remove" } | { type: "replace"; value: string } | { type: "keep"; value: string };

export const generateExportSalt = (): string => {
  const array = new Uint8Array(8);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
};

export const hashForCorrelation = (value: string, salt: string): string => {
  let hash = 0;
  const combined = value + salt;
  for (let i = 0; i < combined.length; i++) {
    const char = combined.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).slice(0, 8);
};

const sanitizeUrlParam = (key: string, value: string, salt: string): UrlParamAction => {
  const lower = key.toLowerCase();
  if (OIDC_SENSITIVE_URL_PARAMS.includes(lower)) {
    return { type: "remove" };
  }
  if (OIDC_HASH_PARAMS.includes(lower)) {
    if (value.length > 0) {
      return { type: "replace", value: `[hash:${hashForCorrelation(value, salt)}]` };
    }
    return { type: "remove" };
  }
  return { type: "keep", value };
};

const buildSanitizedParams = (params: URLSearchParams, salt: string): string => {
  const parts: string[] = [];
  for (const [key, value] of params.entries()) {
    const action = sanitizeUrlParam(key, value, salt);
    if (action.type === "keep") {
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(action.value)}`);
    } else if (action.type === "replace") {
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(action.value)}`);
    }
  }
  return parts.join("&");
};

export const sanitizeUrlParams = (urlStr: string, salt: string): string => {
  if (!urlStr || urlStr.length < 5) return urlStr;
  try {
    const url = new URL(urlStr);
    const sanitizedQuery = buildSanitizedParams(url.searchParams, salt);
    url.search = sanitizedQuery;
    if (url.hash.length > 1) {
      const fragmentParams = new URLSearchParams(url.hash.slice(1));
      const sanitizedFragment = buildSanitizedParams(fragmentParams, salt);
      url.hash = sanitizedFragment;
    }
    return url.toString();
  } catch {
    return sanitizeRelativeUrl(urlStr, salt);
  }
};

const sanitizeRelativeUrl = (str: string, salt: string): string => {
  const hasFragment = str.includes("#");
  const [basePart, fragmentPart] = hasFragment ? str.split("#", 2) : [str, ""];
  const hasQuery = basePart.includes("?");
  const [base, queryPart] = hasQuery ? basePart.split("?", 2) : [basePart, ""];
  const queryParams = new URLSearchParams(queryPart);
  const sanitizedQuery = buildSanitizedParams(queryParams, salt);
  const queryStr = hasQuery ? "?" + sanitizedQuery : "";
  let fragmentStr = "";
  if (fragmentPart) {
    const fragParams = new URLSearchParams(fragmentPart);
    const sanitizedFrag = buildSanitizedParams(fragParams, salt);
    fragmentStr = sanitizedFrag ? "#" + sanitizedFrag : "";
  }
  return base + queryStr + fragmentStr;
};

export const sanitizeOidcEventUrls = (event: unknown, salt: string): unknown => {
  if (typeof event !== "object" || event === null) return event;
  const e = event as Record<string, unknown>;
  if (e.url && typeof e.url === "string") {
    return { ...e, url: sanitizeUrlParams(e.url, salt) };
  }
  return event;
};

export const sanitizeOidcEventPayload = (obj: unknown, salt: string): unknown => {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === "string") return obj;
  if (Array.isArray(obj)) return obj.map((item) => sanitizeOidcEventPayload(item, salt));
  if (typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const lowerKey = key.toLowerCase();
      if (NESTED_URL_KEYS.includes(lowerKey) && typeof value === "string") {
        result[key] = sanitizeUrlParams(value, salt);
      } else {
        result[key] = sanitizeOidcEventPayload(value, salt);
      }
    }
    return result;
  }
  return obj;
};

const OIDC_REMOVE_FIELDS = [
  "idToken",
  "accessTokenJwt", 
  "accessTokenOpaque",
  "codeVerifier",
  "sessionState"
] as const;

const OIDC_HASH_FIELDS = ["state", "nonce", "code"] as const;

export const sanitizeOidcTopLevelFields = (
  event: NormalizedOidcEvent,
  salt: string
): SanitizedOidcEvent => {
  const sanitized: SanitizedOidcEvent = {
    id: event.id,
    tabId: event.tabId,
    timestamp: event.timestamp,
    protocol: event.protocol,
    kind: event.kind,
    url: event.url ? sanitizeUrlParams(event.url, salt) : undefined,
    host: event.host,
    method: event.method,
    statusCode: event.statusCode,
    artifacts: event.artifacts,
    rawRef: event.rawRef,
  };
  
  if (event.state) {
    sanitized.state = `[hash:${hashForCorrelation(event.state, salt)}]`;
  }
  if (event.nonce) {
    sanitized.nonce = `[hash:${hashForCorrelation(event.nonce, salt)}]`;
  }
  if (event.code) {
    sanitized.code = `[hash:${hashForCorrelation(event.code, salt)}]`;
  }
  
  if (event.issuer) sanitized.issuer = event.issuer;
  if (event.clientId) sanitized.clientId = event.clientId;
  if (event.redirectUri) sanitized.redirectUri = event.redirectUri;
  if (event.responseType) sanitized.responseType = event.responseType;
  if (event.responseMode) sanitized.responseMode = event.responseMode;
  if (event.scope) sanitized.scope = event.scope;
  if (event.error) sanitized.error = event.error;
  if (event.errorDescription) sanitized.errorDescription = event.errorDescription;
  if (event.tokenEndpointAuthMethod) sanitized.tokenEndpointAuthMethod = event.tokenEndpointAuthMethod;
  if (event.codeChallenge) sanitized.codeChallenge = event.codeChallenge;
  if (event.codeChallengeMethod) sanitized.codeChallengeMethod = event.codeChallengeMethod;
  if (event.prompt) sanitized.prompt = event.prompt;
  if (event.maxAge) sanitized.maxAge = event.maxAge;
  if (event.acrValues) sanitized.acrValues = event.acrValues;
  if (event.uiLocales) sanitized.uiLocales = event.uiLocales;
  if (event.claimsLocales) sanitized.claimsLocales = event.claimsLocales;
  if (event.idTokenHint) sanitized.idTokenHint = event.idTokenHint;
  if (event.postLogoutRedirectUri) sanitized.postLogoutRedirectUri = event.postLogoutRedirectUri;
  if (event.flowType) sanitized.flowType = event.flowType;
  
  return sanitized;
};

export const isSecretKey = (key: string): boolean => {
  const lower = key.toLowerCase();
  if (SECRET_KEYS.includes(lower)) return true;
  if (SECRET_PATTERNS.some((p) => p.test(key))) return true;
  return false;
};

export const isUserIdField = (key: string): boolean => {
  const lower = key.toLowerCase();
  return USER_ID_FIELDS.includes(lower);
};

export const isProtocolCriticalField = (key: string): boolean => {
  const lower = key.toLowerCase();
  return PROTOCOL_CRITICAL_FIELDS.some((f) => lower === f || lower.endsWith("." + f));
};

export const hashValue = (value: string, len = 8): string => {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    const char = value.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  const hex = Math.abs(hash).toString(16);
  return hex.slice(0, len) + "...";
};

export const isEmailLike = (value: string): boolean => {
  if (typeof value !== "string") return false;
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailPattern.test(value);
};

export const isSecretValue = (value: string): boolean => {
  if (typeof value !== "string") return false;
  if (value.length > 200) return false;
  const jwtPattern = /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
  const base64TokenPattern = /^[A-Za-z0-9+/]{40,}={0,2}$/;
  return jwtPattern.test(value) || base64TokenPattern.test(value);
};

export const mask = (value: string, left = 4, right = 3): string => {
  if (value.length <= left + right) {
    return "***";
  }
  return `${value.slice(0, left)}...${value.slice(-right)}`;
};

export const redactValue = (
  key: string,
  value: unknown,
  counts: Map<string, number>
): unknown => {
  if (typeof value !== "string") return value;

  const lowerKey = key.toLowerCase();

  if (isProtocolCriticalField(lowerKey)) {
    return value;
  }

  if (isSecretKey(lowerKey)) {
    counts.set("secret", (counts.get("secret") || 0) + 1);
    return mask(value);
  }

  if (isSecretValue(value)) {
    counts.set("secret", (counts.get("secret") || 0) + 1);
    return mask(value);
  }

  if (isEmailLike(value)) {
    counts.set("email", (counts.get("email") || 0) + 1);
    return mask(value, 2, 2);
  }

  if (["nameid", "email", "sub"].includes(lowerKey)) {
    counts.set("email", (counts.get("email") || 0) + 1);
    return mask(value, 2, 2);
  }

  if (isUserIdField(lowerKey)) {
    counts.set("user_id", (counts.get("user_id") || 0) + 1);
    return hashValue(value);
  }

  return value;
};

export const redactRecord = (
  record: Record<string, unknown>,
  counts: Map<string, number> = new Map()
): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(record)) {
    out[k] = redactValue(k, v, counts);
  }
  return out;
};

export const sanitizeRelayState = (relayState: string): string => {
  if (!relayState) return relayState;
  try {
    const url = new URL(relayState);
    const params = new URLSearchParams(url.search);
    const sensitiveKeys: string[] = [];

    for (const key of params.keys()) {
      const lower = key.toLowerCase();
      if (SENSITIVE_QUERY_PARAMS.some((s) => lower.includes(s))) {
        sensitiveKeys.push(key);
      }
    }

    if (sensitiveKeys.length === 0) {
      return relayState;
    }

    const safeParams = new URLSearchParams();
    params.forEach((value, key) => {
      if (!sensitiveKeys.includes(key)) {
        safeParams.append(key, value);
      } else {
        safeParams.append(key, "***");
      }
    });

    url.search = safeParams.toString();
    return url.toString();
  } catch {
    return relayState;
  }
};

export const buildRedactionSummary = (
  counts: Map<string, number>
): RedactionSummary[] => {
  const summaries: RedactionSummary[] = [];
  const categoryMap: Record<string, RedactionCategory> = {
    secret: "secret",
    email: "email",
    user_id: "user_id",
    org_id: "org_id"
  };

  for (const [key, count] of counts) {
    if (count > 0) {
      summaries.push({
        category: categoryMap[key] || "other",
        action: key === "user_id" ? "hashed" : "masked",
        count
      });
    }
  }

  return summaries;
};