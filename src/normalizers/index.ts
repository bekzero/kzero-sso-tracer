import { decodeJwt } from "../parsers/jwt";
import { attachTokenArtifacts, parseFragmentOrQuery } from "../parsers/oidc";
import { decodeSamlArtifact } from "../parsers/saml";
import type { NormalizedEvent, NormalizedOidcEvent, NormalizedSamlEvent, RawCaptureEvent } from "../shared/models";
import { parseQueryString, safeUrl } from "../shared/utils";

const parseBodyParams = (body?: string): Record<string, string> => {
  if (!body) return {};
  return parseQueryString(body);
};

const buildSaml = (raw: RawCaptureEvent): NormalizedSamlEvent | undefined => {
  const fromQuery = raw.queryParams ?? {};
  const fromBody = parseBodyParams(raw.postBody);
  const samlRequest = fromQuery.SAMLRequest ?? fromBody.SAMLRequest;
  const samlResponse = fromQuery.SAMLResponse ?? fromBody.SAMLResponse;
  const relayState = fromQuery.RelayState ?? fromBody.RelayState;
  if (!samlRequest && !samlResponse) return undefined;

  const binding: "redirect" | "post" | "unknown" = raw.method === "POST" || raw.source === "content-form" ? "post" : "redirect";
  return {
    id: raw.id,
    tabId: raw.tabId,
    timestamp: raw.timestamp,
    protocol: "SAML",
    kind: samlResponse ? "saml-response" : "saml-request",
    url: raw.url,
    host: raw.host ?? safeUrl(raw.url)?.host ?? "",
    method: raw.method,
    statusCode: raw.statusCode,
    rawRef: raw.id,
    artifacts: {
      relayState,
      binding,
      requestHeaders: raw.requestHeaders,
      responseHeaders: raw.responseHeaders
    },
    binding,
    relayState,
    samlRequest: samlRequest ? decodeSamlArtifact(samlRequest, binding) : undefined,
    samlResponse: samlResponse ? decodeSamlArtifact(samlResponse, binding) : undefined
  };
};

const classifyOidcKind = (url: string): NormalizedOidcEvent["kind"] => {
  if (url.includes("/.well-known/openid-configuration")) return "discovery";
  if (url.includes("/protocol/openid-connect/auth")) return "authorize";
  if (url.includes("/protocol/openid-connect/token")) return "token";
  if (url.includes("/protocol/openid-connect/userinfo")) return "userinfo";
  if (url.includes("/protocol/openid-connect/logout")) return "logout";
  if (url.includes("/protocol/openid-connect/certs")) return "jwks";
  const params = parseFragmentOrQuery(url);
  if (params.code || params.error || params.id_token || params.access_token) return "callback";
  return "unknown";
};

const buildOidc = (raw: RawCaptureEvent): NormalizedOidcEvent | undefined => {
  const oidcHint =
    raw.url.includes("openid") ||
    raw.url.includes("/protocol/openid-connect/") ||
    Object.keys(raw.queryParams ?? {}).some((k) => ["client_id", "redirect_uri", "response_type"].includes(k));
  if (!oidcHint) return undefined;

  const url = safeUrl(raw.url);
  const query = raw.queryParams ?? (url ? parseQueryString(url.search.slice(1)) : {});
  const body = parseBodyParams(raw.postBody);
  const callbackParams = parseFragmentOrQuery(raw.url);
  const kind = classifyOidcKind(raw.url);

  const event: NormalizedOidcEvent = {
    id: raw.id,
    tabId: raw.tabId,
    timestamp: raw.timestamp,
    protocol: "OIDC",
    kind,
    url: raw.url,
    host: raw.host ?? url?.host ?? "",
    method: raw.method,
    statusCode: raw.statusCode,
    rawRef: raw.id,
    artifacts: {
      query,
      body,
      callbackParams,
      requestHeaders: raw.requestHeaders,
      responseHeaders: raw.responseHeaders
    },
    clientId: query.client_id ?? body.client_id,
    redirectUri: query.redirect_uri ?? body.redirect_uri,
    responseType: query.response_type,
    responseMode: query.response_mode,
    scope: query.scope,
    state: query.state ?? callbackParams.state ?? body.state,
    nonce: query.nonce ?? callbackParams.nonce,
    code: callbackParams.code ?? body.code,
    error: callbackParams.error,
    errorDescription: callbackParams.error_description,
    codeChallenge: query.code_challenge,
    codeChallengeMethod: query.code_challenge_method,
    codeVerifier: body.code_verifier
  };

  if (kind === "callback" && callbackParams.id_token) {
    event.idToken = decodeJwt(callbackParams.id_token);
  }

  if (kind === "discovery" && raw.responseBody) {
    try {
      const discovery = JSON.parse(raw.responseBody) as Record<string, unknown>;
      event.issuer = typeof discovery.issuer === "string" ? discovery.issuer : undefined;
      event.artifacts.discovery = discovery;
    } catch {
      event.artifacts.discoveryError = "Discovery response is not valid JSON";
    }
  }

  if (kind === "token") {
    attachTokenArtifacts(event, raw.responseBody);
  }

  return event;
};

export const normalizeRawEvent = (raw: RawCaptureEvent): NormalizedEvent => {
  const saml = buildSaml(raw);
  if (saml) return saml;
  const oidc = buildOidc(raw);
  if (oidc) return oidc;
  return {
    id: raw.id,
    tabId: raw.tabId,
    timestamp: raw.timestamp,
    protocol: raw.source === "webrequest-error" ? "network" : "unknown",
    kind: raw.source,
    url: raw.url,
    host: raw.host ?? safeUrl(raw.url)?.host ?? "",
    method: raw.method,
    statusCode: raw.statusCode,
    rawRef: raw.id,
    artifacts: {
      errorText: raw.errorText,
      redirectUrl: raw.redirectUrl
    }
  };
};
