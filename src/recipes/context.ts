import type { CaptureSession, NormalizedEvent, NormalizedOidcEvent, NormalizedSamlEvent } from "../shared/models";

export type FlowType = "auth-code" | "implicit" | "hybrid" | "unknown";

export interface OidcCorrelation {
  stateRoundTrip: boolean;
  pkcePresent: boolean;
  pkceMethod?: string;
  pkceVerified?: boolean;
  redirectUriMatch?: boolean;
  issuerMatch?: boolean;
  discoveryVisible: boolean;
  flowCorrelated: boolean;
  flowType: FlowType;
  tokenVisible: boolean;
  lateCapture: boolean;
  callbackError?: string;
  landingUrl?: string;
  errorClue?: string;
}

export interface TraceContextOidc {
  discovery?: NormalizedOidcEvent;
  authorize?: NormalizedOidcEvent;
  callback?: NormalizedOidcEvent;
  token?: NormalizedOidcEvent;
  jwks?: NormalizedOidcEvent;
  logout?: NormalizedOidcEvent;
  correlation: OidcCorrelation;
}

export interface TraceContext {
  kzeroHosts: string[];
  tenants: string[];
  oidc: TraceContextOidc;
  saml: {
    request?: NormalizedSamlEvent;
    response?: NormalizedSamlEvent;
  };
}

const isOidc = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === "OIDC";
const isSaml = (e: NormalizedEvent): e is NormalizedSamlEvent => e.protocol === "SAML";

export const computeOidcCorrelation = (
  oidc: Omit<TraceContextOidc, "correlation">
): OidcCorrelation => {
  const hasAuthorize = Boolean(oidc.authorize);
  const hasCallback = Boolean(oidc.callback);
  const hasDiscovery = Boolean(oidc.discovery);
  const hasToken = Boolean(oidc.token);
  const hasLogout = Boolean(oidc.logout);

  const stateRoundTrip = hasAuthorize && hasCallback &&
    Boolean(oidc.authorize?.state) && Boolean(oidc.callback?.state) &&
    oidc.authorize!.state === oidc.callback!.state;

  const pkcePresent = Boolean(hasAuthorize && oidc.authorize?.codeChallenge);
  const pkceMethod = oidc.authorize?.codeChallengeMethod;
  const pkceVerified = pkcePresent && Boolean(oidc.token?.codeVerifier);

  let redirectUriMatch: boolean | undefined;
  if (oidc.authorize?.redirectUri && hasCallback) {
    try {
      const callbackUrl = new URL(oidc.callback!.url);
      const redirectUrl = new URL(oidc.authorize!.redirectUri!);
      redirectUriMatch =
        callbackUrl.origin === redirectUrl.origin &&
        callbackUrl.pathname === redirectUrl.pathname;
    } catch {
      redirectUriMatch = false;
    }
  }

  let issuerMatch: boolean | undefined;
  const discoveryIssuer = oidc.discovery?.issuer;
  const tokenIssuer = hasToken && oidc.token?.idToken?.payload?.iss
    ? String(oidc.token.idToken.payload.iss)
    : undefined;
  if (discoveryIssuer && tokenIssuer) {
    issuerMatch = discoveryIssuer === tokenIssuer;
  }

  const flowType = oidc.authorize?.flowType ?? "unknown";

  const tokenVisible = hasToken && Boolean(oidc.token?.artifacts.responseBody);

  const lateCapture = !hasAuthorize && hasCallback;

  const flowCorrelated = (hasAuthorize && hasCallback) || lateCapture;

  const callbackError = hasCallback ? oidc.callback?.error : undefined;

  const errorClue = callbackError ??
    (hasToken ? oidc.token?.error : undefined) ??
    (hasLogout ? oidc.logout?.error : undefined);

  const discoveryVisible = hasDiscovery;

  const landingUrl = hasCallback ? oidc.callback?.artifacts.landingUrl as string | undefined : undefined;

  return {
    stateRoundTrip,
    pkcePresent,
    pkceMethod,
    pkceVerified,
    redirectUriMatch,
    issuerMatch,
    discoveryVisible,
    flowCorrelated,
    flowType,
    tokenVisible,
    lateCapture,
    callbackError,
    landingUrl,
    errorClue
  };
};

export const buildTraceContext = (session: CaptureSession | null): TraceContext => {
  const events = session?.normalizedEvents ?? [];
  const kzeroHosts = [...new Set(events.map((e) => e.host).filter((h) => h.endsWith("auth.kzero.com")))];
  const tenants = events
    .map((e) => e.url.match(/\/realms\/([^/]+)/i)?.[1])
    .filter((v): v is string => Boolean(v));

  const oidcEvents = events.filter(isOidc);
  const saml = events.filter(isSaml);

  const oidcEventsByKind = {
    discovery: oidcEvents.find((e) => e.kind === "discovery"),
    authorize: oidcEvents.find((e) => e.kind === "authorize"),
    callback: oidcEvents.find((e) => e.kind === "callback"),
    token: oidcEvents.find((e) => e.kind === "token"),
    jwks: oidcEvents.find((e) => e.kind === "jwks"),
    logout: oidcEvents.find((e) => e.kind === "logout")
  };

  const correlation = computeOidcCorrelation(oidcEventsByKind);

  return {
    kzeroHosts,
    tenants,
    oidc: {
      ...oidcEventsByKind,
      correlation
    },
    saml: {
      request: saml.find((e) => e.kind === "saml-request"),
      response: saml.find((e) => e.kind === "saml-response")
    }
  };
};
