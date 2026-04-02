import type { CaptureSession, SummaryExportBundle, ExportMetadata, NormalizedEvent, NormalizedOidcEvent } from "../shared/models";
import { filterEventsByMode, detectAuthBoundary, getAuthHosts, isNoiseEvent } from "./filtering";

const isOidc = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === "OIDC";

const extractOidcSummary = (events: NormalizedEvent[]): SummaryExportBundle["oidcSummary"] => {
  const oidc = events.filter(isOidc);
  const authorize = oidc.find((e) => e.kind === "authorize");
  const callback = oidc.find((e) => e.kind === "callback");
  const token = oidc.find((e) => e.kind === "token");
  const discovery = oidc.find((e) => e.kind === "discovery");

  const boundary = detectAuthBoundary(events);

  if (!authorize && !callback && !discovery) return undefined;

  const extractRedirectUriHostPath = (uri: string | undefined): string | undefined => {
    if (!uri) return undefined;
    try {
      const url = new URL(uri);
      return url.origin + url.pathname;
    } catch {
      return undefined;
    }
  };

  const redirectUri = authorize?.redirectUri;
  const computedRedirectUri = typeof redirectUri === "string" ? extractRedirectUriHostPath(redirectUri) : undefined;

  const stateRoundTrip = authorize?.state && callback?.state 
    ? authorize.state === callback.state 
    : undefined;

  return {
    protocol: "OIDC",
    authorizeHost: authorize?.host,
    callbackHost: callback?.host,
    redirectUri: computedRedirectUri,
    issuer: discovery?.issuer,
    statePresent: !!authorize?.state,
    stateRoundTrip,
    noncePresent: !!authorize?.nonce,
    pkcePresent: !!authorize?.codeChallenge,
    pkceMethod: authorize?.codeChallengeMethod,
    callbackHasCode: !!callback?.code,
    callbackHasError: !!callback?.error,
    callbackError: callback?.error,
    tokenExchangeVisible: !!token,
    tokenResponseBodyVisible: !!(token?.artifacts?.responseBody),
    authBoundaryDetected: boundary.detected,
    landingHost: boundary.landingEvent?.host
  };
};

export const buildSummaryExport = (session: CaptureSession | null): SummaryExportBundle | null => {
  if (!session) return null;

  const boundary = detectAuthBoundary(session.normalizedEvents);
  const filteredEvents = filterEventsByMode(session.normalizedEvents, {
    mode: "summary",
    includePostLoginActivity: false
  });

  const originalNoiseCount = session.normalizedEvents.filter(isNoiseEvent).length;
  const filteredNoiseCount = filteredEvents.filter(isNoiseEvent).length;
  const postLoginTrimmed = originalNoiseCount > filteredNoiseCount;

  const authHosts = getAuthHosts(session.normalizedEvents);
  const duration = session.stoppedAt && session.startedAt
    ? session.stoppedAt - session.startedAt
    : undefined;

  const metadata: ExportMetadata = {
    mode: "summary",
    generatedAt: new Date().toISOString(),
    includePostLoginActivity: false,
    authBoundaryDetected: boundary.detected,
    redactionsApplied: []
  };

  const oidcSummary = extractOidcSummary(session.normalizedEvents);

  return {
    generatedAt: metadata.generatedAt,
    product: "KZero Passwordless SSO Tracer",
    tabId: session.tabId,
    metadata,
    summary: {
      eventCount: session.normalizedEvents.length,
      findingCount: session.findings.length,
      problemCount: session.findings.filter((f) => f.severity === "error").length,
      warningCount: session.findings.filter((f) => f.severity === "warning").length,
      infoCount: session.findings.filter((f) => f.severity === "info").length,
      duration
    },
    authHosts,
    oidcSummary,
    findings: session.findings.map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      severity: f.severity,
      title: f.title
    })),
    postLoginTrimmed
  };
};