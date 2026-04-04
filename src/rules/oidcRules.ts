import type { Finding, NormalizedEvent, NormalizedOidcEvent } from "../shared/models";
import { makeFinding } from "./helpers";
import { computeOidcCorrelation } from "../recipes/context";
import { detectLanding } from "../shared/landing";

const isOidc = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === "OIDC";

const hasStrongDownstreamActivity = (events: NormalizedOidcEvent[]): boolean => {
  return events.some((e) => e.kind === "token" || e.kind === "userinfo" || e.kind === "logout");
};

export const runOidcRules = (events: NormalizedEvent[]): Finding[] => {
  const findings: Finding[] = [];
  const oidc = events.filter(isOidc);
  const discovery = oidc.find((e) => e.kind === "discovery");
  const authorize = oidc.find((e) => e.kind === "authorize");
  const callback = oidc.find((e) => e.kind === "callback");
  const token = oidc.find((e) => e.kind === "token");
  const jwks = oidc.find((e) => e.kind === "jwks");
  const userinfo = oidc.find((e) => e.kind === "userinfo");
  const logoutEvent = oidc.find((e) => e.kind === "logout");

  const correlation = computeOidcCorrelation({
    discovery,
    authorize,
    callback,
    token,
    jwks,
    logout: logoutEvent
  });
  const landing = detectLanding(events);

  if (discovery && discovery.statusCode && discovery.statusCode >= 400) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_DISCOVERY_UNREACHABLE",
        severity: "error",
        protocol: "OIDC",
        likelyOwner: "network",
        title: "Discovery URL unreachable",
        explanation: "The OIDC discovery endpoint returned an error status.",
        observed: `Discovery status ${discovery.statusCode}`,
        expected: "HTTP 200 with valid OpenID metadata",
        evidence: [discovery.url],
        action: "Verify Discovery Endpoint, DNS/TLS reachability, and WAF rules.",
        confidence: 0.9,
        disqualifyingEvidence: ["Discovery endpoint returns HTTP 200"]
      })
    );
  }

  if (discovery?.issuer) {
    const expected = discovery.url.split("/.well-known/openid-configuration")[0];
    if (discovery.issuer !== expected) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_DISCOVERY_ISSUER_MISMATCH",
          severity: "error",
          protocol: "OIDC",
          likelyOwner: "KZero",
          title: "Discovery issuer mismatch",
          explanation: "The issuer in discovery does not match the tenant endpoint used for discovery.",
          observed: discovery.issuer,
          expected,
          evidence: [discovery.url],
          action: "Compare tenant casing and ensure Discovery Endpoint and Issuer values match exactly.",
          confidence: 0.92,
          disqualifyingEvidence: ["Issuer in discovery matches the tenant endpoint used"]
        })
      );
    }
  }

  if (discovery?.artifacts?.discoveryError) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_DISCOVERY_MALFORMED",
        severity: "error",
        protocol: "OIDC",
        likelyOwner: "user data",
        title: "Discovery document is malformed",
        explanation: "The discovery response could not be parsed as valid JSON.",
        observed: String(discovery.artifacts.discoveryError),
        expected: "Valid JSON in discovery response",
        evidence: [discovery.url],
        action: "Verify the discovery URL returns valid JSON. Check for proxy/gateway that may be returning error HTML instead of JSON, or that the URL is correct for your IdP.",
        confidence: 0.94,
        disqualifyingEvidence: ["Discovery document parses as valid JSON"]
      })
    );
  }

  if (discovery?.artifacts?.discovery) {
    const disc = discovery.artifacts.discovery as Record<string, unknown>;
    const issuerHost = typeof disc.issuer === "string" ? disc.issuer : null;
    const authEndpoint = typeof disc.authorization_endpoint === "string" ? disc.authorization_endpoint : null;
    const tokenEndpoint = typeof disc.token_endpoint === "string" ? disc.token_endpoint : null;
    const jwksUri = typeof disc.jwks_uri === "string" ? disc.jwks_uri : null;

    const isPrivateNetworkPattern = (host: string): boolean => {
      const h = host.toLowerCase();
      if (h === "localhost" || h === "127.0.0.1") return true;
      if (/^10\.\d+\.\d+\.\d+$/.test(h)) return true;
      if (/^192\.168\.\d+\.\d+$/.test(h)) return true;
      if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(h)) return true;
      if (h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".corp")) return true;
      if (!h.includes(".")) return true;
      return false;
    };

    const getHostFamily = (urlStr: string): string | null => {
      try {
        const url = new URL(urlStr);
        const host = url.hostname.toLowerCase();
        if (isPrivateNetworkPattern(host)) return "private";
        const parts = host.split(".");
        if (parts.length >= 2) {
          return parts.slice(-2).join(".");
        }
        return host;
      } catch {
        return null;
      }
    };

    const endpointHosts = [authEndpoint, tokenEndpoint, jwksUri].filter(Boolean) as string[];
    const hasPrivateEndpoint = endpointHosts.some((ep) => {
      try {
        return isPrivateNetworkPattern(new URL(ep).hostname);
      } catch {
        return false;
      }
    });

    if (hasPrivateEndpoint) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_DISCOVERY_PUBLIC_REACHABILITY_CLUE",
          severity: "warning",
          protocol: "OIDC",
          likelyOwner: "network",
          title: "Discovery endpoints may not be publicly reachable",
          explanation: "Discovery endpoints contain internal or localhost addresses.",
          observed: "Internal-looking endpoint URLs in discovery",
          expected: "Publicly accessible endpoint URLs",
          evidence: [discovery.url],
          action: "Verify IdP endpoints are publicly accessible. Internal-only endpoints will fail for cloud/SaaS vendors.",
          confidence: 0.58,
          isAmbiguous: true,
          ambiguityNote: "Internal-looking endpoints could be valid for VPN-based setups or private IdP deployments. Verify this matches your deployment model."
        })
      );
    } else if (issuerHost) {
      const issuerFamily = getHostFamily(issuerHost);
      let suspiciousHostFound = false;

      for (const endpoint of endpointHosts) {
        const endpointFamily = getHostFamily(endpoint);
        if (endpointFamily && endpointFamily !== "private" && issuerFamily && endpointFamily !== issuerFamily) {
          suspiciousHostFound = true;
          break;
        }
      }

      if (suspiciousHostFound) {
        findings.push(
          makeFinding({
            ruleId: "OIDC_DISCOVERY_ENDPOINT_HOST_SUSPICIOUS",
            severity: "warning",
            protocol: "OIDC",
            likelyOwner: "user data",
            title: "Discovery endpoint host differs from issuer",
            explanation: "The authorization_endpoint, token_endpoint, or jwks_uri host does not match the issuer host family.",
            observed: "Endpoint hosts differ across incompatible families",
            expected: "Consistent host family across issuer and endpoints",
            evidence: [discovery.url],
            action: "Verify all endpoint URLs use the expected host family. Mismatched hosts may indicate copied values from another environment or cross-environment configuration.",
            confidence: 0.72,
            isAmbiguous: true,
            ambiguityNote: "Endpoint host differences could indicate multi-tenant setup, CDN, reverse proxy, or actual misconfiguration. Check if this is expected for your IdP.",
            disqualifyingEvidence: ["All endpoints use consistent host family matching issuer"]
          })
        );
      }
    }
  }

  if (authorize && (!authorize.scope || !authorize.scope.includes("openid"))) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_MISSING_OPENID_SCOPE",
        severity: "error",
        protocol: "OIDC",
        likelyOwner: "vendor SP",
        title: "Missing required openid scope",
        explanation: "OIDC authorization requests must include the openid scope.",
        observed: authorize.scope ?? "(missing)",
        expected: "scope contains openid",
        evidence: [authorize.url],
        action: "Update vendor scope list to include openid and keep profile/email as needed.",
        confidence: 0.98,
        disqualifyingEvidence: ["Authorization request includes 'openid' scope"]
      })
    );
  }

  if (authorize && callback && authorize.redirectUri) {
    const normalizeRedirect = (url: string): string => {
      try {
        const u = new URL(url);
        return `${u.origin}${u.pathname.replace(/\/$/, "")}`;
      } catch {
        return url;
      }
    };
    const callbackUrl = new URL(callback.url);
    const observed = normalizeRedirect(`${callbackUrl.origin}${callbackUrl.pathname}`);
    const expected = normalizeRedirect(authorize.redirectUri);
    if (observed !== expected) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_REDIRECT_URI_MISMATCH",
          severity: "error",
          protocol: "OIDC",
          likelyOwner: "vendor SP",
          title: "Redirect URI mismatch",
          explanation: "The callback URL reached by the browser does not match the requested redirect_uri.",
          observed,
          expected: authorize.redirectUri,
          evidence: [authorize.url, callback.url],
          action: "Align redirect URI values exactly on both sides (scheme, host, path, trailing slash).",
          confidence: 0.95,
          disqualifyingEvidence: ["Callback URL matches redirect_uri exactly"]
        })
      );
    }
  }

  const errSource = callback?.error ? callback : token?.error ? token : undefined;
  if (errSource?.error) {
    const map = {
      invalid_client: "OIDC_INVALID_CLIENT",
      invalid_scope: "OIDC_INVALID_SCOPE",
      unauthorized_client: "OIDC_UNAUTHORIZED_CLIENT",
      unsupported_response_type: "OIDC_UNSUPPORTED_RESPONSE_TYPE",
      unsupported_response_mode: "OIDC_UNSUPPORTED_RESPONSE_MODE"
    } as const;
    const rule = map[errSource.error as keyof typeof map] ?? "OIDC_CALLBACK_ERROR";
    findings.push(
      makeFinding({
        ruleId: rule,
        severity: "error",
        protocol: "OIDC",
        likelyOwner: "vendor SP",
        title: `OIDC error: ${errSource.error}`,
        explanation: "The authorization or token flow returned an explicit OIDC error.",
        observed: `${errSource.error}${errSource.errorDescription ? ` (${errSource.errorDescription})` : ""}`,
        expected: "No OAuth/OIDC error parameter",
        evidence: [errSource.url],
        action: "Use the exact error to align client credentials, scopes, and supported response settings.",
        confidence: 0.97
      })
    );
  }

  if (authorize && callback) {
    if (!authorize.state || !callback.state || authorize.state !== callback.state) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_STATE_MISSING_OR_MISMATCH",
          severity: "error",
          protocol: "OIDC",
          likelyOwner: "browser",
          title: "State missing or mismatch",
          explanation: "State protects against CSRF and must match between authorize request and callback.",
          observed: `authorize=${authorize.state ?? "(missing)"}, callback=${callback.state ?? "(missing)"}`,
          expected: "Matching non-empty state values",
          evidence: [authorize.url, callback.url],
          action: "Ensure vendor preserves state through redirects and no browser plugin strips query/fragment values.",
          confidence: 0.91
        })
      );
    }

    if (authorize.responseType?.includes("id_token") && !authorize.nonce) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_NONCE_MISSING",
          severity: "warning",
          protocol: "OIDC",
          likelyOwner: "vendor SP",
          title: "Nonce missing for ID token response",
          explanation: "Nonce should be present when id_token is returned from the authorization endpoint.",
          observed: "nonce missing",
          expected: "nonce present",
          evidence: [authorize.url],
          action: "Enable nonce generation/validation in vendor OIDC client settings.",
          confidence: 0.85
        })
      );
    }
  }

  if (authorize?.codeChallenge && token && !token.codeVerifier) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_PKCE_INCONSISTENT",
        severity: "error",
        protocol: "OIDC",
        likelyOwner: "vendor SP",
        title: "PKCE code_verifier missing",
        explanation: "Authorization used a code_challenge but token exchange did not include code_verifier.",
        observed: "code_verifier missing at token endpoint",
        expected: "code_verifier present",
        evidence: [authorize.url, token.url],
        action: "Verify Use PKCE and vendor token exchange logic are both enabled and consistent.",
        confidence: 0.93
      })
    );
  }

  if (jwks && jwks.statusCode && jwks.statusCode >= 400) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_JWKS_FETCH_FAILURE",
        severity: "error",
        protocol: "OIDC",
        likelyOwner: "network",
        title: "JWKS fetch failure",
        explanation: "Public key retrieval failed, so token signature validation may fail.",
        observed: `JWKS status ${jwks.statusCode}`,
        expected: "HTTP 200 with valid JWKS JSON",
        evidence: [jwks.url],
        action: "Check WAF/TLS/public access for JWKS endpoint and compare discovery jwks_uri.",
        confidence: 0.89
      })
    );

    if ([401, 403, 408, 429, 502, 503, 504].includes(jwks.statusCode)) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_REACHABILITY_WAF_TLS_SUSPECTED",
          severity: "warning",
          protocol: "OIDC",
          likelyOwner: "network",
          title: "Public reachability / WAF / TLS suspicion",
          explanation: "JWKS failure pattern matches common gateway/WAF/reachability blocking.",
          observed: `JWKS status ${jwks.statusCode}`,
          expected: "Publicly reachable JWKS over TLS",
          evidence: [jwks.url],
          action: "Validate DNS, TLS chain, and WAF allow rules for vendor to reach KZero endpoints.",
          confidence: 0.83
        })
      );
    }
  }

  if (token?.idToken?.payload?.iss && discovery?.issuer && token.idToken.payload.iss !== discovery.issuer) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_TOKEN_ISSUER_MISMATCH",
        severity: "error",
        protocol: "OIDC",
        likelyOwner: "KZero",
        title: "Token issuer mismatch",
        explanation: "ID token issuer does not match discovery issuer.",
        observed: String(token.idToken.payload.iss),
        expected: discovery.issuer,
        evidence: [token.url, discovery.url],
        action: "Validate tenant URLs and ensure app is not mixing environments.",
        confidence: 0.96
      })
    );
  }

  if (callback?.code && (!token || (token.statusCode ?? 0) >= 400 || token.error)) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_CALLBACK_TOKEN_EXCHANGE_BROKEN",
        severity: "warning",
        protocol: "OIDC",
        likelyOwner: "vendor SP",
        title: "Callback reached but token exchange appears broken",
        explanation: "Authorization returned a code, but token exchange is missing or failed.",
        observed: token ? `token status ${token.statusCode ?? "unknown"}` : "no token call captured",
        expected: "Successful token endpoint response",
        evidence: [callback.url, token?.url ?? "(missing token request)"],
        action: "Verify Token URL, client auth method, and backend outbound connectivity.",
        confidence: 0.86
      })
    );
  }

  if (token?.tokenEndpointAuthMethod) {
    const body = token.artifacts.body as Record<string, string> | undefined;
    const headers = token.artifacts.requestHeaders as Record<string, string> | undefined;
    const hasAuthHeader = Boolean(headers?.authorization);
    const hasClientSecretInBody = Boolean(body?.client_secret);
    if (
      (token.tokenEndpointAuthMethod === "client_secret_basic" && hasClientSecretInBody) ||
      (token.tokenEndpointAuthMethod === "client_secret_post" && hasAuthHeader)
    ) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_TOKEN_AUTH_METHOD_MISMATCH_CLUE",
          severity: "warning",
          protocol: "OIDC",
          likelyOwner: "vendor SP",
          title: "Token auth method mismatch clue",
          explanation: "Observed token request style does not align with declared auth method clues.",
          observed: `${token.tokenEndpointAuthMethod} with request pattern mismatch`,
          expected: "Token request uses matching client authentication style",
          evidence: [token.url],
          action: "Compare Client authentication setting with vendor token auth method implementation.",
          confidence: 0.7
        })
      );
    }
  }

  if (logoutEvent) {
    const logoutParams = logoutEvent.artifacts.query as Record<string, string> | undefined;
    if ((logoutEvent.statusCode ?? 0) >= 400 || logoutParams?.error) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_LOGOUT_REDIRECT_MISMATCH_CLUE",
          severity: "warning",
          protocol: "OIDC",
          likelyOwner: "vendor SP",
          title: "Logout redirect mismatch clue",
          explanation: "Logout request returned error, often from post logout redirect mismatch.",
          observed: `logout status ${logoutEvent.statusCode ?? "unknown"}`,
          expected: "Valid logout with accepted post logout redirect",
          evidence: [logoutEvent.url],
          action: "Verify Logout URL and registered post logout redirect URI values.",
          confidence: 0.69
        })
      );
    }
  }

  if (token?.accessTokenOpaque) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_ACCESS_TOKEN_OPAQUE",
        severity: "info",
        protocol: "OIDC",
        likelyOwner: "unknown",
        title: "Access token is opaque",
        explanation: "Opaque access tokens are normal for some integrations.",
        observed: "token is not JWT",
        expected: "JWT or opaque depending on vendor design",
        evidence: [token.url],
        action: "Treat as informational unless vendor incorrectly expects JWT access tokens.",
        confidence: 0.8
      })
    );
  }

  if (!authorize && callback) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_LATE_CAPTURE_CLUE",
        severity: "info",
        protocol: "OIDC",
        likelyOwner: "unknown",
        title: "Capture started after authorization request",
        explanation: "Callback was captured but no authorize request is present in this trace.",
        observed: "Callback captured but authorize missing",
        expected: "Full flow with authorize and callback",
        action: "If this should be a complete trace, start capture before clicking login.",
        evidence: callback ? [callback.url] : [],
        confidence: 0.6,
        isAmbiguous: true,
        ambiguityNote: "This is informational - the flow may have succeeded, but capture started after the authorize was sent. This usually means capture started late, the initial authorize happened outside the captured tab/window, or the authorize request was not retained.",
        traceGaps: ["Authorize request not captured"],
        disqualifyingEvidence: ["Authorize request captured", "Full flow observed"]
      })
    );
  }

  if (!authorize && !callback && hasStrongDownstreamActivity(oidc)) {
    const downstreamEvent = token ?? userinfo ?? logoutEvent;
    findings.push(
      makeFinding({
        ruleId: "OIDC_MISSING_AUTHORIZE_REQUEST_CLUE",
        severity: "info",
        protocol: "OIDC",
        likelyOwner: "unknown",
        title: "Authorization request not captured but downstream activity present",
        explanation: "Token, userinfo, or logout activity was captured without the authorize request.",
        observed: "Callback or token activity was captured, but the authorize request was not present in this trace.",
        expected: "Authorize request present in trace",
        action: "This usually means capture started late, the initial authorize happened outside the captured tab/window, or the authorize request was not retained. If SP-initiated flow is expected, start capture before initiating login.",
        evidence: downstreamEvent ? [downstreamEvent.url] : [],
        confidence: 0.58,
        isAmbiguous: true,
        ambiguityNote: "This usually means capture started late, the initial authorize happened outside the captured tab/window, or the authorize request was not retained.",
        traceGaps: ["Authorize request not captured"],
        disqualifyingEvidence: ["Authorize request captured"]
      })
    );
  }

  if (authorize && !callback && !correlation.lateCapture) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_MISSING_CALLBACK",
        severity: "warning",
        protocol: "OIDC",
        likelyOwner: "vendor SP",
        title: "No callback captured after authorization request",
        explanation: "Authorize request was captured but no callback was detected.",
        observed: "Authorize sent but no callback captured",
        expected: "OIDC callback with code or error",
        action: "Verify the app received a callback to the configured redirect URI, including form_post if that response_mode is in use. Check for browser extension/CSP blocking or vendor redirect handler issues.",
        evidence: [authorize.url],
        confidence: 0.68,
        traceGaps: ["OIDC callback not captured"],
        disqualifyingEvidence: ["Callback captured", "Callback error present"]
      })
    );
  }

  if (authorize && authorize.responseType?.includes("code") && !authorize.codeChallenge) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_PKCE_MISSING_WHEN_CODE_FLOW",
        severity: "warning",
        protocol: "OIDC",
        likelyOwner: "vendor SP",
        title: "PKCE not used in Authorization Code flow",
        explanation: "response_type=code was used but no code_challenge was present in the authorize request.",
        observed: "response_type=code but no code_challenge present",
        expected: "PKCE code_challenge for Authorization Code flow",
        action: "Enable PKCE (Use PKCE) in vendor OIDC client - recommended for all Authorization Code flows for security.",
        evidence: [authorize.url],
        confidence: 0.74,
        disqualifyingEvidence: ["code_challenge present in authorize request"]
      })
    );
  }

  if (authorize?.codeChallengeMethod && authorize.codeChallengeMethod !== "S256") {
    findings.push(
      makeFinding({
        ruleId: "OIDC_PKCE_METHOD_WEAK_OR_UNEXPECTED",
        severity: "warning",
        protocol: "OIDC",
        likelyOwner: "vendor SP",
        title: "Weak or unexpected PKCE method",
        explanation: "PKCE code_challenge_method is not the recommended S256.",
        observed: `code_challenge_method=${authorize.codeChallengeMethod}`,
        expected: "code_challenge_method=S256",
        action: "Set code_challenge_method to S256 in vendor OIDC client. Plain method is considered weak and not recommended.",
        evidence: [authorize.url],
        confidence: 0.84,
        disqualifyingEvidence: ["code_challenge_method=S256"]
      })
    );
  }

  if (discovery) {
    const requiredFields = ["issuer", "authorization_endpoint", "token_endpoint"];
    const missingFields = requiredFields.filter((f) => {
      const artifacts = discovery.artifacts as Record<string, unknown>;
      return !artifacts[f];
    });
    if (missingFields.length > 0) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_DISCOVERY_ENDPOINT_INCONSISTENT",
          severity: "error",
          protocol: "OIDC",
          likelyOwner: "user data",
          title: "Discovery document missing required fields",
          explanation: "Discovery document is missing required OpenID Connect metadata fields.",
          observed: `Missing fields: ${missingFields.join(", ")}`,
          expected: "All required fields present in discovery document",
          action: "Verify discovery document structure - may indicate stale copied values, wrong discovery URL, or malformed IdP metadata. Check all required fields are present and properly formatted.",
          evidence: [discovery.url],
          confidence: 0.86,
          disqualifyingEvidence: ["Discovery document validates and passes structural checks"]
        })
      );
    }
  }

  if (userinfo && (userinfo.statusCode ?? 0) >= 400) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_USERINFO_FAILED",
        severity: "warning",
        protocol: "OIDC",
        likelyOwner: "vendor SP",
        title: "UserInfo endpoint request failed",
        explanation: "The UserInfo endpoint returned an error status.",
        observed: `userinfo status ${userinfo.statusCode}`,
        expected: "HTTP 200 with user claims",
        action: "Check UserInfo endpoint accessibility, token validity, and vendor UserInfo URL configuration.",
        evidence: [userinfo.url],
        confidence: 0.76,
        disqualifyingEvidence: ["UserInfo returns HTTP 200"]
      })
    );
  }

  if (authorize && !callback) {
    const recentAuthorizes = oidc.filter((e) => e.kind === "authorize");
    if (recentAuthorizes.length > 2) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_BROWSER_STORAGE_OR_COOKIE_BLOCKING_CLUE",
          severity: "warning",
          protocol: "OIDC",
          likelyOwner: "browser",
          title: "Multiple authorize requests without callback - possible cookie/storage blocking",
          explanation: "Multiple authorization requests were captured without any callback, which may indicate the browser is blocking cookies or storage.",
          observed: `${recentAuthorizes.length} authorize requests without callback`,
          expected: "Single authorize → callback flow",
          action: "Check browser for blocked cookies or storage - common with incognito mode or privacy extensions.",
          evidence: recentAuthorizes.map((e) => e.url),
          confidence: 0.52,
          isAmbiguous: true,
          ambiguityNote: "Pattern suggests cookie/storage blocking, but could also be vendor redirect loop. Verify in browser devtools.",
          traceGaps: ["Callback event captured"],
          disqualifyingEvidence: ["Callback captured after authorize", "Single authorize → callback flow observed"]
        })
      );
    }
  }

  if (callback?.code && !landing.detected) {
    findings.push(
      makeFinding({
        ruleId: "OIDC_CALLBACK_SEEN_BUT_NO_APP_LANDING_CLUE",
        severity: "warning",
        protocol: "OIDC",
        likelyOwner: "vendor SP",
        title: "Callback succeeded but no app landing detected",
        explanation: "OIDC callback with authorization code was captured, but no app landing was detected within the capture window.",
        observed: "Callback succeeded but no app landing detected within capture window",
        expected: "App landing after successful callback",
        action: "Check if vendor callback handler properly redirects to app landing page. Verify redirect URI points to correct app URL.",
        evidence: [callback.url],
        confidence: 0.64,
        isAmbiguous: true,
        ambiguityNote: "Landing may have happened but was filtered as noise, occurred outside capture window, or SPA routing finished without full navigation event. This is a clue, not a definitive failure.",
        traceGaps: ["App landing event captured"],
        disqualifyingEvidence: ["Landing event captured", "Successful flow with landing observed"]
      })
    );
  }

  return findings;
};
