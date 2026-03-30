import type { Finding, NormalizedEvent, NormalizedOidcEvent } from "../shared/models";
import { makeFinding } from "./helpers";

const isOidc = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === "OIDC";

export const runOidcRules = (events: NormalizedEvent[]): Finding[] => {
  const findings: Finding[] = [];
  const oidc = events.filter(isOidc);
  const discovery = oidc.find((e) => e.kind === "discovery");
  const authorize = oidc.find((e) => e.kind === "authorize");
  const callback = oidc.find((e) => e.kind === "callback");
  const token = oidc.find((e) => e.kind === "token");
  const jwks = oidc.find((e) => e.kind === "jwks");

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
        confidence: 0.9
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
          confidence: 0.92
        })
      );
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
        confidence: 0.98
      })
    );
  }

  if (authorize && callback && authorize.redirectUri) {
    const callbackUrl = new URL(callback.url);
    const observed = `${callbackUrl.origin}${callbackUrl.pathname}`;
    if (!observed.startsWith(authorize.redirectUri)) {
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
          confidence: 0.95
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

  const logout = oidc.find((e) => e.kind === "logout");
  if (logout) {
    const logoutParams = logout.artifacts.query as Record<string, string> | undefined;
    if ((logout.statusCode ?? 0) >= 400 || logoutParams?.error) {
      findings.push(
        makeFinding({
          ruleId: "OIDC_LOGOUT_REDIRECT_MISMATCH_CLUE",
          severity: "warning",
          protocol: "OIDC",
          likelyOwner: "vendor SP",
          title: "Logout redirect mismatch clue",
          explanation: "Logout request returned error, often from post logout redirect mismatch.",
          observed: `logout status ${logout.statusCode ?? "unknown"}`,
          expected: "Valid logout with accepted post logout redirect",
          evidence: [logout.url],
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

  return findings;
};
