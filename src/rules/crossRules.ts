import type { Finding, NormalizedEvent } from "../shared/models";
import { makeFinding } from "./helpers";

const extractTenants = (events: NormalizedEvent[]): string[] => {
  const tenants: string[] = [];
  for (const event of events) {
    const match = event.url.match(/\/realms\/([^/]+)/i);
    if (match) tenants.push(match[1]);
  }
  return tenants;
};

export const runCrossRules = (events: NormalizedEvent[]): Finding[] => {
  const findings: Finding[] = [];
  const tenants = extractTenants(events);

  if (tenants.length > 1) {
    const lower = new Set(tenants.map((r) => r.toLowerCase()));
    if (lower.size < tenants.length) {
      findings.push(
        makeFinding({
          ruleId: "REALM_CASE_MISMATCH",
          severity: "error",
          protocol: "unknown",
          likelyOwner: "KZero",
          title: "Tenant name casing mismatch",
          explanation: "Tenant names are case-sensitive; mixed casing was observed in the same trace.",
          observed: tenants.join(", "),
          expected: "Single tenant name with exact consistent casing",
          evidence: tenants,
          action: "Normalize tenant casing across Discovery Endpoint, Issuer, and SAML/OIDC endpoints.",
          confidence: 0.94
        })
      );
    }
  }

  const nonKzeroHosts = events.filter(
    (e) => e.protocol !== "unknown" && e.host && !e.host.endsWith("auth.kzero.com") && !e.host.includes("localhost")
  );
  if (nonKzeroHosts.length > 0) {
    findings.push(
      makeFinding({
        ruleId: "WRONG_HOST_OR_ENVIRONMENT",
        severity: "warning",
        protocol: "unknown",
        likelyOwner: "unknown",
        title: "Potential wrong host or environment mix",
        explanation: "Trace includes auth endpoints outside expected KZero host family.",
        observed: nonKzeroHosts.map((e) => e.host).join(", "),
        expected: "Consistent endpoint family per environment",
        evidence: nonKzeroHosts.slice(0, 3).map((e) => e.url),
        action: "Check for copied values from another environment and confirm tenant endpoint family.",
        confidence: 0.74
      })
    );
  }

  const legacyFamily = events.find((e) => e.url.includes("/auth/realms/"));
  if (legacyFamily) {
    findings.push(
      makeFinding({
        ruleId: "WRONG_REALM_ENDPOINT_FAMILY",
        severity: "warning",
        protocol: "unknown",
        likelyOwner: "KZero",
        title: "Unexpected endpoint path family",
        explanation: "Legacy /auth/realms path detected; this often indicates stale docs or copied config.",
        observed: legacyFamily.url,
        expected: "https://<host>/realms/<tenant>/...",
        evidence: [legacyFamily.url],
        action: "Replace legacy endpoint values with current KZero URL patterns.",
        confidence: 0.88
      })
    );
  }

  const parseFailures = events.filter(
    (e) => String(e.artifacts.errorText ?? "").length > 0 || String(e.artifacts.discoveryError ?? "").length > 0
  );
  if (parseFailures.length > 0) {
    findings.push(
      makeFinding({
        ruleId: "METADATA_COPY_PASTE_TRUNCATION",
        severity: "info",
        protocol: "unknown",
        likelyOwner: "user data",
        title: "Potential copy/paste truncation",
        explanation: "Malformed metadata or payload parse errors can indicate copied values were truncated.",
        observed: parseFailures.map((e) => e.url).join(", "),
        expected: "Full metadata/payload values",
        evidence: parseFailures.slice(0, 3).map((e) => e.id),
        action: "Re-copy metadata URLs/XML from source and avoid manual edits in the middle of long values.",
        confidence: 0.61
      })
    );
  }

  const samlPostedButRejected = events.find(
    (e) => e.protocol === "SAML" && e.kind === "saml-response" && (e.statusCode ?? 0) >= 400
  );
  if (samlPostedButRejected) {
    findings.push(
      makeFinding({
        ruleId: "VENDOR_VALIDATION_REJECTING_METADATA_CLUE",
        severity: "warning",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Vendor validation likely rejecting metadata",
        explanation: "SAML response reached SP endpoint but was rejected by validation checks.",
        observed: `ACS status ${(samlPostedButRejected.statusCode ?? 0).toString()}`,
        expected: "SP accepts metadata/assertion values",
        evidence: [samlPostedButRejected.url],
        action: "Review vendor strict validation requirements and compare against KZero metadata fields.",
        confidence: 0.65
      })
    );
  }

  const callbackErrorNoToken =
    events.some((e) => e.protocol === "OIDC" && e.kind === "callback" && String((e as any).error ?? "").length > 0) &&
    !events.some((e) => e.protocol === "OIDC" && e.kind === "token");
  if (callbackErrorNoToken) {
    findings.push(
      makeFinding({
        ruleId: "CLIENT_SIDE_VS_BACKEND_VALIDATION_DISTINCTION",
        severity: "info",
        protocol: "OIDC",
        likelyOwner: "browser",
        title: "Likely client-side validation before backend token exchange",
        explanation: "Callback error appears in browser and no token request was attempted.",
        observed: "callback includes error and token request missing",
        expected: "backend token exchange attempted when callback has authorization code",
        evidence: ["OIDC callback event present", "OIDC token event missing"],
        action: "Check browser/client redirect handler logic before backend token exchange path.",
        confidence: 0.62
      })
    );
  }

  const networkErrors = events.filter((e) => e.protocol === "network");
  if (networkErrors.length > 0) {
    findings.push(
      makeFinding({
        ruleId: "NETWORK_TLS_REACHABILITY_SUSPECTED",
        severity: "warning",
        protocol: "network",
        likelyOwner: "network",
        title: "Network/TLS/public accessibility suspicion",
        explanation: "Request-level network errors were captured during auth flow.",
        observed: networkErrors.map((e) => String(e.artifacts.errorText ?? "network error")).join(", "),
        expected: "No network-level failures on auth endpoints",
        evidence: networkErrors.slice(0, 3).map((e) => e.url),
        action: "Verify firewall, WAF, DNS, and TLS chain from browser and vendor backend paths.",
        confidence: 0.86
      })
    );
  }

  const mixedRealmHosts = new Set(events.map((e) => e.host)).size > 3;
  if (mixedRealmHosts) {
    findings.push(
      makeFinding({
        ruleId: "STALE_VALUES_FROM_ANOTHER_ENVIRONMENT",
        severity: "info",
        protocol: "unknown",
        likelyOwner: "user data",
        title: "Suspected stale copied values from another environment",
        explanation: "Auth flow touches many unrelated hosts, which often indicates copied endpoint values.",
        observed: `${new Set(events.map((e) => e.host)).size} hosts in one auth trace`,
        expected: "Small, consistent host set for one tenant integration",
        evidence: events.slice(0, 5).map((e) => e.url),
        action: "Re-validate all endpoint URLs against the current environment and tenant.",
        confidence: 0.57
      })
    );
  }

  return findings;
};
