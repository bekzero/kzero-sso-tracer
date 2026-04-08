import type { Finding, NormalizedEvent, NormalizedSamlEvent } from "../shared/models";
import { makeFinding } from "./helpers";
import { inferSamlDirection } from "../analysis/flowClassifier";

const isSaml = (e: NormalizedEvent): e is NormalizedSamlEvent => e.protocol === "SAML";

const isKzeroHost = (host?: string): boolean => {
  if (!host) return false;
  const h = host.toLowerCase();
  return h.endsWith("auth.kzero.com") || h.includes(".auth.kzero.com") || h.includes("keycloak");
};

const isKzeroSamlEndpoint = (event: NormalizedEvent): boolean => {
  if (!isKzeroHost(event.host)) return false;
  const url = event.url.toLowerCase();
  return url.includes("/protocol/saml") || url.includes("saml");
};

const KNOWN_STATIC_HOSTS = [
  "zohocdn.com", "static.zohocdn.com",
  "google-analytics.com", "googletagmanager.com",
  "segment.io", "segment.com",
  "hotjar.com", "intercom.io", "zendesk.com"
];

const isKnownStaticHost = (host: string): boolean => {
  const h = host.toLowerCase();
  return KNOWN_STATIC_HOSTS.some((s) => h === s || h.endsWith("." + s));
};

const normalizeUrl = (urlStr: string): string => {
  try {
    const url = new URL(urlStr);
    const normalized = new URL(url.origin);
    normalized.pathname = (url.pathname.replace(/\/+$/, "") || "/").toLowerCase();
    const sortedParams = [...new URLSearchParams(url.search)].sort((a, b) => a[0].localeCompare(b[0]));
    normalized.search = sortedParams.map(([k, v]) => `${k}=${v}`).join("&");
    return normalized.toString().replace(/\/+$/, "");
  } catch {
    return urlStr;
  }
};

const urlsMatch = (url1: string, url2: string): "exact" | "path" | "host" | "none" => {
  const n1 = normalizeUrl(url1);
  const n2 = normalizeUrl(url2);
  if (n1 === n2) return "exact";
  try {
    const u1 = new URL(url1);
    const u2 = new URL(url2);
    if (u1.host.toLowerCase() !== u2.host.toLowerCase()) return "none";
    const p1 = u1.pathname.replace(/\/+$/, "");
    const p2 = u2.pathname.replace(/\/+$/, "");
    if (p1 === p2) return "path";
    if (p1.startsWith(p2 + "/")) return "path";
    if (p2.startsWith(p1 + "/")) return "path";
    return "host";
  } catch {
    return "none";
  }
};

const isLikelyDocumentLanding = (event: NormalizedSamlEvent): boolean => {
  try {
    const url = new URL(event.url);
    const pathname = url.pathname;
    if (/\.(css|js|png|svg|woff|ico|jpg|jpeg|gif|webp|json)(\?|$)/i.test(pathname)) return false;
    if (pathname.includes("/ws/") || pathname.includes("/chat/") || pathname.includes("/status")) return false;
    if (url.hostname.includes("statuspage") || url.hostname.includes("wss.")) return false;
    if (isKnownStaticHost(url.hostname)) return false;
    if (pathname === "/" || pathname === "" || pathname === "/home" || pathname === "/app" || pathname === "/dashboard") return true;
    if (pathname.endsWith(".html") || pathname.endsWith(".htm")) return true;
    return false;
  } catch {
    return false;
  }
};

const detectSamlFlow = (
  events: NormalizedEvent[],
  responseEvent: NormalizedSamlEvent
): { success: "clear" | "probable" | "none"; captureCompleteness: "complete" | "late" | "unknown" } => {
  if ((responseEvent.statusCode ?? 0) >= 400) {
    return { success: "none", captureCompleteness: "unknown" };
  }

  const _samlEvents = events.filter(isSaml);
  const relayState = responseEvent.relayState;
  let relayStateUrl: URL | undefined;
  if (relayState) {
    try {
      relayStateUrl = new URL(relayState);
    } catch {
      // not a valid URL
    }
  }

  const windowStart = responseEvent.timestamp;
  const windowEnd = responseEvent.timestamp + 30000;

  // Look for any GET requests in the time window (not just SAML events)
  const postAcsRequests = events.filter(
    (e) =>
      e.timestamp >= windowStart &&
      e.timestamp <= windowEnd &&
      e.method === "GET" &&
      (!e.statusCode || e.statusCode < 400 || (e.statusCode >= 300 && e.statusCode < 400))
  ).filter((e): e is NormalizedSamlEvent => isLikelyDocumentLanding(e as NormalizedSamlEvent));

  let matchLevel: "exact" | "path" | "host" | "none" = "none";
  if (relayStateUrl) {
    for (const req of postAcsRequests) {
      const m = urlsMatch(req.url, relayStateUrl!.href);
      if (m === "exact" || m === "path") {
        matchLevel = m;
        break;
      }
      if (matchLevel === "none" && m === "host") {
        matchLevel = "host";
      }
    }
  }

  if (matchLevel === "exact" || matchLevel === "path") {
    return { success: "clear", captureCompleteness: "late" };
  }
  if (matchLevel === "host" || postAcsRequests.length > 0) {
    return { success: "probable", captureCompleteness: "late" };
  }
  return { success: "none", captureCompleteness: "unknown" };
};

export const runSamlRules = (events: NormalizedEvent[]): Finding[] => {
  const findings: Finding[] = [];
  const samlEvents = events.filter(isSaml);
  const requestEvent = samlEvents.find((e) => e.samlRequest);
  const responseEvent = samlEvents.find((e) => e.samlResponse);
  const kzeroSamlEndpoint4xx =
    requestEvent && !responseEvent
      ? events.find(
          (e) =>
            isKzeroSamlEndpoint(e) &&
            (e.statusCode ?? 0) >= 400 &&
            e.timestamp >= requestEvent.timestamp - 5000 &&
            e.timestamp <= requestEvent.timestamp + 45000
        )
      : undefined;

  if (requestEvent && !responseEvent && kzeroSamlEndpoint4xx) {
    const acs = requestEvent.samlRequest?.destination ?? requestEvent.samlRequest?.recipient ?? "(not captured)";
    findings.push(
      makeFinding({
        ruleId: "SAML_AUTHNREQUEST_REJECTED_BY_KZERO",
        severity: "error",
        protocol: "SAML",
        likelyOwner: "KZero",
        title: "KZero rejected the sign-in request before sending a SAML response",
        explanation:
          "The service provider sent an AuthnRequest, but KZero returned an error before login completed and before any SAMLResponse was produced.",
        observed: `KZero SAML endpoint returned HTTP ${kzeroSamlEndpoint4xx.statusCode ?? "unknown"}`,
        expected: "KZero accepts the AuthnRequest and proceeds to login/SAMLResponse",
        evidence: [requestEvent.url, kzeroSamlEndpoint4xx.url],
        action:
          `Open the KZero integration and compare these values: (1) Requested ACS URL from the trace: ${acs}, (2) KZero Valid Redirect URIs, (3) KZero Assertion Consumer Service POST Binding URL. They must match exactly. Check for wrong hostname, wrong tenant, wrong environment, extra slash, or outdated copied URL.`,
        confidence: 0.98,
        disqualifyingEvidence: ["SAMLResponse captured after AuthnRequest", "KZero endpoint returns HTTP 200"]
      })
    );
  }

  if (!responseEvent) {
    findings.push(
      makeFinding({
        ruleId: "SAML_MISSING_RESPONSE",
        severity: kzeroSamlEndpoint4xx ? "info" : "error",
        protocol: "SAML",
        likelyOwner: kzeroSamlEndpoint4xx ? "analysis" : "vendor SP",
        title: kzeroSamlEndpoint4xx ? "No SAMLResponse captured after KZero rejection" : "Missing SAMLResponse",
        explanation: kzeroSamlEndpoint4xx
          ? "This is a supporting clue. The primary issue appears to be KZero rejecting the request before a response could be generated."
          : "No SAMLResponse was captured in this trace.",
        observed: "SAMLResponse not found",
        expected: "SAMLResponse posted to ACS",
        evidence: samlEvents.map((e) => e.url),
        action: kzeroSamlEndpoint4xx
          ? "Focus on the KZero rejection finding first. After fixing that, confirm a SAMLResponse is generated and posted to ACS."
          : "Confirm vendor ACS endpoint receives POST and browser is not blocked by extensions/CSP.",
        confidence: kzeroSamlEndpoint4xx ? 0.66 : 0.88,
        isAmbiguous: Boolean(kzeroSamlEndpoint4xx),
        ambiguityNote: kzeroSamlEndpoint4xx
          ? "No SAMLResponse was captured, but the stronger evidence is a KZero endpoint 4xx before response generation."
          : undefined,
        traceGaps: kzeroSamlEndpoint4xx ? ["SAMLResponse payload not captured because login ended early"] : undefined
      })
    );
  }

  // REGRESSION: If requestEvent exists, never emit SAML_MISSING_REQUEST
  if (!requestEvent) {
    const flow = responseEvent
      ? detectSamlFlow(events, responseEvent)
      : { success: "none" as const, captureCompleteness: "unknown" as const };
    const samlDirection = inferSamlDirection(events, requestEvent, responseEvent);
    const likelyIdpInitiated = samlDirection === "KZero -> SP";

    const isSuccessful = flow.success === "clear" || flow.success === "probable";

    // Emit info note for any successful flow with no request
    if (isSuccessful) {
      findings.push(
        makeFinding({
          ruleId: "SAML_CAPTURE_STARTED_LATE",
          severity: "info",
          protocol: "SAML",
          likelyOwner: "analysis",
          title: "Capture started after AuthnRequest",
          explanation:
            flow.success === "clear"
              ? "Flow appears successful but no AuthnRequest was captured - this is often normal for KZero-launched sign-in or when capture starts late."
              : "Post-ACS activity detected but AuthnRequest was not captured - capture may be incomplete or KZero-launched.",
          observed: "AuthnRequest not captured",
          expected: "Full SAML flow with both request and response",
          evidence: samlEvents.map((e) => e.url),
          action: likelyIdpInitiated
            ? "If users launch sign-in from KZero, missing AuthnRequest can be normal. If SP-initiated is expected, start capture before clicking the app icon."
            : "If this should be SP-initiated, start capture before clicking the app icon.",
          confidence: 0.6,
          isAmbiguous: true,
          ambiguityNote: "No AuthnRequest was captured. This could mean: (1) capture started after the request was sent, (2) IdP-initiated login that has no AuthnRequest, or (3) redirect binding AuthnRequest that wasn't captured.",
          traceGaps: ["AuthnRequest not captured"],
          disqualifyingEvidence: ["Captured AuthnRequest in the trace"]
        })
      );
    }

    // Only suppress on clear success; downgrade to info on probable
    if (flow.success === "clear") {
      // Suppress completely - don't emit SAML_MISSING_REQUEST
    } else if (flow.success === "probable") {
      findings.push(
        makeFinding({
          ruleId: "SAML_MISSING_REQUEST",
          severity: "info",
          protocol: "SAML",
          likelyOwner: "vendor SP",
          title: "Missing SAMLRequest",
          explanation: "No SP-initiated AuthnRequest was captured - flow may be IdP-initiated or capture started late.",
          observed: "SAMLRequest not found",
          expected: "SAMLRequest for SP-initiated flow",
          evidence: samlEvents.map((e) => e.url),
          action: "If this should be SP-initiated, confirm the app starts login with SAMLRequest.",
          confidence: 0.72,
          isAmbiguous: true,
          ambiguityNote: "No AuthnRequest captured. Could be SP-initiated with late capture, or IdP-initiated login.",
          traceGaps: ["AuthnRequest not captured"],
          disqualifyingEvidence: ["Captured AuthnRequest matching this response"]
        })
      );
    } else {
      // No success evidence - keep warning unless flow likely starts from KZero
      findings.push(
        makeFinding({
          ruleId: "SAML_MISSING_REQUEST",
          severity: likelyIdpInitiated ? "info" : "warning",
          protocol: "SAML",
          likelyOwner: likelyIdpInitiated ? "analysis" : "vendor SP",
          title: likelyIdpInitiated
            ? "We did not capture the service provider sign-in request"
            : "Missing SAMLRequest",
          explanation: likelyIdpInitiated
            ? "No SP AuthnRequest was captured. This can be normal for KZero-launched sign-in, but can also mean capture started late."
            : "No SP-initiated AuthnRequest was captured.",
          observed: "SAMLRequest not found",
          expected: "SAMLRequest for SP-initiated flow",
          evidence: samlEvents.map((e) => e.url),
          action: likelyIdpInitiated
            ? "If this is KZero-launched, this can be expected. If SP-initiated should occur, confirm the app starts login with SAMLRequest and begin capture before clicking sign-in."
            : "If this should be SP-initiated, confirm the app starts login with SAMLRequest.",
          confidence: 0.72,
          traceGaps: ["AuthnRequest not captured"],
          isAmbiguous: likelyIdpInitiated,
          ambiguityNote: likelyIdpInitiated
            ? "The trace indicates KZero-to-SP direction, so missing AuthnRequest may be normal rather than a configuration error."
            : undefined
        })
      );
    }
  }

  const parseErrorEvent = samlEvents.find(
    (e) => e.samlRequest?.parseError || e.samlResponse?.parseError
  );
  if (parseErrorEvent) {
    findings.push(
      makeFinding({
        ruleId: "SAML_UNPARSEABLE_ARTIFACT",
        severity: "error",
        protocol: "SAML",
        likelyOwner: "browser",
        title: "SAML artifact could not be parsed",
        explanation: "Base64 decode, DEFLATE decode, or XML parse failed.",
        observed: parseErrorEvent.samlRequest?.parseError ?? parseErrorEvent.samlResponse?.parseError ?? "unknown parse error",
        expected: "Valid base64 and XML payload",
        evidence: [parseErrorEvent.url],
        action: "Check whether copied SAML payload was truncated or incorrectly URL-encoded.",
        confidence: 0.94
      })
    );
  }

  if (responseEvent?.samlResponse?.destination) {
    const destination = responseEvent.samlResponse.destination;
    if (destination !== responseEvent.url) {
      findings.push(
        makeFinding({
          ruleId: "SAML_DESTINATION_MISMATCH",
          severity: "error",
          protocol: "SAML",
          likelyOwner: "vendor SP",
          title: "SAML Destination mismatch",
          explanation: "Destination in SAMLResponse does not match receiving endpoint.",
          observed: destination,
          expected: responseEvent.url,
          evidence: [responseEvent.url],
          action: "Compare SSO URL and vendor ACS/Destination values for exact match.",
          confidence: 0.93
        })
      );
    }
  }

  if (responseEvent?.samlResponse?.recipient && responseEvent.samlResponse.recipient !== responseEvent.url) {
    findings.push(
      makeFinding({
        ruleId: "SAML_ACS_RECIPIENT_MISMATCH",
        severity: "error",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Recipient / ACS mismatch",
        explanation: "Assertion SubjectConfirmation Recipient does not match ACS endpoint.",
        observed: responseEvent.samlResponse.recipient,
        expected: responseEvent.url,
        evidence: [responseEvent.url],
        action: "Align Assertion Consumer Service URL with vendor ACS and posted endpoint.",
        confidence: 0.96
      })
    );
  }

  if (
    responseEvent?.samlResponse?.audience &&
    requestEvent?.samlRequest?.issuer &&
    responseEvent.samlResponse.audience !== requestEvent.samlRequest.issuer
  ) {
    findings.push(
      makeFinding({
        ruleId: "SAML_AUDIENCE_MISMATCH",
        severity: "error",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Audience / Entity ID mismatch",
        explanation: "Audience in assertion does not match SP Entity ID from request.",
        observed: responseEvent.samlResponse.audience,
        expected: requestEvent.samlRequest.issuer,
        evidence: [requestEvent.url, responseEvent.url],
        action: "Compare Service provider Entity ID in KZero with vendor SP Entity ID/Audience URI.",
        confidence: 0.95
      })
    );
  }

  if (responseEvent?.samlResponse?.issuer && requestEvent?.url.includes("auth.kzero.com")) {
    const tenantBase = requestEvent.url.split("/protocol/saml")[0];
    if (responseEvent.samlResponse.issuer !== tenantBase) {
      findings.push(
        makeFinding({
          ruleId: "SAML_ISSUER_MISMATCH",
          severity: "error",
          protocol: "SAML",
          likelyOwner: "KZero",
          title: "SAML issuer mismatch",
          explanation: "Issuer in SAMLResponse does not match KZero tenant base URL.",
          observed: responseEvent.samlResponse.issuer,
          expected: tenantBase,
          evidence: [responseEvent.url],
          action: "Verify Identity provider entity ID and tenant name casing in KZero.",
          confidence: 0.91
        })
      );
    }
  }

  if (responseEvent && !responseEvent.samlResponse?.nameId) {
    findings.push(
      makeFinding({
        ruleId: "SAML_MISSING_NAMEID",
        severity: "error",
        protocol: "SAML",
        likelyOwner: "user data",
        title: "Missing NameID",
        explanation: "Assertion has no NameID value for user identity mapping.",
        observed: "NameID missing",
        expected: "NameID present",
        evidence: [responseEvent.url],
        action: "Check Principal type, Pass subject, and NameID Policy Format mappings.",
        confidence: 0.9
      })
    );
  }

  if (responseEvent?.relayState && !requestEvent?.relayState) {
    const flow = responseEvent ? detectSamlFlow(samlEvents, responseEvent) : { success: "none" as const, captureCompleteness: "unknown" as const };
    const severity = flow.success === "clear" || flow.success === "probable" ? "info" : "warning";
    const isAmbiguous = flow.success !== "none" && !requestEvent;
    findings.push(
      makeFinding({
        ruleId: "SAML_RELAYSTATE_UNEXPECTED",
        severity,
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Unexpected RelayState behavior",
        explanation: flow.success !== "none"
          ? "RelayState present in response but not request - likely capture started late."
          : "RelayState appeared in response without matching request value.",
        observed: "response RelayState present, request missing",
        expected: "Stable RelayState round-trip",
        evidence: [responseEvent.url],
        action: "Verify vendor Relay State setting and preserve value across redirects.",
        confidence: 0.75,
        isAmbiguous,
        ambiguityNote: isAmbiguous ? "No AuthnRequest was captured, so we cannot verify if RelayState was expected on the request side." : undefined,
        traceGaps: !requestEvent ? ["AuthnRequest not captured - cannot verify RelayState round-trip"] : undefined
      })
    );
  }

  if (responseEvent && !responseEvent.samlResponse?.assertionSigned) {
    findings.push(
      makeFinding({
        ruleId: "SAML_ASSERTION_SIGNATURE_MISSING",
        severity: "warning",
        protocol: "SAML",
        likelyOwner: "KZero",
        title: "Assertion signature not detected",
        explanation: "No assertion-level signature was found in parsed XML.",
        observed: "assertion signature not detected",
        expected: "Signed assertion when vendor requires it",
        evidence: [responseEvent.url],
        action: "Confirm Want assertions signed and Validate signatures settings.",
        confidence: 0.78
      })
    );
  }

  if (responseEvent && !responseEvent.samlResponse?.documentSigned) {
    findings.push(
      makeFinding({
        ruleId: "SAML_DOCUMENT_SIGNATURE_MISSING",
        severity: "info",
        protocol: "SAML",
        likelyOwner: "unknown",
        title: "Document signature not detected",
        explanation: "Response-level signature was not detected.",
        observed: "document signature not detected",
        expected: "Signed response when SP requires document signature",
        evidence: [responseEvent.url],
        action: "Match signing expectations between vendor and KZero signature settings.",
        confidence: 0.7
      })
    );
  }

  if (responseEvent?.samlResponse?.notOnOrAfter) {
    const expiry = Date.parse(responseEvent.samlResponse.notOnOrAfter);
    if (!Number.isNaN(expiry) && expiry < Date.now()) {
      findings.push(
        makeFinding({
          ruleId: "SAML_CLOCK_SKEW",
          severity: "error",
          protocol: "SAML",
          likelyOwner: "network",
          title: "SAML assertion expired",
          explanation: "Assertion validity window has already ended.",
          observed: responseEvent.samlResponse.notOnOrAfter,
          expected: "Assertion still within NotOnOrAfter window",
          evidence: [responseEvent.url],
          action: "Check system clocks and adjust Allow clock skew if needed.",
          confidence: 0.9
        })
      );
    }
  }

  if (responseEvent?.samlResponse?.notBefore) {
    const notBefore = Date.parse(responseEvent.samlResponse.notBefore);
    if (!Number.isNaN(notBefore) && notBefore > Date.now()) {
      findings.push(
        makeFinding({
          ruleId: "SAML_CLOCK_SKEW_NOT_BEFORE",
          severity: "error",
          protocol: "SAML",
          likelyOwner: "network",
          title: "SAML assertion not yet valid",
          explanation: "NotBefore is in the future relative to local capture time.",
          observed: responseEvent.samlResponse.notBefore,
          expected: "Current time after NotBefore",
          evidence: [responseEvent.url],
          action: "Check system clocks and increase Allow clock skew where appropriate.",
          confidence: 0.9
        })
      );
    }
  }

  if (responseEvent && requestEvent?.samlRequest && !responseEvent.samlResponse?.inResponseTo) {
    findings.push(
      makeFinding({
        ruleId: "SAML_INRESPONSETO_MISSING",
        severity: "warning",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "InResponseTo missing",
        explanation: "SP-initiated flow usually expects InResponseTo in SAMLResponse.",
        observed: "InResponseTo missing",
        expected: "InResponseTo references AuthnRequest ID",
        evidence: [responseEvent.url],
        action: "Confirm SP-initiated mode and whether IdP-initiated responses are accepted.",
        confidence: 0.76
      })
    );
  }

  if (responseEvent?.samlResponse?.encryptedAssertion) {
    findings.push(
      makeFinding({
        ruleId: "SAML_ASSERTION_ENCRYPTED",
        severity: "warning",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Assertion is encrypted",
        explanation: "Some SP implementations fail when encrypted assertions are enabled.",
        observed: "EncryptedAssertion present",
        expected: "SP supports encrypted assertions with correct certificate",
        evidence: [responseEvent.url],
        action: "Check Want assertions encrypted and vendor certificate compatibility.",
        confidence: 0.73
      })
    );
  }

  if (responseEvent?.samlResponse?.nameId && responseEvent.samlResponse.nameIdFormat) {
    const format = responseEvent.samlResponse.nameIdFormat.toLowerCase();
    const value = responseEvent.samlResponse.nameId;
    if (format.includes("email") && !value.includes("@")) {
      findings.push(
        makeFinding({
          ruleId: "SAML_NAMEID_FORMAT_MISMATCH",
          severity: "warning",
          protocol: "SAML",
          likelyOwner: "user data",
          title: "Likely wrong NameID format",
          explanation: "NameID format indicates email but value is not email-like.",
          observed: `${responseEvent.samlResponse.nameIdFormat} -> ${value}`,
          expected: "Email NameID format with email value",
          evidence: [responseEvent.url],
          action: "Align NameID Policy Format with actual principal value mapping.",
          confidence: 0.87
        })
      );
    }
  }

  if (!requestEvent && responseEvent?.samlResponse?.inResponseTo) {
    findings.push(
      makeFinding({
        ruleId: "SAML_IDP_SP_INIT_MISMATCH_CLUE",
        severity: "info",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "IdP vs SP initiated flow mismatch clue",
        explanation: "Response carries InResponseTo but no AuthnRequest is present in this capture.",
        observed: `InResponseTo=${responseEvent.samlResponse.inResponseTo}`,
        expected: "Captured AuthnRequest for SP-initiated flow",
        evidence: [responseEvent.url],
        action: "Verify capture start timing and whether the app expects IdP-initiated or SP-initiated login.",
        confidence: 0.64,
        isAmbiguous: true,
        ambiguityNote: "Response contains InResponseTo (suggesting SP-initiated) but no AuthnRequest was captured. This could mean capture started late, or this is actually an IdP-initiated flow that includes InResponseTo from a prior SP-initiated request.",
        traceGaps: ["AuthnRequest not captured"],
        disqualifyingEvidence: ["Captured AuthnRequest that matches InResponseTo", "Confirmed IdP-initiated login without InResponseTo"]
      })
    );
  }

  if (responseEvent?.binding === "redirect" && responseEvent.samlResponse) {
    findings.push(
      makeFinding({
        ruleId: "SAML_WRONG_BINDING_CLUE",
        severity: "warning",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Unexpected SAML response binding",
        explanation: "SAMLResponse over Redirect binding can fail with SPs expecting POST binding.",
        observed: "Response binding=redirect",
        expected: "HTTP-POST binding response where required",
        evidence: [responseEvent.url],
        action: "Compare HTTP-POST binding response settings on KZero and vendor SAML config.",
        confidence: 0.72
      })
    );
  }

  if ((responseEvent?.statusCode ?? 0) >= 400 && responseEvent?.samlResponse) {
    findings.push(
      makeFinding({
        ruleId: "SAML_CERT_SIGNATURE_VALIDATION_CLUE",
        severity: "warning",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Signature/certificate validation mismatch clue",
        explanation: "SP endpoint returned an error while receiving a SAML assertion, often due to cert/signature expectations.",
        observed: `ACS status ${responseEvent.statusCode}`,
        expected: "ACS accepts assertion and returns success",
        evidence: [responseEvent.url],
        action: "Compare Tenant certificate/XML data and Validate signatures settings with vendor certificate configuration.",
        confidence: 0.67
      })
    );
  }

  if (requestEvent?.samlRequest?.forceAuthn || requestEvent?.samlRequest?.allowCreate === false) {
    findings.push(
      makeFinding({
        ruleId: "SAML_POLICY_MISMATCH_CLUE",
        severity: "info",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "NameID / ForceAuthn policy mismatch clue",
        explanation: "AuthnRequest policy flags can conflict with current IdP/SP expectations.",
        observed: `ForceAuthn=${requestEvent.samlRequest.forceAuthn}, AllowCreate=${requestEvent.samlRequest.allowCreate}`,
        expected: "Policy flags aligned with SP requirements",
        evidence: [requestEvent.url],
        action: "Review Force authentication, Allow create, and NameID Policy Format values.",
        confidence: 0.58
      })
    );
  }

  if (requestEvent?.binding === "redirect" && requestEvent.samlRequest && !requestEvent.url.includes("Signature=")) {
    findings.push(
      makeFinding({
        ruleId: "SAML_AUTHNREQUEST_SIGN_EXPECTATION_MISMATCH",
        severity: "info",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "AuthnRequest signature may be missing",
        explanation: "Redirect binding request appears unsigned.",
        observed: "Signature parameter not found",
        expected: "Signed AuthnRequest when Want AuthnRequests signed is enabled",
        evidence: [requestEvent.url],
        action: "Compare Want AuthnRequests signed with vendor signed request requirement.",
        confidence: 0.68
      })
    );
  }

  return findings;
};
