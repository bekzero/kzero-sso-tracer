import type { Finding, NormalizedEvent, NormalizedSamlEvent } from "../shared/models";
import { makeFinding } from "./helpers";

const isSaml = (e: NormalizedEvent): e is NormalizedSamlEvent => e.protocol === "SAML";

export const runSamlRules = (events: NormalizedEvent[]): Finding[] => {
  const findings: Finding[] = [];
  const samlEvents = events.filter(isSaml);
  const requestEvent = samlEvents.find((e) => e.samlRequest);
  const responseEvent = samlEvents.find((e) => e.samlResponse);

  if (!responseEvent) {
    findings.push(
      makeFinding({
        ruleId: "SAML_MISSING_RESPONSE",
        severity: "error",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Missing SAMLResponse",
        explanation: "No SAMLResponse was captured in this trace.",
        observed: "SAMLResponse not found",
        expected: "SAMLResponse posted to ACS",
        evidence: samlEvents.map((e) => e.url),
        action: "Confirm vendor ACS endpoint receives POST and browser is not blocked by extensions/CSP.",
        confidence: 0.88
      })
    );
  }

  if (!requestEvent) {
    findings.push(
      makeFinding({
        ruleId: "SAML_MISSING_REQUEST",
        severity: "warning",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Missing SAMLRequest",
        explanation: "No SP-initiated AuthnRequest was captured.",
        observed: "SAMLRequest not found",
        expected: "SAMLRequest for SP-initiated flow",
        evidence: samlEvents.map((e) => e.url),
        action: "If this should be SP-initiated, confirm the app starts login with SAMLRequest.",
        confidence: 0.72
      })
    );
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
    findings.push(
      makeFinding({
        ruleId: "SAML_RELAYSTATE_UNEXPECTED",
        severity: "warning",
        protocol: "SAML",
        likelyOwner: "vendor SP",
        title: "Unexpected RelayState behavior",
        explanation: "RelayState appeared in response without matching request value.",
        observed: "response RelayState present, request missing",
        expected: "Stable RelayState round-trip",
        evidence: [responseEvent.url],
        action: "Verify vendor Relay State setting and preserve value across redirects.",
        confidence: 0.75
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
        confidence: 0.64
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
