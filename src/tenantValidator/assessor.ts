import type { NormalizedEvent, NormalizedOidcEvent, NormalizedSamlEvent } from "../shared/models";
import { inferSamlDirection } from "../analysis/flowClassifier";
import type {
  ErrorAnalysisResult,
  MetadataParseResult,
  TenantScanResult,
  ValidatorAssessment,
  ValidatorHypothesis
} from "./types";

const asOidc = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === "OIDC";
const asSaml = (e: NormalizedEvent): e is NormalizedSamlEvent => e.protocol === "SAML";

const rank = (h: ValidatorHypothesis): number => {
  const confidenceScore = h.confidence === "high" ? 3 : h.confidence === "medium" ? 2 : 1;
  const kindScore = h.kind === "confirmed" ? 3 : h.kind === "likely" ? 2 : 1;
  return confidenceScore * 10 + kindScore;
};

const add = (list: ValidatorHypothesis[], item: ValidatorHypothesis): void => {
  if (!list.some((h) => h.id === item.id)) list.push(item);
};

export const assessTrace = (input: {
  events: NormalizedEvent[];
  scan?: TenantScanResult | null;
  metadata?: MetadataParseResult | null;
  error?: ErrorAnalysisResult | null;
  tenantInput?: string;
}): ValidatorAssessment => {
  const hypotheses: ValidatorHypothesis[] = [];
  const events = input.events;
  const samlEvents = events.filter(asSaml);
  const oidcEvents = events.filter(asOidc);
  const samlResponse = samlEvents.find((e) => e.samlResponse);
  const samlRequest = samlEvents.find((e) => e.samlRequest);
  const oidcAuthorize = oidcEvents.find((e) => e.kind === "authorize");
  const oidcCallback = oidcEvents.find((e) => e.kind === "callback");
  const oidcToken = oidcEvents.find((e) => e.kind === "token");

  if (samlResponse?.samlResponse?.destination && samlResponse.url && samlResponse.samlResponse.destination !== samlResponse.url) {
    add(hypotheses, {
      id: "saml-destination-mismatch",
      title: "ACS URL mismatch is likely blocking sign-in",
      confidence: "high",
      kind: "confirmed",
      summary: "The SAML response destination does not match the URL that received the response.",
      why: [
        `Response was posted to: ${samlResponse.url}`,
        `SAML Destination says: ${samlResponse.samlResponse.destination}`,
        "These values must match exactly."
      ],
      howToFix: [
        "Open the SAML app settings in KZero and your service provider.",
        "Compare Assertion Consumer Service POST Binding URL and the ACS/Redirect URL values.",
        "They must match exactly (scheme, host, path, trailing slash, tenant/environment)."
      ],
      evidence: [samlResponse.url, samlResponse.samlResponse.destination]
    });
  }

  if (samlResponse?.samlResponse?.recipient && samlResponse.url && samlResponse.samlResponse.recipient !== samlResponse.url) {
    add(hypotheses, {
      id: "saml-recipient-mismatch",
      title: "SAML Recipient value does not match ACS URL",
      confidence: "high",
      kind: "confirmed",
      summary: "The Recipient in the assertion does not match the actual endpoint URL.",
      why: [
        `Recipient: ${samlResponse.samlResponse.recipient}`,
        `Posted to: ${samlResponse.url}`
      ],
      howToFix: [
        "In both KZero and the service provider, compare Recipient/ACS fields.",
        "Use one exact URL value across both sides.",
        "Check for wrong tenant, wrong environment, or extra trailing slash."
      ],
      evidence: [samlResponse.samlResponse.recipient, samlResponse.url]
    });
  }

  if (oidcAuthorize?.redirectUri && oidcCallback?.url) {
    let callbackUrl = oidcCallback.url;
    try {
      const parsed = new URL(oidcCallback.url);
      callbackUrl = `${parsed.origin}${parsed.pathname}`;
    } catch {
      // keep full callback URL
    }
    if (callbackUrl !== oidcAuthorize.redirectUri) {
      add(hypotheses, {
        id: "oidc-redirect-mismatch",
        title: "OIDC callback URL mismatch",
        confidence: "high",
        kind: "confirmed",
        summary: "The callback URL does not match the redirect URI sent in the authorize request.",
        why: [
          `Requested redirect URI: ${oidcAuthorize.redirectUri}`,
          `Observed callback URL: ${callbackUrl}`
        ],
        howToFix: [
          "Open OIDC client settings in KZero and the vendor app.",
          "Compare Redirect URI and callback URL values.",
          "They must match exactly, including path and trailing slash."
        ],
        evidence: [oidcAuthorize.url, oidcCallback.url]
      });
    }
  }

  if (oidcAuthorize && oidcCallback && (!oidcAuthorize.state || !oidcCallback.state || oidcAuthorize.state !== oidcCallback.state)) {
    add(hypotheses, {
      id: "oidc-state-mismatch",
      title: "OIDC state value mismatch",
      confidence: "high",
      kind: "confirmed",
      summary: "State protection did not round-trip correctly.",
      why: [
        `Authorize state: ${oidcAuthorize.state ?? "(missing)"}`,
        `Callback state: ${oidcCallback.state ?? "(missing)"}`
      ],
      howToFix: [
        "Confirm the service provider preserves query/fragment values across redirects.",
        "Disable extensions that rewrite callback URLs during troubleshooting.",
        "Retry capture from the beginning of the sign-in flow."
      ],
      evidence: [oidcAuthorize.url, oidcCallback.url]
    });
  }

  if (input.scan?.hasMismatch) {
    add(hypotheses, {
      id: "tenant-mismatch",
      title: "Tenant/environment mismatch detected",
      confidence: "high",
      kind: "confirmed",
      summary: "Captured endpoints use a different tenant than the one entered.",
      why: input.scan.mismatches.slice(0, 3).map((m) => `Expected ${m.inputTenant}, found ${m.extractedTenant} at ${m.host}`),
      howToFix: [
        "Check tenant name casing and environment values in all SAML/OIDC URLs.",
        "Compare production vs staging hostnames and tenant names.",
        "Update vendor and KZero settings so they point to the same tenant."
      ],
      evidence: input.scan.mismatches.slice(0, 3).map((m) => m.url)
    });
  }

  if (samlResponse?.samlResponse?.nameIdFormat?.toLowerCase().includes("email") && samlResponse.samlResponse.nameId && !samlResponse.samlResponse.nameId.includes("@")) {
    add(hypotheses, {
      id: "nameid-format-mismatch",
      title: "NameID format likely does not match expected user value",
      confidence: "medium",
      kind: "likely",
      summary: "NameID is marked as email format but value does not look like an email address.",
      why: [
        `NameID format: ${samlResponse.samlResponse.nameIdFormat}`,
        `NameID value: ${samlResponse.samlResponse.nameId}`
      ],
      howToFix: [
        "In KZero, review Principal type / Pass subject / NameID policy format.",
        "Make sure the NameID format matches the value the service provider expects.",
        "If email is required, ensure the selected user attribute is an email value."
      ],
      evidence: [samlResponse.url]
    });
  }

  const direction = inferSamlDirection(events, samlRequest, samlResponse);
  if (!samlRequest && samlResponse && direction === "KZero -> SP") {
    add(hypotheses, {
      id: "idp-initiated-missing-request",
      title: "Missing SAMLRequest may be expected for KZero-launched sign-in",
      confidence: "medium",
      kind: "missing-evidence",
      summary: "No SP request was captured, but the trace direction looks like KZero to service provider.",
      why: [
        "SAML response exists without a captured SAML request.",
        "Issuer/traffic suggests the flow started from KZero."
      ],
      howToFix: [
        "If users launch from KZero, this can be normal.",
        "If SP-initiated is expected, start capture before clicking Sign in on the service provider.",
        "Use the tab handoff warning to follow popups/new tabs during login."
      ],
      evidence: [samlResponse.url]
    });
  }

  if (input.error?.matchedPattern) {
    add(hypotheses, {
      id: `error-${input.error.matchedPattern.id}`,
      title: `Most likely error category: ${input.error.matchedPattern.cause}`,
      confidence: input.error.matchedPattern.severity === "error" ? "high" : "medium",
      kind: "likely",
      summary: input.error.matchedPattern.fix,
      why: [`Matched pattern: ${input.error.matchedPattern.pattern.toString()}`],
      howToFix: input.error.suggestions,
      evidence: [input.error.inputError.slice(0, 180)]
    });
  }

  if (!samlResponse && samlEvents.length > 0) {
    add(hypotheses, {
      id: "missing-saml-response",
      title: "SAML response not captured",
      confidence: "medium",
      kind: "missing-evidence",
      summary: "The trace has SAML-related activity, but no SAMLResponse payload was captured.",
      why: ["No SAMLResponse found in captured SAML events."],
      howToFix: [
        "Start capture before initiating login.",
        "If login opens in a popup/new tab, switch tracer to that tab.",
        "Check browser extensions that may block form posts."
      ],
      evidence: samlEvents.slice(0, 3).map((e) => e.url)
    });
  }

  if (oidcAuthorize && !oidcCallback && !oidcToken) {
    add(hypotheses, {
      id: "missing-oidc-callback",
      title: "OIDC callback not captured",
      confidence: "medium",
      kind: "missing-evidence",
      summary: "Authorize request exists but callback/token events were not captured.",
      why: ["Authorize request is present, callback and token exchange are missing."],
      howToFix: [
        "Verify redirect URI registration on both sides.",
        "Start capture before login and follow popup/new tab handoff.",
        "Check if callback is blocked by browser policies or extensions."
      ],
      evidence: [oidcAuthorize.url]
    });
  }

  const sorted = hypotheses.sort((a, b) => rank(b) - rank(a));
  return {
    top: sorted[0],
    hypotheses: sorted
  };
};
