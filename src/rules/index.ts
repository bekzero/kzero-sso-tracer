import type { Finding, NormalizedEvent, NormalizedSamlEvent, NormalizedOidcEvent } from "../shared/models";
import { runCrossRules } from "./crossRules";
import { runOidcRules } from "./oidcRules";
import { runSamlRules } from "./samlRules";

const isSamlSuccess = (events: NormalizedEvent[]): boolean => {
  const samlEvents = events.filter((e): e is NormalizedSamlEvent => e.protocol === "SAML");
  const response = samlEvents.find((e) => e.samlResponse);
  if (!response) return false;
  
  const statusCode = response.statusCode ?? 200;
  if (statusCode >= 400) return false;
  
  if (response.samlResponse?.nameId) return true;
  
  const hasSuccessfulResponse = samlEvents.some((e) => 
    e.samlResponse && (e.statusCode ?? 200) < 400
  );
  return hasSuccessfulResponse;
};

const isOidcSuccess = (events: NormalizedEvent[]): boolean => {
  const oidc = events.filter((e): e is NormalizedOidcEvent => e.protocol === "OIDC");
  const token = oidc.find((e) => e.kind === "token");
  if (token) {
    const hasSuccessStatus = (token.statusCode ?? 200) < 400;
    const hasTokens = Boolean(token.idToken || token.artifacts.access_token || token.accessTokenOpaque);
    const noError = !token.error;
    return hasSuccessStatus && hasTokens && noError;
  }
  const callback = oidc.find((e) => e.kind === "callback");
  if (callback?.code && !callback.error) {
    return true;
  }
  return false;
};

const isLoginSuccessful = (events: NormalizedEvent[]): boolean => {
  return isSamlSuccess(events) || isOidcSuccess(events);
};

const INFO_RULES_ALWAYS_NOISE = [
  "SAML_DOCUMENT_SIGNATURE_MISSING",
  "OIDC_ACCESS_TOKEN_OPAQUE",
] as const;

const INFO_RULES_NOISE_ON_SUCCESS = [
  "SAML_IDP_SP_INIT_MISMATCH_CLUE",
  "SAML_AUTHNREQUEST_SIGN_EXPECTATION_MISMATCH",
  "SAML_POLICY_MISMATCH_CLUE",
  "STALE_VALUES_FROM_ANOTHER_ENVIRONMENT",
  "TENANT_CASE_MISMATCH",
] as const;

const ERROR_RULES_NOISE_ON_SUCCESS = [
  "SAML_MISSING_NAMEID",
] as const;

const WARNING_RULES_NOISE_IDP_INITIATED = [
  "SAML_MISSING_REQUEST",
  "SAML_INRESPONSETO_MISSING",
] as const;

const filterNoise = (findings: Finding[], events: NormalizedEvent[]): Finding[] => {
  const success = isLoginSuccessful(events);
  
  return findings.filter((f) => {
    if (f.severity === "info") {
      if (INFO_RULES_ALWAYS_NOISE.includes(f.ruleId as typeof INFO_RULES_ALWAYS_NOISE[number])) {
        return false;
      }
      if (success && INFO_RULES_NOISE_ON_SUCCESS.includes(f.ruleId as typeof INFO_RULES_NOISE_ON_SUCCESS[number])) {
        return false;
      }
    }
    
    if (f.severity === "error") {
      if (success && ERROR_RULES_NOISE_ON_SUCCESS.includes(f.ruleId as typeof ERROR_RULES_NOISE_ON_SUCCESS[number])) {
        return false;
      }
    }
    
    if (f.severity === "warning" && success) {
      if (WARNING_RULES_NOISE_IDP_INITIATED.includes(f.ruleId as typeof WARNING_RULES_NOISE_IDP_INITIATED[number])) {
        const samlEvents = events.filter((e): e is NormalizedSamlEvent => e.protocol === "SAML");
        const requestEvent = samlEvents.find((e) => e.samlRequest);
        if (!requestEvent) {
          return false;
        }
      }
    }
    
    return true;
  });
};

export const runFindingsEngine = (events: NormalizedEvent[]): Finding[] => {
  const findings = [...runSamlRules(events), ...runOidcRules(events), ...runCrossRules(events)];
  const dedupe = new Map<string, Finding>();
  for (const finding of findings) {
    const key = `${finding.ruleId}-${finding.observed}-${finding.expected}`;
    if (!dedupe.has(key)) {
      dedupe.set(key, finding);
    }
  }
  const dedupedFindings = [...dedupe.values()];
  return filterNoise(dedupedFindings, events);
};
