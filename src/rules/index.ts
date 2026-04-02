import type { Finding, NormalizedEvent } from "../shared/models";
import { runCrossRules } from "./crossRules";
import { runOidcRules } from "./oidcRules";
import { runSamlRules } from "./samlRules";

const ALWAYS_NOISE_RULES = [
  "SAML_DOCUMENT_SIGNATURE_MISSING",
  "OIDC_ACCESS_TOKEN_OPAQUE",
] as const;

const filterNoise = (findings: Finding[]): Finding[] => {
  return findings.filter((f) => {
    if (ALWAYS_NOISE_RULES.includes(f.ruleId as typeof ALWAYS_NOISE_RULES[number])) {
      return false;
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
  return filterNoise([...dedupe.values()]);
};
