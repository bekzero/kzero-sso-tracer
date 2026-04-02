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
  const samlFindings = runSamlRules(events);
  const oidcFindings = runOidcRules(events);
  const crossFindings = runCrossRules(events);
  
  console.log("[Findings] SAML rules:", samlFindings.length, "OIDC:", oidcFindings.length, "Cross:", crossFindings.length);
  
  const findings = [...samlFindings, ...oidcFindings, ...crossFindings];
  const dedupe = new Map<string, Finding>();
  for (const finding of findings) {
    const key = `${finding.ruleId}-${finding.observed}-${finding.expected}`;
    if (!dedupe.has(key)) {
      dedupe.set(key, finding);
    }
  }
  const dedupedFindings = [...dedupe.values()];
  console.log("[Findings] After dedupe:", dedupedFindings.length, "Rules:", dedupedFindings.map(f => f.ruleId));
  return filterNoise(dedupedFindings);
};
