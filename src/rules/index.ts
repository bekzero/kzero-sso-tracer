import type { Finding, NormalizedEvent } from "../shared/models";
import { runCrossRules } from "./crossRules";
import { runOidcRules } from "./oidcRules";
import { runSamlRules } from "./samlRules";

const ALWAYS_NOISE_RULES = [
  "SAML_DOCUMENT_SIGNATURE_MISSING",
  "OIDC_ACCESS_TOKEN_OPAQUE",
] as const;

const severityRank = (severity: Finding["severity"]): number =>
  severity === "error" ? 3 : severity === "warning" ? 2 : 1;

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
    const key = `${finding.ruleId}-${finding.eventId ?? "none"}-${finding.observed}-${finding.expected}-${finding.likelyOwner}`;
    const existing = dedupe.get(key);
    if (!existing) {
      dedupe.set(key, finding);
      continue;
    }
    const existingScore = severityRank(existing.severity) * 100 + Math.round(existing.confidence * 100);
    const candidateScore = severityRank(finding.severity) * 100 + Math.round(finding.confidence * 100);
    if (candidateScore > existingScore) {
      dedupe.set(key, finding);
    }
  }
  return filterNoise([...dedupe.values()]).sort((a, b) => {
    const severityDelta = severityRank(b.severity) - severityRank(a.severity);
    if (severityDelta !== 0) return severityDelta;
    return b.confidence - a.confidence;
  });
};
