import type { Finding, NormalizedEvent } from "../shared/models";
import { runCrossRules } from "./crossRules";
import { runOidcRules } from "./oidcRules";
import { runSamlRules } from "./samlRules";

export const runFindingsEngine = (events: NormalizedEvent[]): Finding[] => {
  const findings = [...runSamlRules(events), ...runOidcRules(events), ...runCrossRules(events)];
  const dedupe = new Map<string, Finding>();
  for (const finding of findings) {
    const key = `${finding.ruleId}-${finding.observed}-${finding.expected}`;
    if (!dedupe.has(key)) {
      dedupe.set(key, finding);
    }
  }
  return [...dedupe.values()];
};
