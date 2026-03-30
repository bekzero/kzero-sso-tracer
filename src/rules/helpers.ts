import type { Finding, Owner, ProtocolType, Severity } from "../shared/models";
import { getFieldMapping } from "../mappings/fieldMappings";
import { nowId } from "../shared/utils";

export interface FindingInput {
  ruleId: string;
  severity: Severity;
  protocol: ProtocolType;
  likelyOwner: Owner;
  title: string;
  explanation: string;
  observed: string;
  expected: string;
  evidence: string[];
  action: string;
  confidence: number;
}

export const makeFinding = (input: FindingInput): Finding => {
  const fields = getFieldMapping(input.ruleId);
  return {
    id: nowId(),
    ruleId: input.ruleId,
    severity: input.severity,
    protocol: input.protocol,
    likelyOwner: input.likelyOwner,
    title: input.title,
    explanation: input.explanation,
    observed: input.observed,
    expected: input.expected,
    evidence: input.evidence,
    likelyFix: {
      kzeroFields: fields.kzeroFields,
      vendorFields: fields.vendorFields,
      action: input.action
    },
    confidence: input.confidence
  };
};
