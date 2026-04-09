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
  isAmbiguous?: boolean;
  ambiguityNote?: string;
  traceGaps?: string[];
  disqualifyingEvidence?: string[];
}

// Confidence calibration assumptions:
// - High (>=0.80): Strong evidence, clear error patterns, direct trace of auth flow
// - Medium (>=0.55): Probable issues, indirect evidence, plausible failure modes
// - Low (<0.55): Weak signals, speculation, or incomplete traces
// These thresholds are legacy-calibrated and may need future audit.
// Review rules with obviously overrated/underrated confidence when calibrate()

const deriveConfidenceLevel = (confidence: number): "high" | "medium" | "low" => {
  if (confidence >= 0.80) return "high";
  if (confidence >= 0.55) return "medium";
  return "low";
};

export const makeFinding = (input: FindingInput): Finding => {
  const fields = getFieldMapping(input.ruleId);
  
  // Consistency guard: ambiguous findings should explain why
  if (input.isAmbiguous && !input.ambiguityNote && !input.traceGaps?.length) {
    console.warn(`Finding ${input.ruleId} is ambiguous but has no ambiguityNote or traceGaps`);
  }

  const confidenceLevel = deriveConfidenceLevel(input.confidence);

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
    confidence: input.confidence,
    confidenceLevel,
    isAmbiguous: input.isAmbiguous,
    ambiguityNote: input.ambiguityNote,
    traceGaps: input.traceGaps,
    disqualifyingEvidence: input.disqualifyingEvidence
  };
};