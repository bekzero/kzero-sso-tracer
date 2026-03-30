import type { Owner, Severity } from "../shared/models";

export interface CopySnippet {
  label: string;
  value: string;
  sensitive?: boolean;
}

export interface FixSection {
  title: string;
  owner: Owner;
  severity?: Severity;
  bullets: string[];
  kzeroFields?: string[];
  vendorFields?: string[];
  fieldExpectations?: Array<{ field: string; expected: string; sensitive?: boolean }>;
  copySnippets?: CopySnippet[];
}

export interface FixRecipe {
  title: string;
  owner: Owner;
  confidence: number;
  sections: FixSection[];
  verify: string[];
  nextEvidence: string[];
}
