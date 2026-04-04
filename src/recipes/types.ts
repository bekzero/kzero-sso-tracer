import type { Owner, Severity } from "../shared/models";

export interface CopySnippet {
  label: string;
  value: string;
  sensitive?: boolean;
}

export interface FixLink {
  label: string;
  url: string;
}

export interface FixSection {
  title: string;
  owner: Owner | string;
  severity?: Severity;
  bullets: string[];
  kzeroFields?: string[];
  vendorFields?: string[];
  fieldExpectations?: Array<{ field: string; expected: string; sensitive?: boolean }>;
  copySnippets?: CopySnippet[];
  links?: FixLink[];
  tooltip?: string;
}

export interface FixRecipe {
  title: string;
  owner: Owner;
  confidence: number;
  sections: FixSection[];
  verify: string[];
  nextEvidence: string[];
}
