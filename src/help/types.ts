import type { Finding, CaptureSession } from "../shared/models";
import type { FixRecipe } from "../recipes/types";

export type MessageSource = "user" | "verified" | "ai" | "suggestion";

export interface HelpMessage {
  id: string;
  source: MessageSource;
  content: string;
  timestamp: number;
  recipeId?: string;
  badge?: string;
}

export interface HelpRequest {
  query: string;
  session?: CaptureSession;
  findings?: Finding[];
}

export interface HelpResponse {
  type: "answer" | "suggestions" | "error";
  message: HelpMessage;
  suggestions?: QuickSuggestion[];
}

export interface QuickSuggestion {
  id: string;
  label: string;
  category: "finding" | "concept" | "troubleshooting";
  icon?: string;
}

export interface HelpContext {
  session: CaptureSession | null;
  findings: Finding[];
  tenants: string[];
  flow?: "saml" | "oidc" | "unknown";
}

export interface IntentMatch {
  intent: string;
  confidence: number;
  ruleIds: string[];
  recipe?: FixRecipe;
}
