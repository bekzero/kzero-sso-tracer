export {
  buildHelpContext,
  mapQueryToIntent,
  getQuickSuggestions,
  getDefaultSuggestions,
  getExplanationForIntent,
  getSuggestionsForQuery
} from "./engines/deterministic";

export { callAI, openAIProvider } from "./ai/provider";
export type { AIRequest, AIResponse, AIProvider } from "./ai/provider";

export type {
  HelpMessage,
  HelpRequest,
  HelpResponse,
  QuickSuggestion,
  HelpContext,
  IntentMatch,
  MessageSource
} from "./types";
