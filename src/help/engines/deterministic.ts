import type { Finding, CaptureSession } from "../../shared/models";
import { RULE_CATALOG } from "../../shared/ruleCatalog";
import type { QuickSuggestion, IntentMatch, HelpContext } from "../types";

interface KeywordMapping {
  keywords: string[];
  ruleIds: string[];
  category: "finding" | "concept" | "troubleshooting";
}

interface PhrasePattern {
  pattern: RegExp;
  ruleIds?: string[];
  category: "finding" | "concept" | "troubleshooting";
  intent?: string;
}

const PHRASE_PATTERNS: PhrasePattern[] = [
  { pattern: /why.*is.*(?:my|the).*(?:login|sign-?in).*(?:not working|failing|failed)/i, category: "troubleshooting", intent: "login_issue" },
  { pattern: /why.*isn'?t.*(?:my|the).*(?:login|sign-?in)/i, category: "troubleshooting", intent: "login_issue" },
  { pattern: /(?:login|sign-?in).*(?:not working|failed|failing)/i, category: "troubleshooting", intent: "login_issue" },
  { pattern: /can'?t.*(?:sign|log).*in/i, category: "troubleshooting", intent: "login_issue" },
  { pattern: /why.*(?:get|getting).*redirected/i, category: "troubleshooting", intent: "redirect_issue", ruleIds: ["OIDC_STATE_MISSING_OR_MISMATCH", "OIDC_REDIRECT_URI_MISMATCH"] },
  { pattern: /why.*callback.*(?:url|uri).*error/i, category: "finding", ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"] },
  { pattern: /invalid.*(?:redirect|callback)/i, category: "finding", ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"] },
  { pattern: /what.*wrong.*(?:callback|redirect)/i, category: "finding", ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"] },
  { pattern: /app.*says.*invalid.*redirect/i, category: "finding", ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"] },
  { pattern: /why.*saml/i, category: "troubleshooting", intent: "saml_issue" },
  { pattern: /saml.*(?:error|fail)/i, category: "troubleshooting", intent: "saml_issue" },
  { pattern: /oidc.*(?:error|fail)/i, category: "troubleshooting", intent: "oidc_issue" },
  { pattern: /how.*(?:fix|resolve|configure)/i, category: "troubleshooting", intent: "how_to_fix" },
  { pattern: /what.*(?:redirect|callback).*uri/i, category: "concept", ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"] },
  { pattern: /what.*issuer/i, category: "concept", ruleIds: ["OIDC_DISCOVERY_ISSUER_MISMATCH"] },
  { pattern: /what.*(?:entity|entity.?id|audience)/i, category: "concept", ruleIds: ["SAML_AUDIENCE_MISMATCH"] },
  { pattern: /what.*saml/i, category: "concept", ruleIds: [] },
  { pattern: /what.*oidc|what.*openid/i, category: "concept", ruleIds: [] },
];

const KEYWORD_MAPPINGS: KeywordMapping[] = [
  {
    keywords: ["redirect", "callback", "uri mismatch", "redirect uri", "callback url", "callback error", "invalid callback", "invalid redirect"],
    ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"],
    category: "finding"
  },
  {
    keywords: ["issuer", "discovery issuer", "issuer mismatch"],
    ruleIds: ["OIDC_DISCOVERY_ISSUER_MISMATCH"],
    category: "finding"
  },
  {
    keywords: ["client", "invalid client", "client id", "client secret", "authentication failed"],
    ruleIds: ["OIDC_INVALID_CLIENT"],
    category: "finding"
  },
  {
    keywords: ["state", "state mismatch", "csrf"],
    ruleIds: ["OIDC_STATE_MISSING_OR_MISMATCH"],
    category: "finding"
  },
  {
    keywords: ["audience", "entity id", "audience mismatch"],
    ruleIds: ["SAML_AUDIENCE_MISMATCH"],
    category: "finding"
  },
  {
    keywords: ["acs", "recipient", "acs url", "assertion consumer"],
    ruleIds: ["SAML_ACS_RECIPIENT_MISMATCH"],
    category: "finding"
  },
  {
    keywords: ["destination", "destination mismatch"],
    ruleIds: ["SAML_DESTINATION_MISMATCH"],
    category: "finding"
  },
  {
    keywords: ["nameid", "name id", "missing nameid", "user identifier"],
    ruleIds: ["SAML_MISSING_NAMEID"],
    category: "finding"
  },
  {
    keywords: ["nameid format", "nameid policy"],
    ruleIds: ["SAML_NAMEID_FORMAT_MISMATCH"],
    category: "finding"
  },
  {
    keywords: ["clock", "skew", "time", "notbefore", "notonorafter", "expired"],
    ruleIds: ["SAML_CLOCK_SKEW", "SAML_CLOCK_SKEW_NOT_BEFORE"],
    category: "finding"
  },
  {
    keywords: ["signature", "signing", "signed", "assertion signature"],
    ruleIds: ["SAML_ASSERTION_SIGNATURE_MISSING", "SAML_DOCUMENT_SIGNATURE_MISSING"],
    category: "finding"
  },
  {
    keywords: ["certificate", "cert", "key", "validation"],
    ruleIds: ["SAML_CERT_SIGNATURE_VALIDATION_CLUE"],
    category: "finding"
  },
  {
    keywords: ["binding", "post binding", "redirect binding"],
    ruleIds: ["SAML_WRONG_BINDING_CLUE"],
    category: "finding"
  },
  {
    keywords: ["nonce"],
    ruleIds: ["OIDC_NONCE_MISSING"],
    category: "finding"
  },
  {
    keywords: ["pkce", "code verifier", "code challenge"],
    ruleIds: ["OIDC_PKCE_INCONSISTENT"],
    category: "finding"
  },
  {
    keywords: ["inresponseto", "sp initiated", "idp initiated"],
    ruleIds: ["SAML_INRESPONSETO_MISSING", "SAML_IDP_SP_INIT_MISMATCH_CLUE"],
    category: "finding"
  },
  {
    keywords: ["tenant", "case mismatch", "tenant name"],
    ruleIds: ["TENANT_CASE_MISMATCH"],
    category: "finding"
  },
  {
    keywords: ["rejected", "kzero rejected", "authnrequest rejected"],
    ruleIds: ["SAML_AUTHNREQUEST_REJECTED_BY_KZERO"],
    category: "finding"
  },
  {
    keywords: ["encryption", "encrypted"],
    ruleIds: ["SAML_ASSERTION_ENCRYPTED"],
    category: "finding"
  },
  {
    keywords: ["invalid redirect uri", "app says invalid", "says invalid redirect"],
    ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"],
    category: "finding"
  }
];

const CONCEPTUAL_KEYWORDS: KeywordMapping[] = [
  {
    keywords: ["saml", "what is saml", "saml explained"],
    ruleIds: [],
    category: "concept"
  },
  {
    keywords: ["oidc", "openid", "what is oidc", "oidc explained"],
    ruleIds: [],
    category: "concept"
  },
  {
    keywords: ["entity id", "what is entity id"],
    ruleIds: ["SAML_AUDIENCE_MISMATCH"],
    category: "concept"
  },
  {
    keywords: ["redirect uri", "what is redirect uri", "callback url"],
    ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"],
    category: "concept"
  },
  {
    keywords: ["issuer", "what is issuer"],
    ruleIds: ["OIDC_DISCOVERY_ISSUER_MISMATCH"],
    category: "concept"
  },
  {
    keywords: ["acs", "assertion consumer service"],
    ruleIds: ["SAML_ACS_RECIPIENT_MISMATCH"],
    category: "concept"
  }
];

const TROUBLESHOOTING_KEYWORDS: KeywordMapping[] = [
  {
    keywords: ["why failed", "why login failed", "why not working", "login not working", "login failed", "sign in failed", "why isn't my login working", "why is my login not working", "why is login failing", "sign in not working", "can't sign in", "cannot sign in"],
    ruleIds: [],
    category: "troubleshooting"
  },
  {
    keywords: ["why am i getting redirected back", "redirected back", "getting redirected", "keep getting redirected", "redirect loop", "why does it keep redirecting"],
    ruleIds: ["OIDC_STATE_MISSING_OR_MISMATCH", "OIDC_REDIRECT_URI_MISMATCH"],
    category: "troubleshooting"
  },
  {
    keywords: ["callback error", "callback url error", "invalid callback", "callback uri error"],
    ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"],
    category: "troubleshooting"
  },
  {
    keywords: ["saml error", "saml failing", "saml login failed", "why is saml failing", "saml not working"],
    ruleIds: [],
    category: "troubleshooting"
  },
  {
    keywords: ["oidc error", "oidc failing", "oidc login failed", "why is oidc failing", "openid not working"],
    ruleIds: [],
    category: "troubleshooting"
  },
  {
    keywords: ["invalid redirect uri", "invalid redirect", "redirect uri error", "redirect uri mismatch", "app says invalid redirect uri", "says invalid redirect uri", "callback url not matching"],
    ruleIds: ["OIDC_REDIRECT_URI_MISMATCH"],
    category: "troubleshooting"
  },
  {
    keywords: ["how to fix", "how do i fix", "fix this", "help me fix", "how do i resolve", "how to resolve"],
    ruleIds: [],
    category: "troubleshooting"
  },
  {
    keywords: ["how to configure", "setup", "configuration"],
    ruleIds: [],
    category: "troubleshooting"
  }
];

export function buildHelpContext(session: CaptureSession | null, findings: Finding[]): HelpContext {
  const tenants: string[] = [];
  
  if (session?.normalizedEvents) {
    const tenantPattern = /\/realms\/([a-zA-Z0-9-]+)/;
    for (const event of session.normalizedEvents) {
      const match = event.url.match(tenantPattern);
      if (match && !tenants.includes(match[1])) {
        tenants.push(match[1]);
      }
    }
  }

  let flow: "saml" | "oidc" | "unknown" = "unknown";
  if (session?.normalizedEvents) {
    const protocols = new Set(session.normalizedEvents.map(e => e.protocol));
    if (protocols.has("SAML") && protocols.has("OIDC")) flow = "oidc";
    else if (protocols.has("SAML")) flow = "saml";
    else if (protocols.has("OIDC")) flow = "oidc";
  }

  return {
    session,
    findings,
    tenants,
    flow
  };
}

export function mapQueryToIntent(query: string, ctx: HelpContext): IntentMatch {
  const normalizedQuery = query.toLowerCase().trim();
  
  for (const phrase of PHRASE_PATTERNS) {
    if (phrase.pattern.test(query)) {
      return {
        intent: phrase.intent || phrase.category,
        confidence: 0.85,
        ruleIds: phrase.ruleIds || (ctx.findings.length > 0 ? ctx.findings.map(f => f.ruleId).slice(0, 3) : [])
      };
    }
  }
  
  const allMappings = [...KEYWORD_MAPPINGS, ...CONCEPTUAL_KEYWORDS, ...TROUBLESHOOTING_KEYWORDS];
  
  let bestMatch: KeywordMapping | null = null;
  let highestScore = 0;

  for (const mapping of allMappings) {
    for (const keyword of mapping.keywords) {
      if (normalizedQuery.includes(keyword)) {
        const score = keyword.length;
        if (score > highestScore) {
          highestScore = score;
          bestMatch = mapping;
        }
      }
    }
  }

  if (!bestMatch) {
    if (ctx.findings.length > 0) {
      return {
        intent: "contextual_help",
        confidence: 0.6,
        ruleIds: ctx.findings.map(f => f.ruleId).slice(0, 3)
      };
    }
    return {
      intent: "general_help",
      confidence: 0.3,
      ruleIds: []
    };
  }

  if (bestMatch.category === "troubleshooting") {
    return {
      intent: "troubleshooting",
      confidence: 0.7,
      ruleIds: ctx.findings.length > 0 ? ctx.findings.map(f => f.ruleId).slice(0, 3) : []
    };
  }

  return {
    intent: bestMatch.category,
    confidence: highestScore > 5 ? 0.8 : 0.5,
    ruleIds: bestMatch.ruleIds
  };
}

export function getQuickSuggestions(ctx: HelpContext): QuickSuggestion[] {
  const suggestions: QuickSuggestion[] = [];

  if (ctx.findings.length > 0) {
    ctx.findings.slice(0, 3).forEach(finding => {
      suggestions.push({
        id: `finding-${finding.ruleId}`,
        label: finding.title,
        category: "finding",
        icon: finding.severity === "error" ? "🔴" : finding.severity === "warning" ? "⚠️" : "ℹ️"
      });
    });
  }

  suggestions.push({
    id: "concept-saml",
    label: "How does SAML work?",
    category: "concept",
    icon: "📖"
  });

  suggestions.push({
    id: "concept-oidc",
    label: "How does OIDC work?",
    category: "concept",
    icon: "📖"
  });

  suggestions.push({
    id: "troubleshoot-login",
    label: "Why is my login failing?",
    category: "troubleshooting",
    icon: "🔧"
  });

  suggestions.push({
    id: "concept-redirect",
    label: "What is a Redirect URI?",
    category: "concept",
    icon: "🔗"
  });

  suggestions.push({
    id: "concept-issuer",
    label: "What is an Issuer?",
    category: "concept",
    icon: "🏷️"
  });

  return suggestions;
}

export function getDefaultSuggestions(): QuickSuggestion[] {
  return [
    {
      id: "concept-saml",
      label: "How does SAML work?",
      category: "concept",
      icon: "📖"
    },
    {
      id: "concept-oidc",
      label: "How does OIDC work?",
      category: "concept",
      icon: "📖"
    },
    {
      id: "troubleshoot-login",
      label: "Why is my login failing?",
      category: "troubleshooting",
      icon: "🔧"
    },
    {
      id: "troubleshoot-config",
      label: "How do I configure my app?",
      category: "troubleshooting",
      icon: "⚙️"
    },
    {
      id: "concept-redirect",
      label: "What is a Redirect URI?",
      category: "concept",
      icon: "🔗"
    },
    {
      id: "concept-issuer",
      label: "What is an Issuer?",
      category: "concept",
      icon: "🏷️"
    }
  ];
}

export function getExplanationForIntent(intent: IntentMatch, ctx: HelpContext): string {
  if (intent.intent === "general_help") {
    return "I can help you understand and fix SSO login issues. Ask me about specific error messages, concepts like SAML or OIDC, or how to configure your application.";
  }

  if (intent.intent === "troubleshooting") {
    if (ctx.findings.length > 0) {
      const errorFindings = ctx.findings.filter(f => f.severity === "error");
      const warningFindings = ctx.findings.filter(f => f.severity === "warning");
      
      let response = "Based on your current findings, ";
      if (errorFindings.length > 0) {
        response += `you have ${errorFindings.length} problem${errorFindings.length > 1 ? "s" : ""} to fix. `;
        response += `The most critical is: ${errorFindings[0].title}. `;
      }
      if (warningFindings.length > 0) {
        response += `You also have ${warningFindings.length} warning${warningFindings.length > 1 ? "s" : ""} that may cause issues.`;
      }
      return response;
    }
    return "To help troubleshoot your login issue, try starting a capture and running a login flow. This will let me analyze what's happening and provide specific guidance.";
  }

  if (intent.intent === "contextual_help") {
    if (ctx.findings.length > 0) {
      const top = ctx.findings[0];
      return `I see you have findings from your capture. The top issue is: **${top.title}**. ${top.explanation}`;
    }
    return getExplanationForIntent({ intent: "general_help", confidence: 0.3, ruleIds: [] }, ctx);
  }

  if (intent.ruleIds.length > 0) {
    const ruleDoc = RULE_CATALOG.find(r => r.ruleId === intent.ruleIds[0]);
    if (ruleDoc) {
      return `${ruleDoc.short} ${ruleDoc.why}`;
    }
  }

  if (intent.intent === "concept") {
    return "I'd be happy to explain this concept. Could you ask a more specific question, like 'What is a Redirect URI?' or 'How does SAML work?'. You can also check the documentation links in each finding.";
  }

  return "I can help with that. Try clicking on one of the suggestions above, or ask a specific question about your login flow.";
}

export function getSuggestionsForQuery(query: string, ctx: HelpContext): QuickSuggestion[] {
  const intent = mapQueryToIntent(query, ctx);
  const suggestions: QuickSuggestion[] = [];

  if (intent.ruleIds.length > 0) {
    intent.ruleIds.forEach(ruleId => {
      const ruleDoc = RULE_CATALOG.find(r => r.ruleId === ruleId);
      if (ruleDoc) {
        suggestions.push({
          id: `suggest-${ruleId}`,
          label: ruleDoc.short,
          category: "finding",
          icon: "🔧"
        });
      }
    });
  }

  if (suggestions.length === 0) {
    if (ctx.findings.length > 0) {
      suggestions.push({
        id: "contextual-issues",
        label: `View ${ctx.findings.length} findings`,
        category: "finding",
        icon: "📋"
      });
    }
  }

  return suggestions;
}
