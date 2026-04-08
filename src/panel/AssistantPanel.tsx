import { useState, useRef, useEffect, useCallback, type KeyboardEvent } from "react";
import type { CaptureSession, Finding } from "../shared/models";
import { RULE_CATALOG } from "../shared/ruleCatalog";
import { buildHelpContext, getQuickSuggestions, getDefaultSuggestions, getExplanationForIntent, mapQueryToIntent, callAI, type QuickSuggestion, type HelpMessage, type AIResponse } from "../help";
import { isAIDisabledByPolicy } from "../help/ai/policy";

interface AssistantPanelProps {
  session: CaptureSession | null;
  findings: Finding[];
  isOpen: boolean;
  onToggle: () => void;
  onSelectFinding?: (ruleId: string) => void;
  aiEnabled?: boolean;
  aiApiKey?: string;
  aiIncludeFindings?: boolean;
}

export const AssistantPanel = ({
  session,
  findings,
  isOpen,
  onToggle,
  onSelectFinding,
  aiEnabled = false,
  aiApiKey = "",
  aiIncludeFindings = true
}: AssistantPanelProps): JSX.Element => {
  const [query, setQuery] = useState("");
  const [messages, setMessages] = useState<HelpMessage[]>([]);
  const [suggestions, setSuggestions] = useState<QuickSuggestion[]>([]);
  const [isExpanded, setIsExpanded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showConsent, setShowConsent] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const ctx = buildHelpContext(session, findings);
  const hasSession = session !== null;
  const hasFindings = findings.length > 0;
  const currentSuggestions = hasSession ? getQuickSuggestions(ctx) : getDefaultSuggestions();
  const aiAvailable = aiEnabled && aiApiKey && !isAIDisabledByPolicy();

  useEffect(() => {
    if (isOpen && suggestions.length === 0) {
      setSuggestions(currentSuggestions);
    }
  }, [isOpen, session]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen, isExpanded]);

  const handleSubmit = useCallback(async (): Promise<void> => {
    if (!query.trim()) return;

    const userMessage: HelpMessage = {
      id: `msg-${Date.now()}`,
      source: "user",
      content: query.trim(),
      timestamp: Date.now()
    };

    const intent = mapQueryToIntent(query, ctx);

    if (aiAvailable) {
      setIsLoading(true);
      setError(null);

      try {
        const aiResponse: AIResponse = await callAI(
          {
            question: query.trim(),
            findings: aiIncludeFindings ? findings : undefined,
            includeFindings: aiIncludeFindings
          },
          aiApiKey
        );

        if (aiResponse.success && aiResponse.content) {
          const assistantMessage: HelpMessage = {
            id: `msg-${Date.now()}-response`,
            source: "ai",
            content: aiResponse.content,
            timestamp: Date.now(),
            badge: "AI"
          };
          setMessages(prev => [...prev, userMessage, assistantMessage]);
        } else {
          const fallbackText = getExplanationForIntent(intent, ctx);
          const fallbackMessage: HelpMessage = {
            id: `msg-${Date.now()}-fallback`,
            source: "verified",
            content: `${fallbackText}\n\n(AI unavailable: ${aiResponse.error})`,
            timestamp: Date.now(),
            badge: "Verified"
          };
          setMessages(prev => [...prev, userMessage, fallbackMessage]);
        }
      } catch {
        const fallbackText = getExplanationForIntent(intent, ctx);
        const fallbackMessage: HelpMessage = {
          id: `msg-${Date.now()}-fallback`,
          source: "verified",
          content: fallbackText,
          timestamp: Date.now(),
          badge: "Verified"
        };
        setMessages(prev => [...prev, userMessage, fallbackMessage]);
      } finally {
        setIsLoading(false);
      }
    } else {
      const responseText = getExplanationForIntent(intent, ctx);

      const assistantMessage: HelpMessage = {
        id: `msg-${Date.now()}-response`,
        source: "verified",
        content: responseText,
        timestamp: Date.now(),
        badge: "Verified"
      };

      setMessages(prev => [...prev, userMessage, assistantMessage]);
    }

    setQuery("");
    const newSuggestions = currentSuggestions.slice(0, 4);
    setSuggestions(newSuggestions);
  }, [query, ctx, aiAvailable, aiApiKey, aiIncludeFindings, findings, currentSuggestions]);

  const handleSuggestionClick = (suggestion: QuickSuggestion): void => {
    if (suggestion.category === "finding" && suggestion.id.startsWith("finding-")) {
      const ruleId = suggestion.id.replace("finding-", "");
      
      const matchingFinding = findings.find(f => f.ruleId === ruleId);
      
      if (matchingFinding && onSelectFinding) {
        onSelectFinding(ruleId);
        return;
      }

      const ruleDoc = RULE_CATALOG.find(r => r.ruleId === ruleId);
      const explanation = ruleDoc 
        ? `${ruleDoc.short} ${ruleDoc.why}` 
        : "This issue was not detected in your current session.";
      
      const assistantMessage: HelpMessage = {
        id: `msg-${Date.now()}-${suggestion.id}`,
        source: "verified",
        content: matchingFinding ? explanation : `${explanation}\n\nStart a capture to detect this issue, or the issue may already be resolved.`,
        timestamp: Date.now(),
        badge: "Verified"
      };

      setMessages(prev => [...prev, assistantMessage]);
      return;
    }

    if (suggestion.category === "concept" || suggestion.category === "troubleshooting") {
      const intent = mapQueryToIntent(suggestion.label, ctx);
      const responseText = getExplanationForIntent(intent, ctx);

      const assistantMessage: HelpMessage = {
        id: `msg-${Date.now()}-${suggestion.id}`,
        source: "verified",
        content: responseText,
        timestamp: Date.now(),
        badge: "Verified"
      };

      setMessages(prev => [...prev, assistantMessage]);
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>): void => {
    if (e.key === "Enter" && !isLoading) {
      handleSubmit();
    }
    if (e.key === "Escape") {
      onToggle();
    }
  };

  const handleToggleExpand = (): void => {
    setIsExpanded(!isExpanded);
  };

  const handleClearChat = (): void => {
    setMessages([]);
    setSuggestions(currentSuggestions);
  };

  if (!isOpen) {
    return (
      <div className="assistant-collapsed-bar" onClick={onToggle}>
        <span className="assistant-collapsed-bar-text">Help</span>
        <span className="assistant-collapsed-bar-chevron">▲</span>
      </div>
    );
  }

  return (
    <div className={`assistant-panel ${isExpanded ? "expanded" : "collapsed"}`}>
      <div className="assistant-header">
        <div className="assistant-header-left">
          <span className="assistant-icon">?</span>
          <span className="assistant-title">Assistant</span>
          {aiAvailable && (
            <span className="assistant-ai-toggle active" style={{ marginLeft: "8px" }}>
              <span className="assistant-ai-toggle-dot" />
              AI
            </span>
          )}
        </div>
        <div className="assistant-header-right">
          {messages.length > 0 && (
            <button
              className="assistant-expand-btn"
              onClick={handleClearChat}
              title="Clear chat"
              style={{ fontSize: "12px", width: "auto", padding: "0 8px" }}
            >
              Clear
            </button>
          )}
          <button
            className="assistant-expand-btn"
            onClick={handleToggleExpand}
            title={isExpanded ? "Collapse" : "Expand"}
          >
            {isExpanded ? "▼" : "▲"}
          </button>
          <button className="assistant-close-btn" onClick={onToggle} title="Close">
            ×
          </button>
        </div>
      </div>

      {isExpanded && (
        <>
          <div className="assistant-messages">
            {messages.length === 0 ? (
              <div className="assistant-empty">
                <p className="assistant-welcome">SSO Assistant</p>
                <p className="assistant-welcome-sub">
                  {hasFindings 
                    ? "Review common issues · Ask a question · Get context-aware help"
                    : "Start a capture to get personalized help based on your findings"}
                  {aiAvailable && <span style={{ display: "block", marginTop: "4px", color: "var(--vendor)", fontSize: "12px" }}>AI assistant available</span>}
                </p>
              </div>
            ) : (
              messages.map(msg => (
                <div key={msg.id} className={`assistant-message assistant-message-${msg.source}`}>
                  {msg.badge && (
                    <span className={`assistant-badge assistant-badge-${msg.source === "ai" ? "ai" : "verified"}`}>
                      {msg.badge}
                    </span>
                  )}
                  <div className="assistant-message-content">{msg.content}</div>
                </div>
              ))
            )}
            {isLoading && (
              <div className="assistant-message assistant-message-ai">
                <span className="assistant-badge assistant-badge-ai">AI</span>
                <div className="assistant-loading">
                  <div className="assistant-loading-dots">
                    <span className="assistant-loading-dot" />
                    <span className="assistant-loading-dot" />
                    <span className="assistant-loading-dot" />
                  </div>
                  <span className="assistant-loading-text">Thinking...</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {messages.length === 0 && (
            <QuickSuggestionsComponent
              suggestions={suggestions}
              onSelect={handleSuggestionClick}
            />
          )}

          <div className="assistant-input-area">
            <input
              ref={inputRef}
              type="text"
              className="assistant-input"
              placeholder={aiAvailable ? "Ask a question..." : "Ask a question (AI available in settings)..."}
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={isLoading}
            />
            <button
              className="assistant-submit"
              onClick={handleSubmit}
              disabled={!query.trim() || isLoading}
            >
              →
            </button>
          </div>
        </>
      )}
    </div>
  );
};

interface QuickSuggestionsComponentProps {
  suggestions: QuickSuggestion[];
  onSelect: (suggestion: QuickSuggestion) => void;
}

const QuickSuggestionsComponent = ({ suggestions, onSelect }: QuickSuggestionsComponentProps): JSX.Element => {
  return (
    <div className="quick-suggestions">
      <div className="quick-suggestions-label">Quick questions</div>
      <div className="quick-suggestions-list">
        {suggestions.map(suggestion => (
          <button
            key={suggestion.id}
            className="quick-suggestion-chip"
            onClick={() => onSelect(suggestion)}
          >
            {suggestion.icon && <span className="suggestion-icon">{suggestion.icon}</span>}
            <span className="suggestion-label">{suggestion.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
};
