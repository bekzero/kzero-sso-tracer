import type { QuickSuggestion } from "../help/types";

interface QuickSuggestionsProps {
  suggestions: QuickSuggestion[];
  onSelect: (suggestion: QuickSuggestion) => void;
}

export const QuickSuggestions = ({ suggestions, onSelect }: QuickSuggestionsProps): JSX.Element => {
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
