import { useMemo, useState } from 'react';
import type { CaptureHistoryItem, Severity } from '../shared/models';

const _severityRank = (_s: Severity): number => 0;

interface ComparisonResult {
  left: CaptureHistoryItem | null;
  right: CaptureHistoryItem | null;
  leftOnlyCount: number;
  rightOnlyCount: number;
  severity: {
    leftProblems: number;
    rightProblems: number;
    improvement: number;
  };
}

export const compareHistoryItems = (
  left: CaptureHistoryItem | null,
  right: CaptureHistoryItem | null
): ComparisonResult => {
  if (!left || !right) {
    return {
      left,
      right,
      leftOnlyCount: left?.findingCount ?? 0,
      rightOnlyCount: right?.findingCount ?? 0,
      severity: { leftProblems: 0, rightProblems: 0, improvement: 0 }
    };
  }

  const leftProblems = left.findingCount;
  const rightProblems = right.findingCount;

  return {
    left,
    right,
    leftOnlyCount: left.findingCount,
    rightOnlyCount: right.findingCount,
    severity: {
      leftProblems,
      rightProblems,
      improvement: leftProblems - rightProblems
    }
  };
};

const SeverityDot = ({ severity }: { severity: Severity }): JSX.Element => (
  <span
    className="severity-dot"
    style={{
      background: severity === 'error' ? '#ff5a67' : severity === 'warning' ? '#ffb020' : '#4dd1ff',
      width: 8,
      height: 8,
      borderRadius: '50%',
      display: 'inline-block',
      flexShrink: 0
    }}
  />
);

interface CompareProps {
  history: CaptureHistoryItem[];
  onClose: () => void;
}

const Compare = ({ history, onClose }: CompareProps): JSX.Element => {
  const [leftId, setLeftId] = useState<string>('');
  const [rightId, setRightId] = useState<string>('');

  const left = leftId ? (history.find((h) => h.id === leftId) ?? null) : null;
  const right = rightId ? (history.find((h) => h.id === rightId) ?? null) : null;

  const comparison = useMemo(() => compareHistoryItems(left, right), [left, right]);

  const sessionLabel = (item: CaptureHistoryItem) => {
    const date = item.startedAt ? new Date(item.startedAt).toLocaleString() : 'Unknown';
    return `Tab ${item.tabId} — ${date}`;
  };

  return (
    <div className="compare-view">
      <div className="compare-head">
        <h2>Compare Sessions</h2>
        <button className="btn btn-ghost" onClick={onClose}>
          Close
        </button>
      </div>

      <div className="compare-selectors">
        <div className="compare-selector">
          <label>Session A (Before)</label>
          <select value={leftId} onChange={(e) => setLeftId(e.target.value)}>
            <option value="">Select a session...</option>
            {history.map((item) => (
              <option key={item.id} value={item.id}>
                {sessionLabel(item)} — {item.findingCount} findings
              </option>
            ))}
          </select>
        </div>
        <div className="compare-arrow">vs</div>
        <div className="compare-selector">
          <label>Session B (After)</label>
          <select value={rightId} onChange={(e) => setRightId(e.target.value)}>
            <option value="">Select a session...</option>
            {history.map((item) => (
              <option key={item.id} value={item.id}>
                {sessionLabel(item)} — {item.findingCount} findings
              </option>
            ))}
          </select>
        </div>
      </div>

      {left && right ? (
        <>
          <div className="compare-summary">
            <div className="compare-stat">
              <div className="compare-stat-num" style={{ color: '#ff5a67' }}>
                {comparison.severity.leftProblems}
              </div>
              <div className="compare-stat-label">Findings before</div>
            </div>
            <div className="compare-stat">
              <div className="compare-stat-num" style={{ color: '#ff5a67' }}>
                {comparison.severity.rightProblems}
              </div>
              <div className="compare-stat-label">Findings after</div>
            </div>
            <div className="compare-stat">
              <div
                className="compare-stat-num"
                style={{
                  color:
                    comparison.severity.improvement > 0
                      ? '#3fe0b1'
                      : comparison.severity.improvement < 0
                        ? '#ff5a67'
                        : '#ffb020'
                }}
              >
                {comparison.severity.improvement > 0
                  ? '-'
                  : comparison.severity.improvement < 0
                    ? '+'
                    : ''}
                {Math.abs(comparison.severity.improvement)}
              </div>
              <div className="compare-stat-label">
                {comparison.severity.improvement > 0
                  ? 'Reduced'
                  : comparison.severity.improvement < 0
                    ? 'Increased'
                    : 'No change'}
              </div>
            </div>
          </div>

          {left.topFindings &&
            right.topFindings &&
            left.topFindings.length > 0 &&
            right.topFindings.length > 0 && (
              <div className="compare-section">
                <div className="compare-section-title">
                  <span className="compare-badge">Top findings comparison</span>
                </div>
                <div style={{ padding: '12px', fontSize: 13, color: 'var(--muted)' }}>
                  Comparing by finding count only — detailed finding comparison requires loading
                  full sessions (not currently persisted).
                </div>
              </div>
            )}
        </>
      ) : (
        <div className="empty" style={{ margin: '24px 16px' }}>
          Select two sessions above to compare findings.
        </div>
      )}
    </div>
  );
};

export default Compare;
