import { useMemo, useState } from "react";
import type { Finding, CaptureSession, Severity } from "../shared/models";

const severityRank = (s: Severity): number => (s === "error" ? 3 : s === "warning" ? 2 : 1);

interface ComparisonResult {
  left: CaptureSession | null;
  right: CaptureSession | null;
  leftOnly: Finding[];
  rightOnly: Finding[];
  shared: Finding[];
  severity: {
    leftProblems: number;
    rightProblems: number;
    improvement: number;
  };
}

export const compareSessions = (left: CaptureSession | null, right: CaptureSession | null): ComparisonResult => {
  if (!left || !right) {
    return {
      left,
      right,
      leftOnly: left?.findings ?? [],
      rightOnly: right?.findings ?? [],
      shared: [],
      severity: { leftProblems: 0, rightProblems: 0, improvement: 0 }
    };
  }

  const leftIds = new Set(left.findings.map(f => f.ruleId));
  const rightIds = new Set(right.findings.map(f => f.ruleId));
  const sharedIds = new Set([...leftIds].filter(id => rightIds.has(id)));

  const leftOnly = left.findings.filter(f => !rightIds.has(f.ruleId));
  const rightOnly = right.findings.filter(f => !leftIds.has(f.ruleId));
  const shared = right.findings.filter(f => sharedIds.has(f.ruleId));

  const leftProblems = left.findings.filter(f => f.severity === "error").length;
  const rightProblems = right.findings.filter(f => f.severity === "error").length;

  return {
    left,
    right,
    leftOnly,
    rightOnly,
    shared,
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
      background: severity === "error" ? "#ff5a67" : severity === "warning" ? "#ffb020" : "#4dd1ff",
      width: 8,
      height: 8,
      borderRadius: "50%",
      display: "inline-block",
      flexShrink: 0
    }}
  />
);

interface CompareProps {
  history: Array<{ id: string; startedAt?: number; tabId: number; findingCount: number; session: CaptureSession }>;
  onClose: () => void;
}

const Compare = ({ history, onClose }: CompareProps): JSX.Element => {
  const [leftId, setLeftId] = useState<string>("");
  const [rightId, setRightId] = useState<string>("");

  const left = leftId ? (history.find(h => h.id === leftId)?.session ?? null) : null;
  const right = rightId ? (history.find(h => h.id === rightId)?.session ?? null) : null;

  const comparison = useMemo(() => compareSessions(left, right), [left, right]);

  const sessionLabel = (session: CaptureSession, tabId: number) => {
    const date = session.startedAt ? new Date(session.startedAt).toLocaleString() : "Unknown";
    return `Tab ${tabId} — ${date}`;
  };

  return (
    <div className="compare-view">
      <div className="compare-head">
        <h2>Compare Sessions</h2>
        <button className="btn btn-ghost" onClick={onClose}>Close</button>
      </div>

      <div className="compare-selectors">
        <div className="compare-selector">
          <label>Session A (Before)</label>
          <select value={leftId} onChange={e => setLeftId(e.target.value)}>
            <option value="">Select a session...</option>
            {history.map(item => (
              <option key={item.id} value={item.id}>
                {sessionLabel(item.session, item.tabId)} — {item.findingCount} findings
              </option>
            ))}
          </select>
        </div>
        <div className="compare-arrow">vs</div>
        <div className="compare-selector">
          <label>Session B (After)</label>
          <select value={rightId} onChange={e => setRightId(e.target.value)}>
            <option value="">Select a session...</option>
            {history.map(item => (
              <option key={item.id} value={item.id}>
                {sessionLabel(item.session, item.tabId)} — {item.findingCount} findings
              </option>
            ))}
          </select>
        </div>
      </div>

      {left && right ? (
        <>
          <div className="compare-summary">
            <div className="compare-stat">
              <div className="compare-stat-num" style={{ color: "#ff5a67" }}>{comparison.severity.leftProblems}</div>
              <div className="compare-stat-label">Problems before</div>
            </div>
            <div className="compare-stat">
              <div className="compare-stat-num" style={{ color: "#ff5a67" }}>{comparison.severity.rightProblems}</div>
              <div className="compare-stat-label">Problems after</div>
            </div>
            <div className="compare-stat">
              <div
                className="compare-stat-num"
                style={{
                  color: comparison.severity.improvement > 0
                    ? "#3fe0b1"
                    : comparison.severity.improvement < 0
                    ? "#ff5a67"
                    : "#ffb020"
                }}
              >
                {comparison.severity.improvement > 0 ? "-" : comparison.severity.improvement < 0 ? "+" : ""}
                {Math.abs(comparison.severity.improvement)}
              </div>
              <div className="compare-stat-label">
                {comparison.severity.improvement > 0 ? "Fixed" : comparison.severity.improvement < 0 ? "New problems" : "No change"}
              </div>
            </div>
            <div className="compare-stat">
              <div className="compare-stat-num" style={{ color: "#a78bfa" }}>{comparison.shared.length}</div>
              <div className="compare-stat-label">Still present</div>
            </div>
          </div>

          {comparison.rightOnly.length > 0 && (
            <div className="compare-section">
              <div className="compare-section-title">
                <span className="compare-badge improved">Resolved in B</span>
                <span className="compare-count">{comparison.rightOnly.length}</span>
              </div>
              <ul className="compare-list">
                {comparison.rightOnly.map(f => (
                  <li key={f.id} className="compare-finding resolved">
                    <SeverityDot severity={f.severity} />
                    <span>{f.title}</span>
                    <span className="compare-owner">{f.likelyOwner}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {comparison.leftOnly.length > 0 && (
            <div className="compare-section">
              <div className="compare-section-title">
                <span className="compare-badge regression">New in B</span>
                <span className="compare-count">{comparison.leftOnly.length}</span>
              </div>
              <ul className="compare-list">
                {comparison.leftOnly.map(f => (
                  <li key={f.id} className="compare-finding new">
                    <SeverityDot severity={f.severity} />
                    <span>{f.title}</span>
                    <span className="compare-owner">{f.likelyOwner}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {comparison.shared.length > 0 && (
            <div className="compare-section">
              <div className="compare-section-title">
                <span className="compare-badge still">Present in both</span>
                <span className="compare-count">{comparison.shared.length}</span>
              </div>
              <ul className="compare-list">
                {comparison.shared.map(f => (
                  <li key={f.id} className="compare-finding shared">
                    <SeverityDot severity={f.severity} />
                    <span>{f.title}</span>
                    <span className="compare-owner">{f.likelyOwner}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {comparison.rightOnly.length === 0 && comparison.leftOnly.length === 0 && comparison.shared.length === 0 && (
            <div className="empty">No findings in either session.</div>
          )}
        </>
      ) : (
        <div className="empty" style={{ margin: "24px 16px" }}>
          Select two sessions above to compare findings across sessions.
        </div>
      )}
    </div>
  );
};

export default Compare;
