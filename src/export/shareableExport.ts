import { buildSanitizedExport } from "./sanitizedExport";
import type { CaptureSession, SanitizedEvent } from "../shared/models";

interface ShareableTrace {
  v: 1;
  tabId: number;
  startedAt: number | undefined;
  stoppedAt: number | undefined;
  events: SanitizedEvent[];
  findings: Array<{ id: string; ruleId: string; title: string; severity: string }>;
  summary: {
    eventCount: number;
    findingCount: number;
    problemCount: number;
    warningCount: number;
    protocolHints: string[];
  };
}

export const buildShareableTrace = (session: CaptureSession | null): ShareableTrace | null => {
  const export_ = buildSanitizedExport(session);
  if (!export_ || !session) return null;
  return {
    v: 1,
    tabId: session.tabId,
    startedAt: session.startedAt,
    stoppedAt: session.stoppedAt,
    events: export_.events,
    findings: session.findings.map(f => ({ id: f.id, ruleId: f.ruleId, title: f.title, severity: f.severity })),
    summary: {
      eventCount: session.normalizedEvents.length,
      findingCount: session.findings.length,
      problemCount: session.findings.filter(f => f.severity === "error").length,
      warningCount: session.findings.filter(f => f.severity === "warning").length,
      protocolHints: [...new Set(session.normalizedEvents.map(e => e.protocol))].filter(p => p !== "unknown")
    }
  };
};

const utf8ToBase64 = (str: string): string => {
  return btoa(unescape(encodeURIComponent(str)));
};

export const encodeShareableTrace = (trace: ShareableTrace): string => {
  const json = JSON.stringify(trace);
  return utf8ToBase64(json);
};

export const buildShareableLink = (session: CaptureSession | null): string | null => {
  const trace = buildShareableTrace(session);
  if (!trace) return null;
  const encoded = encodeShareableTrace(trace);
  const viewerUrl = chrome.runtime.getURL("viewer.html");
  return `${viewerUrl}?trace=${encodeURIComponent(encoded)}`;
};

export const downloadShareableTrace = (session: CaptureSession | null): void => {
  const trace = buildShareableTrace(session);
  if (!trace) return;
  const encoded = encodeShareableTrace(trace);
  const blob = new Blob([encoded], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `kzero-trace-shareable-${trace.tabId}-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
};

export const copyShareableLink = async (session: CaptureSession | null): Promise<string | null> => {
  const link = buildShareableLink(session);
  if (!link) return null;
  await navigator.clipboard.writeText(link);
  return link;
};
