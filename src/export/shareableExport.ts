import { buildSanitizedExport } from "./sanitizedExport";
import type { CaptureSession } from "../shared/models";

interface ShareableTrace {
  v: 1;
  tabId: number;
  startedAt: number | undefined;
  stoppedAt: number | undefined;
  events: ReturnType<typeof buildSanitizedExport>["events"];
  findings: ReturnType<typeof buildSanitizedExport>["findings"];
  summary: {
    eventCount: number;
    findingCount: number;
    problemCount: number;
    warningCount: number;
    protocolHints: string[];
  };
}

export const buildShareableTrace = (session: CaptureSession): ShareableTrace => {
  const export_ = buildSanitizedExport(session);
  return {
    v: 1,
    tabId: session.tabId,
    startedAt: session.startedAt,
    stoppedAt: session.stoppedAt,
    events: export_.events,
    findings: export_.findings,
    summary: {
      eventCount: session.normalizedEvents.length,
      findingCount: session.findings.length,
      problemCount: session.findings.filter(f => f.severity === "error").length,
      warningCount: session.findings.filter(f => f.severity === "warning").length,
      protocolHints: [...new Set(session.normalizedEvents.map(e => e.protocol))].filter(p => p !== "unknown")
    }
  };
};

export const encodeShareableTrace = (trace: ShareableTrace): string => {
  const json = JSON.stringify(trace);
  const encoded = btoa(unescape(encodeURIComponent(json)));
  return encoded;
};

export const buildShareableLink = (session: CaptureSession): string => {
  const trace = buildShareableTrace(session);
  const encoded = encodeShareableTrace(trace);
  return `https://kzero.app/sso-tracer?trace=${encoded}`;
};

export const downloadShareableTrace = (session: CaptureSession): void => {
  const trace = buildShareableTrace(session);
  const encoded = encodeShareableTrace(trace);
  const blob = new Blob([encoded], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `kzero-trace-shareable-${session.tabId}-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
};

export const copyShareableLink = async (session: CaptureSession): Promise<string> => {
  const link = buildShareableLink(session);
  await navigator.clipboard.writeText(link);
  return link;
};
