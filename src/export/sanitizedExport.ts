import type { CaptureSession, NormalizedEvent, SanitizedExportBundle } from "../shared/models";
import { redactRecord } from "../shared/redaction";

const sanitizeEvent = (event: NormalizedEvent): NormalizedEvent => ({
  ...event,
  artifacts: redactRecord(event.artifacts)
});

export const buildSanitizedExport = (session: CaptureSession): SanitizedExportBundle => ({
  generatedAt: new Date().toISOString(),
  product: "KZero Passwordless SSO Tracer",
  notice: "Captured auth data stays local unless explicitly exported.",
  tabId: session.tabId,
  events: session.normalizedEvents.map(sanitizeEvent),
  findings: session.findings
});
