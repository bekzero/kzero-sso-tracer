import type { CaptureSession, ExportMetadata } from "../shared/models";
import { detectAuthBoundary } from "./filtering";

export interface RawExportBundle {
  generatedAt: string;
  product: string;
  tabId: number;
  events: CaptureSession["normalizedEvents"];
  findings: CaptureSession["findings"];
  metadata: ExportMetadata;
}

export const buildRawExport = (session: CaptureSession | null): RawExportBundle | null => {
  if (!session) return null;

  const boundary = detectAuthBoundary(session.normalizedEvents);

  const metadata: ExportMetadata = {
    mode: "raw",
    generatedAt: new Date().toISOString(),
    includePostLoginActivity: true,
    authBoundaryDetected: boundary.detected,
    redactionsApplied: []
  };

  return {
    generatedAt: metadata.generatedAt,
    product: "KZero Passwordless SSO Tracer",
    tabId: session.tabId,
    events: session.normalizedEvents,
    findings: session.findings,
    metadata
  };
};