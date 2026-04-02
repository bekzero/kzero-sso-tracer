import type { CaptureSession, NormalizedEvent, NormalizedSamlEvent, NormalizedOidcEvent, SanitizedExportBundle, ExportMetadata, ExportMode } from "../shared/models";
import { redactRecord, sanitizeRelayState, buildRedactionSummary, isEmailLike, generateExportSalt, sanitizeOidcEventUrls, sanitizeOidcEventPayload } from "../shared/redaction";
import { filterEventsByMode, detectAuthBoundary } from "./filtering";

export interface SanitizedExportOptions {
  mode: ExportMode;
  includePostLoginActivity: boolean;
}

const isOidc = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === "OIDC";

const sanitizeOidcEvent = (
  event: NormalizedOidcEvent,
  salt: string,
  mode: ExportMode
): NormalizedOidcEvent => {
  const urlSanitized = sanitizeOidcEventUrls(event, salt) as NormalizedOidcEvent;
  const payloadSanitized = sanitizeOidcEventPayload(urlSanitized, salt) as NormalizedOidcEvent;
  return payloadSanitized;
};

const sanitizeEvent = (
  event: NormalizedEvent,
  counts: Map<string, number>,
  salt: string,
  mode: ExportMode
): NormalizedEvent => {
  if (mode !== "raw" && isOidc(event)) {
    return sanitizeOidcEvent(event as NormalizedOidcEvent, salt, mode);
  }

  const sanitized: NormalizedEvent = {
    ...event,
    artifacts: redactRecord(event.artifacts, counts)
  };

  if (event.protocol === "SAML") {
    const samlEvent = event as NormalizedSamlEvent;
    if (samlEvent.relayState) {
      (sanitized as NormalizedSamlEvent).relayState = sanitizeRelayState(samlEvent.relayState);
    }
    const nameIdValue = samlEvent.samlResponse?.nameId;
    if (nameIdValue && typeof nameIdValue === "string" && isEmailLike(nameIdValue)) {
      counts.set("email", (counts.get("email") || 0) + 1);
      const masked = nameIdValue.slice(0, 2) + "..." + nameIdValue.slice(-2);
      (sanitized as NormalizedSamlEvent).samlResponse = {
        ...samlEvent.samlResponse,
        nameId: masked
      } as any;
    }
  }

  return sanitized;
};

export const buildSanitizedExport = (
  session: CaptureSession | null,
  options?: Partial<SanitizedExportOptions>
): SanitizedExportBundle | null => {
  if (!session) return null;

  const mode = options?.mode ?? "sanitized";
  const includePostLogin = options?.includePostLoginActivity ?? false;
  const salt = generateExportSalt();

  const filteredEvents = filterEventsByMode(session.normalizedEvents, {
    mode,
    includePostLoginActivity: includePostLogin
  });

  const counts = new Map<string, number>();
  const sanitizedEvents = filteredEvents.map((e) => sanitizeEvent(e, counts, salt, mode));

  const boundary = detectAuthBoundary(session.normalizedEvents);

  const metadata: ExportMetadata = {
    mode,
    generatedAt: new Date().toISOString(),
    includePostLoginActivity: includePostLogin,
    authBoundaryDetected: boundary.detected,
    redactionsApplied: buildRedactionSummary(counts)
  };

  return {
    generatedAt: metadata.generatedAt,
    product: "KZero Passwordless SSO Tracer",
    notice: "Captured auth data stays local unless explicitly exported.",
    tabId: session.tabId,
    events: sanitizedEvents,
    findings: session.findings,
    metadata
  };
};