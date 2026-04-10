import type {
  CaptureSession,
  NormalizedEvent,
  NormalizedSamlEvent,
  NormalizedOidcEvent,
  SanitizedExportBundle,
  SanitizedEvent,
  SanitizedOidcEvent as SanitizedOidcEventType,
  ExportMetadata,
  ExportMode,
  Finding,
  SanitizedFinding
} from '../shared/models';
import {
  redactRecord,
  sanitizeRelayState,
  buildRedactionSummary,
  isEmailLike,
  generateExportSalt,
  sanitizeOidcTopLevelFields,
  sanitizeUrlParams
} from '../shared/redaction';
import { filterEventsByMode, detectAuthBoundary } from './filtering';

export interface SanitizedExportOptions {
  mode: ExportMode;
  includePostLoginActivity: boolean;
}

const isOidc = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === 'OIDC';
const isSaml = (e: NormalizedEvent): e is NormalizedSamlEvent => e.protocol === 'SAML';

const sanitizeOidcEvent = (
  event: NormalizedOidcEvent,
  salt: string,
  _mode: ExportMode
): SanitizedOidcEventType => {
  return sanitizeOidcTopLevelFields(event, salt);
};

const sanitizeEvent = (
  event: NormalizedEvent,
  counts: Map<string, number>,
  salt: string,
  mode: ExportMode
): SanitizedEvent => {
  if (mode !== 'raw' && isOidc(event)) {
    return sanitizeOidcEvent(event as NormalizedOidcEvent, salt, mode);
  }

  if (mode !== 'raw' && isSaml(event)) {
    const samlEvent = event as NormalizedSamlEvent;
    let maskedNameId = samlEvent.samlResponse?.nameId;
    if (maskedNameId && typeof maskedNameId === 'string' && isEmailLike(maskedNameId)) {
      counts.set('email', (counts.get('email') || 0) + 1);
      maskedNameId = maskedNameId.slice(0, 2) + '...' + maskedNameId.slice(-2);
    }
    return {
      ...samlEvent,
      url: samlEvent.url ? sanitizeUrlParams(samlEvent.url, salt) : undefined,
      artifacts: redactRecord(samlEvent.artifacts, counts),
      relayState: samlEvent.relayState ? sanitizeRelayState(samlEvent.relayState) : undefined,
      samlResponse: samlEvent.samlResponse
        ? {
            ...samlEvent.samlResponse,
            nameId: maskedNameId
          }
        : undefined
    };
  }

  return {
    ...event,
    url: event.url ? sanitizeUrlParams(event.url, salt) : undefined,
    artifacts: redactRecord(event.artifacts, counts)
  };
};

const sanitizeFinding = (finding: Finding): SanitizedFinding => {
  return {
    id: finding.id,
    ruleId: finding.ruleId,
    severity: finding.severity,
    protocol: finding.protocol,
    likelyOwner: finding.likelyOwner,
    title: finding.title,
    explanation: finding.explanation,
    confidence: finding.confidence,
    confidenceLevel: finding.confidenceLevel,
    eventId: finding.eventId,
    likelyFix: finding.likelyFix
      ? {
          kzeroFields: finding.likelyFix.kzeroFields,
          vendorFields: finding.likelyFix.vendorFields,
          action: finding.likelyFix.action
        }
      : undefined
  };
};

export const buildSanitizedExport = (
  session: CaptureSession | null,
  options?: Partial<SanitizedExportOptions>
): SanitizedExportBundle | null => {
  if (!session) return null;

  const mode = options?.mode ?? 'sanitized';
  const includePostLogin = options?.includePostLoginActivity ?? false;
  const salt = generateExportSalt();

  const filteredEvents = filterEventsByMode(session.normalizedEvents, {
    mode,
    includePostLoginActivity: includePostLogin
  });

  const counts = new Map<string, number>();
  const sanitizedEvents = filteredEvents.map((e) => sanitizeEvent(e, counts, salt, mode));
  const sanitizedFindings = session.findings.map((f) => sanitizeFinding(f));

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
    product: 'KZero Passwordless SSO Tracer',
    notice: 'Captured auth data stays local unless explicitly exported.',
    tabId: session.tabId,
    events: sanitizedEvents,
    findings: sanitizedFindings,
    metadata
  };
};
