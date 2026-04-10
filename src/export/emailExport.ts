import type { CaptureSession } from '../shared/models';
import { buildSanitizedExport } from './sanitizedExport';

export const generateEmailExport = (session: CaptureSession | null): Blob | null => {
  if (!session) return null;

  const sanitized = buildSanitizedExport(session, {
    mode: 'sanitized',
    includePostLoginActivity: false
  });

  if (!sanitized) return null;

  const content = JSON.stringify(sanitized, null, 2);
  return new Blob([content], { type: 'application/json' });
};

export const emailSessionToSupport = (session: CaptureSession | null): void => {
  const blob = generateEmailExport(session);
  if (!blob) return;

  const timestamp = Date.now();
  const tabId = session?.tabId ?? 'unknown';
  const filename = `kzero-session-${tabId}-${timestamp}.json`;

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);

  const subject = encodeURIComponent(`KZero SSO Tracer Session - Tab ${tabId}`);
  const body = encodeURIComponent(
    "Hi KZero Support,\n\nI've attached my session trace for support review.\n\nPlease review the attached file.\n\nThanks!"
  );

  window.open(`mailto:?subject=${subject}&body=${body}`);
};
