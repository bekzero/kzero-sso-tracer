import type { CaptureSession } from '../shared/models';

const escape = (value: string): string => {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
};

const escapeRow = (values: string[]): string => values.map(escape).join(',');

export const buildFindingsCsv = (session: CaptureSession | null): string => {
  if (!session) return '';
  const lines: string[] = [];

  lines.push(
    escapeRow([
      'Rule ID',
      'Severity',
      'Owner',
      'Protocol',
      'Title',
      'Explanation',
      'Confidence',
      'Linked Event'
    ])
  );

  for (const f of session.findings) {
    lines.push(
      escapeRow([
        f.ruleId,
        f.severity,
        f.likelyOwner,
        f.protocol,
        f.title,
        f.explanation,
        String(f.confidence),
        f.eventId ?? ''
      ])
    );
  }

  return lines.join('\n');
};

export const downloadFindingsCsv = (session: CaptureSession | null): void => {
  if (!session) return;
  const content = buildFindingsCsv(session);
  const blob = new Blob([content], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `kzero-findings-${session.tabId}-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
};

export const buildSummaryCsv = (session: CaptureSession | null): string => {
  if (!session) return '';
  const lines: string[] = [];
  lines.push('KZero Passwordless SSO Tracer — Session Summary');
  lines.push('');
  lines.push(escapeRow(['Tab ID', String(session.tabId)]));
  lines.push(
    escapeRow(['Started', session.startedAt ? new Date(session.startedAt).toISOString() : '-'])
  );
  lines.push(
    escapeRow(['Stopped', session.stoppedAt ? new Date(session.stoppedAt).toISOString() : '-'])
  );
  lines.push(
    escapeRow([
      'Duration (ms)',
      session.startedAt && session.stoppedAt ? String(session.stoppedAt - session.startedAt) : '-'
    ])
  );
  lines.push(escapeRow(['Total Events', String(session.normalizedEvents.length)]));
  lines.push(escapeRow(['Total Findings', String(session.findings.length)]));
  lines.push(
    escapeRow(['Problems', String(session.findings.filter((f) => f.severity === 'error').length)])
  );
  lines.push(
    escapeRow(['Warnings', String(session.findings.filter((f) => f.severity === 'warning').length)])
  );
  lines.push(
    escapeRow(['Notices', String(session.findings.filter((f) => f.severity === 'info').length)])
  );
  lines.push('');
  lines.push('Findings:');
  lines.push(buildFindingsCsv(session));
  return lines.join('\n');
};

export const downloadSummaryCsv = (session: CaptureSession | null): void => {
  if (!session) return;
  const content = buildSummaryCsv(session);
  const blob = new Blob([content], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `kzero-summary-${session.tabId}-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
};
