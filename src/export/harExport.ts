import type { CaptureSession } from '../shared/models';
import { sanitizeUrlParams, generateExportSalt } from '../shared/redaction';

interface HarEntry {
  startedDateTime: string;
  time: number;
  request: {
    method: string;
    url: string;
    httpVersion: string;
    headers: Array<{ name: string; value: string }>;
    queryString: Array<{ name: string; value: string }>;
    postData?: {
      mimeType: string;
      text: string;
    };
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    headers: Array<{ name: string; value: string }>;
    content: {
      size: number;
      mimeType: string;
      text?: string;
    };
    redirectURL: string;
  };
  cache: Record<string, unknown>;
  timings: { send: number; wait: number; receive: number };
}

interface HarLog {
  version: string;
  creator: { name: string; version: string };
  entries: HarEntry[];
}

interface Har {
  log: HarLog;
}

const SENSITIVE_HEADERS = [/authorization|cookie|x-api-key|secret|token|bearer/i];
const SENSITIVE_QUERY = [/access_token|id_token|code|state|nonce|saml|sso/i];

const statusText = (code: number): string => {
  if (code === 0) return 'Aborted';
  if (code < 200) return 'Informational';
  if (code < 300) return 'Success';
  if (code < 400) return 'Redirect';
  if (code < 500) return 'Client Error';
  if (code < 600) return 'Server Error';
  return 'Unknown';
};

const sanitizeHeaderValue = (name: string, value: string): string => {
  if (SENSITIVE_HEADERS.some((p) => p.test(name))) {
    return '[redacted]';
  }
  return value;
};

const sanitizeQueryParam = (name: string, value: string): string => {
  if (SENSITIVE_QUERY.some((p) => p.test(name))) {
    return '[redacted]';
  }
  return value;
};

const entriesFromSession = (
  session: CaptureSession | null,
  mode: 'raw' | 'sanitized'
): HarEntry[] => {
  if (!session) return [];
  const salt = mode === 'sanitized' ? generateExportSalt() : '';

  return session.rawEvents.map((raw): HarEntry => {
    const reqHeaders = Object.entries(raw.requestHeaders ?? {}).map(([name, value]) => ({
      name,
      value: mode === 'sanitized' ? sanitizeHeaderValue(name, value) : value
    }));
    const resHeaders = Object.entries(raw.responseHeaders ?? {}).map(([name, value]) => ({
      name,
      value: mode === 'sanitized' ? sanitizeHeaderValue(name, value) : value
    }));

    let url = raw.url;
    if (mode === 'sanitized') {
      try {
        url = sanitizeUrlParams(raw.url, salt);
      } catch {
        /* keep original url */
      }
    }

    const qs = Object.entries(raw.queryParams ?? {}).map(([name, value]) => ({
      name,
      value: mode === 'sanitized' ? sanitizeQueryParam(name, value) : value
    }));

    return {
      startedDateTime: new Date(raw.timestamp).toISOString(),
      time: raw.timingMs ?? 0,
      request: {
        method: raw.method ?? 'GET',
        url,
        httpVersion: 'HTTP/1.1',
        headers: reqHeaders,
        queryString: qs,
        postData:
          mode === 'raw' && raw.postBody
            ? {
                mimeType: 'application/x-www-form-urlencoded',
                text: raw.postBody
              }
            : undefined
      },
      response: {
        status: raw.statusCode ?? 0,
        statusText: statusText(raw.statusCode ?? 0),
        httpVersion: 'HTTP/1.1',
        headers: resHeaders,
        content: {
          size: mode === 'raw' && raw.responseBody ? raw.responseBody.length : 0,
          mimeType: 'text/html',
          text: mode === 'raw' ? raw.responseBody : undefined
        },
        redirectURL: raw.redirectUrl ?? ''
      },
      cache: {},
      timings: {
        send: 0,
        wait: raw.timingMs ?? 0,
        receive: 0
      }
    };
  });
};

export const buildHarExport = (
  session: CaptureSession | null,
  mode: 'raw' | 'sanitized' = 'sanitized'
): string => {
  const har: Har = {
    log: {
      version: '1.2',
      creator: {
        name: 'KZero Passwordless SSO Tracer',
        version: chrome.runtime.getManifest().version
      },
      entries: entriesFromSession(session, mode)
    }
  };
  return JSON.stringify(har, null, 2);
};

export const downloadHar = (
  session: CaptureSession | null,
  mode: 'raw' | 'sanitized' = 'sanitized'
): void => {
  if (!session) return;
  const content = buildHarExport(session, mode);
  const blob = new Blob([content], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `kzero-trace-${session.tabId}-${Date.now()}.har`;
  a.click();
  URL.revokeObjectURL(url);
};
