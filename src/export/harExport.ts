import type { CaptureSession } from "../shared/models";

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

const statusText = (code: number): string => {
  if (code === 0) return "Aborted";
  if (code < 200) return "Informational";
  if (code < 300) return "Success";
  if (code < 400) return "Redirect";
  if (code < 500) return "Client Error";
  if (code < 600) return "Server Error";
  return "Unknown";
};

const entriesFromSession = (session: CaptureSession | null): HarEntry[] => {
  if (!session) return [];
  return session.rawEvents.map((raw): HarEntry => {
    const reqHeaders = Object.entries(raw.requestHeaders ?? {}).map(([name, value]) => ({ name, value }));
    const resHeaders = Object.entries(raw.responseHeaders ?? {}).map(([name, value]) => ({ name, value }));
    const qs = Object.entries(raw.queryParams ?? {}).map(([name, value]) => ({ name, value }));

    return {
      startedDateTime: new Date(raw.timestamp).toISOString(),
      time: raw.timingMs ?? 0,
      request: {
        method: raw.method ?? "GET",
        url: raw.url,
        httpVersion: "HTTP/1.1",
        headers: reqHeaders,
        queryString: qs,
        postData: raw.postBody
          ? {
              mimeType: "application/x-www-form-urlencoded",
              text: raw.postBody
            }
          : undefined
      },
      response: {
        status: raw.statusCode ?? 0,
        statusText: statusText(raw.statusCode ?? 0),
        httpVersion: "HTTP/1.1",
        headers: resHeaders,
        content: {
          size: raw.responseBody ? raw.responseBody.length : 0,
          mimeType: "text/html",
          text: raw.responseBody
        },
        redirectURL: raw.redirectUrl ?? ""
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

export const buildHarExport = (session: CaptureSession | null): string => {
  const har: Har = {
    log: {
      version: "1.2",
      creator: {
        name: "KZero Passwordless SSO Tracer",
        version: chrome.runtime.getManifest().version
      },
      entries: entriesFromSession(session)
    }
  };
  return JSON.stringify(har, null, 2);
};

export const downloadHar = (session: CaptureSession | null): void => {
  if (!session) return;
  const content = buildHarExport(session);
  const blob = new Blob([content], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `kzero-trace-${session.tabId}-${Date.now()}.har`;
  a.click();
  URL.revokeObjectURL(url);
};
