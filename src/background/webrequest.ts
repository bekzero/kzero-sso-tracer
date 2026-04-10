import { addRawEvent } from '../capture/sessionStore';
import { parseQueryString, toHeaderMap } from '../shared/utils';
import type { RawCaptureEvent } from '../shared/models';
import { nowId } from '../shared/utils';
import { sendToPanel } from './ports';

const makeWebRequestEvent = (
  tabId: number,
  url: string,
  method?: string,
  statusCode?: number,
  requestHeaders?: Record<string, string>,
  responseHeaders?: Record<string, string>,
  queryParams?: Record<string, string>,
  errorText?: string,
  redirectUrl?: string,
  timingMs?: number
): RawCaptureEvent => ({
  id: nowId(),
  tabId,
  source: errorText ? 'webrequest-error' : 'webrequest',
  timestamp: Date.now(),
  url,
  method,
  statusCode,
  requestHeaders,
  responseHeaders,
  queryParams,
  errorText,
  redirectUrl,
  timingMs,
  host: (() => {
    try {
      return new URL(url).host;
    } catch {
      return '';
    }
  })()
});

export const setupWebRequestListeners = (): void => {
  chrome.webRequest.onCompleted.addListener(
    (details) => {
      if (details.tabId < 0) return;
      const event = makeWebRequestEvent(
        details.tabId,
        details.url,
        details.method,
        details.statusCode,
        undefined,
        details.responseHeaders ? toHeaderMap(details.responseHeaders) : undefined,
        parseQueryString(details.url.split('?')[1] ?? '')
      );
      addRawEvent(details.tabId, event).then((session) => {
        if (session) {
          sendToPanel(details.tabId, { type: 'SESSION_UPDATE', session });
        }
      });
    },
    { urls: ['<all_urls>'] }
  );

  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (details.tabId < 0) return;
      let postBody: string | undefined;
      if (details.requestBody?.raw?.[0]?.bytes) {
        const bytes = details.requestBody.raw[0].bytes as ArrayBuffer;
        if (bytes.byteLength > 100 * 1024) {
          postBody = '[body truncated — exceeds 100KB]';
        } else {
          postBody = String.fromCharCode(...new Uint8Array(bytes));
        }
      }
      const event: RawCaptureEvent = {
        id: nowId(),
        tabId: details.tabId,
        source: 'webrequest',
        timestamp: Date.now(),
        url: details.url,
        method: details.method,
        postBody,
        queryParams: parseQueryString(details.url.split('?')[1] ?? ''),
        host: (() => {
          try {
            return new URL(details.url).host;
          } catch {
            return '';
          }
        })()
      };
      addRawEvent(details.tabId, event).then((session) => {
        if (session) {
          sendToPanel(details.tabId, { type: 'SESSION_UPDATE', session });
        }
      });
    },
    { urls: ['<all_urls>'], types: ['main_frame', 'sub_frame'] },
    ['requestBody']
  );

  chrome.webRequest.onErrorOccurred.addListener(
    (details) => {
      if (details.tabId < 0) return;
      const event = makeWebRequestEvent(
        details.tabId,
        details.url,
        details.method,
        undefined,
        undefined,
        undefined,
        parseQueryString(details.url.split('?')[1] ?? ''),
        details.error
      );
      addRawEvent(details.tabId, event).then((session) => {
        if (session) {
          sendToPanel(details.tabId, { type: 'SESSION_UPDATE', session });
        }
      });
    },
    { urls: ['<all_urls>'] }
  );
};

export const makeRawEventFromDevtools = (
  tabId: number,
  payload: {
    url: string;
    method?: string;
    statusCode?: number;
    requestHeaders?: Array<{ name: string; value?: string }>;
    responseHeaders?: Array<{ name: string; value?: string }>;
    queryString?: Array<{ name: string; value: string }>;
    postData?: string;
    responseBody?: string;
    redirectURL?: string;
    startedDateTime?: string;
    time?: number;
  }
): RawCaptureEvent => ({
  id: nowId(),
  tabId,
  source: 'devtools-network',
  timestamp: payload.startedDateTime ? Date.parse(payload.startedDateTime) : Date.now(),
  url: payload.url,
  method: payload.method,
  statusCode: payload.statusCode,
  requestHeaders: toHeaderMap(payload.requestHeaders ?? []),
  responseHeaders: toHeaderMap(payload.responseHeaders ?? []),
  queryParams: parseQueryString(
    (payload.queryString ?? [])
      .map((entry) => `${encodeURIComponent(entry.name)}=${encodeURIComponent(entry.value)}`)
      .join('&')
  ),
  postBody: payload.postData,
  responseBody: payload.responseBody,
  redirectUrl: payload.redirectURL,
  timingMs: payload.time,
  host: (() => {
    try {
      return new URL(payload.url).host;
    } catch {
      return '';
    }
  })()
});
