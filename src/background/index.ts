import { addRawEvent, clearSession, getHistory, getSession, loadHistoryItem, startCapture, stopCapture } from "../capture/sessionStore";
import type { RuntimeMessage, RuntimeResponse } from "../shared/messages";
import { nowId, parseQueryString, toHeaderMap } from "../shared/utils";
import type { CaptureSession, RawCaptureEvent } from "../shared/models";

const panelPorts = new Map<number, chrome.runtime.Port[]>();
const contentPorts = new Map<number, chrome.runtime.Port>();

chrome.alarms.create("keepalive", { periodInMinutes: 0.25 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== "keepalive") return;
  void getSession(0);
});

chrome.runtime.onInstalled.addListener(() => {
  const sidePanel = (chrome as unknown as { sidePanel?: { setPanelBehavior?: (input: { openPanelOnActionClick: boolean }) => Promise<void> } }).sidePanel;
  if (!sidePanel?.setPanelBehavior) return;
  void sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
});

chrome.commands.onCommand.addListener((command) => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0]?.id;
    if (typeof tabId !== "number") return;

    const ports = panelPorts.get(tabId) ?? [];
    ports.forEach((port) => port.postMessage({ type: "COMMAND", command }));
  });
});

const broadcast = (tabId: number, session: CaptureSession): void => {
  const ports = panelPorts.get(tabId) ?? [];
  ports.forEach((port) => port.postMessage({ type: "SESSION_UPDATE", session }));
};

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "kzero-panel") return;
  let tabId = port.sender?.tab?.id ?? -1;
  port.onMessage.addListener((msg) => {
    if (msg.type === "PANEL_INIT") {
      tabId = msg.tabId ?? tabId;
      const ports = panelPorts.get(tabId) ?? [];
      ports.push(port);
      panelPorts.set(tabId, ports);
      port.postMessage({ type: "SESSION_UPDATE", session: getSession(tabId) });
    }
  });
  port.onDisconnect.addListener(() => {
    if (tabId < 0) return;
    const ports = (panelPorts.get(tabId) ?? []).filter((p) => p !== port);
    panelPorts.set(tabId, ports);
  });
});

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "kzero-content") return;
  const tabId = port.sender?.tab?.id;
  if (typeof tabId !== "number") return;
  contentPorts.set(tabId, port);
  port.onDisconnect.addListener(() => {
    const existing = contentPorts.get(tabId);
    if (existing === port) contentPorts.delete(tabId);
  });
  port.onMessage.addListener((msg) => {
    if (msg?.type === "UI_SCAN_RESULT") {
      const ports = panelPorts.get(tabId) ?? [];
      ports.forEach((p) => p.postMessage({ ...msg, tabId }));
    }
  });
});

chrome.runtime.onMessage.addListener((message: RuntimeMessage, sender, sendResponse) => {
  const respond = (response: RuntimeResponse): void => sendResponse(response);

  if (message.type === "GET_HISTORY") {
    void getHistory().then((history) => respond({ ok: true, history }));
    return true;
  }

  if (message.type === "LOAD_HISTORY_ITEM") {
    void loadHistoryItem(message.itemId).then((item) => {
      if (!item) {
        respond({ ok: false, error: "History item not found" });
        return;
      }
      respond({ ok: true, session: item.session });
    });
    return true;
  }

  if (message.type === "REQUEST_UI_SCAN") {
    const port = contentPorts.get(message.tabId);
    if (port) {
      port.postMessage({ type: "SCAN_FIELDS", requestId: message.requestId, labels: message.labels });
      respond({ ok: true });
    } else {
      void (async () => {
        try {
          await chrome.scripting.executeScript({
            target: { tabId: message.tabId },
            files: ["content.js"]
          });
          const retryPort = contentPorts.get(message.tabId);
          if (retryPort) {
            retryPort.postMessage({ type: "SCAN_FIELDS", requestId: message.requestId, labels: message.labels });
            respond({ ok: true });
          } else {
            respond({ ok: false, error: "Content script did not connect after injection" });
          }
        } catch (err) {
          respond({ ok: false, error: `Could not inject content script: ${err}` });
        }
      })();
    }
    return true;
  }

  if (message.type === "REQUEST_UI_HIGHLIGHT") {
    const port = contentPorts.get(message.tabId);
    if (port) {
      port.postMessage({ type: "HIGHLIGHT_FIELD", requestId: message.requestId, labels: message.labels });
      respond({ ok: true });
    } else {
      void (async () => {
        try {
          await chrome.scripting.executeScript({
            target: { tabId: message.tabId },
            files: ["content.js"]
          });
          const retryPort = contentPorts.get(message.tabId);
          if (retryPort) {
            retryPort.postMessage({ type: "HIGHLIGHT_FIELD", requestId: message.requestId, labels: message.labels });
          }
        } catch {
          // silently fail for highlights
        }
      })();
    }
    return;
  }

  if (message.type === "OPEN_POPUP") {
    const url = chrome.runtime.getURL(`sidepanel.html?popup=1&targetTabId=${encodeURIComponent(String(message.targetTabId))}`);
    chrome.windows.create(
      {
        url,
        type: "popup",
        width: 560,
        height: 860
      },
      () => respond({ ok: true })
    );
    return true;
  }

  const tabId = message.tabId ?? sender.tab?.id;
  if (typeof tabId !== "number") {
    respond({ ok: false, error: "Missing tabId" });
    return;
  }

  switch (message.type) {
    case "START_CAPTURE": {
      const session = startCapture(tabId);
      broadcast(tabId, session);
      respond({ ok: true, session });
      return;
    }
    case "STOP_CAPTURE": {
      const session = stopCapture(tabId);
      broadcast(tabId, session);
      respond({ ok: true, session });
      return;
    }
    case "CLEAR_SESSION": {
      const session = clearSession(tabId);
      broadcast(tabId, session);
      respond({ ok: true, session });
      return;
    }
    case "GET_SESSION": {
      respond({ ok: true, session: getSession(tabId) });
      return;
    }
    case "DEVTOOLS_NETWORK_EVENT":
    case "CONTENT_FORM_EVENT": {
      const session = addRawEvent(tabId, message.event);
      if (session) broadcast(tabId, session);
      respond({ ok: true, session: session ?? getSession(tabId) });
      return;
    }
    default:
      respond({ ok: false, error: "Unsupported message type" });
  }
  return true;
});

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
  source: errorText ? "webrequest-error" : "webrequest",
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
      return "";
    }
  })()
});

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const event = makeWebRequestEvent(
      details.tabId,
      details.url,
      details.method,
      details.statusCode,
      toHeaderMap(details.requestHeaders),
      toHeaderMap(details.responseHeaders),
      parseQueryString(details.url.split("?")[1] ?? "")
    );
    void chrome.storage.local.set({ _debug_last_event: event });
    const session = addRawEvent(details.tabId, event);
    if (session) broadcast(details.tabId, session);
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const event: RawCaptureEvent = {
      id: nowId(),
      tabId: details.tabId,
      source: "webrequest",
      timestamp: Date.now(),
      url: details.url,
      method: details.method,
      postBody: details.requestBody?.raw?.[0]?.bytes
        ? String.fromCharCode(...new Uint8Array(details.requestBody.raw[0].bytes as ArrayBuffer))
        : undefined,
      queryParams: parseQueryString(details.url.split("?")[1] ?? ""),
      host: (() => {
        try {
          return new URL(details.url).host;
        } catch {
          return "";
        }
      })()
    };
    void chrome.storage.local.set({ _debug_last_event: event });
    const session = addRawEvent(details.tabId, event);
    if (session) broadcast(details.tabId, session);
  },
  { urls: ["<all_urls>"], types: ["main_frame", "sub_frame"] },
  ["requestBody"]
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
      parseQueryString(details.url.split("?")[1] ?? ""),
      details.error
    );
    const session = addRawEvent(details.tabId, event);
    if (session) broadcast(details.tabId, session);
  },
  { urls: ["<all_urls>"] }
);

export const makeRawEventFromDevtools = (tabId: number, payload: {
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
}): RawCaptureEvent => ({
  id: nowId(),
  tabId,
  source: "devtools-network",
  timestamp: payload.startedDateTime ? Date.parse(payload.startedDateTime) : Date.now(),
  url: payload.url,
  method: payload.method,
  statusCode: payload.statusCode,
  requestHeaders: toHeaderMap(payload.requestHeaders ?? []),
  responseHeaders: toHeaderMap(payload.responseHeaders ?? []),
  queryParams: parseQueryString(
    (payload.queryString ?? []).map((entry) => `${encodeURIComponent(entry.name)}=${encodeURIComponent(entry.value)}`).join("&")
  ),
  postBody: payload.postData,
  responseBody: payload.responseBody,
  redirectUrl: payload.redirectURL,
  timingMs: payload.time,
  host: (() => {
    try {
      return new URL(payload.url).host;
    } catch {
      return "";
    }
  })()
});
