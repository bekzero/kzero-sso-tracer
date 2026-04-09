import type { RuntimeMessage, RuntimeResponse } from "../shared/messages";
import type { RawCaptureEvent } from "../shared/models";
import { 
  startCapture, stopCapture, clearSession, 
  getSession, getHistory, clearHistory, loadHistoryItem,
  addRawEvent
} from "../capture/sessionStore";
import { logDebug } from "../shared/debugLog";
import { broadcast, getContentPort, setContentPort, deleteContentPort, addPanelPort, removePanelPort, getPanelPorts } from "./ports";
import { makeRawEventFromDevtools } from "./webrequest";

const sendOk = (respond: (r: RuntimeResponse) => void, data?: Partial<RuntimeResponse>): void => {
  respond({ ok: true, ...data } as RuntimeResponse);
};

const sendError = (respond: (r: RuntimeResponse) => void, error: string): void => {
  respond({ ok: false, error });
};

const getTabId = (message: RuntimeMessage, sender: chrome.runtime.MessageSender): number | undefined => {
  return (message as { tabId?: number }).tabId ?? sender.tab?.id;
};

const ensureTabId = (tabId: number | undefined, respond: (r: RuntimeResponse) => void): tabId is number => {
  if (typeof tabId !== "number") {
    sendError(respond, "Missing tabId");
    return false;
  }
  return true;
};

const injectContentScript = async (tabId: number): Promise<boolean> => {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content.js"]
    });
    return true;
  } catch {
    return false;
  }
};

const handleScanRequest = async (
  respond: (r: RuntimeResponse) => void,
  tabId: number,
  messageType: "SCAN_FIELDS" | "HIGHLIGHT_FIELD",
  message: { requestId?: string; labels?: string[] }
): Promise<void> => {
  const port = getContentPort(tabId);
  if (port) {
    try {
      port.postMessage({ type: messageType, ...message });
      sendOk(respond);
      return;
    } catch {
      deleteContentPort(tabId);
    }
  }

  const injected = await injectContentScript(tabId);
  if (!injected) {
    sendError(respond, "Could not inject content script");
    return;
  }

  const retryPort = getContentPort(tabId);
  if (retryPort) {
    retryPort.postMessage({ type: messageType, ...message });
    sendOk(respond);
  } else {
    sendError(respond, "Content script did not connect after injection");
  }
};

export const setupMessageHandlers = (): void => {
  chrome.runtime.onMessage.addListener((message: RuntimeMessage, sender, sendResponse) => {
    const respond = (response: RuntimeResponse): void => sendResponse(response);

    if (message.type === "CONTENT_PORT_DISCONNECTED") {
      const tabId = sender.tab?.id;
      if (typeof tabId === "number") {
        deleteContentPort(tabId);
      }
      sendOk(respond);
      return true;
    }

    if (message.type === "GET_HISTORY") {
      void logDebug("background", "GET_HISTORY request");
      void getHistory().then((history) => sendOk(respond, { history }));
      return true;
    }

    if (message.type === "CLEAR_HISTORY") {
      void logDebug("background", "CLEAR_HISTORY request");
      clearHistory().then(() => getHistory()).then((history) => sendOk(respond, { history }));
      return true;
    }

    if (message.type === "SET_TAB") {
      const tabId = (message as { tabId?: number }).tabId;
      if (typeof tabId !== "number") {
        sendError(respond, "Missing tabId");
        return true;
      }
      void chrome.tabs.get(tabId, (tab) => {
        if (tab?.url) {
          sendOk(respond, { session: getSession(tabId) });
        } else {
          sendError(respond, "Tab not found");
        }
      });
      return true;
    }

    if (message.type === "LOAD_HISTORY_ITEM") {
      const msg = message as { itemId: string };
      void loadHistoryItem(msg.itemId).then((item) => {
        if (!item) {
          sendError(respond, "History item not found");
          return;
        }
        sendOk(respond, { session: undefined });
      });
      return true;
    }

    if (message.type === "REQUEST_UI_SCAN") {
      const msg = message as { tabId: number; requestId?: string; labels?: string[] };
      handleScanRequest(respond, msg.tabId, "SCAN_FIELDS", { requestId: msg.requestId, labels: msg.labels });
      return true;
    }

    if (message.type === "REQUEST_UI_HIGHLIGHT") {
      const msg = message as { tabId: number; requestId?: string; labels?: string[] };
      handleScanRequest(respond, msg.tabId, "HIGHLIGHT_FIELD", { requestId: msg.requestId, labels: msg.labels });
      return true;
    }

    if (message.type === "OPEN_POPUP") {
      const msg = message as { targetTabId?: number };
      const targetTabId = msg.targetTabId ?? -1;
      const url = chrome.runtime.getURL(`sidepanel.html?popup=1&targetTabId=${encodeURIComponent(String(targetTabId))}`);
      chrome.windows.create({ url, type: "popup", width: 560, height: 860 }, () => sendOk(respond));
      return true;
    }

    if (message.type === "REQUEST_AI") {
      const msg = message as { question: string; findings?: unknown[]; includeFindings: boolean; apiKey: string };
      void logDebug("background", "REQUEST_AI received", { 
        questionLength: msg.question?.length,
        hasFindings: Boolean(msg.findings && msg.findings.length > 0),
        hasApiKey: Boolean(msg.apiKey && msg.apiKey.trim().length > 0)
      });
      
      import("../help/ai/provider").then(({ callAI }) => {
        const findings = msg.findings as never;
        return callAI({ question: msg.question, findings, includeFindings: msg.includeFindings }, msg.apiKey);
      }).then((result) => {
        void logDebug("background", "REQUEST_AI completed", { 
          success: result.success,
          contentLength: result.content?.length
        });
        sendOk(respond, result);
      }).catch((err) => {
        const errorMsg = err instanceof Error ? err.message : "Unknown error";
        void logDebug("background", "REQUEST_AI failed", { error: errorMsg });
        sendError(respond, errorMsg);
      });
      return true;
    }

    const tabId = getTabId(message, sender);
    if (!ensureTabId(tabId, respond)) {
      return true;
    }

    switch (message.type) {
      case "START_CAPTURE": {
        void chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] }).catch(() => {});
        startCapture(tabId).then(session => {
          broadcast(tabId, session);
          sendOk(respond, { session });
        }).catch(() => {
          sendOk(respond, { session: getSession(tabId) });
        });
        return true;
      }
      case "STOP_CAPTURE": {
        const session = stopCapture(tabId);
        broadcast(tabId, session);
        sendOk(respond, { session });
        return;
      }
      case "CLEAR_SESSION": {
        const session = clearSession(tabId);
        broadcast(tabId, session);
        sendOk(respond, { session });
        return;
      }
      case "GET_SESSION": {
        sendOk(respond, { session: getSession(tabId) });
        return;
      }
      case "DEVTOOLS_NETWORK_EVENT": {
        const msg = message as { event: RawCaptureEvent };
        const event = makeRawEventFromDevtools(tabId, msg.event as never);
        addRawEvent(tabId, event).then(session => {
          if (session) broadcast(tabId, session);
          sendOk(respond, { session: session ?? getSession(tabId) });
        }).catch(() => {
          sendOk(respond, { session: getSession(tabId) });
        });
        return true;
      }
      case "CONTENT_FORM_EVENT": {
        const msg = message as { event: RawCaptureEvent };
        addRawEvent(tabId, msg.event).then(session => {
          if (session) broadcast(tabId, session);
          sendOk(respond, { session: session ?? getSession(tabId) });
        }).catch(() => {
          sendOk(respond, { session: getSession(tabId) });
        });
        return true;
      }
      default:
        sendError(respond, "Unsupported message type");
    }
    return true;
  });
};

export const setupPortListeners = (): void => {
  chrome.runtime.onConnect.addListener((port) => {
    if (port.name === "kzero-panel") {
      let tabId = port.sender?.tab?.id ?? -1;
      port.onMessage.addListener((msg: unknown) => {
        const message = msg as { type: string; tabId?: number };
        if (message.type === "PANEL_INIT") {
          tabId = message.tabId ?? tabId;
          addPanelPort(tabId, port);
          port.postMessage({ type: "SESSION_UPDATE", session: getSession(tabId) });
        }
      });
      port.onDisconnect.addListener(() => {
        if (tabId < 0) return;
        removePanelPort(tabId, port);
      });
    }

    if (port.name === "kzero-content") {
      const tabId = port.sender?.tab?.id;
      if (typeof tabId !== "number") return;
      setContentPort(tabId, port);
      port.onDisconnect.addListener(() => {
        const existing = getContentPort(tabId);
        if (existing === port) deleteContentPort(tabId);
      });
      port.onMessage.addListener((msg: unknown) => {
        const message = msg as { type: string };
        if (message?.type === "UI_SCAN_RESULT") {
          const ports = getPanelPorts(tabId);
          const fullMsg = msg as { [key: string]: unknown };
          ports.forEach((p) => p.postMessage({ ...fullMsg, tabId }));
        }
      });
    }
  });
};