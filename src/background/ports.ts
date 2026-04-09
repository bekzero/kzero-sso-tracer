import type { CaptureSession } from "../shared/models";

export const panelPorts = new Map<number, chrome.runtime.Port[]>();
export const contentPorts = new Map<number, chrome.runtime.Port>();

export const broadcast = (tabId: number, session: CaptureSession): void => {
  const ports = panelPorts.get(tabId) ?? [];
  ports.forEach((port) => {
    try {
      port.postMessage({ type: "SESSION_UPDATE", session });
    } catch {
      panelPorts.delete(tabId);
    }
  });
};

export const getPanelPorts = (tabId: number): chrome.runtime.Port[] => panelPorts.get(tabId) ?? [];

export const getContentPort = (tabId: number): chrome.runtime.Port | undefined => contentPorts.get(tabId);

export const setContentPort = (tabId: number, port: chrome.runtime.Port): void => {
  contentPorts.set(tabId, port);
};

export const deleteContentPort = (tabId: number): void => {
  contentPorts.delete(tabId);
};

export const addPanelPort = (tabId: number, port: chrome.runtime.Port): void => {
  const ports = panelPorts.get(tabId) ?? [];
  ports.push(port);
  panelPorts.set(tabId, ports);
};

export const removePanelPort = (tabId: number, port: chrome.runtime.Port): void => {
  const ports = (panelPorts.get(tabId) ?? []).filter((p) => p !== port);
  panelPorts.set(tabId, ports);
};

export const sendToPanel = (tabId: number, message: unknown): void => {
  const ports = panelPorts.get(tabId) ?? [];
  ports.forEach((p) => {
    try {
      p.postMessage(message);
    } catch {
      // Port may be disconnected
    }
  });
};