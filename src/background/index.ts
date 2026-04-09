import { getSession } from "../capture/sessionStore";
import { setupMessageHandlers, setupPortListeners } from "./handlers";
import { setupWebRequestListeners } from "./webrequest";

chrome.alarms.create("keepalive", { periodInMinutes: 0.25 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== "keepalive") return;
  chrome.tabs.query({ currentWindow: true, active: true }, (tabs) => {
    const tabId = tabs[0]?.id;
    if (typeof tabId === "number") {
      getSession(tabId);
    }
  });
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

    import("./ports").then(({ getPanelPorts }) => {
      const ports = getPanelPorts(tabId) ?? [];
      ports.forEach((port) => port.postMessage({ type: "COMMAND", command }));
    });
  });
});

setupPortListeners();
setupMessageHandlers();
setupWebRequestListeners();