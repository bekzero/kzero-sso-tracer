import type { RawCaptureEvent } from "../shared/models";
import { nowId } from "../shared/utils";

type UiFieldScanValue = { found: boolean; value?: string; kind?: string };

const normalizeLabel = (value: string): string =>
  value
    .replace(/\s+/g, " ")
    .replace(/[\*\?]+\s*$/g, "")
    .trim()
    .toLowerCase();

const SENSITIVE_INPUT_TYPES = new Set(["password", "hidden", "secret", "token"]);

const readControlValue = (el: Element): UiFieldScanValue | null => {
  const input = el as HTMLInputElement;
  if (input instanceof HTMLInputElement) {
    if (SENSITIVE_INPUT_TYPES.has(input.type.toLowerCase())) return null;
    if (input.type === "checkbox") return { found: true, value: input.checked ? "On" : "Off", kind: "checkbox" };
    return { found: true, value: input.value, kind: "input" };
  }
  if (el instanceof HTMLTextAreaElement) return { found: true, value: el.value, kind: "textarea" };
  if (el instanceof HTMLSelectElement) {
    const opt = el.selectedOptions?.[0];
    return { found: true, value: opt ? opt.textContent ?? "" : el.value, kind: "select" };
  }
  const ariaChecked = el.getAttribute("aria-checked");
  if (ariaChecked) return { found: true, value: ariaChecked === "true" ? "On" : "Off", kind: "aria-toggle" };
  const role = el.getAttribute("role");
  if (role === "combobox" || role === "switch") {
    return { found: true, value: (el as HTMLElement).innerText?.trim() ?? "", kind: role };
  }
  if ((el as HTMLElement).isContentEditable) return { found: true, value: (el as HTMLElement).innerText?.trim() ?? "", kind: "contenteditable" };
  return { found: true, value: (el as HTMLElement).innerText?.trim() ?? "", kind: "element" };
};

const findControlNearLabel = (labelEl: Element): Element | undefined => {
  if (labelEl instanceof HTMLLabelElement && labelEl.htmlFor) {
    const byFor = document.getElementById(labelEl.htmlFor);
    if (byFor) return byFor;
  }
  const container = labelEl.closest("div") ?? labelEl.parentElement;
  if (container) {
    const direct = container.querySelector(
      "input, textarea, select, [role='combobox'], [role='switch'], [contenteditable='true']"
    );
    if (direct) return direct;
  }
  const next = labelEl.nextElementSibling;
  if (next) {
    const within = next.querySelector(
      "input, textarea, select, [role='combobox'], [role='switch'], [contenteditable='true']"
    );
    if (within) return within;
    if (next.matches("input, textarea, select")) return next;
  }
  return undefined;
};

const findLabelElement = (targetLabel: string): Element | undefined => {
  const wanted = normalizeLabel(targetLabel);
  const candidates = Array.from(
    document.querySelectorAll(
      "label, [role='label'], [aria-label], [data-testid*='label'], [class*='label'], [class*='Label']"
    )
  );
  for (const el of candidates) {
    const aria = el.getAttribute("aria-label");
    if (aria && normalizeLabel(aria) === wanted) return el;
    const txt = (el as HTMLElement).innerText?.trim() ?? "";
    if (txt && normalizeLabel(txt) === wanted) return el;
  }

  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node: Node | null;
  while ((node = walker.nextNode())) {
    const text = node.textContent?.trim() ?? "";
    if (!text) continue;
    if (normalizeLabel(text) === wanted) {
      const parent = node.parentElement;
      if (parent) return parent;
    }
  }
  return undefined;
};

const scanFields = (labels: string[]): Record<string, UiFieldScanValue> => {
  const results: Record<string, UiFieldScanValue> = {};
  for (const label of labels) {
    const labelEl = findLabelElement(label);
    if (!labelEl) {
      results[label] = { found: false };
      continue;
    }
    const control = findControlNearLabel(labelEl);
    if (!control) {
      results[label] = { found: false };
      continue;
    }
    const result = readControlValue(control);
    if (result === null) {
      results[label] = { found: false };
      continue;
    }
    results[label] = result;
  }
  return results;
};

const highlightField = (label: string): boolean => {
  const labelEl = findLabelElement(label);
  if (!labelEl) return false;
  const target = findControlNearLabel(labelEl) ?? labelEl;
  const el = target as HTMLElement;
  el.scrollIntoView({ behavior: "smooth", block: "center" });

  const prev = el.getAttribute("data-kzero-highlight");
  el.setAttribute("data-kzero-highlight", "true");
  const oldOutline = el.style.outline;
  const oldBg = el.style.backgroundColor;
  el.style.outline = "2px solid #4dd1ff";
  el.style.backgroundColor = "rgba(77, 209, 255, 0.08)";

  window.setTimeout(() => {
    if (!prev) el.removeAttribute("data-kzero-highlight");
    el.style.outline = oldOutline;
    el.style.backgroundColor = oldBg;
  }, 2500);
  return true;
};

const highlightFirst = (labels: string[]): boolean => {
  for (const label of labels) {
    if (highlightField(label)) return true;
  }
  return false;
};

const safePostMessage = (port: chrome.runtime.Port, msg: unknown): void => {
  try {
    if (port) {
      port.postMessage(msg);
    }
  } catch {
    // Port may be disconnected or context invalidated
  }
};

const safeDisconnectPort = (port: chrome.runtime.Port | null | undefined): void => {
  try {
    if (port) {
      port.disconnect();
    }
  } catch {
    // Port already disconnected or context invalidated
  }
};

const safeSendMessage = (msg: unknown): void => {
  try {
    if (typeof chrome !== "undefined" && chrome.runtime?.id) {
      void chrome.runtime.sendMessage(msg);
    }
  } catch {
    // Extension context invalidated
  }
};

let port: chrome.runtime.Port | null = null;
let portAlive = false;

const initPort = (): void => {
  if (port) return;
  
  try {
    port = chrome.runtime.connect({ name: "kzero-content" });
    portAlive = true;
    
    port.onDisconnect.addListener(() => {
      portAlive = false;
      port = null;
      safeSendMessage({ type: "CONTENT_PORT_DISCONNECTED", tabId: undefined });
    });

    port.onMessage.addListener((msg) => {
      if (!portAlive || !port) return;
      if (msg?.type === "SCAN_FIELDS") {
        const results = scanFields(Array.isArray(msg.labels) ? msg.labels : []);
        safePostMessage(port, { type: "UI_SCAN_RESULT", requestId: msg.requestId, results });
      }
      if (msg?.type === "HIGHLIGHT_FIELD") {
        const labels = Array.isArray(msg.labels) ? msg.labels.map(String) : [String(msg.label ?? "")];
        highlightFirst(labels);
      }
    });
  } catch {
    // Failed to connect - extension context may be invalid
    port = null;
    portAlive = false;
  }
};

initPort();

window.addEventListener("pagehide", () => {
  portAlive = false;
  safeDisconnectPort(port);
  port = null;
});

window.addEventListener("pageshow", () => {
  if (!port && typeof chrome !== "undefined" && chrome.runtime?.id) {
    initPort();
  }
});

const extractForm = (form: HTMLFormElement): Record<string, string> => {
  const output: Record<string, string> = {};
  const formData = new FormData(form);
  formData.forEach((value, key) => {
    output[key] = String(value);
  });
  return output;
};

const sendSamlForm = (form: HTMLFormElement): void => {
  const fields = extractForm(form);
  if (!fields.SAMLRequest && !fields.SAMLResponse) return;

  const event: RawCaptureEvent = {
    id: nowId(),
    tabId: -1,
    source: "content-form",
    timestamp: Date.now(),
    url: form.action || location.href,
    method: (form.method || "POST").toUpperCase(),
    postBody: new URLSearchParams(fields).toString(),
    host: location.host
  };

  void chrome.runtime.sendMessage({ type: "CONTENT_FORM_EVENT", tabId: undefined, event });
};

document.addEventListener(
  "submit",
  (evt) => {
    const target = evt.target;
    if (!(target instanceof HTMLFormElement)) return;
    sendSamlForm(target);
  },
  true
);

const origSubmit = HTMLFormElement.prototype.submit;
HTMLFormElement.prototype.submit = function () {
  const fields = extractForm(this);
  if (fields.SAMLRequest || fields.SAMLResponse) {
    sendSamlForm(this);
  }
  return origSubmit.call(this);
};

const observedForms = new WeakSet<HTMLFormElement>();

const scanForms = (): void => {
  const forms = document.querySelectorAll<HTMLFormElement>("form[action]");
  const formArray = Array.from(forms);
  for (const form of formArray) {
    if (observedForms.has(form)) continue;
    observedForms.add(form);
    const fields = extractForm(form);
    if (fields.SAMLRequest || fields.SAMLResponse) {
      sendSamlForm(form);
    }
  }
};

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", scanForms);
} else {
  scanForms();
}

const domObserver = new MutationObserver(() => {
  scanForms();
});
domObserver.observe(document.documentElement, { childList: true, subtree: true });
