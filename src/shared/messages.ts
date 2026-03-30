import type { CaptureHistoryItem, CaptureSession, RawCaptureEvent } from "./models";

export type RuntimeMessage =
  | { type: "START_CAPTURE"; tabId: number }
  | { type: "STOP_CAPTURE"; tabId: number }
  | { type: "CLEAR_SESSION"; tabId: number }
  | { type: "GET_SESSION"; tabId: number }
  | { type: "GET_HISTORY" }
  | { type: "LOAD_HISTORY_ITEM"; itemId: string }
  | { type: "REQUEST_UI_SCAN"; tabId: number; requestId: string; labels: string[] }
  | { type: "REQUEST_UI_HIGHLIGHT"; tabId: number; requestId: string; labels: string[] }
  | { type: "OPEN_POPUP"; targetTabId: number }
  | { type: "DEVTOOLS_NETWORK_EVENT"; tabId: number; event: RawCaptureEvent }
  | { type: "CONTENT_FORM_EVENT"; tabId: number; event: RawCaptureEvent };

export type RuntimeResponse =
  | { ok: true; session?: CaptureSession; history?: CaptureHistoryItem[] }
  | { ok: false; error: string };

export interface UiFieldScanValue {
  found: boolean;
  value?: string;
  kind?: string;
}

export interface UiScanResultPayload {
  type: "UI_SCAN_RESULT";
  tabId: number;
  requestId: string;
  results: Record<string, UiFieldScanValue>;
}
