import type {
  CaptureHistoryItem,
  CaptureHistorySummary,
  CaptureSession,
  RawCaptureEvent,
  Finding
} from './models';

export type RuntimeMessage =
  | { type: 'START_CAPTURE'; tabId: number }
  | { type: 'STOP_CAPTURE'; tabId: number }
  | { type: 'CLEAR_SESSION'; tabId: number }
  | { type: 'CLEAR_HISTORY' }
  | { type: 'GET_SESSION'; tabId: number }
  | { type: 'GET_HISTORY' }
  | { type: 'SET_TAB'; tabId: number }
  | { type: 'LOAD_HISTORY_ITEM'; itemId: string }
  | { type: 'REQUEST_UI_SCAN'; tabId: number; requestId: string; labels: string[] }
  | { type: 'REQUEST_UI_HIGHLIGHT'; tabId: number; requestId: string; labels: string[] }
  | {
      type: 'REQUEST_AI';
      question: string;
      findings?: Finding[];
      includeFindings: boolean;
      apiKey: string;
    }
  | { type: 'OPEN_POPUP'; targetTabId: number }
  | { type: 'DEVTOOLS_NETWORK_EVENT'; tabId: number; event: RawCaptureEvent }
  | { type: 'CONTENT_FORM_EVENT'; tabId: number; event: RawCaptureEvent }
  | { type: 'CONTENT_PORT_DISCONNECTED'; tabId?: number };

export type RuntimeResponse =
  | {
      ok: true;
      session?: CaptureSession;
      history?: CaptureHistoryItem[];
      historySummary?: CaptureHistorySummary;
      content?: string;
      provider?: string;
      success?: boolean;
      error?: string;
    }
  | { ok: false; error: string };

export interface UiFieldScanValue {
  found: boolean;
  value?: string;
  kind?: string;
}

export interface UiScanResultPayload {
  type: 'UI_SCAN_RESULT';
  tabId: number;
  requestId: string;
  results: Record<string, UiFieldScanValue>;
}
