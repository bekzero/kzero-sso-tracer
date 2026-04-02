import { normalizeRawEvent } from "../normalizers";
import { runFindingsEngine } from "../rules";
import type { CaptureHistoryItem, CaptureSession, RawCaptureEvent } from "../shared/models";
import { nowId } from "../shared/utils";

const sessions = new Map<number, CaptureSession>();
const sessionCache = new Map<number, CaptureSession>();
const HISTORY_KEY = "history:sessions";
const HISTORY_MAX = 30;
const MAX_EVENTS_PER_SESSION = 500;
const MAX_SESSION_SIZE_BYTES = 512 * 1024;

const GLOBAL_TAB_ID = 0;

const storageGet = async <T>(key: string): Promise<T | undefined> => {
  const result = await chrome.storage.local.get(key);
  return result[key] as T | undefined;
};

const storageSet = async (key: string, value: unknown): Promise<void> => {
  await chrome.storage.local.set({ [key]: value });
};

const storageRemove = async (key: string): Promise<void> => {
  await chrome.storage.local.remove(key);
};

const SESSION_KEY = (tabId: number): string => `session:${tabId}`;

void chrome.storage.local.get(null, (items) => {
  for (const [key, value] of Object.entries(items)) {
    if (key.startsWith("session:") && value && typeof value === "object") {
      const s = value as CaptureSession;
      sessionCache.set(s.tabId, s);
      if (s.active) {
        sessions.set(s.tabId, s);
      }
    }
  }
});

const ensureSession = (tabId: number): CaptureSession => {
  const existing = sessions.get(tabId);
  if (existing) return existing;
  const stored = sessionCache.get(tabId);
  if (stored) {
    sessions.set(tabId, stored);
    return stored;
  }
  const created: CaptureSession = {
    tabId,
    active: false,
    rawEvents: [],
    normalizedEvents: [],
    findings: []
  };
  sessions.set(tabId, created);
  return created;
};

export const isGlobalCaptureActive = (): boolean => {
  const globalSession = sessions.get(GLOBAL_TAB_ID);
  return globalSession?.active ?? false;
};

export const startCapture = (_tabId: number): CaptureSession => {
  const session = ensureSession(GLOBAL_TAB_ID);
  session.active = true;
  session.startedAt = Date.now();
  session.rawEvents = [];
  session.normalizedEvents = [];
  session.findings = [];
  void storageSet(SESSION_KEY(GLOBAL_TAB_ID), session);
  return session;
};

export const stopCapture = (_tabId: number): CaptureSession => {
  const session = ensureSession(GLOBAL_TAB_ID);
  session.active = false;
  session.stoppedAt = Date.now();
  void storageSet(SESSION_KEY(GLOBAL_TAB_ID), session);
  void persistHistoryItem(session);
  return session;
};

export const clearSession = (_tabId: number): CaptureSession => {
  const session = ensureSession(GLOBAL_TAB_ID);
  session.rawEvents = [];
  session.normalizedEvents = [];
  session.findings = [];
  void storageRemove(SESSION_KEY(GLOBAL_TAB_ID));
  return session;
};

export const addRawEvent = (tabId: number, raw: RawCaptureEvent): CaptureSession | undefined => {
  const globalSession = sessions.get(GLOBAL_TAB_ID);
  if (!globalSession?.active) {
    return undefined;
  }

  if (globalSession.rawEvents.length >= MAX_EVENTS_PER_SESSION) return globalSession;

  const sessionSize = new Blob([JSON.stringify(globalSession)]).size;
  const rawSize = new Blob([JSON.stringify(raw)]).size;
  if (sessionSize + rawSize > MAX_SESSION_SIZE_BYTES) return globalSession;

  globalSession.rawEvents.push(raw);
  const normalized = normalizeRawEvent(raw);
  globalSession.normalizedEvents.push(normalized);
  globalSession.normalizedEvents.sort((a, b) => a.timestamp - b.timestamp);
  
  globalSession.findings = runFindingsEngine(globalSession.normalizedEvents);
  void storageSet(SESSION_KEY(GLOBAL_TAB_ID), globalSession);

  return globalSession;
};

export const getSession = (_tabId: number): CaptureSession => ensureSession(GLOBAL_TAB_ID);

const persistHistoryItem = async (session: CaptureSession): Promise<void> => {
  if (!session.startedAt || !session.stoppedAt) return;
  const history = (await storageGet<CaptureHistoryItem[]>(HISTORY_KEY)) ?? [];
  const protocolHints = [...new Set(session.normalizedEvents.map((event) => event.protocol))]
    .filter((p) => p !== "unknown")
    .map((p) => String(p));
  const snapshot: CaptureHistoryItem = {
    id: nowId(),
    tabId: session.tabId,
    startedAt: session.startedAt,
    stoppedAt: session.stoppedAt,
    protocolHints,
    findingCount: session.findings.length,
    session: JSON.parse(JSON.stringify(session)) as CaptureSession
  };
  const next = [snapshot, ...history].slice(0, HISTORY_MAX);
  await storageSet(HISTORY_KEY, next);
};

export const getHistory = async (): Promise<CaptureHistoryItem[]> =>
  (await storageGet<CaptureHistoryItem[]>(HISTORY_KEY)) ?? [];

export const clearHistory = async (): Promise<void> => {
  await storageRemove(HISTORY_KEY);
};

export const loadHistoryItem = async (itemId: string): Promise<CaptureHistoryItem | undefined> => {
  const history = await getHistory();
  return history.find((item) => item.id === itemId);
};
