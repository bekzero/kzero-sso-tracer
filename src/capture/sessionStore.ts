import { normalizeRawEvent } from '../normalizers';
import { runFindingsEngine } from '../rules';
import type {
  CaptureHistoryItem,
  CaptureHistorySummary,
  CaptureSession,
  RawCaptureEvent
} from '../shared/models';
import { nowId } from '../shared/utils';
import { classifyEvent } from './hostClassifier';
import { getSettings } from '../shared/settings';
import { logDebug } from '../shared/debugLog';

const sessions = new Map<number, CaptureSession>();
const HISTORY_KEY = 'history:sessions';
const MAX_EVENTS_PER_SESSION = 500;
const MAX_SESSION_SIZE_BYTES = 512 * 1024;

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

void (async () => {
  const items = await chrome.storage.local.get(null);
  const legacySessionKeys: string[] = [];
  for (const key of Object.keys(items)) {
    if (key.startsWith('session:')) {
      legacySessionKeys.push(key);
    }
  }
  if (legacySessionKeys.length > 0) {
    await chrome.storage.local.remove(legacySessionKeys);
    void logDebug('capture', `Cleaned up ${legacySessionKeys.length} legacy session keys`);
  }
})();

const ensureSession = (tabId: number): CaptureSession => {
  const existing = sessions.get(tabId);
  if (existing) return existing;
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

const isHostAllowed = (host: string, allowedHosts: string[]): boolean => {
  const hostLower = host.toLowerCase();
  return allowedHosts.some((h) => {
    const allowedLower = h.toLowerCase();
    return hostLower === allowedLower || hostLower.endsWith('.' + allowedLower);
  });
};

const shouldCaptureEvent = async (raw: RawCaptureEvent): Promise<boolean> => {
  const settings = await getSettings();
  const { classification } = classifyEvent(raw);

  if (settings.captureScope === 'full') {
    return true;
  }

  if (settings.captureScope === 'auth-only') {
    if (classification === 'noise') {
      void logDebug('capture', 'Event filtered (noise)', {
        url: raw.url,
        host: raw.host,
        classification
      });
      return false;
    }
    return true;
  }

  if (settings.captureScope === 'auth-plus-allowlist') {
    if (classification === 'noise') {
      const allowed = isHostAllowed(raw.host ?? '', settings.allowedHosts);
      if (!allowed) {
        void logDebug('capture', 'Event filtered (noise, not allowlisted)', {
          url: raw.url,
          host: raw.host,
          classification
        });
      }
      return allowed;
    }
    return true;
  }

  return true;
};

const sessionDiscoveredHosts = new Map<number, Set<string>>();

const getDiscoveredHostsForTab = (tabId: number): Set<string> => {
  if (!sessionDiscoveredHosts.has(tabId)) {
    sessionDiscoveredHosts.set(tabId, new Set());
  }
  return sessionDiscoveredHosts.get(tabId)!;
};

export const isTabCaptureActive = (tabId: number): boolean => {
  const tabSession = sessions.get(tabId);
  return tabSession?.active ?? false;
};

export const startCapture = async (tabId: number): Promise<CaptureSession> => {
  const session: CaptureSession = {
    tabId,
    active: true,
    startedAt: Date.now(),
    rawEvents: [],
    normalizedEvents: [],
    findings: []
  };
  sessions.set(tabId, session);
  getDiscoveredHostsForTab(tabId).clear();
  void logDebug('capture', 'Capture started (memory-only)', { tabId: session.tabId });
  return session;
};

export const stopCapture = (tabId: number): CaptureSession => {
  const session = ensureSession(tabId);
  session.active = false;
  session.stoppedAt = Date.now();
  void logDebug('capture', 'Capture stopped', {
    tabId: session.tabId,
    eventCount: session.rawEvents.length,
    startedAt: session.startedAt,
    stoppedAt: session.stoppedAt
  });
  void persistHistoryItem(session)
    .then(() => {
      void logDebug('capture', 'History item persisted (sanitized)', { tabId: session.tabId });
    })
    .catch((err) => {
      void logDebug('capture', 'History persist failed', { error: String(err) });
    });
  sessions.delete(tabId);
  return session;
};

export const clearSession = (tabId: number): CaptureSession => {
  const session = ensureSession(tabId);
  session.rawEvents = [];
  session.normalizedEvents = [];
  session.findings = [];
  getDiscoveredHostsForTab(tabId).clear();
  return session;
};

export const addRawEvent = async (
  tabId: number,
  raw: RawCaptureEvent
): Promise<CaptureSession | undefined> => {
  const tabSession = sessions.get(tabId);
  if (!tabSession?.active) {
    return undefined;
  }

  if (!(await shouldCaptureEvent(raw))) {
    return tabSession;
  }

  if (tabSession.rawEvents.length >= MAX_EVENTS_PER_SESSION) return tabSession;

  const sessionSize = new Blob([JSON.stringify(tabSession)]).size;
  const rawSize = new Blob([JSON.stringify(raw)]).size;
  if (sessionSize + rawSize > MAX_SESSION_SIZE_BYTES) {
    void logDebug('capture', 'Event dropped (session size limit)', { url: raw.url });
    return tabSession;
  }

  const { isAuthRelevant } = classifyEvent(raw);
  if (isAuthRelevant && raw.host) {
    getDiscoveredHostsForTab(tabId).add(raw.host);
  }

  tabSession.rawEvents.push(raw);
  const normalized = normalizeRawEvent(raw);
  tabSession.normalizedEvents.push(normalized);
  tabSession.normalizedEvents.sort((a, b) => a.timestamp - b.timestamp);

  tabSession.findings = runFindingsEngine(tabSession.normalizedEvents);

  return tabSession;
};

export const getSession = (tabId: number): CaptureSession => ensureSession(tabId);

const persistHistoryItem = async (session: CaptureSession): Promise<void> => {
  if (!session.startedAt || !session.stoppedAt) {
    void logDebug('capture', 'History skipped - no start/stop times', {
      startedAt: session.startedAt,
      stoppedAt: session.stoppedAt
    });
    return;
  }
  const settings = await getSettings();
  void logDebug('capture', 'Persisting history item', {
    eventCount: session.normalizedEvents.length,
    findingCount: session.findings.length,
    startedAt: session.startedAt,
    stoppedAt: session.stoppedAt
  });
  const history = (await storageGet<CaptureHistoryItem[]>(HISTORY_KEY)) ?? [];
  const protocolHints = [...new Set(session.normalizedEvents.map((event) => event.protocol))]
    .filter((p) => p !== 'unknown')
    .map((p) => String(p));

  const topFindings = session.findings.slice(0, 3).map((f) => ({
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity
  }));

  const snapshot: CaptureHistorySummary = {
    id: nowId(),
    tabId: session.tabId,
    startedAt: session.startedAt,
    stoppedAt: session.stoppedAt,
    protocolHints,
    findingCount: session.findings.length,
    topFindings
  };
  const next = [snapshot, ...history].slice(0, settings.maxHistoryItems);
  await storageSet(HISTORY_KEY, next);
  void logDebug('capture', 'History saved (summary only)', { historyCount: next.length });
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

export const getDiscoveredAuthHosts = (_tabId?: number): string[] => {
  const allHosts = new Set<string>();
  for (const hosts of sessionDiscoveredHosts.values()) {
    hosts.forEach((h) => allHosts.add(h));
  }
  return Array.from(allHosts);
};
