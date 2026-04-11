import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import type { RawCaptureEvent } from '../src/shared/models';

const createRawEvent = (overrides: Partial<RawCaptureEvent> = {}): RawCaptureEvent => ({
  id: 'test-1',
  tabId: 1,
  source: 'webrequest',
  timestamp: Date.now(),
  url: 'https://example.com/',
  host: 'example.com',
  ...overrides
});

const mockStorage: Record<string, unknown> = {};
const mockStorageLocal = {
  get: vi.fn(
    (keys: string | string[] | null, callback?: (items: Record<string, unknown>) => void) => {
      const result =
        keys === null
          ? { ...mockStorage }
          : typeof keys === 'string'
            ? { [keys]: mockStorage[keys] }
            : Object.fromEntries(
                (keys as string[]).filter((k) => k in mockStorage).map((k) => [k, mockStorage[k]])
              );
      if (callback) {
        callback(result as Record<string, unknown>);
      }
      return Promise.resolve(result);
    }
  ),
  set: vi.fn((items: Record<string, unknown>) => {
    Object.assign(mockStorage, items);
    return Promise.resolve();
  }),
  remove: vi.fn((keys: string | string[]) => {
    if (typeof keys === 'string') {
      delete mockStorage[keys];
    } else {
      for (const key of keys) {
        delete mockStorage[key];
      }
    }
    return Promise.resolve();
  })
};

vi.stubGlobal('chrome', {
  storage: {
    local: mockStorageLocal
  }
});

beforeEach(() => {
  Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
  mockStorage['settings:kzero'] = {
    captureScope: 'auth-only',
    settingsVersion: 4,
    hasSeenScopeNotice: true
  };
  vi.clearAllMocks();
  initialized = false;
});

let initialized = false;

afterEach(() => {
  vi.resetAllMocks();
});

describe('sessionStore storage behavior', () => {
  it('does not rehydrate active sessions from storage on startup', async () => {
    mockStorage['session:123'] = {
      tabId: 123,
      active: true,
      rawEvents: [{ url: 'http://test.com', timestamp: 1000 }],
      normalizedEvents: [],
      findings: []
    };
    mockStorage['history:sessions'] = [];

    vi.resetModules();
    const { startCapture, isTabCaptureActive, getSession } = await import(
      '../src/capture/sessionStore'
    );

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(isTabCaptureActive(123)).toBe(false);

    const session = getSession(123);
    expect(session.active).toBe(false);
    expect(session.rawEvents).toHaveLength(0);
  });

  it('cleans up legacy session:* keys on startup', async () => {
    mockStorage['session:100'] = {
      tabId: 100,
      active: false,
      rawEvents: [],
      normalizedEvents: [],
      findings: []
    };
    mockStorage['session:200'] = {
      tabId: 200,
      active: true,
      rawEvents: [],
      normalizedEvents: [],
      findings: []
    };

    vi.resetModules();
    await import('../src/capture/sessionStore');

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(mockStorage['session:100']).toBeUndefined();
    expect(mockStorage['session:200']).toBeUndefined();
    expect(mockStorageLocal.remove).toHaveBeenCalledWith(['session:100', 'session:200']);
  });

  it('preserves history:sessions data', async () => {
    const existingHistory = [
      {
        id: 'h1',
        tabId: 1,
        startedAt: 1000,
        stoppedAt: 2000,
        protocolHints: ['SAML'],
        findingCount: 2,
        topFindings: []
      }
    ];
    mockStorage['history:sessions'] = existingHistory;

    const { getHistory } = await import('../src/capture/sessionStore');

    await new Promise((resolve) => setTimeout(resolve, 10));

    const history = await getHistory();
    expect(history).toEqual(existingHistory);
  });

  it('active capture does not write full session data to storage', async () => {
    mockStorage['history:sessions'] = [];

    const { startCapture, addRawEvent } = await import('../src/capture/sessionStore');

    await new Promise((resolve) => setTimeout(resolve, 10));

    await startCapture(999);

    await addRawEvent(
      999,
      createRawEvent({
        url: 'http://auth.example.com/login',
        method: 'POST',
        tabId: 999,
        postBody: 'SAMLRequest=abc'
      })
    );

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(mockStorage['session:999']).toBeUndefined();
    expect(mockStorage['history:sessions']).toEqual([]);
  });

  it('stopCapture writes only summary to history, not full session', async () => {
    mockStorage['history:sessions'] = [];

    vi.resetModules();
    const { startCapture, addRawEvent, stopCapture, getHistory } = await import(
      '../src/capture/sessionStore'
    );

    await new Promise((resolve) => setTimeout(resolve, 10));

    const tabId = 888 + Date.now();
    const session = await startCapture(tabId);

    await addRawEvent(
      tabId,
      createRawEvent({
        url: 'http://test.com',
        method: 'GET',
        tabId,
        host: 'test.com'
      })
    );

    stopCapture(tabId);

    await new Promise((resolve) => setTimeout(resolve, 50));

    const history = await getHistory();
    expect(history).toHaveLength(1);
    expect(history[0].tabId).toBe(tabId);
    expect(history[0].findingCount).toBeGreaterThanOrEqual(0);
    expect((history[0] as any).rawEvents).toBeUndefined();
    expect((history[0] as any).normalizedEvents).toBeUndefined();
  });

  it('clearSession does not write or delete from storage', async () => {
    mockStorage['history:sessions'] = [];
    mockStorage['settings:kzero'] = { captureScope: 'auth-only' };

    const { startCapture, clearSession } = await import('../src/capture/sessionStore');

    await new Promise((resolve) => setTimeout(resolve, 10));

    startCapture(777);
    clearSession(777);

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(mockStorage['session:777']).toBeUndefined();
    expect(mockStorage['history:sessions']).toEqual([]);
    expect(mockStorage['settings:kzero']).toEqual({ captureScope: 'auth-only' });
  });
});
