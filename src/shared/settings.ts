export type CaptureScope = "auth-only" | "auth-plus-allowlist" | "full";

export interface AISettings {
  enabled: boolean;
  apiKey: string;
  includeFindings: boolean;
  hasSeenConsent: boolean;
}

export interface Settings {
  autoStartOnTabSwitch: boolean;
  maxHistoryItems: number;
  redactionStrictness: "strict" | "moderate" | "off";
  defaultDetailTab: "fix" | "happened" | "evidence" | "artifacts" | "xml";
  showOnboarding: boolean;
  captureScope: CaptureScope;
  allowedHosts: string[];
  hasSeenScopeNotice: boolean;
  settingsVersion: number;
  debugEnabled: boolean;
  ai: AISettings;
}

const SETTINGS_VERSION = 4;

const DEFAULT_AI_SETTINGS: AISettings = {
  enabled: false,
  apiKey: "",
  includeFindings: true,
  hasSeenConsent: false
};

const DEFAULT_SETTINGS_V4: Settings = {
  autoStartOnTabSwitch: false,
  maxHistoryItems: 30,
  redactionStrictness: "strict",
  defaultDetailTab: "happened",
  showOnboarding: true,
  captureScope: "auth-only",
  allowedHosts: [],
  hasSeenScopeNotice: true,
  settingsVersion: SETTINGS_VERSION,
  debugEnabled: false,
  ai: { ...DEFAULT_AI_SETTINGS }
};

const _DEFAULT_SETTINGS_V3: Settings = {
  autoStartOnTabSwitch: false,
  maxHistoryItems: 30,
  redactionStrictness: "strict",
  defaultDetailTab: "happened",
  showOnboarding: true,
  captureScope: "auth-only",
  allowedHosts: [],
  hasSeenScopeNotice: true,
  settingsVersion: 3,
  debugEnabled: false,
  ai: { ...DEFAULT_AI_SETTINGS }
};

const _DEFAULT_SETTINGS_V2: Settings = {
  autoStartOnTabSwitch: false,
  maxHistoryItems: 30,
  redactionStrictness: "strict",
  defaultDetailTab: "happened",
  showOnboarding: true,
  captureScope: "auth-only",
  allowedHosts: [],
  hasSeenScopeNotice: true,
  settingsVersion: SETTINGS_VERSION,
  debugEnabled: false,
  ai: { ...DEFAULT_AI_SETTINGS }
};

const _DEFAULT_SETTINGS_V1: Settings = {
  autoStartOnTabSwitch: false,
  maxHistoryItems: 30,
  redactionStrictness: "strict",
  defaultDetailTab: "happened",
  showOnboarding: true,
  captureScope: "full",
  allowedHosts: [],
  hasSeenScopeNotice: false,
  settingsVersion: 1,
  debugEnabled: false,
  ai: { ...DEFAULT_AI_SETTINGS }
};

const SETTINGS_KEY = "settings";

export const migrateSettings = (stored: Partial<Settings> | undefined): Settings => {
  if (!stored) {
    return { ...DEFAULT_SETTINGS_V4 };
  }

  if (!stored.settingsVersion || stored.settingsVersion < SETTINGS_VERSION) {
    return {
      ...DEFAULT_SETTINGS_V4,
      ...stored,
      captureScope: stored.captureScope ?? "auth-only",
      hasSeenScopeNotice: false,
      settingsVersion: SETTINGS_VERSION,
      debugEnabled: stored.debugEnabled ?? false,
      ai: stored.ai ? { ...DEFAULT_AI_SETTINGS, ...stored.ai } : { ...DEFAULT_AI_SETTINGS }
    };
  }

  return { ...DEFAULT_SETTINGS_V4, ...stored };
};

export const getSettings = async (): Promise<Settings> => {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  const stored = result[SETTINGS_KEY] as Partial<Settings> | undefined;
  return migrateSettings(stored);
};

export const saveSettings = async (settings: Settings): Promise<void> => {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
};

export const resetSettings = async (): Promise<Settings> => {
  await chrome.storage.local.remove(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS_V4 };
};

export const isValidHostname = (input: string): boolean => {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) return false;
  if (trimmed.includes("/") || trimmed.includes(":") || trimmed.includes("?") || trimmed.includes("#")) return false;
  if (!/^[a-z0-9.-]+$/.test(trimmed)) return false;
  if (trimmed.startsWith(".") || trimmed.endsWith(".") || trimmed.includes("..")) return false;
  return true;
};

export const normalizeHostname = (input: string): string => {
  return input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
};