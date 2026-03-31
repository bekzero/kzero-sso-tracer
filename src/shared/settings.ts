export interface Settings {
  autoStartOnTabSwitch: boolean;
  maxHistoryItems: number;
  redactionStrictness: "strict" | "moderate" | "off";
  defaultDetailTab: "fix" | "happened" | "evidence" | "artifacts" | "xml";
  showOnboarding: boolean;
}

const DEFAULT_SETTINGS: Settings = {
  autoStartOnTabSwitch: false,
  maxHistoryItems: 30,
  redactionStrictness: "strict",
  defaultDetailTab: "happened",
  showOnboarding: true
};

const SETTINGS_KEY = "settings";

export const getSettings = async (): Promise<Settings> => {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  const stored = result[SETTINGS_KEY] as Partial<Settings> | undefined;
  return { ...DEFAULT_SETTINGS, ...stored };
};

export const saveSettings = async (settings: Settings): Promise<void> => {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
};

export const resetSettings = async (): Promise<Settings> => {
  await chrome.storage.local.remove(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS };
};
