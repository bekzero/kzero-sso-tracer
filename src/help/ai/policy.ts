export interface LocalSettings {
  aiDisabled: boolean;
}

export function getLocalSettings(): LocalSettings {
  try {
    const stored = localStorage.getItem("local_settings");
    if (stored) {
      return JSON.parse(stored);
    }
  } catch {
  }
  return { aiDisabled: false };
}

export function isAIDisabledLocally(): boolean {
  return getLocalSettings().aiDisabled;
}

export function setLocalAISettings(disabled: boolean): void {
  try {
    const settings = getLocalSettings();
    settings.aiDisabled = disabled;
    localStorage.setItem("local_settings", JSON.stringify(settings));
  } catch {
  }
}