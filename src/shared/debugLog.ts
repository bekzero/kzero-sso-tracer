import { getSettings } from "./settings";

const DEBUG_KEY = "debug:logs";
const MAX_DEBUG_ENTRIES = 500;

export interface DebugLogEntry {
  timestamp: number;
  source: string;
  message: string;
  data?: unknown;
}

export const logDebug = async (source: string, message: string, data?: unknown): Promise<void> => {
  try {
    const settings = await getSettings();
    if (!settings.debugEnabled) {
      return;
    }
    
    const result = await chrome.storage.local.get(DEBUG_KEY);
    const logs = (result[DEBUG_KEY] as DebugLogEntry[]) ?? [];
    
    const entry: DebugLogEntry = {
      timestamp: Date.now(),
      source,
      message,
      data
    };
    
    const updated = [entry, ...logs].slice(0, MAX_DEBUG_ENTRIES);
    await chrome.storage.local.set({ [DEBUG_KEY]: updated });
  } catch {
    // Silently fail - debug logging should never break functionality
  }
};

export const getDebugLogs = async (): Promise<DebugLogEntry[]> => {
  try {
    const result = await chrome.storage.local.get(DEBUG_KEY);
    return (result[DEBUG_KEY] as DebugLogEntry[]) ?? [];
  } catch {
    return [];
  }
};

export const clearDebugLogs = async (): Promise<void> => {
  await chrome.storage.local.remove(DEBUG_KEY);
};