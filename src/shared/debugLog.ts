const debugLogs: Array<{ timestamp: number; source: string; message: string; data?: unknown }> = [];
const MAX_DEBUG_ENTRIES = 500;

export interface DebugLogEntry {
  timestamp: number;
  source: string;
  message: string;
  data?: unknown;
}

export const logDebug = async (_source: string, _message: string, _data?: unknown): Promise<void> => {
  // Debug logging is now memory-only for security
  // To re-enable persistent logging, add a proper debug viewer UI
  // that respects user consent and doesn't persist sensitive data
};

export const getDebugLogs = async (): Promise<DebugLogEntry[]> => {
  return debugLogs.slice(0, MAX_DEBUG_ENTRIES);
};

export const clearDebugLogs = async (): Promise<void> => {
  debugLogs.length = 0;
};