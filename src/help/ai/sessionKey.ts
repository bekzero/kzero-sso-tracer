let sessionApiKey: string | null = null;

export const setSessionApiKey = (key: string): void => {
  sessionApiKey = key;
};

export const getSessionApiKey = (): string | null => {
  return sessionApiKey;
};

export const clearSessionApiKey = (): void => {
  sessionApiKey = null;
};

export const hasSessionApiKey = (): boolean => {
  return Boolean(sessionApiKey && sessionApiKey.trim().length > 0);
};