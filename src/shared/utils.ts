export const nowId = (): string => `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

export const parseQueryString = (input: string): Record<string, string> => {
  const output: Record<string, string> = {};
  const params = new URLSearchParams(input);
  for (const [key, value] of params.entries()) {
    output[key] = value;
  }
  return output;
};

export const toHeaderMap = (
  headers: Array<{ name: string; value?: string | number } | { name?: string; value?: string }> | undefined
): Record<string, string> => {
  const map: Record<string, string> = {};
  if (!headers) return map;
  headers.forEach((h) => {
    if (!h.name) return;
    map[h.name.toLowerCase()] = String(h.value ?? "");
  });
  return map;
};

export const safeJsonParse = <T>(value: string): T | undefined => {
  try {
    return JSON.parse(value) as T;
  } catch {
    return undefined;
  }
};

export const safeUrl = (value: string): URL | undefined => {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
};
