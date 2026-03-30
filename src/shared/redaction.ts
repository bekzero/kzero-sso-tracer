const SECRET_KEYS = [
  "client_secret",
  "refresh_token",
  "access_token",
  "id_token",
  "authorization",
  "code",
  "samlresponse",
  "samlrequest"
];

export const isSecretKey = (key: string): boolean => SECRET_KEYS.includes(key.toLowerCase());

export const mask = (value: string, left = 4, right = 3): string => {
  if (value.length <= left + right) {
    return "***";
  }
  return `${value.slice(0, left)}...${value.slice(-right)}`;
};

export const redactValue = (key: string, value: unknown): unknown => {
  if (typeof value !== "string") return value;
  if (isSecretKey(key)) return mask(value);
  if (["nameid", "email", "sub"].includes(key.toLowerCase())) return mask(value, 2, 2);
  return value;
};

export const redactRecord = (record: Record<string, unknown>): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(record)) {
    out[k] = redactValue(k, v);
  }
  return out;
};
