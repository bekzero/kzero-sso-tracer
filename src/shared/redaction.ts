const SECRET_KEYS = [
  "client_secret",
  "refresh_token",
  "access_token",
  "id_token",
  "authorization",
  "authorization",
  "code",
  "samlresponse",
  "samlrequest",
  "assertion",
  "singedinfo",
  "private_key",
  "certificate",
  "keystore"
];

const SECRET_PATTERNS = [
  /secret/i,
  /token/i,
  /password/i,
  /credential/i,
  /private/i,
  /authorization/i,
  /assertion/i,
  /certificate/i,
  /keystore/i
];

export const isSecretKey = (key: string): boolean => {
  const lower = key.toLowerCase();
  if (SECRET_KEYS.includes(lower)) return true;
  if (SECRET_PATTERNS.some((p) => p.test(key))) return true;
  return false;
};

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
