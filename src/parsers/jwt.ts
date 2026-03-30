import type { JwtDecoded } from "../shared/models";

const b64UrlDecode = (input: string): string => {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(input.length / 4) * 4, "=");
  return atob(padded);
};

export const decodeJwt = (token: string): JwtDecoded | undefined => {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const header = JSON.parse(b64UrlDecode(parts[0])) as Record<string, unknown>;
    const payload = JSON.parse(b64UrlDecode(parts[1])) as Record<string, unknown>;
    return { header, payload, signature: parts[2] };
  } catch {
    return undefined;
  }
};

export const isJwt = (value?: string): boolean => Boolean(value && value.split(".").length === 3);
