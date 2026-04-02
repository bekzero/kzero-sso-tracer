import type { NormalizedEvent, RawCaptureEvent } from "../shared/models";

export type EventClassification = "noise" | "auth-critical" | "flow-adjacent" | "unknown";

export interface ClassificationResult {
  classification: EventClassification;
  reasons: string[];
  isAuthRelevant: boolean;
}

const NOISE_HOSTS = [
  "google-analytics.com",
  "www.google-analytics.com",
  "googletagmanager.com",
  "www.googletagmanager.com",
  "facebook.com",
  "www.facebook.com",
  "fbcdn.net",
  "www.fbcdn.net",
  "doubleclick.net",
  "www.doubleclick.net",
  "adnxs.com",
  "www.adnxs.com",
  "criteo.com",
  "www.criteo.com",
  "hotjar.com",
  "www.hotjar.com",
  "mixpanel.com",
  "www.mixpanel.com",
  "segment.com",
  "www.segment.com",
  "amplitude.com",
  "www.amplitude.com",
  "newrelic.com",
  "www.newrelic.com",
  "nr-data.net",
  "www.nr-data.net",
  "sentry.io",
  "www.sentry.io",
  "datadog.com",
  "www.datadog.com",
  "loggly.com",
  "www.loggly.com",
  "papertrail.com",
  "www.papertrail.com"
];

const AUTH_PATH_PATTERNS = [
  /\/saml\//i,
  /\/sso\//i,
  /\/oauth2?\//i,
  /openid-connect\//i,
  /\/auth\//i,
  /\/login\//i,
  /\/acs\//i,
  /\/callback\//i,
  /\/token\//i,
  /\/userinfo\//i,
  /\/logout\//i,
  /\/authorize\//i,
  /\/register\//i,
  /\/signup\//i,
  /\/signin\//i
];

const AUTH_PARAM_KEYS = [
  "samlrequest",
  "samlresponse",
  "relaystate",
  "code",
  "id_token",
  "access_token",
  "state",
  "nonce",
  "redirect_uri",
  "response_type",
  "scope"
];

const CALLBACK_PATTERNS = [
  /\?code=/i,
  /\?state=/i,
  /\?id_token=/i,
  /\?access_token=/i,
  /\/oauth2\/callback/i,
  /\/oauth\/callback/i,
  /\/saml\/acs/i,
  /\/sso\/saml\/acs/i
];

export const classifyEvent = (event: RawCaptureEvent | NormalizedEvent): ClassificationResult => {
  const reasons: string[] = [];
  let classification: EventClassification = "unknown";

  const hostLower = event.host?.toLowerCase() ?? "";
  
  if (hostLower) {
    for (const noiseHost of NOISE_HOSTS) {
      if (hostLower === noiseHost || hostLower.endsWith("." + noiseHost)) {
        return { 
          classification: "noise", 
          reasons: [`known noise host: ${event.host}`], 
          isAuthRelevant: false 
        };
      }
    }
  }

  const url = event.url ?? "";
  
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname.toLowerCase();
    const query = urlObj.search.toLowerCase();
    const method = event.method?.toUpperCase() ?? "GET";

    for (const pattern of AUTH_PATH_PATTERNS) {
      if (pattern.test(path)) {
        classification = "auth-critical";
        reasons.push(`auth path pattern: ${pattern.source}`);
        break;
      }
    }

    for (const key of AUTH_PARAM_KEYS) {
      if (query.includes(key.toLowerCase())) {
        if (classification === "unknown") classification = "flow-adjacent";
        reasons.push(`auth param: ${key}`);
      }
    }

    for (const pattern of CALLBACK_PATTERNS) {
      if (pattern.test(path) || pattern.test(query)) {
        if (classification === "unknown") classification = "flow-adjacent";
        reasons.push("callback pattern");
      }
    }

    if (method === "POST") {
      let postBody = "";
      if ("postBody" in event && typeof event.postBody === "string") {
        postBody = event.postBody.toLowerCase();
      } else if ("artifacts" in event && event.artifacts && typeof event.artifacts === "object") {
        const artifacts = event.artifacts as Record<string, unknown>;
        if (typeof artifacts.body === "string") {
          postBody = (artifacts.body as string).toLowerCase();
        }
      }
      if (postBody.includes("saml") || postBody.includes("samlrequest") || postBody.includes("samlresponse")) {
        classification = "auth-critical";
        reasons.push("SAML POST body");
      }
    }

    if (event.statusCode !== undefined) {
      if (event.statusCode >= 400) {
        if (classification === "unknown") {
          reasons.push(`error response: ${event.statusCode}`);
        }
      }
    }

  } catch {
    reasons.push("invalid URL - kept as unknown");
  }

  if ("protocol" in event && event.protocol !== "unknown" && event.protocol !== "network") {
    if (classification === "unknown") classification = "auth-critical";
    if (!reasons.some(r => r.startsWith("protocol:"))) {
      reasons.push(`protocol: ${event.protocol}`);
    }
  }

  if (reasons.length === 0) {
    reasons.push("no classification match");
  }

  const isAuthRelevant = classification === "auth-critical" || classification === "flow-adjacent";

  return { classification, reasons, isAuthRelevant };
};

export const isNoiseHost = (host: string): boolean => {
  const hostLower = host.toLowerCase();
  return NOISE_HOSTS.some(h => hostLower === h || hostLower.endsWith("." + h));
};

export const isAuthPath = (url: string): boolean => {
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname.toLowerCase();
    return AUTH_PATH_PATTERNS.some(p => p.test(path)) || AUTH_PARAM_KEYS.some(k => urlObj.search.toLowerCase().includes(k.toLowerCase()));
  } catch {
    return false;
  }
};

export const hasAuthParams = (url: string): boolean => {
  try {
    const urlObj = new URL(url);
    const query = urlObj.search.toLowerCase();
    return AUTH_PARAM_KEYS.some(key => query.includes(key.toLowerCase()));
  } catch {
    return false;
  }
};