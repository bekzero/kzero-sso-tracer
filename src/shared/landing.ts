import type { NormalizedEvent, NormalizedOidcEvent, NormalizedSamlEvent } from "./models";

const KNOWN_STATIC_HOSTS = [
  "zohocdn.com", "static.zohocdn.com",
  "google-analytics.com", "googletagmanager.com",
  "segment.io", "segment.com",
  "hotjar.com", "intercom.io", "zendesk.com"
];

const isKnownStaticHost = (host: string): boolean => {
  const h = host.toLowerCase();
  return KNOWN_STATIC_HOSTS.some((s) => h === s || h.endsWith("." + s));
};

export const isAppLanding = (event: NormalizedEvent, targetHosts?: Set<string>): boolean => {
  try {
    const url = new URL(event.url);
    const pathname = url.pathname;
    if (/\.(css|js|png|svg|woff|ico|jpg|jpeg|gif|webp|json)(\?|$)/i.test(pathname)) return false;
    if (pathname.includes("/ws/") || pathname.includes("/chat/") || pathname.includes("/status")) return false;
    if (url.hostname.includes("statuspage") || url.hostname.includes("wss.")) return false;
    if (isKnownStaticHost(url.hostname)) return false;
    if (pathname === "/" || pathname === "" || pathname === "/home" || pathname === "/app" || pathname === "/dashboard") return true;
    if (pathname.endsWith(".html") || pathname.endsWith(".htm")) return true;
    return false;
  } catch {
    return false;
  }
};

export interface LandingResult {
  detected: boolean;
  landingEvent?: NormalizedEvent;
  boundaryEvent?: NormalizedEvent;
}

const isOidcCallback = (event: NormalizedEvent): event is NormalizedOidcEvent => {
  return event.protocol === "OIDC" && event.kind === "callback";
};

const isOidcToken = (event: NormalizedEvent): event is NormalizedOidcEvent => {
  return event.protocol === "OIDC" && event.kind === "token";
};

const isSamlResponse = (event: NormalizedEvent): event is NormalizedSamlEvent => {
  return event.protocol === "SAML" && event.kind === "saml-response";
};

const isOidcAuthEvent = (event: NormalizedEvent): boolean => {
  if (event.protocol !== "OIDC") return false;
  const kind = (event as NormalizedOidcEvent).kind;
  return kind === "discovery" || kind === "authorize" || kind === "callback" || 
         kind === "token" || kind === "userinfo" || kind === "jwks" || kind === "logout";
};

const isSamlAuthEvent = (event: NormalizedEvent): boolean => {
  return event.protocol === "SAML";
};

export const detectLanding = (events: NormalizedEvent[]): LandingResult => {
  if (!events.length) {
    return { detected: false };
  }

  const authEvents = events.filter((e) => isOidcAuthEvent(e) || isSamlAuthEvent(e));
  
  let boundaryEvent: NormalizedEvent | undefined;
  let landingEvent: NormalizedEvent | undefined;
  const knownIdpHosts = new Set<string>();
  const knownSpHosts = new Set<string>();

  for (const event of authEvents) {
    if (isSamlResponse(event)) {
      boundaryEvent = event;
      if (event.samlResponse?.issuer) {
        try {
          const issuerUrl = new URL(event.samlResponse.issuer);
          knownIdpHosts.add(issuerUrl.host);
        } catch {
          // ignore invalid URL
        }
      }
    }

    if (isOidcCallback(event) && (event as NormalizedOidcEvent).code && !boundaryEvent) {
      boundaryEvent = event;
      if (event.redirectUri) {
        try {
          const redirectUrl = new URL(event.redirectUri);
          knownSpHosts.add(redirectUrl.host);
        } catch {
          // ignore invalid URL
        }
      }
    }

    if (isOidcToken(event) && boundaryEvent) {
      const artifacts = event.artifacts as Record<string, unknown>;
      const hasAccessToken = Boolean(artifacts.accessToken || artifacts.idToken);
      if (hasAccessToken) {
        boundaryEvent = event;
      }
    }
  }

  if (!boundaryEvent) {
    return { detected: false };
  }

  const boundaryIndex = events.indexOf(boundaryEvent);
  const remainingEvents = events.slice(boundaryIndex + 1);

  for (const event of remainingEvents) {
    const targetHosts = knownSpHosts.size > 0 ? knownSpHosts : knownIdpHosts;
    if (isAppLanding(event, targetHosts)) {
      landingEvent = event;
      break;
    }
  }

  return {
    detected: Boolean(landingEvent),
    landingEvent,
    boundaryEvent
  };
};