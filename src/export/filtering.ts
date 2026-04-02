import type { NormalizedEvent, NormalizedSamlEvent, NormalizedOidcEvent } from "../shared/models";

const NOISE_HOST_PATTERNS = [
  /^google-analytics\.com$/,
  /^www\.google-analytics\.com$/,
  /^googletagmanager\.com$/,
  /^www\.googletagmanager\.com$/,
  /^facebook\.com$/,
  /^www\.facebook\.com$/,
  /^fbcdn\.net$/,
  /^www\.fbcdn\.net$/,
  /^doubleclick\.net$/,
  /^www\.doubleclick\.net$/,
  /^adnxs\.com$/,
  /^www\.adnxs\.com$/,
  /^criteo\.com$/,
  /^www\.criteo\.com$/,
  /^hotjar\.com$/,
  /^www\.hotjar\.com$/,
  /^mixpanel\.com$/,
  /^www\.mixpanel\.com$/,
  /^segment\.com$/,
  /^www\.segment\.com$/,
  /^amplitude\.com$/,
  /^www\.amplitude\.com$/,
  /^newrelic\.com$/,
  /^www\.newrelic\.com$/,
  /^nr-data\.net$/,
  /^www\.nr-data\.net$/,
  /^sentry\.io$/,
  /^www\.sentry\.io$/,
  /^datadog\.com$/,
  /^www\.datadog\.com$/,
  /^loggly\.com$/,
  /^www\.loggly\.com$/,
  /^papertrail\.com$/,
  /^www\.papertrail\.com$/,
  /^(cdn|static|assets)\./,
  /\.(jsdelivr|unpkg|cdnjs|cloudflare)\.com$/
];

const NOISE_PATH_PATTERNS = [
  /^\/socket\.io\//,
  /^\/api\/v\d+\/socket\//,
  /^\/poll/,
  /^\/longpoll/,
  /^\/events\/stream/,
  /^\/_health$/,
  /^\/status$/,
  /^\/ping$/,
  /^\/metrics$/,
  /^\/telemetry/,
  /^\/teleport/,
  /^\/api\/heartbeat/,
  /^\/api\/health/,
  /^\/__health__/,
  /\.(js|css|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|ico|webp)(\?.*)?$/
];

const NOISE_QUERY_PATTERNS = [
  /_t=/,
  /_v=/,
  /_cb=/,
  /v=/,
  /t=/,
  /__r=/
];

const OIDC_KINDS = ["discovery", "authorize", "callback", "token", "userinfo", "jwks", "logout"];
const SAML_KINDS = ["saml-request", "saml-response"];

const isSaml = (e: NormalizedEvent): e is NormalizedSamlEvent => e.protocol === "SAML";
const isOidc = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === "OIDC";

export interface AuthBoundary {
  detected: boolean;
  authEvents: NormalizedEvent[];
  boundaryEvent?: NormalizedEvent;
  landingEvent?: NormalizedEvent;
  graceEvents: NormalizedEvent[];
}

export const isNoiseEvent = (event: NormalizedEvent): boolean => {
  const hostLower = event.host.toLowerCase();
  if (NOISE_HOST_PATTERNS.some((p) => p.test(hostLower))) {
    return true;
  }

  try {
    const url = new URL(event.url);
    const path = url.pathname;
    if (NOISE_PATH_PATTERNS.some((p) => p.test(path))) {
      return true;
    }

    const search = url.search;
    if (NOISE_QUERY_PATTERNS.some((p) => p.test(search))) {
      return true;
    }
  } catch {
  }

  return false;
};

export const isAuthEvent = (event: NormalizedEvent): boolean => {
  if (isSaml(event)) return true;
  if (isOidc(event) && OIDC_KINDS.includes(event.kind)) return true;
  return false;
};

export const isSamlResponse = (event: NormalizedEvent): event is NormalizedSamlEvent => {
  return isSaml(event) && event.kind === "saml-response";
};

export const isOidcCallback = (event: NormalizedEvent): event is NormalizedOidcEvent => {
  return isOidc(event) && event.kind === "callback";
};

export const isOidcToken = (event: NormalizedEvent): event is NormalizedOidcEvent => {
  return isOidc(event) && event.kind === "token";
};

export const isAppLanding = (event: NormalizedEvent, knownHosts: Set<string>): boolean => {
  if (!knownHosts.size) return false;
  if (!event.host) return false;
  const hostLower = event.host.toLowerCase();
  
  for (const known of knownHosts) {
    if (hostLower === known || hostLower.endsWith("." + known)) {
      if (event.statusCode !== undefined && event.statusCode >= 200 && event.statusCode < 400) {
        const urlLower = event.url.toLowerCase();
        if (!urlLower.includes("/saml") && 
            !urlLower.includes("/oauth") && 
            !urlLower.includes("/openid") &&
            !urlLower.includes("/auth") &&
            !NOISE_PATH_PATTERNS.some(p => p.test(new URL(event.url).pathname))) {
          return true;
        }
      }
    }
  }
  return false;
};

export const extractRelaysateTarget = (event: NormalizedSamlEvent): string | undefined => {
  if (event.relayState) {
    try {
      const url = new URL(event.relayState);
      return url.origin + url.pathname;
    } catch {
      return event.relayState;
    }
  }
  return undefined;
};

export const detectAuthBoundary = (events: NormalizedEvent[]): AuthBoundary => {
  if (!events.length) {
    return { detected: false, authEvents: [], graceEvents: [] };
  }

  const authEvents: NormalizedEvent[] = [];
  let boundaryEvent: NormalizedEvent | undefined;
  let landingEvent: NormalizedEvent | undefined;
  const knownIdpHosts = new Set<string>();
  const knownSpHosts = new Set<string>();

  for (const event of events) {
    if (!isAuthEvent(event)) continue;

    authEvents.push(event);

    const hostLower = event.host.toLowerCase();
    if (isSamlResponse(event)) {
      boundaryEvent = event;
      if (event.samlResponse?.issuer) {
        try {
          const issuerUrl = new URL(event.samlResponse.issuer);
          knownIdpHosts.add(issuerUrl.host);
        } catch {
        }
      }
    }

    if (isOidcCallback(event) && event.code && !boundaryEvent) {
      boundaryEvent = event;
      if (event.redirectUri) {
        try {
          const redirectUrl = new URL(event.redirectUri);
          knownSpHosts.add(redirectUrl.host);
        } catch {
        }
      }
    }

    if (isOidcToken(event) && boundaryEvent) {
      const hasAccessToken = event.artifacts.accessToken || event.artifacts.idToken;
      if (hasAccessToken) {
        boundaryEvent = event;
      }
    }
  }

  if (!boundaryEvent) {
    return { detected: false, authEvents, graceEvents: [] };
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
    detected: true,
    authEvents,
    boundaryEvent,
    landingEvent,
    graceEvents: []
  };
};

export interface FilterOptions {
  mode: "summary" | "sanitized" | "raw";
  includePostLoginActivity: boolean;
}

export const filterEventsByMode = (
  events: NormalizedEvent[],
  options: FilterOptions
): NormalizedEvent[] => {
  if (options.mode === "raw") {
    return events;
  }

  const boundary = detectAuthBoundary(events);
  const authEvents = events.filter((e) => isAuthEvent(e));

  if (options.mode === "summary") {
    const result: NormalizedEvent[] = [...authEvents];
    if (boundary.landingEvent) {
      result.push(boundary.landingEvent);
    }
    return result;
  }

  const result: NormalizedEvent[] = [...authEvents];
  
  if (boundary.landingEvent) {
    result.push(boundary.landingEvent);

    if (!options.includePostLoginActivity) {
      const landingIndex = events.indexOf(boundary.landingEvent);
      const afterLanding = events.slice(landingIndex + 1);
      const boundaryTime = boundary.landingEvent.timestamp;
      const graceEndTime = boundaryTime + 3000;
      const graceEvents = afterLanding.filter((e) => {
        if (e.timestamp > graceEndTime) return false;
        if (isNoiseEvent(e)) return false;
        return true;
      }).slice(0, 5);
      result.push(...graceEvents);
    } else {
      const landingIndex = events.indexOf(boundary.landingEvent);
      const afterLanding = events.slice(landingIndex + 1);
      const boundaryTime = boundary.landingEvent.timestamp;
      const graceEndTime = boundaryTime + 30000;
      const graceEvents = afterLanding.filter((e) => {
        if (e.timestamp > graceEndTime) return false;
        return true;
      }).slice(0, 20);
      result.push(...graceEvents);
    }
  } else {
    const lastAuthEvent = authEvents[authEvents.length - 1];
    if (lastAuthEvent) {
      const lastAuthIndex = events.indexOf(lastAuthEvent);
      const afterAuth = events.slice(lastAuthIndex + 1);
      const boundaryTime = lastAuthEvent.timestamp;
      const graceEndTime = boundaryTime + 10000;
      const graceEvents = afterAuth.filter((e) => {
        if (e.timestamp > graceEndTime) return false;
        if (isNoiseEvent(e) && !options.includePostLoginActivity) return false;
        return true;
      }).slice(0, 5);
      result.push(...graceEvents);
    }
  }

  return result;
};

export const getAuthHosts = (events: NormalizedEvent[]): { idpHost?: string; spAppHost?: string; protocol?: string } => {
  const hosts: { idpHost?: string; spAppHost?: string; protocol?: string } = {};
  const protocols = new Set<string>();

  for (const event of events) {
    if (isAuthEvent(event)) {
      protocols.add(event.protocol);
    }
  }

  if (protocols.size === 1) {
    hosts.protocol = protocols.values().next().value;
  }

  const samlEvents = events.filter(isSaml);
  const samlResponses = samlEvents.filter(isSamlResponse);

  for (const event of samlResponses) {
    if (event.samlResponse?.issuer) {
      try {
        hosts.idpHost = new URL(event.samlResponse.issuer).host;
      } catch {
      }
    }
    if (event.relayState) {
      try {
        hosts.spAppHost = new URL(event.relayState).host;
      } catch {
      }
    }
  }

  const oidcEvents = events.filter(isOidc);
  for (const event of oidcEvents) {
    if (event.issuer && !hosts.idpHost) {
      try {
        hosts.idpHost = new URL(event.issuer).host;
      } catch {
      }
    }
    if (event.redirectUri && !hosts.spAppHost) {
      try {
        hosts.spAppHost = new URL(event.redirectUri).host;
      } catch {
      }
    }
  }

  return hosts;
};