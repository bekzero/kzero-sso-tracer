import type { NormalizedEvent, NormalizedSamlEvent } from "../shared/models";

export type CaptureFlowLabel =
  | "Unknown"
  | "SP -> KZero"
  | "KZero -> SP"
  | "OIDC"
  | "SAML"
  | "Mixed / partial capture";

const isKzeroHost = (host: string | undefined): boolean => {
  if (!host) return false;
  const h = host.toLowerCase();
  return h.endsWith("auth.kzero.com") || h.includes(".auth.kzero.com");
};

export const inferSamlDirection = (
  events: NormalizedEvent[],
  requestEvent?: NormalizedSamlEvent,
  responseEvent?: NormalizedSamlEvent
): "SP -> KZero" | "KZero -> SP" | "unknown" => {
  if (requestEvent && isKzeroHost(requestEvent.host)) {
    return "SP -> KZero";
  }

  if (responseEvent?.samlResponse?.issuer) {
    try {
      const issuerHost = new URL(responseEvent.samlResponse.issuer).host;
      if (isKzeroHost(issuerHost)) return "KZero -> SP";
    } catch {
      // ignore parse errors
    }
  }

  const samlEvents = events.filter((e): e is NormalizedSamlEvent => e.protocol === "SAML");
  const hasKzeroSamlTraffic = samlEvents.some((e) => isKzeroHost(e.host));
  const hasVendorSamlTraffic = samlEvents.some((e) => !isKzeroHost(e.host));

  if (hasKzeroSamlTraffic && hasVendorSamlTraffic) {
    return requestEvent ? "SP -> KZero" : "KZero -> SP";
  }

  return "unknown";
};

export const classifyCaptureFlow = (events: NormalizedEvent[]): CaptureFlowLabel => {
  if (!events.length) return "Unknown";

  const hasSaml = events.some((e) => e.protocol === "SAML");
  const hasOidc = events.some((e) => e.protocol === "OIDC");

  if (hasSaml && hasOidc) return "Mixed / partial capture";
  if (hasOidc) return "OIDC";

  if (hasSaml) {
    const samlEvents = events.filter((e): e is NormalizedSamlEvent => e.protocol === "SAML");
    const requestEvent = samlEvents.find((e) => e.samlRequest);
    const responseEvent = samlEvents.find((e) => e.samlResponse);
    const direction = inferSamlDirection(events, requestEvent, responseEvent);
    if (direction === "SP -> KZero") return "SP -> KZero";
    if (direction === "KZero -> SP") return "KZero -> SP";
    return "SAML";
  }

  return "Unknown";
};
