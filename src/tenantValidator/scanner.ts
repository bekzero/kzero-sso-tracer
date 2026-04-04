import type { NormalizedEvent, NormalizedOidcEvent, NormalizedSamlEvent } from "../shared/models";
import type { TenantScanResult, TenantMismatch } from "./types";

const extractTenantFromUrl = (url: string): string | null => {
  const match = url.match(/\/realms\/([^/?#]+)/i);
  return match ? match[1] : null;
};

const isOidcEvent = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === "OIDC";
const isSamlEvent = (e: NormalizedEvent): e is NormalizedSamlEvent => e.protocol === "SAML";

export const scanForTenantMismatches = (
  events: NormalizedEvent[],
  inputTenant: string
): TenantScanResult => {
  if (!inputTenant || inputTenant.trim() === "") {
    return {
      inputTenant: "",
      totalEvents: 0,
      samlEvents: 0,
      oidcEvents: 0,
      mismatches: [],
      hasMismatch: false
    };
  }

  const trimmedTenant = inputTenant.trim();

  const samlEvents = events.filter(isSamlEvent);
  const oidcEvents = events.filter(isOidcEvent);
  const allRelevantEvents = [...samlEvents, ...oidcEvents];

  const mismatches: TenantMismatch[] = [];

  for (const event of allRelevantEvents) {
    const extractedTenant = extractTenantFromUrl(event.url);
    
    if (extractedTenant !== null && extractedTenant !== trimmedTenant) {
      mismatches.push({
        eventId: event.id,
        eventKind: event.kind,
        url: event.url,
        host: event.host,
        extractedTenant,
        inputTenant: trimmedTenant
      });
    }
  }

  return {
    inputTenant: trimmedTenant,
    totalEvents: allRelevantEvents.length,
    samlEvents: samlEvents.length,
    oidcEvents: oidcEvents.length,
    mismatches,
    hasMismatch: mismatches.length > 0
  };
};

export const getAllTenantsInSession = (events: NormalizedEvent[]): string[] => {
  const tenants = new Set<string>();
  
  for (const event of events) {
    const tenant = extractTenantFromUrl(event.url);
    if (tenant) {
      tenants.add(tenant);
    }
  }
  
  return Array.from(tenants).sort();
};

export const getKzeroHostsInSession = (events: NormalizedEvent[]): string[] => {
  const hosts = new Set<string>();
  
  for (const event of events) {
    if (event.host.endsWith("auth.kzero.com") || event.host.includes(".auth.kzero.com")) {
      hosts.add(event.host);
    }
  }
  
  return Array.from(hosts).sort();
};