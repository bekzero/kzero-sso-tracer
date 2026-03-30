import type { CaptureSession, NormalizedEvent, NormalizedOidcEvent, NormalizedSamlEvent } from "../shared/models";

export interface TraceContext {
  kzeroHosts: string[];
  tenants: string[];
  oidc: {
    discovery?: NormalizedOidcEvent;
    authorize?: NormalizedOidcEvent;
    callback?: NormalizedOidcEvent;
    token?: NormalizedOidcEvent;
    jwks?: NormalizedOidcEvent;
    logout?: NormalizedOidcEvent;
  };
  saml: {
    request?: NormalizedSamlEvent;
    response?: NormalizedSamlEvent;
  };
}

const isOidc = (e: NormalizedEvent): e is NormalizedOidcEvent => e.protocol === "OIDC";
const isSaml = (e: NormalizedEvent): e is NormalizedSamlEvent => e.protocol === "SAML";

export const buildTraceContext = (session: CaptureSession | null): TraceContext => {
  const events = session?.normalizedEvents ?? [];
  const kzeroHosts = [...new Set(events.map((e) => e.host).filter((h) => h.endsWith("auth.kzero.com")))];
  const tenants = events
    .map((e) => e.url.match(/\/realms\/([^/]+)/i)?.[1])
    .filter((v): v is string => Boolean(v));

  const oidc = events.filter(isOidc);
  const saml = events.filter(isSaml);

  return {
    kzeroHosts,
    tenants,
    oidc: {
      discovery: oidc.find((e) => e.kind === "discovery"),
      authorize: oidc.find((e) => e.kind === "authorize"),
      callback: oidc.find((e) => e.kind === "callback"),
      token: oidc.find((e) => e.kind === "token"),
      jwks: oidc.find((e) => e.kind === "jwks"),
      logout: oidc.find((e) => e.kind === "logout")
    },
    saml: {
      request: saml.find((e) => e.kind === "saml-request"),
      response: saml.find((e) => e.kind === "saml-response")
    }
  };
};
