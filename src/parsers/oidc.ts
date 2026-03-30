import { decodeJwt, isJwt } from "./jwt";
import { parseQueryString, safeJsonParse, safeUrl } from "../shared/utils";
import type { NormalizedOidcEvent } from "../shared/models";

export const parseFragmentOrQuery = (url: string): Record<string, string> => {
  const parsed = safeUrl(url);
  if (!parsed) return {};
  if (parsed.hash.length > 1) return parseQueryString(parsed.hash.slice(1));
  if (parsed.search.length > 1) return parseQueryString(parsed.search.slice(1));
  return {};
};

export const attachTokenArtifacts = (event: NormalizedOidcEvent, body?: string): void => {
  if (!body) return;
  const json = safeJsonParse<Record<string, unknown>>(body);
  if (!json) return;
  const idToken = typeof json.id_token === "string" ? json.id_token : undefined;
  const accessToken = typeof json.access_token === "string" ? json.access_token : undefined;
  const error = typeof json.error === "string" ? json.error : undefined;
  const errorDescription = typeof json.error_description === "string" ? json.error_description : undefined;

  if (idToken && isJwt(idToken)) {
    event.idToken = decodeJwt(idToken);
  }
  if (accessToken) {
    if (isJwt(accessToken)) {
      event.accessTokenJwt = decodeJwt(accessToken);
    } else {
      event.accessTokenOpaque = true;
    }
  }
  if (error) event.error = error;
  if (errorDescription) event.errorDescription = errorDescription;

  const authMethod = typeof json.token_endpoint_auth_method === "string" ? json.token_endpoint_auth_method : undefined;
  if (authMethod) {
    event.tokenEndpointAuthMethod = authMethod;
  }
};
