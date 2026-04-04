import type { OidcMetadata, MetadataParseResult } from "../types";

export const parseOidcMetadata = (content: string): MetadataParseResult => {
  try {
    const json = JSON.parse(content);
    
    if (!json.issuer) {
      return { type: "error", error: "Missing 'issuer' field in OIDC discovery document" };
    }

    const metadata: OidcMetadata = {
      issuer: json.issuer,
      authorizationEndpoint: json.authorization_endpoint ?? "",
      tokenEndpoint: json.token_endpoint ?? "",
      userinfoEndpoint: json.userinfo_endpoint,
      jwksUri: json.jwks_uri ?? "",
      endSessionEndpoint: json.end_session_endpoint,
      grantTypesSupported: json.grant_types_supported,
      responseTypesSupported: json.response_types_supported,
      subjectTypesSupported: json.subject_types_supported,
      idTokenSigningAlgValuesSupported: json.id_token_signing_alg_values_supported,
      tokenEndpointAuthMethodsSupported: json.token_endpoint_auth_methods_supported,
      scopesSupported: json.scopes_supported
    };

    return { type: "oidc", data: metadata };
  } catch (e) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return { type: "error", error: `Failed to parse OIDC metadata: ${message}` };
  }
};

export const isOidcMetadata = (content: string): boolean => {
  try {
    const json = JSON.parse(content);
    return Boolean(json.issuer && (json.authorization_endpoint || json.token_endpoint || json.jwks_uri));
  } catch {
    return false;
  }
};