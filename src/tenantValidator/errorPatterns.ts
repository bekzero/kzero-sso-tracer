import type { ErrorPattern, ErrorAnalysisResult } from "./types";

export const ERROR_PATTERNS: ErrorPattern[] = [
  {
    id: "invalid_grant",
    pattern: /invalid_grant/i,
    cause: "Invalid grant - authorization code expired, already used, or revoked",
    fix: "Re-initiate the login flow. The authorization code is single-use and expires quickly. If this happens repeatedly, check for network issues causing delays.",
    severity: "error"
  },
  {
    id: "invalid_grant_code_expired",
    pattern: /invalid_grant.*code.*expired/i,
    cause: "Authorization code has expired",
    fix: "Re-initiate the login flow. The code expires after a short time (typically 60 seconds). Ensure the login completes without delays.",
    severity: "error"
  },
  {
    id: "invalid_grant_code_used",
    pattern: /invalid_grant.*code.*used/i,
    cause: "Authorization code was already used",
    fix: "The authorization code can only be exchanged once. This typically indicates a duplicate request - ensure the client doesn't retry automatically.",
    severity: "error"
  },
  {
    id: "invalid_client",
    pattern: /invalid_client/i,
    cause: "Client authentication failed - invalid client_id or client_secret",
    fix: "Verify the Client ID and Client Secret in your KZero client configuration match exactly what the vendor is using. Check for trailing spaces or case sensitivity.",
    severity: "error"
  },
  {
    id: "invalid_client_no_credentials",
    pattern: /invalid_client.*authentication/i,
    cause: "No client credentials provided or authentication method mismatch",
    fix: "Check the Client Authentication method in KZero matches what the vendor expects (e.g., client_secret_basic, client_secret_post, private_key_jwt).",
    severity: "error"
  },
  {
    id: "invalid_request_redirect_uri",
    pattern: /invalid_request.*redirect.?uri/i,
    cause: "Redirect URI not in allowed list or doesn't match exactly",
    fix: "Add the exact redirect URI to the Valid Redirect URIs list in KZero client settings. Must match exactly including trailing slash.",
    severity: "error"
  },
  {
    id: "redirect_uri_mismatch",
    pattern: /redirect.?uri.?mismatch/i,
    cause: "Redirect URI in request doesn't match any allowed URIs",
    fix: "Add the exact redirect URI to Valid Redirect URIs in KZero. Check that the vendor is using the exact same URL including scheme (https://) and path.",
    severity: "error"
  },
  {
    id: "access_denied",
    pattern: /access_denied/i,
    cause: "Access denied - user or client not authorized",
    fix: "Check if the user has proper permissions in KZero. Also verify the client has required grant types enabled. Check if 'Direct Access Grants' is enabled for password flow.",
    severity: "error"
  },
  {
    id: "invalid_scope",
    pattern: /invalid_scope/i,
    cause: "Requested scope is invalid or not allowed",
    fix: "Verify requested scopes are enabled in the KZero client. Add any custom scopes to the Client Scopes assignment. Standard scopes: openid, profile, email.",
    severity: "error"
  },
  {
    id: "unauthorized_client",
    pattern: /unauthorized_client/i,
    cause: "Client not authorized for this grant type",
    fix: "Enable the required grant type in KZero client settings (e.g., Authorization Code, Implicit, Password, Client Credentials). Check 'Standard Flow' and 'Direct Access Grants'.",
    severity: "error"
  },
  {
    id: "unsupported_response_type",
    pattern: /unsupported_response_type/i,
    cause: "Response type not supported by the client",
    fix: "Check which response types are enabled in KZero (code, token, id_token). Ensure the vendor is requesting a supported type or combination.",
    severity: "error"
  },
  {
    id: "unsupported_response_mode",
    pattern: /unsupported_response_mode/i,
    cause: "Response mode not supported",
    fix: "Check the Response Mode setting in KZero client. Common modes: query, fragment, form_post.",
    severity: "error"
  },
  {
    id: "interaction_required",
    pattern: /interaction_required/i,
    cause: "User interaction is required but not possible",
    fix: "The request requires user interaction but prompt=none was set. Either remove prompt=none or ensure user has a valid session.",
    severity: "warning"
  },
  {
    id: "login_required",
    pattern: /login_required/i,
    cause: "User must authenticate but session doesn't exist",
    fix: "User needs to authenticate. Check if 'Remember Me' is enabled in KZero. Verify session timeout settings. Ensure user is not excluded by authentication policies.",
    severity: "warning"
  },
  {
    id: "account_selection_required",
    pattern: /account_selection_required/i,
    cause: "User must select an account but none available",
    fix: "Check KZero account linking settings. This usually happens with multiple identity providers or when account linking is required.",
    severity: "warning"
  },
  {
    id: "consent_required",
    pattern: /consent_required/i,
    cause: "User consent is required but not granted",
    fix: "Either enable 'Consent' settings in KZero or update client to skip consent. Check if 'Consent' is required in Client settings.",
    severity: "warning"
  },
  {
    id: "temporarily_unavailable",
    pattern: /temporarily_unavailable/i,
    cause: "Auth server is temporarily unavailable",
    fix: "Check KZero server status, load, and any maintenance. This can also occur if the authentication executor is unavailable.",
    severity: "warning"
  },
  {
    id: "server_error",
    pattern: /server_error|internal_server_error/i,
    cause: "KZero server encountered an error",
    fix: "Check KZero server logs for details. This could indicate configuration issues, database problems, or transient failures.",
    severity: "error"
  },
  {
    id: "invalid_request",
    pattern: /invalid_request/i,
    cause: "The request is missing a required parameter or malformed",
    fix: "Review the exact error description. Check that required parameters (client_id, response_type, redirect_uri) are present in the request.",
    severity: "error"
  },
  {
    id: "unknown_error",
    pattern: /error.*unknown|unknown_error/i,
    cause: "Unrecognized error from KZero",
    fix: "Check KZero server logs for details. This could be a configuration issue or unexpected state.",
    severity: "error"
  },
  {
    id: "saml_assertion_expired",
    pattern: /assertion.*expired|conditions.*not.*on.*or.*after/i,
    cause: "SAML assertion has expired",
    fix: "Increase 'Allow clock skew' in KZero realm settings (try 30-60 seconds). Check that server times are synchronized via NTP.",
    severity: "error"
  },
  {
    id: "saml_signature_invalid",
    pattern: /signature.*invalid|signature.*validation/i,
    cause: "SAML signature verification failed",
    fix: "Check that signing is configured in KZero client settings. Verify the vendor's certificate is properly imported. Check 'Sign Assertions' setting.",
    severity: "error"
  },
  {
    id: "saml_issuer_mismatch",
    pattern: /issuer.*mismatch|issuer.*not.*trusted/i,
    cause: "SAML issuer doesn't match expected value",
    fix: "Verify the Identity Provider Entity ID in KZero matches the vendor's configuration. Check Realm settings > General > Issuer URL.",
    severity: "error"
  },
  {
    id: "saml_audience_mismatch",
    pattern: /audience.*invalid|audience.*mismatch/i,
    cause: "SAML audience restriction not satisfied",
    fix: "Check that the Service Provider Entity ID is set as an Audience in the SAML assertion. Configure in KZero client settings.",
    severity: "error"
  },
  {
    id: "saml_destination_mismatch",
    pattern: /destination.*mismatch|destination.*invalid/i,
    cause: "SAML Destination doesn't match the response URL",
    fix: "Verify the Master SAML Processing URL in KZero client matches what the vendor expects.",
    severity: "error"
  },
  {
    id: "saml_nameid_not_found",
    pattern: /nameid.*not.*found|user.*not.*found/i,
    cause: "User corresponding to NameID not found",
    fix: "Check the Name ID format mapping in KZero. Ensure the user exists and the NameID format matches what the vendor sends.",
    severity: "error"
  },
  {
    id: "saml_consent_denied",
    pattern: /consent.*denied|consent.*required/i,
    cause: "User consent required but denied",
    fix: "Either enable implicit consent in KZero or ensure the vendor doesn't request consent. Check client 'Consent' setting.",
    severity: "warning"
  }
];

export const analyzeError = (errorText: string): ErrorAnalysisResult => {
  const suggestions: string[] = [];
  let matchedPattern: ErrorPattern | undefined = undefined;

  for (const pattern of ERROR_PATTERNS) {
    if (pattern.pattern.test(errorText)) {
      matchedPattern = pattern;
      break;
    }
  }

  if (!matchedPattern) {
    suggestions.push("No matching error pattern found. Check KZero server logs for more details.");
    suggestions.push("Common issues: check client credentials, redirect URIs, and grant types.");
    suggestions.push("Verify the KZero realm is properly configured and accessible.");
  } else {
    if (matchedPattern.fix) {
      suggestions.push(matchedPattern.fix);
    }
  }

  return {
    inputError: errorText,
    matchedPattern,
    suggestions
  };
};