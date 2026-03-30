const ALIASES: Record<string, string[]> = {
  "Redirect URL": ["Valid Redirect URIs", "Valid redirect URIs"],
  "Logout URL": ["Valid post logout redirect URIs", "Valid post logout redirect URIs"],
  "Client authentication": ["Client Authentication", "Client Authenticator"],
  "Use PKCE": ["PKCE Method", "PKCE method", "Require PKCE"],
  "Assertion Consumer Service URL": [
    "Assertion Consumer Service POST Binding URL",
    "Assertion Consumer Service Redirect Binding URL",
    "Assertion Consumer Service URL"
  ],
  "Service provider Entity ID": ["Client ID"],
  "NameID Policy Format": ["Name ID format", "NameID Policy Format"],
  "Want assertions signed": ["Sign assertions"],
  "Want assertions encrypted": ["Encrypt assertions", "Encrypt assertion"],
  "Want AuthnRequests signed": ["Sign documents"],
  "Validate signatures": ["Signature and Encryption", "Signature"],
  "Issuer": ["OIDC Issuer", "Issuer URL", "Issuer"],
  "Discovery Endpoint": ["Discovery Endpoint", "openid-configuration"],
  "Client Secret": ["Client Secret"],
  "Client ID": ["Client ID"]
};

export const labelVariants = (label: string): string[] => {
  const variants = [label, ...(ALIASES[label] ?? [])];
  return [...new Set(variants)];
};
