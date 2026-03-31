import { formatNavigationSteps, getFieldNavigation } from "./navigation";
import { getTermTooltip } from "./terminology";
import { detectVendor, getVendorGuideUrl } from "./vendors";

export interface OidcStep {
  text: string;
  important?: boolean;
  warning?: boolean;
  field?: string;
  vendorHint?: string;
}

export function buildOidcNavigationSteps(advanced: boolean = true): string[] {
  return formatNavigationSteps("oidc", advanced);
}

export function buildRedirectUriFix(observed: string, expected: string, vendorName?: string): OidcStep[] {
  const steps: OidcStep[] = [
    {
      text: "Go to your KZero dashboard → Select your tenant",
      important: true
    },
    {
      text: "Navigate to: Integrations → Applications → [Select your OIDC app]",
      important: true
    },
    {
      text: "Click 'Advanced Console' (on the right side)",
      important: true
    },
    {
      text: "Select 'Client' and search for your app"
    },
    {
      text: "Scroll down to 'Access settings' section",
      important: true
    },
    {
      text: "Find 'Valid Redirect URIs' field",
      field: "Valid Redirect URIs",
      important: true
    },
    {
      text: `Update to: ${expected}`,
      important: true,
      warning: true
    },
    {
      text: "The redirect URI must match EXACTLY - including https:// and trailing slash",
      important: true,
      warning: true
    },
    {
      text: "Click 'Save' at the bottom of the page",
      important: true
    }
  ];

  if (vendorName) {
    const guideUrl = getVendorGuideUrl(vendorName);
    if (guideUrl) {
      steps.push({
        text: `📖 See the [${vendorName} setup guide](${guideUrl}) for exact values`,
        vendorHint: vendorName
      });
    }
  }

  steps.push({
    text: "Test the login flow to confirm the fix works",
    important: true
  });

  return steps;
}

export function buildClientIdFix(observed: string, expected: string, vendorName?: string): OidcStep[] {
  const steps: OidcStep[] = [
    {
      text: "Go to your KZero dashboard → Select your tenant",
      important: true
    },
    {
      text: "Navigate to: Integrations → Applications → [Select your OIDC app]",
      important: true
    },
    {
      text: "Click 'Advanced Console'",
      important: true
    },
    {
      text: "Select 'Client' and search for your app"
    },
    {
      text: "Check 'General settings' section for 'Client ID'",
      field: "Client ID"
    },
    {
      text: `Update Client ID to exactly match: ${expected}`,
      important: true,
      warning: true
    },
    {
      text: "Click 'Save'",
      important: true
    }
  ];

  if (vendorName) {
    const guideUrl = getVendorGuideUrl(vendorName);
    if (guideUrl) {
      steps.push({
        text: `📖 See the [${vendorName} setup guide](${guideUrl}) for exact values`,
        vendorHint: vendorName
      });
    }
  }

  return steps;
}

export function buildClientSecretFix(vendorName?: string): OidcStep[] {
  const steps: OidcStep[] = [
    {
      text: "Go to your KZero dashboard → Select your tenant",
      important: true
    },
    {
      text: "Navigate to: Integrations → Applications → [Select your OIDC app]",
      important: true
    },
    {
      text: "Click 'Advanced Console'",
      important: true
    },
    {
      text: "Select 'Client' and search for your app"
    },
    {
      text: "Go to 'Credentials' tab",
      important: true
    },
    {
      text: "Click 'Regenerate' if the secret was exposed, or copy existing secret",
      important: true,
      warning: true
    },
    {
      text: "Update the vendor app with the new Client Secret",
      important: true
    }
  ];

  if (vendorName) {
    const guideUrl = getVendorGuideUrl(vendorName);
    if (guideUrl) {
      steps.push({
        text: `📖 See the [${vendorName} setup guide](${guideUrl}) for where to enter the secret`,
        vendorHint: vendorName
      });
    }
  }

  return steps;
}

export function buildDiscoveryUrlFix(expected: string): OidcStep[] {
  return [
    {
      text: "Go to your KZero dashboard → Select your tenant",
      important: true
    },
    {
      text: "Navigate to: Configure → Realm settings → General tab",
      important: true
    },
    {
      text: "Scroll to the 'Endpoints' section at the bottom of the page",
      important: true
    },
    {
      text: "Click 'OpenID Endpoint Configuration' to see the discovery document",
      field: "OIDC Discovery URL"
    },
    {
      text: `Your OIDC Discovery URL is: ${expected}`,
      important: true
    },
    {
      text: "Ensure the vendor app is configured with the exact same URL (case-sensitive)",
      important: true,
      warning: true
    }
  ];
}

export function buildIssuerFix(observed: string, expected: string): OidcStep[] {
  return [
    {
      text: "Go to your KZero dashboard → Select your tenant",
      important: true
    },
    {
      text: "Navigate to: Configure → Realm settings → General tab",
      important: true
    },
    {
      text: "Scroll to the 'Endpoints' section",
      important: true
    },
    {
      text: "The Issuer URL is derived from your realm name",
      field: "Issuer"
    },
    {
      text: `Expected issuer: ${expected}`,
      important: true,
      warning: true
    },
    {
      text: "⚠️ The issuer URL is CASE SENSITIVE - check for uppercase/lowercase mismatches",
      important: true,
      warning: true
    },
    {
      text: "Update the vendor app with the exact issuer URL",
      important: true
    }
  ];
}

export function buildClientAuthFix(enable: boolean, vendorName?: string): OidcStep[] {
  const steps: OidcStep[] = [
    {
      text: "Go to your KZero dashboard → Select your tenant",
      important: true
    },
    {
      text: "Navigate to: Integrations → Applications → [Select your OIDC app]",
      important: true
    },
    {
      text: "Click 'Advanced Console'",
      important: true
    },
    {
      text: "Select 'Client' and search for your app"
    },
    {
      text: "Go to 'Capability Config' section",
      important: true
    }
  ];

  if (enable) {
    steps.push({
      text: "Enable 'Client Authentication' (for confidential clients with secrets)",
      field: "Client Authentication",
      important: true
    });
    steps.push({
      text: "Go to 'Credentials' tab and copy the Client Secret",
      important: true
    });
    steps.push({
      text: "Enter the Client Secret in the vendor app",
      important: true
    });
  } else {
    steps.push({
      text: "Disable 'Client Authentication' (for public/SPAs without secrets)",
      field: "Client Authentication"
    });
    steps.push({
      text: "Ensure the vendor app doesn't expect a client secret",
      warning: true
    });
  }

  steps.push({
    text: "Click 'Save'",
    important: true
  });

  if (vendorName) {
    const guideUrl = getVendorGuideUrl(vendorName);
    if (guideUrl) {
      steps.push({
        text: `📖 See the [${vendorName} setup guide](${guideUrl}) for authentication requirements`,
        vendorHint: vendorName
      });
    }
  }

  return steps;
}

export function buildPkceFix(required: boolean, vendorName?: string): OidcStep[] {
  const steps: OidcStep[] = [
    {
      text: "Go to your KZero dashboard → Select your tenant",
      important: true
    },
    {
      text: "Navigate to: Integrations → Applications → [Select your OIDC app]",
      important: true
    },
    {
      text: "Click 'Advanced Console'",
      important: true
    },
    {
      text: "Select 'Client' and search for your app"
    },
    {
      text: "Go to 'Capability Config' section",
      important: true
    }
  ];

  if (required) {
    steps.push({
      text: "Set 'PKCE Method' to 'S256' (recommended) or 'Plain'",
      field: "PKCE Method",
      important: true
    });
    steps.push({
      text: "Ensure the vendor app also uses PKCE when making authorization requests",
      important: true,
      warning: true
    });
  } else {
    steps.push({
      text: "PKCE is optional - vendor doesn't require it",
      important: false
    });
  }

  steps.push({
    text: "Click 'Save'",
    important: true
  });

  return steps;
}

export function buildScopeFix(scopes: string[], vendorName?: string): OidcStep[] {
  const steps: OidcStep[] = [
    {
      text: "Go to your KZero dashboard → Select your tenant",
      important: true
    },
    {
      text: "Navigate to: Integrations → Applications → [Select your OIDC app]",
      important: true
    },
    {
      text: "Click 'Advanced Console'",
      important: true
    },
    {
      text: "Select 'Client' and search for your app"
    },
    {
      text: "Go to 'Client Scopes' tab",
      important: true
    },
    {
      text: `Ensure these scopes are assigned: ${scopes.join(", ")}`,
      field: "Assigned Scopes",
      important: true
    },
    {
      text: "Common scopes to include: openid, profile, email",
      important: true
    },
    {
      text: "Click 'Save'",
      important: true
    }
  ];

  if (vendorName) {
    const guideUrl = getVendorGuideUrl(vendorName);
    if (guideUrl) {
      steps.push({
        text: `📖 See the [${vendorName} setup guide](${guideUrl}) for required scopes`,
        vendorHint: vendorName
      });
    }
  }

  return steps;
}

export function getOidcFieldTooltip(field: string): string | undefined {
  return getTermTooltip(field);
}

export function detectOidcVendor(redirectUri?: string, clientId?: string): string | null {
  const url = redirectUri || clientId || "";
  const detected = detectVendor(url);
  return detected?.vendor || null;
}
