import { formatNavigationSteps, getFieldNavigation } from "./navigation";
import { getTermTooltip } from "./terminology";
import { detectVendor, getVendorGuideUrl } from "./vendors";

export interface SsoStep {
  text: string;
  important?: boolean;
  warning?: boolean;
  field?: string;
  vendorHint?: string;
}

export interface SslFieldFix {
  field: string;
  section: string;
  expected: string;
  importance: "required" | "recommended" | "optional";
  why: string;
}

export function buildSamlNavigationSteps(advanced: boolean = true): string[] {
  return formatNavigationSteps("saml", advanced);
}

export function getAcsUrlNavPath(): string {
  return getFieldNavigation("Master SAML Processing URL", "saml");
}

export function getEntityIdNavPath(): string {
  return getFieldNavigation("Client ID", "saml");
}

export function buildAcsUrlFix(observed: string, expected: string, vendorName?: string): SsoStep[] {
  const steps: SsoStep[] = [
    {
      text: "🔹 Go to your KZero dashboard → Select your tenant.",
      important: true
    },
    {
      text: "🔹 Click 'Advanced Console' → Select 'Clients' → Search for your app.",
      important: true
    },
    {
      text: "🔹 Go to 'Access settings' section.",
      important: true
    },
    {
      text: "🔹 Find 'Master SAML Processing URL' field.",
      important: true,
      field: "Master SAML Processing URL"
    },
    {
      text: `🔴 Enter the exact URL: ${expected}`,
      important: true,
      warning: true
    },
    {
      text: "💾 Click 'Save' at the bottom of the page.",
      important: true
    }
  ];

  if (vendorName) {
    const guideUrl = getVendorGuideUrl(vendorName);
    if (guideUrl) {
      steps.push({
        text: `📖 See ${vendorName} setup guide: ${guideUrl}`,
        vendorHint: vendorName
      });
    }
  }

  steps.push({
    text: "✅ Test the login flow to confirm the fix works.",
    important: true
  });

  return steps;
}

export function buildEntityIdFix(observed: string, expected: string, vendorName?: string): SsoStep[] {
  const steps: SsoStep[] = [
    {
      text: "🔹 Go to your KZero dashboard → Select your tenant.",
      important: true
    },
    {
      text: "🔹 Click 'Advanced Console' → Select 'Clients' → Search for your app.",
      important: true
    },
    {
      text: "🔹 Check 'General settings' section for 'Client ID'.",
      field: "Client ID"
    },
    {
      text: `🔴 Update the Client ID to exactly match: ${expected}`,
      important: true,
      warning: true
    },
    {
      text: "💾 Click 'Save'.",
      important: true
    }
  ];

  if (vendorName) {
    const guideUrl = getVendorGuideUrl(vendorName);
    if (guideUrl) {
      steps.push({
        text: `📖 See ${vendorName} setup guide: ${guideUrl}`,
        vendorHint: vendorName
      });
    }
  }

  return steps;
}

export function buildIssuerFix(observed: string, expected: string): SsoStep[] {
  return [
    {
      text: "🔹 Go to your KZero dashboard → Select your tenant.",
      important: true
    },
    {
      text: "🔹 Navigate to: Configure → Realm settings → General tab.",
      important: true
    },
    {
      text: "🔹 Scroll to the 'Endpoints' section at the bottom of the page.",
      important: true
    },
    {
      text: "🔹 Your KZero Issuer URL is shown in the OIDC Endpoint Configuration link.",
      field: "Issuer URL"
    },
    {
      text: `🔴 The correct issuer should be: ${expected}`,
      important: true,
      warning: true
    },
    {
      text: "⚠️ Ensure the vendor app is configured with the exact issuer URL (case-sensitive).",
      important: true
    }
  ];
}

export function buildNameIdFix(format: string, vendorName?: string): SsoStep[] {
  const steps: SsoStep[] = [
    {
      text: "🔹 Go to your KZero dashboard → Select your tenant.",
      important: true
    },
    {
      text: "🔹 Click 'Advanced Console' → Select 'Clients' → Search for your app.",
      important: true
    },
    {
      text: "🔹 Go to 'SAML Capabilities' section.",
      important: true
    },
    {
      text: `🔹 Check 'Name ID format' is set to: ${format}`,
      field: "Name ID format",
      important: true
    },
    {
      text: "🔹 Enable 'Force Name ID Format' if the vendor requires this format.",
      field: "Force Name ID Format"
    },
    {
      text: "💾 Click 'Save'.",
      important: true
    }
  ];

  if (vendorName) {
    const guideUrl = getVendorGuideUrl(vendorName);
    if (guideUrl) {
      steps.push({
        text: `📖 See ${vendorName} setup guide: ${guideUrl}`,
        vendorHint: vendorName
      });
    }
  }

  return steps;
}

export function buildSigningFix(action: "enable" | "disable", what: "assertions" | "documents", vendorName?: string): SsoStep[] {
  const steps: SsoStep[] = [
    {
      text: "🔹 Go to your KZero dashboard → Select your tenant.",
      important: true
    },
    {
      text: "🔹 Click 'Advanced Console' → Select 'Clients' → Search for your app.",
      important: true
    },
    {
      text: "🔹 Go to 'Signature & Encryption' section.",
      important: true
    }
  ];

  if (action === "enable") {
    steps.push({
      text: what === "assertions" 
        ? "🔹 Enable 'Sign Assertions' (usually required by vendors)."
        : "🔹 Enable 'Sign Documents' (rarely needed).",
      field: what === "assertions" ? "Sign Assertions" : "Sign Documents",
      important: true
    });
  } else {
    steps.push({
      text: what === "assertions"
        ? "🔹 Disable 'Sign Assertions' if vendor doesn't support signed assertions."
        : "🔹 Disable 'Sign Documents' (usually not needed).",
      field: what === "assertions" ? "Sign Assertions" : "Sign Documents"
    });
  }

  steps.push({
    text: "💾 Click 'Save'.",
    important: true
  });

  if (vendorName) {
    const guideUrl = getVendorGuideUrl(vendorName);
    if (guideUrl) {
      steps.push({
        text: `📖 See ${vendorName} setup guide: ${guideUrl}`,
        vendorHint: vendorName
      });
    }
  }

  return steps;
}

export function buildBindingFix(forcePost: boolean, vendorName?: string): SsoStep[] {
  const steps: SsoStep[] = [
    {
      text: "🔹 Go to your KZero dashboard → Select your tenant.",
      important: true
    },
    {
      text: "🔹 Click 'Advanced Console' → Select 'Clients' → Search for your app.",
      important: true
    },
    {
      text: "🔹 Go to 'SAML Capabilities' section.",
      important: true
    }
  ];

  if (forcePost) {
    steps.push({
      text: "🔴 Enable 'Force POST Binding' (vendor requires POST binding).",
      field: "Force POST Binding",
      important: true,
      warning: true
    });
  } else {
    steps.push({
      text: "🔹 Disable 'Force POST Binding' (vendor accepts redirect binding).",
      field: "Force POST Binding"
    });
  }

  steps.push({
    text: "💾 Click 'Save'.",
    important: true
  });

  return steps;
}

export function getSamlFieldTooltip(field: string): string | undefined {
  return getTermTooltip(field);
}

export function detectSamlVendor(entityId?: string, acsUrl?: string): string | null {
  const url = entityId || acsUrl || "";
  const detected = detectVendor(url);
  return detected?.vendor || null;
}