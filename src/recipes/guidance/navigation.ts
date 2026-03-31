export interface NavigationField {
  section: string;
  fieldName: string;
  description?: string;
}

export interface NavigationSection {
  name: string;
  fields: Record<string, NavigationField>;
}

export const kzeroNavigation = {
  clientSettings: {
    protocol: "both" as const,
    basicPath: "Integrations → Applications → [Select App]",
    advancedPath: "Integrations → Applications → [Select App] → Advanced Console → Client → [Search App]",
    steps: [
      "Go to your KZero dashboard",
      "Select your tenant",
      "Navigate to: Integrations → Applications",
      "Find your app in the list and click on it (or create a new one)",
      "For advanced settings: Click 'Advanced Console' on the right side",
      "Select 'Client' and search for your app"
    ],
    sections: {
      general: {
        name: "General settings",
        description: "Basic app configuration including Client ID and display settings",
        fields: {
          "Client ID": {
            section: "General settings",
            fieldName: "Client ID",
            description: "Unique identifier for this app (usually matches the Entity ID for SAML)"
          },
          "Name": {
            section: "General settings",
            fieldName: "Name",
            description: "Display name for this app in the KZero dashboard"
          },
          "Description": {
            section: "General settings",
            fieldName: "Description",
            description: "Optional description to help identify this app"
          },
          "Always Display in UI": {
            section: "General settings",
            fieldName: "Always Display in UI",
            description: "Whether this app appears in the KZero login page application list"
          }
        }
      },
      access: {
        name: "Access settings",
        description: "URLs where users are redirected during SSO flow",
        fields: {
          "Home URL": {
            section: "Access settings",
            fieldName: "Home URL",
            description: "Where users go after clicking the app from the KZero dashboard"
          },
          "Valid Redirect URIs": {
            section: "Access settings",
            fieldName: "Valid Redirect URIs",
            description: "Allowed callback URLs after OIDC login (must match exactly)"
          },
          "Master SAML Processing URL": {
            section: "Access settings",
            fieldName: "Master SAML Processing URL",
            description: "ACS URL where SAML responses are received"
          },
          "IDP-Initiated SSO URL Name": {
            section: "Access settings",
            fieldName: "IDP-Initiated SSO URL Name",
            description: "Identifier for IdP-initiated SSO (if supported)"
          }
        }
      },
      samlCapabilities: {
        name: "SAML Capabilities",
        description: "SAML-specific authentication and formatting settings",
        fields: {
          "Name ID format": {
            section: "SAML Capabilities",
            fieldName: "Name ID format",
            description: "Format of the user identifier sent to the vendor"
          },
          "Force Name ID Format": {
            section: "SAML Capabilities",
            fieldName: "Force Name ID Format",
            description: "Override any NameID format requested by the vendor"
          },
          "Force POST Binding": {
            section: "SAML Capabilities",
            fieldName: "Force POST Binding",
            description: "Always use POST binding even if vendor requests redirect"
          },
          "Include AuthnStatement": {
            section: "SAML Capabilities",
            fieldName: "Include AuthnStatement",
            description: "Include authentication timestamp in assertions"
          }
        }
      },
      signature: {
        name: "Signature & Encryption",
        description: "Cryptographic signing and encryption settings",
        fields: {
          "Sign Documents": {
            section: "Signature & Encryption",
            fieldName: "Sign Documents",
            description: "Sign the entire SAML document (usually not needed)"
          },
          "Sign Assertions": {
            section: "Signature & Encryption",
            fieldName: "Sign Assertions",
            description: "Sign the assertion portion (usually required by vendors)"
          },
          "Sign Responses": {
            section: "Signature & Encryption",
            fieldName: "Sign Responses",
            description: "Sign the SAML response wrapper"
          }
        }
      },
      capabilityConfig: {
        name: "Capability Config",
        description: "OIDC-specific authentication flow settings",
        fields: {
          "Client Authentication": {
            section: "Capability Config",
            fieldName: "Client Authentication",
            description: "How the app authenticates with KZero (ON = secret, OFF = none)"
          },
          "Standard Flow": {
            section: "Capability Config",
            fieldName: "Standard Flow",
            description: "Enable Authorization Code flow for browser apps"
          },
          "Direct Access Grants": {
            section: "Capability Config",
            fieldName: "Direct Access Grants",
            description: "Enable direct OAuth grants for non-browser apps"
          },
          "PKCE Method": {
            section: "Capability Config",
            fieldName: "PKCE Method",
            description: "PKCE protection method (S256 recommended)"
          }
        }
      },
      logout: {
        name: "Logout settings",
        description: "Single Logout (SLO) configuration",
        fields: {
          "Front Channel Logout URL": {
            section: "Logout settings",
            fieldName: "Front Channel Logout URL",
            description: "URL called during browser-based logout"
          },
          "Backchannel Logout URL": {
            section: "Logout settings",
            fieldName: "Backchannel Logout URL",
            description: "URL called during server-to-server logout"
          }
        }
      }
    }
  },
  realmSettings: {
    path: "Realm settings → General tab",
    steps: [
      "Go to your KZero dashboard",
      "Select your tenant",
      "Navigate to: Configure → Realm settings",
      "Click on the 'General' tab",
      "Scroll to the 'Endpoints' section at the bottom"
    ],
    fields: {
      "OpenID Endpoint Configuration": {
        fieldName: "OpenID Endpoint Configuration",
        description: "Link to the OIDC discovery document"
      },
      "SAML 2.0 Identity Provider Metadata": {
        fieldName: "SAML 2.0 Identity Provider Metadata",
        description: "Link to download SAML metadata XML"
      }
    }
  }
};

export function getNavigationPath(protocol: "saml" | "oidc", advanced: boolean = true): string {
  if (advanced) {
    return `${kzeroNavigation.clientSettings.basicPath}
→ Click 'Advanced Console' on the right side
→ Select 'Client' and search for your app`;
  }
  return kzeroNavigation.clientSettings.basicPath;
}

export function getFieldNavigation(fieldName: string, protocol: "saml" | "oidc"): string {
  const allSections = protocol === "saml" 
    ? { ...kzeroNavigation.clientSettings.sections }
    : kzeroNavigation.clientSettings.sections;
  
  for (const sectionKey of Object.keys(allSections)) {
    const section = allSections[sectionKey as keyof typeof allSections];
    if (section.fields && section.fields[fieldName]) {
      return `${section.name} → ${section.fields[fieldName].fieldName}`;
    }
  }
  
  return `Client settings → ${fieldName}`;
}

export function formatNavigationSteps(protocol: "saml" | "oidc", advanced: boolean = true): string[] {
  const baseSteps = [
    "Go to your KZero dashboard",
    "Select your tenant",
    "Navigate to: Integrations → Applications"
  ];
  
  const advancedSteps = advanced ? [
    "Click 'Advanced Console' (on the right side of the screen)",
    "Select 'Client' and search for your app"
  ] : [];
  
  return [...baseSteps, ...advancedSteps];
}
