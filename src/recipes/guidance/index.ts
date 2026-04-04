export { terminology, getTermTooltip, type TermExplanation } from "./terminology";
export { 
  kzeroNavigation, 
  getNavigationPath, 
  getFieldNavigation, 
  formatNavigationSteps,
  type NavigationField,
  type NavigationSection
} from "./navigation";
export { 
  detectVendor, 
  getVendorGuideUrl, 
  getVendorGuideMarkdown,
  isVendorVerified,
  formatVendorNotice,
  vendorGuides,
  type VendorGuide,
  type VendorPattern,
  type VendorDetection
} from "./vendors";

import { buildIssuerFix as samlBuildIssuerFix } from "./saml";
import { buildIssuerFix as oidcBuildIssuerFix } from "./oidc";

export const buildSamlIssuerFix = samlBuildIssuerFix;
export const buildOidcIssuerFix = oidcBuildIssuerFix;

export const docsUrls = {
  samlOverview: "https://kzpp.vercel.app/library/admin-guides/generic-integrations/saml-sso-integration-guide",
  oidcOverview: "https://kzpp.vercel.app/library/admin-guides/generic-integrations/openid-connect-oidc-sso-integration-guide",
  samlClients: "https://kzpp.vercel.app/library/admin-guides/generic-integrations/saml-sso-integration-guide",
  oidcClients: "https://kzpp.vercel.app/library/admin-guides/generic-integrations/openid-connect-oidc-sso-integration-guide",
  samlBindings: "https://kzpp.vercel.app/library/admin-guides/generic-integrations/saml-sso-integration-guide",
  realmSettings: "https://kzpp.vercel.app/library/admin-guides/generic-integrations/openid-connect-oidc-sso-integration-guide",
  identityBroker: "https://kzpp.vercel.app/library/admin-guides/generic-integrations/saml-sso-integration-guide",
  partnerGuides: "https://kzpp.vercel.app/library/admin-guides/generic-integrations/saml-sso-integration-guide"
};

export function getDocUrl(type: keyof typeof docsUrls): string {
  return docsUrls[type];
}

export function formatDocLink(label: string, type: keyof typeof docsUrls): string {
  return `[${label}](${docsUrls[type]})`;
}

export function buildDocNotice(): string {
  return [
    "Documentation:",
    `- [SAML SSO Integration Guide](${docsUrls.samlOverview})`,
    `- [OIDC SSO Integration Guide](${docsUrls.oidcOverview})`,
    `- [Partner SSO Guides](${docsUrls.partnerGuides})`
  ].join("\n");
}
