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
  samlOverview: "https://docs.kzero.com/server_admin/index.html#_sso_protocols",
  oidcOverview: "https://docs.kzero.com/server_admin/index.html#con-oidc_server_administration_guide",
  samlClients: "https://docs.kzero.com/server_admin/index.html#_client-saml-configuration",
  oidcClients: "https://docs.kzero.com/server_admin/index.html#_oidc_clients",
  samlBindings: "https://docs.kzero.com/server_admin/index.html#con-saml-bindings_server_administration_guide",
  realmSettings: "https://docs.kzero.com/server_admin/index.html#_configuring_realms",
  identityBroker: "https://docs.kzero.com/server_admin/index.html#_identity_broker",
  partnerGuides: "https://kzpp.vercel.app/library/admin-guides/sso-configuration"
};

export function getDocUrl(type: keyof typeof docsUrls): string {
  return docsUrls[type];
}

export function formatDocLink(label: string, type: keyof typeof docsUrls): string {
  return `[${label}](${docsUrls[type]})`;
}

export function buildDocNotice(): string {
  return [
    "📚 Documentation:",
    `- [SSO Protocols Overview](${docsUrls.samlOverview})`,
    `- [SAML Client Configuration](${docsUrls.samlClients})`,
    `- [OIDC Client Configuration](${docsUrls.oidcClients})`,
    `- [Partner SSO Guides](${docsUrls.partnerGuides})`
  ].join("\n");
}
