export interface VendorGuide {
  name: string;
  folder: string;
  slug: string;
  verified?: boolean;
}

export interface VendorPattern {
  pattern: string;
  vendor: string;
  protocol?: "saml" | "oidc" | "both";
}

const vendorPatterns: VendorPattern[] = [
  // A-D
  { pattern: "activecampaign.com", vendor: "Active Campaign", protocol: "saml" },
  { pattern: "drata.com", vendor: "Drata", protocol: "saml" },
  { pattern: "adobe.com", vendor: "Adobe", protocol: "saml" },
  { pattern: "cultureamp.com", vendor: "Culture Amp", protocol: "saml" },
  { pattern: "cyberark.com", vendor: "CyberArk", protocol: "saml" },
  
  // E-H
  { pattern: "freshworks.com", vendor: "Freshworks", protocol: "saml" },
  { pattern: "goto.com", vendor: "GoTo", protocol: "saml" },
  { pattern: "heap.io", vendor: "Heap", protocol: "saml" },
  { pattern: "figma.com", vendor: "Figma", protocol: "saml" },
  { pattern: "egnyte.com", vendor: "Egnyte", protocol: "saml" },
  
  // I-M
  { pattern: "mendix.com", vendor: "Mendix", protocol: "oidc" },
  { pattern: "mulesoft.com", vendor: "MuleSoft", protocol: "oidc" },
  { pattern: "moodle.com", vendor: "Moodle", protocol: "saml" },
  { pattern: "miro.com", vendor: "Miro", protocol: "saml" },
  { pattern: "joomla.com", vendor: "Joomla", protocol: "saml" },
  
  // N-R
  { pattern: "pulseway.com", vendor: "Pulseway", protocol: "saml" },
  { pattern: "optimizely.com", vendor: "Optimizely", protocol: "saml" },
  { pattern: "paloaltonetworks.com", vendor: "Palo Alto Networks", protocol: "saml" },
  { pattern: "outsystems.com", vendor: "OutSystems", protocol: "saml" },
  { pattern: "pipedrive.com", vendor: "Pipedrive", protocol: "saml" },
  
  // S-V
  { pattern: "shopify.com", vendor: "Shopify Plus", protocol: "saml" },
  { pattern: "successfactors.com", vendor: "SAP SuccessFactors", protocol: "saml" },
  { pattern: "concur.com", vendor: "SAP Concur", protocol: "saml" },
  { pattern: "sophos.com", vendor: "Sophos Central", protocol: "saml" },
  { pattern: "citrixsharefile.com", vendor: "ShareFile", protocol: "saml" },
  
  // W-Z
  { pattern: "wordpress.com", vendor: "WordPress", protocol: "saml" },
  { pattern: "workday.com", vendor: "Workday", protocol: "saml" },
  { pattern: "wpengine.com", vendor: "WP Engine", protocol: "saml" },
  { pattern: "zoominfo.com", vendor: "ZoomInfo", protocol: "saml" },
  { pattern: "wrike.com", vendor: "Wrike", protocol: "saml" },
  { pattern: "zoom.us", vendor: "Zoom", protocol: "saml" },
  { pattern: "github.com", vendor: "GitHub", protocol: "oidc" },
  { pattern: "gitlab.com", vendor: "GitLab", protocol: "oidc" },
  { pattern: "slack.com", vendor: "Slack", protocol: "oidc" },
  { pattern: "atlassian.com", vendor: "Atlassian", protocol: "oidc" },
  { pattern: "jira", vendor: "Jira", protocol: "oidc" },
  { pattern: "confluence", vendor: "Confluence", protocol: "oidc" },
  { pattern: "hubspot.com", vendor: "HubSpot", protocol: "saml" },
  { pattern: "zendesk.com", vendor: "Zendesk", protocol: "saml" },
  { pattern: "salesforce.com", vendor: "Salesforce", protocol: "saml" },
  { pattern: "servicenow.com", vendor: "ServiceNow", protocol: "saml" },
  { pattern: "workday.com", vendor: "Workday", protocol: "saml" },
  { pattern: "okta.com", vendor: "Okta", protocol: "both" },
  { pattern: "azure.com", vendor: "Microsoft Azure AD", protocol: "both" },
  { pattern: "microsoftonline.com", vendor: "Microsoft 365", protocol: "both" },
  { pattern: "google.com", vendor: "Google Workspace", protocol: "oidc" },
];

export const vendorGuides: Record<string, VendorGuide> = {
  "Active Campaign": { name: "Active Campaign", folder: "a-d", slug: "active-campaign-sso-configuration" },
  "Drata": { name: "Drata", folder: "a-d", slug: "drata-sso-configuration" },
  "Adobe": { name: "Adobe", folder: "a-d", slug: "adobe-sso-configuration" },
  "Culture Amp": { name: "Culture Amp", folder: "a-d", slug: "culture-amp-sso-configuration" },
  "CyberArk": { name: "CyberArk", folder: "a-d", slug: "cyberark-sso-configuration" },
  "Freshworks": { name: "Freshworks", folder: "e-h", slug: "freshworks-sso-configuration" },
  "GoTo": { name: "GoTo", folder: "e-h", slug: "goto-sso-configuration" },
  "Heap": { name: "Heap", folder: "e-h", slug: "heap-sso-configuration" },
  "Figma": { name: "Figma", folder: "e-h", slug: "figma-sso-configuration" },
  "Egnyte": { name: "Egnyte", folder: "e-h", slug: "egnyte-sso-configuration" },
  "Mendix": { name: "Mendix", folder: "i-m", slug: "mendix-sso-configuration", verified: true },
  "MuleSoft": { name: "MuleSoft", folder: "i-m", slug: "mulesoft-sso-integration" },
  "Moodle": { name: "Moodle", folder: "i-m", slug: "moodle-sso-configuration" },
  "Miro": { name: "Miro", folder: "i-m", slug: "miro-sso-configuration" },
  "Joomla": { name: "Joomla", folder: "i-m", slug: "joomla-sso-configuration" },
  "Pulseway": { name: "Pulseway", folder: "n-r", slug: "pulseway-sso-configuration" },
  "Optimizely": { name: "Optimizely", folder: "n-r", slug: "optimizely-sso-configuration" },
  "Palo Alto Networks": { name: "Palo Alto Networks", folder: "n-r", slug: "palo-alto-next-gen-firewalls-v11-x-sso-configuration" },
  "OutSystems": { name: "OutSystems", folder: "n-r", slug: "outsystems-apps-sso-configuration" },
  "Pipedrive": { name: "Pipedrive", folder: "n-r", slug: "pipedrive-sso-configuration" },
  "Shopify Plus": { name: "Shopify Plus", folder: "s-v", slug: "shopify-sso-configuration" },
  "SAP SuccessFactors": { name: "SAP SuccessFactors", folder: "s-v", slug: "sap-successfactors-sso-configuration" },
  "SAP Concur": { name: "SAP Concur", folder: "s-v", slug: "sap-concur-sso-configuration" },
  "Sophos Central": { name: "Sophos Central", folder: "s-v", slug: "sophos-central-sso-configuration" },
  "ShareFile": { name: "ShareFile", folder: "s-v", slug: "sharefile-sso-configuration" },
  "WordPress": { name: "WordPress", folder: "w-z", slug: "wordpress-sso-configuration" },
  "Workday": { name: "Workday", folder: "w-z", slug: "workday-sso-configuration" },
  "WP Engine": { name: "WP Engine", folder: "w-z", slug: "wp-engine-sso-configuration" },
  "ZoomInfo": { name: "ZoomInfo", folder: "w-z", slug: "zoominfo-sso-configuration" },
  "Wrike": { name: "Wrike", folder: "w-z", slug: "wrike-sso-configuration" },
};

const baseUrl = "https://kzpp.vercel.app/library/admin-guides/sso-configuration";

export interface VendorDetection {
  vendor: string;
  guide?: VendorGuide;
}

export function detectVendor(url: string): VendorDetection | null {
  const urlLower = url.toLowerCase();
  
  for (const pattern of vendorPatterns) {
    if (urlLower.includes(pattern.pattern)) {
      const vendorName = pattern.vendor;
      const guide = vendorGuides[vendorName];
      return { 
        vendor: vendorName, 
        guide
      };
    }
  }
  
  return null;
}

export function getVendorGuideUrl(vendor: string): string | null {
  const guide = vendorGuides[vendor];
  if (!guide) return null;
  
  return `${baseUrl}/${guide.folder}/${guide.slug}`;
}

export function getVendorGuideMarkdown(vendor: string): string | null {
  const url = getVendorGuideUrl(vendor);
  if (!url) return null;
  
  return `[${vendor} SSO Configuration Guide](${url})`;
}

export function isVendorVerified(vendor: string): boolean {
  const guide = vendorGuides[vendor];
  return guide?.verified === true;
}

export function formatVendorNotice(vendor: string, _protocol: "saml" | "oidc" | "both"): string {
  const detected = detectVendor(vendor);
  if (!detected) return "";
  
  const guide = detected.guide;
  if (!guide) return "";
  
  const verificationStatus = guide.verified ? "✅ Verified by KZero" : "⚠️ Reference guide only";
  const guideUrl = getVendorGuideUrl(detected.vendor);
  
  return [
    `${verificationStatus}`,
    guideUrl ? `📖 [${detected.vendor} SSO Configuration Guide](${guideUrl})` : ""
  ].filter(Boolean).join("\n\n");
}
