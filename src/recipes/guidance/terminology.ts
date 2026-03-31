export interface TermExplanation {
  what: string;
  why: string;
  commonMistakes?: string[];
  plainEnglish: string;
}

export const terminology: Record<string, TermExplanation> = {
  "ACS URL": {
    what: "The web address where the vendor app receives the login confirmation from KZero",
    why: "If this is wrong, the vendor app never knows you logged in successfully",
    commonMistakes: [
      "Forgetting the trailing slash (https://vendor.com ≠ https://vendor.com/)",
      "Using http:// instead of https://",
      "Copying the wrong URL from vendor documentation",
      "Having extra spaces before or after the URL"
    ],
    plainEnglish: "Think of it like a delivery address for your login confirmation - it must be exact"
  },
  "Entity ID": {
    what: "A unique name that identifies each party (KZero and the vendor app) during SSO",
    why: "Both sides need to agree on who each other are - mismatched Entity IDs mean they don't trust each other",
    commonMistakes: [
      "Using the wrong Entity ID from vendor docs",
      "Case sensitivity - Entity IDs are case-sensitive",
      "Copying Entity ID from staging instead of production"
    ],
    plainEnglish: "Like a company name on a business card - both sides need to agree on the exact name"
  },
  "Assertion": {
    what: "A package of information that KZero sends to the vendor app confirming you logged in",
    why: "Contains your identity information (like email) that the vendor app uses to recognize you",
    commonMistakes: [
      "Not signing assertions when vendor requires it",
      "Encrypting assertions when vendor can't decrypt them"
    ],
    plainEnglish: "Your digital passport that proves you are who you say you are"
  },
  "NameID": {
    what: "The unique identifier for your account that gets sent in the login confirmation",
    why: "The vendor app uses this to match you to their user account",
    commonMistakes: [
      "Using email format when vendor expects persistent ID",
      "Not forcing the NameID format when vendor requires a specific one"
    ],
    plainEnglish: "Your account's ID number that the vendor uses to recognize you"
  },
  "Certificate": {
    what: "A digital file that proves KZero is who it claims to be",
    why: "The vendor app verifies this certificate to ensure it's really talking to KZero",
    commonMistakes: [
      "Using an expired certificate",
      "Not exporting the full certificate (missing BEGIN/END markers)",
      "Using the wrong certificate from a different environment"
    ],
    plainEnglish: "Like a government-issued ID - it proves KZero's identity to the vendor app"
  },
  "Redirect URI": {
    what: "The web address where the vendor app sends users after they log in",
    why: "Must be registered with KZero to prevent unauthorized redirects",
    commonMistakes: [
      "Adding extra paths that don't exist",
      "Using http:// for production (should be https://)",
      "Not including all variations (with/without www)"
    ],
    plainEnglish: "Where the vendor app sends you back after KZero verifies your identity"
  },
  "Client ID": {
    what: "A unique identifier for your vendor app in KZero's system",
    why: "KZero uses this to know which SSO configuration to use",
    commonMistakes: [
      "Copying the wrong Client ID from vendor docs",
      "Using the Entity ID instead of Client ID"
    ],
    plainEnglish: "Like a username for your app in KZero's database"
  },
  "Client Secret": {
    what: "A password that your app uses to authenticate with KZero (OIDC only)",
    why: "Proves to KZero that the request is coming from your real app, not an imposter",
    commonMistakes: [
      "Exposing the secret in public code repositories",
      "Using the wrong secret (staging vs production)",
      "Not regenerating after a suspected breach"
    ],
    plainEnglish: "Like a password for your app - keep it secret and safe"
  },
  "Signing": {
    what: "A cryptographic seal that proves the SSO message really came from KZero",
    why: "Without signing, anyone could pretend to be KZero and fake login responses",
    commonMistakes: [
      "Turning off signing when vendor requires signed assertions",
      "Not renewing signing keys before they expire"
    ],
    plainEnglish: "Like a wax seal on a letter - proves nobody tampered with it"
  },
  "Binding": {
    what: "The method used to send the SSO response (POST sends data, Redirect sends you to a URL)",
    why: "Some vendors only accept one method - using the wrong one causes login failures",
    commonMistakes: [
      "Using Redirect binding when vendor requires POST",
      "Not enabling 'Force POST Binding' when vendor expects it"
    ],
    plainEnglish: "Like choosing between sending a letter vs handing it to them in person"
  },
  "PKCE": {
    what: "An extra security step for OIDC that prevents authorization code interception",
    why: "Protects against attackers stealing your login session",
    commonMistakes: [
      "Mismatching PKCE settings between KZero and vendor",
      "Not implementing PKCE when vendor requires it"
    ],
    plainEnglish: "Like adding a second lock on your door - extra protection"
  },
  "Nonce": {
    what: "A unique, random value included in the login request to prevent replay attacks",
    why: "Ensures the login response is for YOUR current login attempt, not an old stolen one",
    commonMistakes: [
      "Not including nonce in the authorization request",
      "Using the same nonce value repeatedly"
    ],
    plainEnglish: "Like a one-time use scratch card - each login has a unique code"
  },
  "State": {
    what: "A random value sent with the login request to prevent cross-site request forgery (CSRF)",
    why: "Ensures the login response is for YOUR browser session, not someone else's",
    commonMistakes: [
      "Not sending state parameter",
      "Using predictable state values",
      "Not validating state on response"
    ],
    plainEnglish: "Like a receipt number - proves this login goes with your shopping cart"
  },
  "Discovery Document": {
    what: "A configuration file that lists all the SSO endpoints and settings for KZero",
    why: "Vendors use this to automatically configure their SSO connection to KZero",
    commonMistakes: [
      "Using the wrong realm name in the URL",
      "Not including the .well-known path"
    ],
    plainEnglish: "Like an index in a manual - tells vendors where to find everything"
  },
  "Issuer": {
    what: "The identity of who created the token/assertion",
    why: "The vendor verifies this matches expected KZero values",
    commonMistakes: [
      "Case sensitivity in realm names",
      "Using http:// instead of https://",
      "Including extra paths in the issuer URL"
    ],
    plainEnglish: "The 'from' address on the token - must be exactly right"
  },
  "Clock Skew": {
    what: "The allowed time difference between KZero and the vendor's servers",
    why: "If servers have different times, valid tokens might appear expired",
    commonMistakes: [
      "Assuming clocks are always perfectly synchronized",
      "Not enabling clock skew when servers have minor time differences"
    ],
    plainEnglish: "Like letting someone in 5 minutes late when their watch says they're on time"
  }
};

export function getTermTooltip(term: string): string | undefined {
  const t = terminology[term];
  if (!t) return undefined;
  
  return [
    `ℹ️ ${term}`,
    "",
    t.plainEnglish,
    "",
    "What it is:",
    t.what,
    "",
    "Why it matters:",
    t.why,
    ...(t.commonMistakes ? ["", "⚠️ Common mistakes:", ...t.commonMistakes] : [])
  ].join("\n");
}
