# KZero Passwordless SSO Tracer

A Chrome extension for debugging SAML and OIDC authentication issues in KZero Passwordless environments.

## What This Tool Is For

This extension captures, decodes, and analyzes browser-based authentication traffic to help troubleshoot SAML and OIDC login failures in KZero Passwordless deployments.

It is designed specifically for KZero customers debugging their IdP-to-SP federation flows. It is not a general-purpose SAML/OIDC tool and makes assumptions about KZero tenant URLs and configuration structures.

## What It Captures / Analyzes

**Network Capture:**

- HTTP requests/responses via Chrome DevTools network API
- SAML POST form submissions via content script listener
- webRequest errors for unreachable/TLS failures

**Protocol Parsing:**

- SAML XML (base64, DEFLATE, XML parsing)
- OIDC parameters (authorize, callback, token endpoints)
- JWT tokens (header and payload decoding)

**Rules Engine:**

- Deterministic checks for common misconfigurations
- Findings with severity, confidence level, and owner attribution
- Step-by-step fix guidance with KZero field mapping

**Exports:**

- Summary export (event counts, findings list, OIDC summary)
- Sanitized export (events with secrets redacted/hashed)
- Raw export (full unmodified data for debugging)

## What It Does NOT Do

- Does not capture cookies
- Does not intercept all browser network traffic (limited by MV3)
- Does not send data to any external server (except optional AI assistant uses OpenAI API when you provide a key)
- Is not a general-purpose packet sniffer
- Does not replace IdP or vendor server-side logs
- Does not guarantee capture of every auth flow edge case
- Is not tested for browsers other than Chrome 120+

## Key Features

- **DevTools Integration**: KZero SSO Tracer tab in Chrome DevTools
- **Side Panel**: Review sessions without keeping DevTools open
- **Capture Scope Settings**:
  - Auth-only (default): captures IdP, SP, and auth endpoints
  - Auth + allowlist: auth-only plus custom allowed hosts
  - Full capture: captures all network traffic
- **Findings Engine**: 30+ rules for SAML, OIDC, and cross-protocol issues
- **Confidence Scoring**: High/Medium/Low with evidence-based findings
- **Ambiguity Handling**: Flags findings that need more context
- **Export Modes**: Choose what level of detail to include
- **Keyboard Shortcuts**: Alt+Shift+S (toggle capture), Alt+Shift+E (export), Alt+Shift+F (search), Alt+Shift+P (settings)

## Privacy and Security Model

**Local-First by Default**: Captured data stays in your browser. The AI Assistant is optional - if enabled, your question and findings are sent to OpenAI. No other external transmission.

**AI Assistant (Optional)**: If you enable the optional AI Assistant, your question and current findings (if enabled) are sent to OpenAI for processing. This is opt-in only and disabled by default.

**Redaction Defaults**: The UI masks secrets by default (tokens, SAML artifacts, credentials). Users can toggle to see raw values.

**Export Options**:

- **Summary**: Event counts, findings list, OIDC summary - minimal detail
- **Sanitized**: Events with secrets removed or hashed - safe for sharing
- **Raw**: Full normalized data including decoded tokens and SAML payloads - includes all parsed artifacts but not raw capture bytes

**Permissions**:

- `<all_urls>` host permission: Required to capture traffic from any website
- webRequest: Required to catch errors that may not appear in DevTools
- storage: Required for settings and history (summary-only)

**Sensitive Data Warning**: Raw exports contain full tokens, SAML assertions, and user identifiers. Handle with care.

## How It Works

```
[Browser Network] → DevTools Network API / webRequest
                       ↓
              [Background Service Worker]
                       ↓
              [Session Store - captures events]
                       ↓
              [Normalizers - classify as SAML/OIDC/network]
                       ↓
              [Parsers - decode SAML XML, JWT, OIDC params]
                       ↓
              [Rules Engine - generate findings with guidance]
                       ↓
              [UI Panel / Side Panel - render findings]
                       ↓
              [Export - optional with redaction]
```

The extension uses Chrome's DevTools Network API as the primary capture mechanism, with webRequest as a fallback for error cases. Content scripts capture SAML POST form submissions. A service worker in the background coordinates capture and stores sessions in chrome.storage.local.

## Repository Structure

```
├── src/
│   ├── background/         # Service worker (capture coordination)
│   ├── capture/            # sessionStore, hostClassifier
│   ├── content/            # Content script (form listener)
│   ├── devtools/           # DevTools panel entry
│   ├── export/             # Export modules (summary/sanitized/raw)
│   ├── mappings/           # KZero field mappings
│   ├── normalizers/        # Event classification
│   ├── panel/              # React UI (main panel)
│   ├── parsers/            # SAML, OIDC, JWT parsers
│   ├── recipes/            # Fix guidance generation
│   ├── rules/              # Findings rules (SAML, OIDC, cross)
│   ├── shared/             # Models, settings, redaction
│   ├── sidepanel/          # Side panel entry
│   └── static/             # manifest.json, icons, HTML
├── tests/                  # Vitest tests (rules, settings, exports)
├── dist/                   # Built extension (load this in Chrome)
├── scripts/               # Build scripts
├── package.json            # npm config
└── tsconfig.json           # TypeScript config
```

Key directories:

- `src/rules/` - Finding rules (samlRules.ts, oidcRules.ts, crossRules.ts)
- `src/parsers/` - Protocol decoders (saml.ts, oidc.ts, jwt.ts)
- `src/export/` - Export format handlers
- `src/panel/` - React UI components

## Installation / Loading the Extension

```bash
npm install
npm run build
```

This produces a `dist/` folder. To load in Chrome:

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `dist/` folder

The extension icon appears in Chrome's toolbar. Click it to open the side panel, or press F12 to open DevTools and find the KZero SSO Tracer tab.

## How to Use It

**Starting a Trace:**

1. Navigate to the vendor application login page
2. Open DevTools (F12) → KZero SSO Tracer tab
3. Click Start capture (or press Alt+Shift+S)
4. Complete the login flow
5. Click Stop capture (or press Alt+Shift+S again)

**Analyzing Findings:**

- The Findings list shows issues detected in your auth flow
- Each finding has severity (error/warning/info), confidence level, and owner
- Click a finding to see:
  - What happened (plain English explanation)
  - Evidence (observed vs expected values)
  - Fix steps (KZero field locations with admin deep links)
  - Artifacts (decoded SAML/XML, token details)

**Exporting:**

- Click Export in the panel header
- Choose mode: Summary, Sanitized, or Raw
- Choose format: JSON, HAR, or CSV

**Settings:**

- Click the gear icon (or press Alt+Shift+P)
- Configure capture scope (auth-only / auth + allowlist / full)
- Manage allowed hosts for auth+allowlist mode
- Adjust redaction strictness

## Export Modes and Redaction Behavior

| Mode      | What's Included                             | Secrets                                                                     |
| --------- | ------------------------------------------- | --------------------------------------------------------------------------- |
| Summary   | Event counts, findings list, OIDC metadata  | None - minimal export                                                       |
| Sanitized | Normalized events with URL params sanitized | Removed (access_token, id_token, code, etc.) or hashed with per-export salt |
| Raw       | Complete raw events and artifacts           | Full - no redaction                                                         |

**Sanitized mode**:

- OIDC tokens removed entirely (access_token, refresh_token, id_token, code)
- State, nonce, session_state replaced with salted hash for correlation
- SAML artifacts preserved but secrets masked in UI
- Nested URL-like fields (callbackUrl, finalUrl) also sanitized

**Redaction strictness levels** (Settings):

- Strict: Aggressive masking of all detected secrets
- Moderate: Mask tokens but show some metadata
- Off: Show all values in UI (still requires explicit toggle)

## Development Workflow

```bash
# Install dependencies
npm install

# Watch mode - rebuild on changes
npm run build

# Run tests
npm test

# Clean dist folder
npm run clean
```

**Adding a new rule:**

1. Add rule logic in `src/rules/samlRules.ts`, `src/rules/oidcRules.ts`, or `src/rules/crossRules.ts`
2. Use `makeFinding()` helper from `src/rules/helpers.ts`
3. Add field mapping in `src/mappings/fieldMappings.ts`
4. Add tests in `tests/samlRules.test.ts` or similar

**Adding a new parser:**

1. Add parser in `src/parsers/`
2. Update normalizer in `src/normalizers/index.ts` to use it

## Testing

```bash
npm test          # Run all tests once
npm run test:watch  # Watch mode for development
```

Test categories:

- `tests/rules.test.ts` - Rules engine
- `tests/saml.test.ts` - SAML parser
- `tests/oidc.test.ts` - OIDC parser
- `tests/oidcRules.test.ts` - OIDC rules
- `tests/settings.test.ts` - Settings migration
- `tests/hostClassifier.test.ts` - Event classification
- `tests/export.test.ts` - Export modes

## Troubleshooting

**Extension not capturing:**

- Check that extension is enabled in chrome://extensions
- Verify you're using Chrome 120+
- Try reloading the page after starting capture
- Check browser console for errors

**Missing events / late capture:**

- Capture must start BEFORE navigating to login page
- If AuthnRequest is missing, the flow may be IdP-initiated or capture started late
- The extension can only see network traffic that Chrome exposes to DevTools

**Findings seem noisy:**

- Use auth-only mode to filter out analytics/tracking
- Review capture scope setting in Settings
- Some findings (like SAML_CAPTURE_STARTED_LATE) are informational, not errors

**Export confusion:**

- Summary is safe for general sharing
- Sanitized is recommended for troubleshooting with colleagues
- Raw contains secrets - handle carefully

**Conflicting findings:**

- Findings are deduplicated by ruleId + observed + expected
- Filter by ruleId using the search box

## Known Limitations

- **Partial browser visibility**: MV3 extensions cannot see all network traffic. Some requests (service worker, CORS-blocked, binary responses) may be invisible.

- **Incomplete traces**: If capture starts after the AuthnRequest or misses the callback, some events will be absent. This is a capture timing issue, not a bug.

- **Heuristic findings**: Some rules use heuristics (e.g., path patterns, host classification) that may produce false positives on unusual configurations.

- **Response bodies**: Not all response bodies are available. Binary responses, CORS restrictions, and some CDN responses may not be captured.

- **Raw export sensitivity**: Raw exports contain full tokens and SAML assertions. Do not share raw exports externally.

- **No IdP/vendor logs**: The extension cannot see server-side logs. Some issues require checking KZero admin console or vendor SP logs.

## Contributing / Maintenance Notes

**Where to add code:**

- New rules → `src/rules/` (samlRules.ts, oidcRules.ts, crossRules.ts)
- New parsers → `src/parsers/`
- New UI components → `src/panel/`
- Field mappings → `src/mappings/fieldMappings.ts`
- Tests → `tests/` (mirror src structure)

**Rules guidelines:**

- Findings must be evidence-backed, not invented
- Use numeric confidence (0.0-1.0) - confidenceLevel is auto-derived
- If ambiguous, include isAmbiguous: true with ambiguityNote or traceGaps
- Prefer specific findings over generic warnings

**Testing guidelines:**

- Add tests for new rules in the appropriate test file
- Use fixtures from tests/fixtures/ for real-world examples
- Run `npm test` before committing

**Release process:**

1. Update version in package.json and manifest.json
2. Run `npm run build`
3. Test in Chrome
4. Commit with version tag
