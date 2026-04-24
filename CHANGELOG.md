# Changelog

All notable changes to **KZero Passwordless SSO Tracer** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.4.0] — 2026-04-24

### Added

- **Friendly JSON export format** — Non-technical-first structure for IT admins and support staff:

  - New top-level fields: `didTheLoginWork`, `copyThisTextToSendToSomeone`, `howToFixIt`, `whatWentWrong`
  - Action items appear first in the JSON, not buried in technical sections
  - Emojis in status values: `✅ YES`, `❌ NO`, `⚠️ INCOMPLETE`
  - Clear "STOP HERE" signal before technical details
  - `technicalDetailsForEngineers` wrapper clearly separates non-technical from technical content

- **Clear export menu labels** for non-technical users:

  - "Quick Fix - for IT admins to get started" — for non-technical users who just need to fix a problem
  - "Full Report - complete technical details" — for technical users who need full data
  - "Debug Data - raw info for developers" — for developers who need raw information

- **Action-oriented export button labels:**
  - "Download - for support email"
  - "Network Data - for browser DevTools"
  - "Problems Only - spreadsheet"
  - "Summary Only - spreadsheet"

### Changed

- JSON exports now use friendly structure by default for summary and sanitized modes
- Email exports use friendly structure for attachments
- `includeEducational` now defaults to `true` for non-raw exports
- Removed redundant `education` block from `technicalDetailsForEngineers` — friendly fields already contain all non-technical content

### Fixed

- **Email to support** — Email now autofills recipient as support@kzero.com with full friendly text summary in body (no attachment needed)
- **Contact Support button** — Replaced confusing "?" button with prominent "Contact Support" button directly in toolbar
- **Non-technical UX** — Support contact is now prominent and discoverable, not hidden in dropdown menus

### Example new friendly export structure:

```json
{
  "didTheLoginWork": "❌ NO - destination URL doesn't match",
  "copyThisTextToSendToSomeone": "SSO failed for user@company.com at 2:34 PM...",
  "howToFixIt": {
    "whereToGoInKZeroAdmin": "KZero Admin → Applications → [App] → SAML Settings",
    "step1_lookFor": "Look for 'Destination URL' field",
    "step2_compareWith": "Compare to value shown in 'whatWentWrong'",
    "step3_changeThis": "Change the KZero value to match what the app sent"
  },
  "whatWentWrong": {
    "simpleStory": "The app asked KZero to log you in, but KZero said no...",
    "stepByStep": [...]
  },
  "howToReadThisFile": {
    "ifYouJustNeedToFixIt": "Read 'howToFixIt'",
    "ifYouNeedToSendThisToSomeone": "Copy 'copyThisTextToSendToSomeone'",
    "forEngineersOnly": "Everything in 'technicalDetailsForEngineers' below"
  },
  "technicalDetailsForEngineers": {
    "note": "STOP HERE if you are non-technical...",
    "events": [...],
    "findings": [...],
    "metadata": {...},
    "education": {...}
  }
}
```

## [0.3.0] — 2026-04-24

### Added

- **Educational export (SAML)** — Optional enriched export block with plain-English explanations (schema `2.1.0`):
  - New `schemaVersion: "2.1.0"` and `exportVersion: "1.1.0"` for downstream detection
  - `aboutThisFile`: "What is this file?" section explaining the export in plain terms
  - `quickVerdict`: Immediate verdict with emoji indicators (🔴/✅) and one-sentence summary
  - `recommendedPath`: Navigation guides for different user types (new users, fixers, learners)
  - `whatHappened`: Plain-English step-by-step narrative (parallel to raw events)
  - `whatWentWrong`: Findings sorted errors-first with plain titles and severity labels
  - `whatToCompare`: Visual side-by-side comparison table + detailed checklist
  - `firstAction`: Concrete first step with exact KZero admin path navigation
  - `supportSummary`: Auto-generated copy-paste text block for escalation
  - `whatThisFileDoesNotContain`: Renamed from notShownInTrace, clearer naming
  - KZero Admin paths included: "KZero Admin → Applications → [app] → Client ID" etc.
  - Guards against implying knowledge of KZero configured values without explicit capture

### Example new sections:

```json
{
  "quickVerdict": {
    "overallStatus": "failure",
    "severityLabel": "🔴 LOGIN FAILED",
    "oneSentenceSummary": "Login failed because the app's Entity ID doesn't match what KZero expects.",
    "mostCriticalIssue": "Entity ID mismatch",
    "confidence": "high"
  },
  "firstAction": {
    "stepNumber": 1,
    "kzeroAdminPath": "KZero Admin → Applications → [your app] → General tab → Details section → Client ID",
    "whatToFind": "Look for 'Client ID' or 'Entity ID'",
    "whatToCompare": "Compare to: https://old-vendor.example.com/sp",
    "whyThisMatters": "If these don't match, KZero won't accept the login request"
  },
  "supportSummary": {
    "copyPasteSummary": "SAML login failed on 2026-04-24..."
  }
}
```

## [0.2.0] — 2026-03-31

### Added

- **Error boundaries** — React component errors are caught and displayed with a friendly fallback UI instead of a blank screen
- **Keyboard shortcuts** — Registered via `chrome.commands`:
  - `S` — Start / stop capture
  - `E` — Export current session
  - `/` — Focus search
  - `,` — Open settings
  - `?` — Show keyboard shortcuts overlay
- **Settings panel** — Persisted preferences via `chrome.storage.local`:
  - Auto-start capture on tab switch
  - Max history session count (10 / 30 / 50 / 100)
  - Redaction level (Strict / Moderate / Off)
  - Default detail tab on finding selection
  - Shortcut reference and reset to defaults
- **Multi-format export** — Export via toolbar dropdown:
  - JSON (full sanitized trace)
  - HAR (loadable in browser DevTools)
  - CSV (findings only)
  - CSV (session summary)
  - Shareable trace (.txt, base64-encoded)
  - Shareable link (base64-encoded, copied to clipboard)
- **Session comparison** — Load two sessions from history side-by-side:
  - Problems fixed / new / still present
  - Per-finding diff with severity indicators
  - Summary stats: before vs after problem count
- **CHANGELOG** — This file, tracking all changes

### Changed

- Default narrow layout tab changed from "Timeline" to "Findings"
- Timeline rows now show protocol via colored left border (pink = SAML, blue = OIDC, gray = unknown)
- Filter dropdown styles fixed for dark theme contrast
- Stop button now updates UI state immediately (was waiting for broadcast)
- Multiple message routing and state initialization bugs fixed in panel ↔ background communication

## [0.1.0] — 2026-03-30

### Added

- Project scaffold: TypeScript, MV3 manifest, service worker, React panel
- Global `webRequest` capture for SAML and OIDC flows (all tabs)
- Content script: hidden form intercept, `form.submit()` override, MutationObserver
- SAML parser: base64 + DEFLATE decode, XML parse, claim extraction
- OIDC parser: redirect parameter extraction, JWT decode
- Deterministic rules engine: ~18 SAML rules + ~18 OIDC rules + cross-cutting rules
- 3-pane panel UI: timeline, findings list, detail view with Fix Steps / What Happened / Evidence / Artifacts / SAML XML tabs
- Fix Recipes with KZero field expectations and vendor checks
- Product UI field scanner: inject on demand, scan visible fields, "Locate" scroll+highlight
- Side Panel support with session history persistence across SW restarts
- Service worker keepalive via `chrome.alarms`
- Session export: sanitized JSON
- Rule ID catalog filter and per-rule documentation
- Dark theme with KZero brand orange (`#f85c3a`) accents
- Extension icons generated from SVG at build time
- Unit tests for JWT decode, SAML decode, rules engine
- README and ARCHITECTURE documentation
