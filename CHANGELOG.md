# Changelog

All notable changes to **KZero Passwordless SSO Tracer** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
