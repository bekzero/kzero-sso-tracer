# KZero Passwordless SSO Tracer

KZero Passwordless SSO Tracer is a Chrome MV3 extension for deterministic SAML/OIDC troubleshooting in KZero Passwordless environments.

It captures active auth traces, decodes federation artifacts, runs deterministic diagnostics, and maps likely fixes to KZero field labels and vendor/SP fields.

## MVP capabilities

- Start/stop/clear capture for the inspected tab.
- Timeline of federation events (SAML + OIDC + network errors).
- Optional Side Panel mode for reviewing saved traces outside DevTools.
- Artifact extraction and decoding:
  - SAMLRequest / SAMLResponse / RelayState
  - Redirect DEFLATE + base64 decode
  - XML parse and core claim extraction
  - OIDC authorize/callback/token/discovery/JWKS/logout fields
  - JWT header/payload decode for ID/access tokens when JWT
- Deterministic findings engine with severity, likely owner, evidence, expected vs observed, and confidence.
- Rule ID catalog filter with per-rule docs in the UI.
- SAML XML XPath inspector with highlights for critical nodes/attributes.
- KZero Passwordless UI helper: scan visible config fields on the current page and compare vs expected; "Locate" scroll+highlight.
- KZero-specific field mapping in suggested fixes.
- Sanitized local export (JSON).
- Persisted multi-session capture history in local extension storage.

## Privacy defaults

- Captured auth data stays local unless explicitly exported.
- Secrets are redacted by default in inspector views.
- No cookies are stored.
- No backend service is required.

## Repository structure

```
src/
  background/        # service worker, session store wiring
  capture/           # session store and event lifecycle
  content/           # hidden SAML form capture
  devtools/          # devtools network capture entry
  export/            # sanitized bundle generation
  fixtures/          # sample traces
  mappings/          # KZero custom field label mapping
  normalizers/       # raw -> normalized events
  panel/             # React DevTools panel UI
  parsers/           # SAML/JWT/OIDC decode helpers
  rules/             # deterministic findings engine
  shared/            # models, message contracts, utilities
  static/            # manifest + html entry points
tests/
  *.test.ts          # decoder + rules tests
```

## Install and run

1. Install dependencies:

```bash
npm install
```

2. Build extension:

```bash
npm run build
```

3. Load in Chrome:
- Open `chrome://extensions`
- Enable **Developer mode**
- Click **Load unpacked**
- Select the `dist/` directory

4. Open target site and DevTools:
- Open DevTools on the tab under test
- Open panel: **KZero Passwordless SSO Tracer**
- Click **Start capture**
- Run login flow
- Click **Stop capture** and inspect timeline/findings
- Click a finding -> **Fix steps** -> use **Check fields** when you have the relevant KZero Passwordless config screen open in the same tab.

5. Optional Side Panel:
- Click the extension action to open the Side Panel.
- Use **Session history** to reopen prior captures and inspect findings/artifacts.
- Use **Use current tab** to target a tab, then open a KZero Passwordless config screen in that tab and use **Check fields** in Fix steps.

## Making it fit

- The Side Panel is designed to work at small widths. When the panel is narrow, the UI switches to a single-pane layout with tabs (Findings/Detail/Timeline/History) so it doesn't become an overly tall stacked layout.
- If you need more space without covering the webpage, click **Pop out** to open the tracer in a separate window while keeping the page fully visible.

Note: Side Panel field scanning uses the `tabs` permission. If you updated permissions, reload the unpacked extension and refresh the target page once.

## Icons

Extension icons are generated at build time from `src/static/icon.svg` into `dist/icons/`.

## Testing

Run unit tests:

```bash
npm test
```

Included tests cover:
- JWT decode
- SAML decode (POST + Redirect DEFLATE)
- Rules engine detection on fixture traces

## Rule coverage in MVP

Implemented deterministic checks include:

- SAML: missing request/response, decode/XML failures, destination mismatch, recipient/ACS mismatch, audience mismatch, issuer mismatch, missing NameID, relay state anomalies, missing signatures, assertion expiry/clock skew clue, missing InResponseTo, encrypted assertion clue, unsigned AuthnRequest clue.
- OIDC: discovery unreachable, discovery issuer mismatch, missing openid scope, redirect_uri mismatch, protocol error responses (`invalid_client`, `invalid_scope`, `unauthorized_client`, `unsupported_response_type`, `unsupported_response_mode`), state mismatch, nonce missing for implicit/hybrid responses, PKCE inconsistency, JWKS fetch failure, token/discovery issuer mismatch, callback-to-token exchange break, opaque access token info.
- Cross/environment: realm case mismatch, wrong endpoint family clue, mixed host/environment clue, potential copy/paste truncation clue.

## Chrome API constraints and design notes

- Response bodies are best-effort via DevTools API.
- Network failures are supplemented with `webRequest.onErrorOccurred`.
- Hidden form SAML POST is captured through content script submit interception.
- Session history snapshots are stored in `chrome.storage.local` (bounded list).
- No unsupported API assumptions (for example, unrestricted response body interception from background) are used.

See `ARCHITECTURE.md` for details and tradeoffs.
