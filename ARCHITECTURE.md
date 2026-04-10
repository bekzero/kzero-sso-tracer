# KZero Passwordless SSO Tracer Architecture

## Why these Chrome APIs

- `chrome.devtools.network.onRequestFinished`: primary capture for inspected tab network events, request metadata, POST bodies (when present), and response bodies via `getContent()`.
- `chrome.webRequest.onErrorOccurred`: fills critical gap for unreachable/TLS/WAF-style failures that may never produce a successful DevTools request finish event.
- `content_scripts` submit listener: captures hidden SAML POST form payloads (`SAMLRequest`/`SAMLResponse`) when browser-submitted forms are the key artifact.
- `chrome.runtime` messaging + `Port`: low-latency session updates from background to DevTools panel.
- `chrome.storage.local`: local-only storage for settings and history summaries (active capture is memory-only).
- `chrome.sidePanel`: optional review surface for saved traces without requiring DevTools to stay open.

## Capture tradeoffs

- Response body visibility is best-effort. `devtools.network.getContent()` works in DevTools context but may be unavailable for some responses (binary, CORS/service worker constraints).
- The extension does not attempt unsupported full packet interception in MV3.
- Cookies are intentionally not stored.

## Processing pipeline

1. Raw capture events enter background session store.
2. Normalizers classify events as SAML/OIDC/network/unknown.
3. Parsers decode SAML (base64 + redirect DEFLATE + XML), JWT header/payload, and OIDC metadata.
4. Deterministic rules generate findings with owner/severity/confidence and KZero field mapping.
5. Panel renders timeline, findings, and artifact inspector with redaction defaults.
6. Side panel can load persisted session history snapshots for later triage.
7. Sanitized export bundles normalized events and findings without raw secrets by default.

## Security posture

- Local-first by design.
- Redaction on UI artifact display unless raw toggle is enabled.
- Export is explicit user action and sanitized.
- No automatic external transmission.

## UX additions

- Rule catalog filter: findings can be filtered by explicit `ruleId`, with inline rule documentation.
- SAML XPath inspector: decoded XML is transformed into XPath-like rows with highlights for high-value claims and conditions fields.
