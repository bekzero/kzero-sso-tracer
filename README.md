# KZero Passwordless SSO Tracer

KZero Passwordless SSO Tracer is a Chrome extension for debugging SAML and OIDC authentication issues in KZero Passwordless environments.

## What It Does

- **Captures** federation traffic (SAML requests/responses, OIDC authorize flows, token exchanges)
- **Decodes** SAML XML, JWT tokens, OIDC parameters
- **Analyzes** the auth flow and identifies common configuration issues
- **Guides** you through fixing problems with step-by-step instructions

## Quick Start

### 1. Install

```bash
npm install
npm run build
```

### 2. Load in Chrome

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `dist/` folder

### 3. Use the Tracer

**Starting a Trace:**
1. Open the website you want to test
2. Open DevTools (F12 or right-click → Inspect)
3. Click the **KZero SSO Tracer** tab in DevTools
4. Click **Start capture**

**Recording a Login:**
1. Perform the login flow (enter credentials, click login)
2. Watch events appear in the timeline
3. Click **Stop capture** when done

**Reviewing Findings:**
- The **Findings** tab shows issues found in your auth flow
- Click a finding to see details
- **Fix steps** shows guided instructions
- **Check fields** helps locate the exact setting in KZero Admin

**Using the Side Panel:**
- Click the extension icon in Chrome's toolbar
- Opens a side panel with session history
- Use **Use current tab** to analyze a page

## Understanding Findings

Findings are color-coded by severity:

| Severity | Meaning | Action |
|----------|---------|--------|
| 🔴 Problem | Likely breaking the login | Fix before going live |
| 🟡 Warning | Could cause issues | Review when convenient |
| 🔵 Info | FYI or configuration note | Usually safe to ignore |

Common findings and what they mean:

### SAML Findings
- **Missing NameID**: User identity not mapped - check Principal type in KZero
- **Destination mismatch**: Assertion sent to wrong URL - verify ACS URL in both systems
- **Audience mismatch**: Token for wrong application - check Audience/Entity ID settings
- **Missing signature**: Assertion not signed - enable "Validate signatures" in KZero

### OIDC Findings  
- **Discovery unreachable**: KZero endpoint not accessible - verify tenant name
- **Redirect URI mismatch**: Callback URL doesn't match - check in both systems
- **Invalid client**: Client ID/secret wrong - verify credentials in KZero

### Cross-Cutting Findings
- **Tenant name casing mismatch**: Tenant names are case-sensitive in URLs
- **Wrong environment mix**: Seeing endpoints from multiple environments

## Shareable Links

After capturing a trace:
1. Click the **Export** dropdown
2. Select **Copy shareable link**
3. Paste the link to share with others

The recipient can view the full trace (events, findings, artifacts) without needing the extension.

## Privacy

- All data stays local in your browser
- Nothing is sent to external servers
- No cookies stored
- Export includes only the trace data you choose to share

## Troubleshooting

**No events appearing?**
- Make sure you're on the tab you want to trace
- Click "Start capture" before performing the login
- Some POST requests may not appear if the page uses JavaScript redirects

**Finding seems wrong?**
- Check if the login actually succeeded - some findings only apply to failures
- Verify you're looking at the right tenant/environment
- Click a finding to see "What Happened" for full explanation

**Need more details?**
- Click any event in the Timeline to see raw decoded data
- Use the search box to filter events
- Click **Artifacts** to see decoded SAML/XML content

## Commands

| Shortcut | Action |
|----------|--------|
| Alt+Shift+S | Start/Stop capture |
| Alt+Shift+E | Export session |
| Alt+Shift+F | Focus search |
| Alt+Shift+P | Open settings |
