# KZero SSO Tracer — Simple Guide

_For everyone who isn't a developer. If something doesn't make sense, that's on us — let us know!_

---

## Wait, what is this?

Think of KZero SSO Tracer like a security camera for your login system. It records what happens when someone signs in to your apps through KZero, so when things go wrong, you can see exactly what happened.

**In plain English:** A tool that watches login attempts and tells you why they failed.

---

## When would I use this?

You'd use this when someone can't log in and the normal error messages don't help. For example:

- "I set up everything correctly but it still won't let me in"
- "The error says something about SAML but I don't know what that means"
- "My users are getting stuck at the login screen"

---

## What will I see?

### Findings — The Issues We Found

When something goes wrong, this tool finds it and lists it under "Findings." Each finding has a colored icon:

| Icon                | Meaning                        | What to do                                       |
| ------------------- | ------------------------------ | ------------------------------------------------ |
| 🔴 Red (Error)      | Something is definitely broken | Fix this first — login won't work until resolved |
| 🟡 Yellow (Warning) | Something might cause problems | Worth looking at, but might work anyway          |
| 🔵 Blue (Info)      | FYI — no problem yet           | Just letting you know something interesting      |

**In plain English:** Red problems stop logins. Yellow warnings might cause issues. Blue notes are just observations.

---

## How do I use this?

### Step 1: Open the tool

- Find the extension icon in your Chrome toolbar (it looks like a little debug symbol)
- Click it to open the side panel
- Or press **F12** to open DevTools, then find the "KZero SSO Tracer" tab

### Step 2: Start recording

- Click the **Start capture** button in the top left
- Or press **Alt + Shift + S** (hold Alt, press Shift+S)

### Step 3: Recreate the problem

- Go through the login that isn't working
- Try to log in as the user who's having trouble

### Step 4: See what happened

- Click **Stop capture**
- Look at the Findings section
- Click on any red or yellow finding to see details

### Step 5: Get help

- Click **Export** to save the trace
- Send it to your support team or KZero help

---

## Reading a Trace — What's happening here?

When someone logs in, here's the basic flow:

```
1. User clicks "Log in" at your app
       ↓
2. App asks KZero "Who is this user?"
       ↓
3. KZero checks (maybe asks for password, MFA, etc.)
       ↓
4. KZero says "Yes, they're who they say they are" — or "No"
       ↓
5. User gets into the app — or gets an error
```

**The tracer records every step.** If step 4 says "No," our tool tries to explain why.

### Example: "ACS URL Mismatch" — In Plain English

_This finding means:_ Your app told KZero to send the login confirmation to the wrong address. It's like giving someone the wrong mailing address — the package (login confirmation) gets returned.

_What to check:_ Compare the address in your KZero setup to the address your app is expecting. They must match exactly.

---

## Common Findings Explained

### "KZero rejected the sign-in request" (Red)

**What happened:** The app tried to log someone in, but KZero said no before even checking their password.

**Why it matters:** This means something is misconfigured in how the app talks to KZero.

**What to check:**

- Does the app's "Entity ID" or "Client ID" match what's in your KZero settings?
- Is the app's "Reply URL" (where_login responses go) correct in KZero?

### "SAML AuthnRequest not captured" (Blue)

**What happened:** We didn't see the app ask KZero to log the user in.

**Why it matters:** This usually means capture started too late — after the user already clicked "Log in." It's like starting the security camera after the package was delivered.

**What to check:** Next time, start capture _before_ clicking the login button.

### "NameID mismatch" (Yellow)

**What happened:** KZero knows who the user is, but the app doesn't recognize the user ID format.

**Why it matters:** It's like KZero says "Here's John Smith" but the app expects "john.smith@company.com" — a naming mismatch.

**What to check:** Check if both sides agree on whether to use email addresses, usernames, or employee IDs.

---

## Troubleshooting — Something's wrong, what do I do?

### "The tool isn't recording anything"

- Did you click **Start capture** first?
- Did you start capture _before_ clicking the login button?
- Try reloading the page and start fresh

### "I see errors but don't understand them"

- Click on the error to see more details
- Look for the plain English explanation (we try to include one in every finding)
- If it's still confusing, export the trace and send it to KZero support

### "The capture is showing too much junk"

- In Settings, switch to **Auth-only** mode
- This tells the tool to ignore analytics, ads, and other noise

### "I don't know what to do next"

- Export the trace (click Export → Sanitized → JSON)
- Send it to your KZero support contact
- Include what you were trying to do when it failed

---

## What NOT to share

This tool can see some sensitive stuff. **Don't share exports with people outside your organization.**

- **Safe to share:** Summary exports and sanitized exports (those have most secrets removed)
- **Be careful:** Detailed exports contain decoded login responses — treat these like passwords

**Quick rule:** If you wouldn't email a password, don't email a detailed export.

---

## Keyboard Shortcuts (Plain Terms)

| Shortcut        | What it does           |
| --------------- | ---------------------- |
| Alt + Shift + S | Start / stop recording |
| Alt + Shift + E | Save an export         |
| Alt + Shift + F | Search for something   |
| Alt + Shift + P | Open settings          |

---

## Glossary — What do the words mean?

**AuthnRequest (Auth-en Request):** The first message from your app to KZero asking "can I log this person in?"

**ACS URL:** The address where KZero should send the login confirmation back. Like a return address on an envelope.

**SAML:** The language two systems use to talk about logging in (Security Assertion Markup Language). You don't need to know more than that.

**Issuer:** Who is saying "this user is who they claim to be" — usually your KZero tenant.

**Entity ID / Client ID:** The unique name that identifies your app in KZero's system.

**Relay State:** A tracking code that helps your app remember where to send the user after login.

**OIDC:** Another way systems talk about logging in (OpenID Connect). SAML's younger cousin.

---

## Quick Reference: What do the colors mean?

| This color | Called  | Means                       |
| ---------- | ------- | --------------------------- |
| 🔴 Red     | Error   | Login definitely won't work |
| 🟡 Yellow  | Warning | Might cause problems        |
| 🔵 Blue    | Info    | Just FYI                    |

---

## Need more help?

- **KZero Support:** Contact your KZero account team
- **For developers:** See README.technical.md in the same folder
- **Something wrong with this guide?** Let us know!

---

_Last updated: April 2026_
