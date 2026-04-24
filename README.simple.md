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

---

## Understanding the JSON Export

If you export the trace as JSON (Export → Sanitized → JSON), you'll see a file with several sections. Here's what each one means:

### Start Here: `quickVerdict` (Most Important!)

This is the very first thing to read. It tells you in one sentence what happened:

```json
{
  "quickVerdict": {
    "overallStatus": "failure",
    "severityLabel": "🔴 LOGIN FAILED",
    "oneSentenceSummary": "Login failed because the app's Entity ID doesn't match what KZero expects."
  }
}
```

**What to do:** Read this first. It tells you immediately if login worked or not.

---

### Next: `recommendedPath`

This tells you which sections to read based on what you need:

```json
{
  "recommendedPath": {
    "forNewUsers": [
      "1. Read 'quickVerdict' to see if login worked",
      "2. Read 'whatHappened' to see what steps happened",
      "3. Read 'whatWentWrong[0]' to understand the main issue",
      "4. Check 'whatToCompare' to see what values need verification"
    ]
  }
}
```

**What to do:** Pick the path that matches your situation and follow the numbered steps.

---

### To Understand What Happened: `whatHappened`

Plain-English summary of the login flow:

```json
{
  "whatHappened": {
    "initiationModelPlain": "App started the login (SP-initiated)",
    "plainEnglishSummary": "The app asked KZero to log you in, but KZero said no.",
    "stepByStep": [
      {
        "plainLabel": "App asked KZero to log you in",
        "plainDetail": "App identified as: https://old-vendor.example.com/sp"
      }
    ]
  }
}
```

**What to do:** Read this to understand the story of what happened, in plain English.

---

### To See What's Wrong: `whatWentWrong`

The problems we found, sorted by importance:

```json
{
  "whatWentWrong": [
    {
      "plainEnglishTitle": "KZero rejected the sign-in request",
      "plainEnglishExplanation": "The Entity ID sent by the app doesn't match KZero config.",
      "whyThisIsLikely": "Observed in the trace: HTTP 400"
    }
  ]
}
```

**What to do:** Read the first item (errors come first). It explains what went wrong in simple terms.

---

### To Fix It: `firstAction`

Your first concrete action step with exact directions:

```json
{
  "firstAction": {
    "stepNumber": 1,
    "kzeroAdminPath": "KZero Admin → Applications → [your app] → General tab → Details section → Client ID",
    "whatToFind": "Look for 'Client ID' or 'Entity ID'",
    "whatToCompare": "Compare to: https://old-vendor.example.com/sp",
    "whyThisMatters": "If these don't match, KZero won't accept the login request"
  }
}
```

**What to do:** Follow these exact steps in your KZero admin panel.

---

### To Compare Values: `whatToCompare`

Side-by-side comparison of what the app sent vs. what KZero expects:

```json
{
  "whatToCompare": {
    "visual": {
      "comparisonTable": [
        {
          "plainFieldName": "Entity ID (who the app says it is)",
          "spSent": "https://old-vendor.example.com/sp",
          "kzeroExpectsNote": "Check KZero Admin → Applications → [app] → Client ID",
          "matchResult": "unknown"
        }
      ]
    }
  }
}
```

**What to do:** This shows you exactly what values to check in KZero Admin. "unknown" means you need to verify in KZero.

---

### For Support: `supportSummary`

Ready-to-copy text you can share with your team or KZero support:

```json
{
  "supportSummary": {
    "copyPasteSummary": "SAML login failed on 2026-04-24 at 4:30 PM.\n\nApp: vendor-sp.example.com\nStatus: 🔴 LOGIN FAILED\n\nWhat to check:\nIn KZero Admin → Applications → [app] → Client ID..."
  }
}
```

**What to do:** Copy this text to share with your team or support.

---

### Quick Reading Order

If you're not sure where to start, read in this order:

1. **`quickVerdidct`** → Did login work or not?
2. **`whatHappened`** → What happened step by step?
3. **`whatWentWrong[0]`** → What went wrong?
4. **`firstAction`** → What do I do next?
5. **`whatToCompare`** → What values do I check?

That's it! You don't need to read the whole file — just follow these sections in order.

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
