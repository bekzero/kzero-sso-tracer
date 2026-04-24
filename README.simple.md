# KZero SSO Tracer — Simple Guide

_For everyone who isn't a developer. If something doesn't make sense, that's on us — let us know!_

---

## IF YOU'RE NOT A DEVELOPER, START HERE

```
╔════════════════════════════════════════════════════════════════════════════╗
║              ↓ YOU FOUND THIS FILE. START HERE. ↓                         ║
╠════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  To FIX the problem:          → Read "howToFixIt" section (line 50-60)     ║
║  To SEND this to someone:     → Copy "copyThisTextToSendToSomeone"        ║
║  To UNDERSTAND what happened  → Read "whatWentWrong" section              ║
║                                                                            ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║  ⚠️  STOP READING after "howToFixIt" if you just need to fix or send.       ║
║      The sections below "technicalDetailsForEngineers" are for developers. ║
║      You don't need to read them.                                          ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
```

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

If you export the trace as JSON (Export → Download JSON), you'll see a file with several sections.

### QUICK READING ORDER

```
1. didTheLoginWork        ← Did it work? (Look for ✅ YES or ❌ NO)
2. copyThisTextToSendToSomeone  ← Copy this text to send to someone
3. howToFixIt             ← What to do next (exact steps)
4. whatWentWrong          ← What happened (plain story)

That's it! You don't need to read anything after "howToReadThisFile"
unless someone asks you for "technical details."
```

---

### What you'll see in the JSON file

#### `didTheLoginWork` — The Most Important Thing

This tells you immediately if login worked or not:

```json
{
  "didTheLoginWork": "❌ NO - destination URL doesn't match"
}
```

**What to do:** If this says ❌ NO, you have a problem. Keep reading.

---

#### `copyThisTextToSendToSomeone` — Ready-to-Send Text

One-click copy text you can paste into an email:

```json
{
  "copyThisTextToSendToSomeone": "SSO failed for user@company.com at 2:34 PM.\n\nApp: vendor-sp.example.com\nStatus: 🔴 LOGIN FAILED\n\nWhat to check:\nIn KZero Admin → Applications → [app] → Client ID..."
}
```

**What to do:** Copy this text. Paste it in an email. Send it to your team.

---

#### `howToFixIt` — Exact Steps to Fix

Your action items with exact directions:

```json
{
  "howToFixIt": {
    "whereToGoInKZeroAdmin": "KZero Admin → Applications → [your app] → SAML Settings",
    "step1_lookFor": "Look for 'Destination URL' field",
    "step2_compareWith": "Compare to value shown in 'whatWentWrong' section",
    "step3_changeThis": "Change the KZero value to match what the app sent",
    "whyThisMatters": "If URLs don't match, login will fail"
  }
}
```

**What to do:** Follow these exact steps in your KZero admin panel.

---

#### `whatWentWrong` — Plain Story of What Happened

Plain-English summary of the login flow:

```json
{
  "whatWentWrong": {
    "simpleStory": "The app asked KZero to log you in, but KZero said no. The destination URL in KZero doesn't match what the app sent.",
    "stepByStep": [
      {
        "stepNumber": 1,
        "whatHappened": "App asked KZero to log you in",
        "plainEnglishDetail": "App identified as: https://vendor-sp.example.com/sp"
      },
      {
        "stepNumber": 2,
        "whatHappened": "KZero rejected the login request",
        "plainEnglishDetail": "KZero returned HTTP 400 - destination URL mismatch"
      }
    ]
  }
}
```

**What to do:** Read this to understand the story of what happened, in plain English.

---

#### `howToReadThisFile` — Your Guide

```json
{
  "howToReadThisFile": {
    "ifYouJustNeedToFixIt": "Read 'howToFixIt' - it has exact steps to fix the problem",
    "ifYouNeedToSendThisToSomeone": "Copy 'copyThisTextToSendToSomeone' - it's ready to paste into an email",
    "ifYouWantToUnderstand": "Read 'whatWentWrong' - it explains what happened in plain English",
    "forEngineersOnly": "Everything in 'technicalDetailsForEngineers' below is raw data for developers"
  }
}
```

---

## STOP! Your Action Items Are Above

The rest of this file contains raw technical data. **You don't need to read it unless**:

- Someone asks for "the technical details"
- You want to understand _why_ something went wrong
- You're a developer

If you just need to fix something or send this to someone, you're done. Close this file and follow the steps in `howToFixIt`.

---

## Common Problems and What to Do

### "Destination URL doesn't match" (🔴 Red)

**What this means:** The app told KZero to send the login confirmation to one address, but KZero is configured to expect a different address. It's like giving someone the wrong mailing address.

**What to check:**

1. Go to `howToFixIt.whereToGoInKZeroAdmin`
2. Look for the Destination URL field
3. Make it match what the app is sending (shown in `whatWentWrong.stepByStep`)

---

### "Entity ID / Client ID mismatch" (🔴 Red)

**What this means:** The app identifies itself with one name, but KZero doesn't recognize that name. It's like introducing yourself with the wrong name.

**What to check:**

1. Go to `howToFixIt.whereToGoInKZeroAdmin`
2. Look for Client ID / Entity ID field
3. Make it match what the app sent

---

### "ACS URL mismatch" (🔴 Red)

**What this means:** The app told KZero where to send the login confirmation, but KZero doesn't accept responses at that address. It's like asking for mail to be delivered to the wrong building.

**What to check:**

1. Go to `howToFixIt.whereToGoInKZeroAdmin`
2. Look for ACS URL / Reply URL field
3. Make it match exactly what the app expects

---

### "NameID format disagreement" (🟡 Yellow)

**What this means:** KZero knows who the user is, but the app doesn't recognize the user ID format. It's like KZero says "Here's John Smith" but the app expects "john.smith@company.com".

**What to check:** Both sides need to agree on whether to use email addresses, usernames, or employee IDs.

---

### "SAML AuthnRequest not captured" (🔵 Blue)

**What this means:** We didn't see the app ask KZero to log the user in. This usually means capture started too late — after the user already clicked "Log in." It's like starting the security camera after the package was delivered.

**What to do:** Next time, start capture _before_ clicking the login button.

---

## Troubleshooting

### "The tool isn't recording anything"

- Did you click **Start capture** first?
- Did you start capture _before_ clicking the login button?
- Try reloading the page and start fresh

### "I see errors but don't understand them"

- Go to `howToFixIt` for exact steps
- If it's still confusing, export the trace and send it to KZero support

### "The capture is showing too much junk"

- In Settings, switch to **Auth-only** mode
- This tells the tool to ignore analytics, ads, and other noise

### "I don't know what to do next"

- Export the trace (click Export → Download JSON)
- Copy `copyThisTextToSendToSomeone`
- Send it to your KZero support contact

---

## What NOT to share

This tool can see some sensitive stuff. **Don't share exports with people outside your organization.**

- **Safe to share:** Summary and sanitized exports (secrets are removed)
- **Be careful:** Detailed exports contain decoded login responses — treat these like passwords

**Quick rule:** If you wouldn't email a password, don't email a detailed export.

---

## Keyboard Shortcuts

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

## Need more help?

- **KZero Support:** Contact your KZero account team
- **For developers:** See README.technical.md in the same folder
- **Something wrong with this guide?** Let us know!

---

_Last updated: April 2026_
