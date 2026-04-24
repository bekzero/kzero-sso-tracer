import type { CaptureSession } from '../shared/models';
import { buildSanitizedExportFriendly } from './sanitizedExport';

const formatFixSteps = (
  friendly: NonNullable<ReturnType<typeof buildSanitizedExportFriendly>>
): string => {
  return `${friendly.howToFixIt.whereToGoInKZeroAdmin}
  
Step 1: ${friendly.howToFixIt.step1_lookFor}
Step 2: ${friendly.howToFixIt.step2_compareWith}
Step 3: ${friendly.howToFixIt.step3_changeThis}

Why this matters: ${friendly.howToFixIt.whyThisMatters}`;
};

const formatWhatWentWrong = (
  friendly: NonNullable<ReturnType<typeof buildSanitizedExportFriendly>>
): string => {
  let result = friendly.whatWentWrong.simpleStory + '\n\n';

  if (friendly.whatWentWrong.stepByStep.length > 0) {
    result += 'What happened:\n';
    for (const step of friendly.whatWentWrong.stepByStep) {
      result += `${step.stepNumber}. ${step.whatHappened}\n   ${step.plainEnglishDetail}\n`;
    }
  }

  return result;
};

export const emailSessionToSupport = (session: CaptureSession | null): void => {
  const friendly = buildSanitizedExportFriendly(session);

  if (!friendly) return;

  const timestamp = new Date().toLocaleString();

  const subject = `KZero SSO Tracer - ${friendly.didTheLoginWork} - ${timestamp}`;

  const body = `KZero SSO Tracer - Support Request
===========================================

Status: ${friendly.didTheLoginWork}
Date: ${timestamp}
${friendly.product}

---
PROBLEM SUMMARY
---
${friendly.whyItFailedOneSentence}

---
READY-TO-SEND SUMMARY
---
${friendly.copyThisTextToSendToSomeone}

---
WHAT WENT WRONG
---
${formatWhatWentWrong(friendly)}

---
HOW TO FIX THIS
---
${formatFixSteps(friendly)}

---
READING THIS TRACE
---
${friendly.howToReadThisFile.ifYouJustNeedToFixIt}
${friendly.howToReadThisFile.ifYouNeedToSendThisToSomeone}
${friendly.howToReadThisFile.ifYouWantToUnderstand}

---
For Engineers Only
---
The section "technicalDetailsForEngineers" in the JSON export contains raw trace data.

---
Need more help? Contact KZero support at support@kzero.com
`;

  const mailtoUrl = `mailto:support@kzero.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

  window.open(mailtoUrl);
};

export const getEmailBody = (session: CaptureSession | null): string | null => {
  const friendly = buildSanitizedExportFriendly(session);

  if (!friendly) return null;

  const timestamp = new Date().toLocaleString();

  return `KZero SSO Tracer - Support Request
===========================================

Status: ${friendly.didTheLoginWork}
Date: ${timestamp}
${friendly.product}

---
PROBLEM SUMMARY
---
${friendly.whyItFailedOneSentence}

---
READY-TO-SEND SUMMARY
---
${friendly.copyThisTextToSendToSomeone}

---
WHAT WENT WRONG
---
${formatWhatWentWrong(friendly)}

---
HOW TO FIX THIS
---
${formatFixSteps(friendly)}

---
READING THIS TRACE
---
${friendly.howToReadThisFile.ifYouJustNeedToFixIt}
${friendly.howToReadThisFile.ifYouNeedToSendThisToSomeone}
${friendly.howToReadThisFile.ifYouWantToUnderstand}

---
For Engineers Only
---
The section "technicalDetailsForEngineers" in the JSON export contains raw trace data.

---
Need more help? Contact KZero support at support@kzero.com
`;
};

export const copyTraceToClipboard = (session: CaptureSession | null): boolean => {
  const body = getEmailBody(session);
  if (!body) return false;

  navigator.clipboard.writeText(body).catch(console.error);
  return true;
};
