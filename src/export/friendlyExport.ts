import type { SanitizedExportBundle, SummaryExportBundle } from '../shared/models';

export interface FriendlyStep {
  stepNumber: number;
  whatHappened: string;
  plainEnglishDetail: string;
}

export interface FriendlyHowToFix {
  whereToGoInKZeroAdmin: string;
  step1_lookFor: string;
  step2_compareWith: string;
  step3_changeThis: string;
  whyThisMatters: string;
}

export interface FriendlyWhatWentWrong {
  simpleStory: string;
  stepByStep: FriendlyStep[];
}

export interface FriendlyExportBundle {
  exportFormat: 'friendly';
  generatedAt: string;
  product: string;

  didTheLoginWork: string;
  whyItFailedOneSentence: string;

  copyThisTextToSendToSomeone: string;

  howToFixIt: FriendlyHowToFix;

  whatWentWrong: FriendlyWhatWentWrong;

  howToReadThisFile: {
    ifYouJustNeedToFixIt: string;
    ifYouNeedToSendThisToSomeone: string;
    ifYouWantToUnderstand: string;
    forEngineersOnly: string;
  };

  technicalDetailsForEngineers: {
    note: string;
    events: unknown[];
    findings: unknown[];
    metadata: unknown;
  };
}

const getStatusEmoji = (status: string): string => {
  switch (status) {
    case 'success':
      return '✅ YES';
    case 'failure':
      return '❌ NO';
    default:
      return '⚠️ INCOMPLETE - TRACE MAY BE INCOMPLETE';
  }
};

const buildHowToReadThis = (): FriendlyExportBundle['howToReadThisFile'] => ({
  ifYouJustNeedToFixIt: "Read 'howToFixIt' - it has exact steps to fix the problem",
  ifYouNeedToSendThisToSomeone:
    "Copy 'copyThisTextToSendToSomeone' - it's ready to paste into an email",
  ifYouWantToUnderstand: "Read 'whatWentWrong' - it explains what happened in plain English",
  forEngineersOnly: "Everything in 'technicalDetailsForEngineers' below is raw data for developers"
});

const transformSanitizedToFriendly = (export_: SanitizedExportBundle): FriendlyExportBundle => {
  const education = export_.education;

  const quickVerdict = education?.quickVerdict;
  const firstAction = education?.firstAction;
  const whatHappened = education?.whatHappened;
  const findings = education?.whatWentWrong ?? [];

  const didTheLoginWork = quickVerdict ? getStatusEmoji(quickVerdict.overallStatus) : '⚠️ UNKNOWN';

  const whyItFailedOneSentence = quickVerdict?.oneSentenceSummary ?? 'Unable to determine outcome';

  const copyThisTextToSendToSomeone =
    education?.supportSummary?.copyPasteSummary ?? 'No summary available';

  const howToFixIt: FriendlyHowToFix = {
    whereToGoInKZeroAdmin: firstAction?.kzeroAdminPath ?? 'KZero Admin → Applications → [your app]',
    step1_lookFor: firstAction?.whatToFind ?? 'Check the relevant configuration field',
    step2_compareWith: firstAction?.whatToCompare ?? 'Compare to values in the trace',
    step3_changeThis: 'Change the KZero value to match what the app sent',
    whyThisMatters: firstAction?.whyThisMatters ?? 'Configuration mismatch prevents login'
  };

  const sortedFindings = [...findings].sort((a, b) => {
    const order = { error: 0, warning: 1, info: 2 };
    return order[a.severity] - order[b.severity];
  });
  const keyFinding = sortedFindings[0];

  const simpleStory =
    whatHappened?.plainEnglishSummary ??
    keyFinding?.plainEnglishExplanation ??
    'The login attempt did not complete successfully.';

  const stepByStep: FriendlyStep[] = (whatHappened?.stepByStep ?? []).map((step, idx) => ({
    stepNumber: idx + 1,
    whatHappened: step.plainLabel,
    plainEnglishDetail: step.plainDetail
  }));

  const whatWentWrong: FriendlyWhatWentWrong = {
    simpleStory,
    stepByStep
  };

  return {
    exportFormat: 'friendly',
    generatedAt: export_.generatedAt,
    product: export_.product,
    didTheLoginWork,
    whyItFailedOneSentence,
    copyThisTextToSendToSomeone,
    howToFixIt,
    whatWentWrong,
    howToReadThisFile: buildHowToReadThis(),
    technicalDetailsForEngineers: {
      note: 'STOP HERE if you are non-technical. The information above is what you need.',
      events: export_.events,
      findings: export_.findings,
      metadata: export_.metadata
    }
  };
};

const transformSummaryToFriendly = (export_: SummaryExportBundle): FriendlyExportBundle => {
  const education = export_.education;

  const quickVerdict = education?.quickVerdict;
  const firstAction = education?.firstAction;
  const whatHappened = education?.whatHappened;
  const findings = education?.whatWentWrong ?? [];

  const didTheLoginWork = quickVerdict ? getStatusEmoji(quickVerdict.overallStatus) : '⚠️ UNKNOWN';

  const whyItFailedOneSentence = quickVerdict?.oneSentenceSummary ?? 'Unable to determine outcome';

  const copyThisTextToSendToSomeone =
    education?.supportSummary?.copyPasteSummary ?? 'No summary available';

  const howToFixIt: FriendlyHowToFix = {
    whereToGoInKZeroAdmin: firstAction?.kzeroAdminPath ?? 'KZero Admin → Applications → [your app]',
    step1_lookFor: firstAction?.whatToFind ?? 'Check the relevant configuration field',
    step2_compareWith: firstAction?.whatToCompare ?? 'Compare to values in the trace',
    step3_changeThis: 'Change the KZero value to match what the app sent',
    whyThisMatters: firstAction?.whyThisMatters ?? 'Configuration mismatch prevents login'
  };

  const sortedFindings = [...findings].sort((a, b) => {
    const order = { error: 0, warning: 1, info: 2 };
    return order[a.severity] - order[b.severity];
  });
  const keyFinding = sortedFindings[0];

  const simpleStory =
    whatHappened?.plainEnglishSummary ??
    keyFinding?.plainEnglishExplanation ??
    'The login attempt did not complete successfully.';

  const stepByStep: FriendlyStep[] = (whatHappened?.stepByStep ?? []).map((step, idx) => ({
    stepNumber: idx + 1,
    whatHappened: step.plainLabel,
    plainEnglishDetail: step.plainDetail
  }));

  const whatWentWrong: FriendlyWhatWentWrong = {
    simpleStory,
    stepByStep
  };

  return {
    exportFormat: 'friendly',
    generatedAt: export_.generatedAt,
    product: export_.product,
    didTheLoginWork,
    whyItFailedOneSentence,
    copyThisTextToSendToSomeone,
    howToFixIt,
    whatWentWrong,
    howToReadThisFile: buildHowToReadThis(),
    technicalDetailsForEngineers: {
      note: 'STOP HERE if you are non-technical. The information above is what you need.',
      events: [],
      findings: export_.findings,
      metadata: export_.metadata
    }
  };
};

export const transformToFriendlyExport = (
  export_: SanitizedExportBundle | SummaryExportBundle | null
): FriendlyExportBundle | null => {
  if (!export_) return null;

  if ('events' in export_) {
    return transformSanitizedToFriendly(export_);
  }

  return transformSummaryToFriendly(export_);
};

export const isFriendlyExport = (export_: unknown): export_ is FriendlyExportBundle => {
  return (
    typeof export_ === 'object' &&
    export_ !== null &&
    'exportFormat' in export_ &&
    (export_ as Record<string, unknown>).exportFormat === 'friendly'
  );
};
