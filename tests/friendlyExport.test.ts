import { describe, expect, it } from 'vitest';
import {
  transformToFriendlyExport,
  isFriendlyExport,
  type FriendlyExportBundle
} from '../src/export/friendlyExport';
import type { SanitizedExportBundle } from '../src/shared/models';

const createMockSanitizedExport = (
  overrides: Partial<{
    overallStatus: string;
    oneSentenceSummary: string;
    copyPasteSummary: string;
    kzeroAdminPath: string;
    whatToFind: string;
    whatToCompare: string;
    whyThisMatters: string;
    plainEnglishSummary: string;
    stepByStep: Array<{ plainLabel: string; plainDetail: string }>;
  }> = {}
) => {
  const {
    overallStatus = 'failure',
    oneSentenceSummary = 'Login failed because destination URL does not match',
    copyPasteSummary = 'SSO failed for user@company.com. Error: Destination URL mismatch.',
    kzeroAdminPath = 'KZero Admin → Applications → Test App → SAML Settings',
    whatToFind = 'Look for Destination URL field',
    whatToCompare = 'Compare to: https://app.example.com',
    whyThisMatters = 'If URLs do not match, login will fail',
    plainEnglishSummary = 'The app asked KZero to log you in, but KZero said no.',
    stepByStep = [
      {
        plainLabel: 'App asked KZero to log you in',
        plainDetail: 'App identified as: https://sp.example.com'
      },
      { plainLabel: 'KZero rejected the login request', plainDetail: 'KZero returned HTTP 400' }
    ]
  } = overrides;

  return {
    generatedAt: '2026-04-24T12:00:00.000Z',
    product: 'KZero Passwordless SSO Tracer',
    notice: 'Captured auth data stays local unless explicitly exported.',
    tabId: 123,
    events: [
      {
        id: 'evt-1',
        protocol: 'SAML',
        tabId: 123,
        timestamp: Date.now(),
        kind: 'saml-request',
        host: 'test.com',
        artifacts: {},
        rawRef: 'raw-1'
      }
    ],
    findings: [
      {
        id: 'f1',
        ruleId: 'TEST',
        severity: 'error' as const,
        protocol: 'SAML' as const,
        likelyOwner: 'KZero' as const,
        title: 'Destination mismatch',
        explanation: 'Test',
        confidence: 0.9,
        confidenceLevel: 'high' as const
      }
    ],
    metadata: {
      mode: 'sanitized',
      generatedAt: '2026-04-24T12:00:00.000Z',
      includePostLoginActivity: false,
      authBoundaryDetected: false,
      redactionsApplied: []
    },
    education: {
      schemaVersion: '2.1.0' as const,
      exportVersion: '1.1.0' as const,
      generatedAt: '2026-04-24T12:00:00.000Z',
      aboutThisFile: {
        whatIsThis: 'Test',
        whatThisShows: 'Test',
        howToUse: 'Test',
        estimatedReadTime: '1 min'
      },
      quickVerdict: {
        overallStatus,
        severityLabel: overallStatus === 'success' ? '✅ SUCCESS' : '🔴 LOGIN FAILED',
        oneSentenceSummary,
        confidence: 'high' as const
      },
      recommendedPath: { forNewUsers: [], forFixers: [], forLearners: [] },
      whatHappened: {
        initiationModel: 'SP-initiated',
        initiationModelPlain: 'App started the login',
        plainEnglishSummary,
        stepByStep: stepByStep.map((s, i) => ({
          ...s,
          stepNumber: i + 1,
          timestamp: Date.now(),
          isAuthRelevant: true
        }))
      },
      whatWentWrong: [],
      whatToCompare: {
        summary: 'Check values',
        visual: { quickSummary: '', comparisonTable: [], matchSummary: '' },
        detailed: { spIdentity: [], acsUrl: [], destination: [], signedRequest: [] }
      },
      firstAction: {
        stepNumber: 1 as const,
        findingThisRelatesTo: 'Destination mismatch',
        kzeroAdminPath,
        kzeroAdminPathDetailed: kzeroAdminPath,
        whatToFind,
        whatToCompare,
        whyThisMatters
      },
      educational: {
        title: 'Test',
        protocol: 'SAML',
        flowOutcome: 'failure' as const,
        initiationModel: 'SP-initiated' as const
      },
      narrative: {
        initiationModel: 'SP-initiated',
        initiationModelExplanation: '',
        flowOutcome: 'failure' as const,
        timelineSummary: [],
        plainEnglishFlow: ''
      },
      observedFacts: [],
      learningAids: { enrichedEvents: [], protocolGlossary: {} },
      noiseEvents: { totalCount: 0, explanation: 'No noise' },
      whatThisFileDoesNotContain: [],
      supportSummary: {
        timestamp: '2026-04-24T12:00:00.000Z',
        status: '🔴 LOGIN FAILED',
        primaryIssue: 'Destination mismatch',
        valuesToShare: [],
        copyPasteSummary
      }
    }
  } as unknown as SanitizedExportBundle;
};

describe('transformToFriendlyExport', () => {
  it('transforms sanitized export to friendly format', () => {
    const sanitized = createMockSanitizedExport();
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly).not.toBeNull();
    expect(friendly?.exportFormat).toBe('friendly');
    expect(friendly?.product).toBe('KZero Passwordless SSO Tracer');
  });

  it('sets didTheLoginWork with emoji for failure', () => {
    const sanitized = createMockSanitizedExport({ overallStatus: 'failure' });
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly?.didTheLoginWork).toBe('❌ NO');
  });

  it('sets didTheLoginWork with emoji for success', () => {
    const sanitized = createMockSanitizedExport({ overallStatus: 'success' });
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly?.didTheLoginWork).toBe('✅ YES');
  });

  it('sets didTheLoginWork with warning for incomplete', () => {
    const sanitized = createMockSanitizedExport({ overallStatus: 'incomplete' });
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly?.didTheLoginWork).toContain('⚠️');
    expect(friendly?.didTheLoginWork).toContain('INCOMPLETE');
  });

  it('copies whyItFailedOneSentence from quickVerdict', () => {
    const summary = 'Custom failure summary text';
    const sanitized = createMockSanitizedExport({ oneSentenceSummary: summary });
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly?.whyItFailedOneSentence).toBe(summary);
  });

  it('copies copyThisTextToSendToSomeone from supportSummary', () => {
    const text = 'Custom copy text for support';
    const sanitized = createMockSanitizedExport({ copyPasteSummary: text });
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly?.copyThisTextToSendToSomeone).toBe(text);
  });

  it('builds howToFixIt from firstAction', () => {
    const path = 'KZero Admin → Applications → My App';
    const find = 'Look for Entity ID';
    const compare = 'Compare to https://sp.example.com';
    const why = 'Must match for login to work';

    const sanitized = createMockSanitizedExport({
      kzeroAdminPath: path,
      whatToFind: find,
      whatToCompare: compare,
      whyThisMatters: why
    });
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly?.howToFixIt.whereToGoInKZeroAdmin).toBe(path);
    expect(friendly?.howToFixIt.step1_lookFor).toBe(find);
    expect(friendly?.howToFixIt.step2_compareWith).toBe(compare);
    expect(friendly?.howToFixIt.step3_changeThis).toBe(
      'Change the KZero value to match what the app sent'
    );
    expect(friendly?.howToFixIt.whyThisMatters).toBe(why);
  });

  it('builds whatWentWrong from whatHappened', () => {
    const summary = 'The login request was rejected';
    const steps = [
      { plainLabel: 'Step 1', plainDetail: 'Detail 1' },
      { plainLabel: 'Step 2', plainDetail: 'Detail 2' }
    ];

    const sanitized = createMockSanitizedExport({
      plainEnglishSummary: summary,
      stepByStep: steps
    });
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly?.whatWentWrong.simpleStory).toBe(summary);
    expect(friendly?.whatWentWrong.stepByStep).toHaveLength(2);
    expect(friendly?.whatWentWrong.stepByStep[0].whatHappened).toBe('Step 1');
    expect(friendly?.whatWentWrong.stepByStep[0].plainEnglishDetail).toBe('Detail 1');
  });

  it('includes howToReadThisFile with guidance', () => {
    const sanitized = createMockSanitizedExport();
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly?.howToReadThisFile.ifYouJustNeedToFixIt).toContain('howToFixIt');
    expect(friendly?.howToReadThisFile.ifYouNeedToSendThisToSomeone).toContain(
      'copyThisTextToSendToSomeone'
    );
    expect(friendly?.howToReadThisFile.ifYouWantToUnderstand).toContain('whatWentWrong');
    expect(friendly?.howToReadThisFile.forEngineersOnly).toContain('technicalDetailsForEngineers');
  });

  it('wraps technical details in technicalDetailsForEngineers', () => {
    const sanitized = createMockSanitizedExport();
    const friendly = transformToFriendlyExport(sanitized);

    expect(friendly?.technicalDetailsForEngineers).toBeDefined();
    expect(friendly?.technicalDetailsForEngineers.note).toContain('STOP HERE');
    expect(friendly?.technicalDetailsForEngineers.events).toEqual(sanitized.events);
    expect(friendly?.technicalDetailsForEngineers.findings).toEqual(sanitized.findings);
    expect(friendly?.technicalDetailsForEngineers.metadata).toEqual(sanitized.metadata);
    expect(friendly?.technicalDetailsForEngineers.education).toEqual(sanitized.education);
  });

  it('returns null for null input', () => {
    const result = transformToFriendlyExport(null);
    expect(result).toBeNull();
  });
});

describe('isFriendlyExport', () => {
  it('returns true for friendly export object', () => {
    const sanitized = createMockSanitizedExport();
    const friendly = transformToFriendlyExport(sanitized);

    expect(isFriendlyExport(friendly)).toBe(true);
  });

  it('returns false for non-friendly export', () => {
    const sanitized = createMockSanitizedExport();
    expect(isFriendlyExport(sanitized)).toBe(false);
  });

  it('returns false for null', () => {
    expect(isFriendlyExport(null)).toBe(false);
  });

  it('returns false for undefined', () => {
    expect(isFriendlyExport(undefined)).toBe(false);
  });

  it('returns false for plain object without exportFormat', () => {
    expect(isFriendlyExport({ foo: 'bar' })).toBe(false);
  });
});

describe('friendly export structure', () => {
  it('has all required top-level fields', () => {
    const sanitized = createMockSanitizedExport();
    const friendly = transformToFriendlyExport(sanitized) as FriendlyExportBundle;

    expect(friendly).toHaveProperty('exportFormat');
    expect(friendly).toHaveProperty('generatedAt');
    expect(friendly).toHaveProperty('product');
    expect(friendly).toHaveProperty('didTheLoginWork');
    expect(friendly).toHaveProperty('whyItFailedOneSentence');
    expect(friendly).toHaveProperty('copyThisTextToSendToSomeone');
    expect(friendly).toHaveProperty('howToFixIt');
    expect(friendly).toHaveProperty('whatWentWrong');
    expect(friendly).toHaveProperty('howToReadThisFile');
    expect(friendly).toHaveProperty('technicalDetailsForEngineers');
  });

  it('has all required howToFixIt fields', () => {
    const sanitized = createMockSanitizedExport();
    const friendly = transformToFriendlyExport(sanitized) as FriendlyExportBundle;

    expect(friendly.howToFixIt).toHaveProperty('whereToGoInKZeroAdmin');
    expect(friendly.howToFixIt).toHaveProperty('step1_lookFor');
    expect(friendly.howToFixIt).toHaveProperty('step2_compareWith');
    expect(friendly.howToFixIt).toHaveProperty('step3_changeThis');
    expect(friendly.howToFixIt).toHaveProperty('whyThisMatters');
  });

  it('has all required whatWentWrong fields', () => {
    const sanitized = createMockSanitizedExport();
    const friendly = transformToFriendlyExport(sanitized) as FriendlyExportBundle;

    expect(friendly.whatWentWrong).toHaveProperty('simpleStory');
    expect(friendly.whatWentWrong).toHaveProperty('stepByStep');
  });

  it('has all required howToReadThisFile fields', () => {
    const sanitized = createMockSanitizedExport();
    const friendly = transformToFriendlyExport(sanitized) as FriendlyExportBundle;

    expect(friendly.howToReadThisFile).toHaveProperty('ifYouJustNeedToFixIt');
    expect(friendly.howToReadThisFile).toHaveProperty('ifYouNeedToSendThisToSomeone');
    expect(friendly.howToReadThisFile).toHaveProperty('ifYouWantToUnderstand');
    expect(friendly.howToReadThisFile).toHaveProperty('forEngineersOnly');
  });

  it('has all required technicalDetailsForEngineers fields', () => {
    const sanitized = createMockSanitizedExport();
    const friendly = transformToFriendlyExport(sanitized) as FriendlyExportBundle;

    expect(friendly.technicalDetailsForEngineers).toHaveProperty('note');
    expect(friendly.technicalDetailsForEngineers).toHaveProperty('events');
    expect(friendly.technicalDetailsForEngineers).toHaveProperty('findings');
    expect(friendly.technicalDetailsForEngineers).toHaveProperty('metadata');
    expect(friendly.technicalDetailsForEngineers).toHaveProperty('education');
  });
});
