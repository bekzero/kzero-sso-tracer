import { describe, expect, it } from 'vitest';
import type { NormalizedSamlEvent, Finding } from '../src/shared/models';
import {
  buildEducationalExport,
  enrichEvent,
  enrichSamlEvent,
  enrichFinding,
  buildFlowNarrative,
  buildComparisonChecklist,
  buildProtocolGlossary,
  classifyNoise,
  detectInitiationModel,
  SCHEMA_VERSION,
  EXPORT_VERSION
} from '../src/export/enrichment';

const createSamlAuthnRequest = (): NormalizedSamlEvent =>
  ({
    id: 'evt-request',
    tabId: 1,
    timestamp: 1000000000000,
    protocol: 'SAML',
    kind: 'saml-request',
    url: 'https://ca.auth.kzero.com/realms/kzero/protocol/saml',
    host: 'vendor-sp.example.com',
    method: 'GET',
    statusCode: 200,
    rawRef: 'raw-1',
    artifacts: {},
    binding: 'redirect',
    samlRequest: {
      encoded: 'base64encoded...',
      issuer: 'https://vendor-sp.example.com/sp',
      destination: 'https://ca.auth.kzero.com/realms/kzero/protocol/saml',
      assertionConsumerServiceURL: 'https://vendor-sp.example.com/acs',
      forceAuthn: false,
      allowCreate: true
    }
  }) as NormalizedSamlEvent;

const createSamlResponse = (): NormalizedSamlEvent =>
  ({
    id: 'evt-response',
    tabId: 1,
    timestamp: 1000000000500,
    protocol: 'SAML',
    kind: 'saml-response',
    url: 'https://ca.auth.kzero.com/realms/kzero/protocol/saml',
    host: 'ca.auth.kzero.com',
    method: 'POST',
    statusCode: 200,
    rawRef: 'raw-2',
    artifacts: {},
    binding: 'post',
    samlResponse: {
      encoded: 'base64encoded...',
      decodedXml: '<?xml version="1.0"?><samlp:Response>...</samlp:Response>',
      issuer: 'https://ca.auth.kzero.com/realms/kzero',
      destination: 'https://vendor-sp.example.com/acs',
      audience: 'https://vendor-sp.example.com/sp',
      nameId: 'user@example.com',
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:email',
      assertionSigned: true,
      documentSigned: false
    }
  }) as NormalizedSamlEvent;

const createKzeroError = (): NormalizedSamlEvent =>
  ({
    id: 'evt-kzero-error',
    tabId: 1,
    timestamp: 1000000000000,
    protocol: 'SAML',
    kind: 'saml-request',
    url: 'https://ca.auth.kzero.com/realms/kzero/protocol/saml',
    host: 'ca.auth.kzero.com',
    method: 'GET',
    statusCode: 400,
    rawRef: 'raw-1',
    artifacts: {},
    binding: 'redirect',
    samlRequest: {
      encoded: 'base64encoded...',
      issuer: 'https://wrong-sp.example.com/sp',
      destination: 'https://ca.auth.kzero.com/realms/kzero/protocol/saml',
      assertionConsumerServiceURL: 'https://wrong-sp.example.com/acs'
    }
  }) as NormalizedSamlEvent;

const createNoiseEvent = (): any => ({
  id: 'evt-noise',
  tabId: 1,
  timestamp: 1000000000200,
  protocol: 'network',
  kind: 'webrequest',
  url: 'https://www.google-analytics.com/collect',
  host: 'www.google-analytics.com',
  method: 'GET',
  statusCode: 200,
  rawRef: 'raw-noise',
  artifacts: {}
});

describe('enrichSamlEvent', () => {
  it('enriches SAML request with plain English explanations', () => {
    const event = createSamlAuthnRequest();
    const enriched = enrichSamlEvent(event);

    expect(enriched.messageDirection).toBe('request');
    expect(enriched.messagePurpose).toBe('request-login');
    expect(enriched.initiatedBy).toBe('SP');
    expect(enriched.authRelevance).toBe('high');
    expect(enriched.plainEnglishSummary).toContain('SAML login request');
    expect(enriched.samlFieldExplanations.length).toBeGreaterThan(0);
    expect(enriched.observedVsExpectedNote).toBeDefined();
  });

  it('enriches SAML response with plain English explanations', () => {
    const event = createSamlResponse();
    const enriched = enrichSamlEvent(event);

    expect(enriched.messageDirection).toBe('response');
    expect(enriched.messagePurpose).toBe('return-login-result');
    expect(enriched.initiatedBy).toBe('IdP');
    expect(enriched.plainEnglishSummary).toContain('SAML login result');
  });

  it('includes observed vs expected note for requests', () => {
    const event = createSamlAuthnRequest();
    const enriched = enrichSamlEvent(event);

    expect(enriched.observedVsExpectedNote).toContain('trace shows what the SP sent');
    expect(enriched.observedVsExpectedNote).toContain('NOT visible');
  });

  it('includes error context for failed responses', () => {
    const event: NormalizedSamlEvent = {
      ...createSamlResponse(),
      statusCode: 400,
      samlResponse: {
        ...createSamlResponse().samlResponse!,
        encoded: 'error'
      }
    };
    const enriched = enrichSamlEvent(event);

    expect(enriched.plainEnglishSummary).toContain('error');
    expect(enriched.observedVsExpectedNote).toContain('configured KZero expected values');
  });
});

describe('enrichEvent', () => {
  it('tags noise events correctly', () => {
    const noiseEvent = createNoiseEvent();
    const enriched = enrichEvent(noiseEvent as any);

    expect(enriched.authRelevance).toBe('noise');
    expect(enriched.noiseReason).toBeDefined();
  });
});

describe('buildFlowNarrative', () => {
  it('creates SP-initiated narrative', () => {
    const events = [createSamlAuthnRequest(), createSamlResponse()];
    const findings: Finding[] = [];
    const narrative = buildFlowNarrative(events as any, findings);

    expect(narrative.initiationModel).toBe('SP-initiated');
    expect(narrative.flowOutcome).toBe('success');
    expect(narrative.initiationModelExplanation).toContain('SP-initiated');
  });

  it('creates failure narrative when KZero rejects', () => {
    const events = [createKzeroError()];
    const findings: Finding[] = [
      {
        id: 'f1',
        ruleId: 'SAML_PREAUTHN_CONFIG_ISSUE',
        severity: 'error',
        protocol: 'SAML',
        likelyOwner: 'KZero',
        title: 'KZero rejected the request',
        explanation: 'Config issue',
        observed: 'HTTP 400',
        expected: 'HTTP 200',
        evidence: [],
        likelyFix: { kzeroFields: [], vendorFields: [], action: 'Fix' },
        confidence: 0.9,
        confidenceLevel: 'high'
      }
    ];
    const narrative = buildFlowNarrative(events as any, findings);

    expect(narrative.flowOutcome).toBe('failure');
    expect(narrative.failureIndicator).toContain('HTTP 400');
  });

  it('includes timeline steps', () => {
    const events = [createSamlAuthnRequest(), createSamlResponse()];
    const findings: Finding[] = [];
    const narrative = buildFlowNarrative(events as any, findings);

    expect(narrative.timelineSummary.length).toBe(2);
    expect(narrative.timelineSummary[0].summary).toContain('AuthnRequest');
  });

  it('generates plain English flow description', () => {
    const events = [createSamlAuthnRequest(), createSamlResponse()];
    const findings: Finding[] = [];
    const narrative = buildFlowNarrative(events as any, findings);

    expect(narrative.plainEnglishFlow).toContain('SP sent AuthnRequest');
  });
});

describe('buildComparisonChecklist', () => {
  it('extracts SP identity from request', () => {
    const events = [createSamlAuthnRequest()];
    const findings: Finding[] = [];
    const checklist = buildComparisonChecklist(events as any, findings);

    expect(checklist.spIdentity.length).toBeGreaterThan(0);
    expect(checklist.spIdentity[0].fieldGroup).toContain('Issuer');
    expect(checklist.spIdentity[0].observedValue).toBe('https://vendor-sp.example.com/sp');
  });

  it('extracts ACS URL from request', () => {
    const events = [createSamlAuthnRequest()];
    const findings: Finding[] = [];
    const checklist = buildComparisonChecklist(events as any, findings);

    expect(checklist.acsUrl.length).toBeGreaterThan(0);
    expect(checklist.acsUrl[0].observedValue).toBe('https://vendor-sp.example.com/acs');
  });

  it('includes common KZero field names', () => {
    const events = [createSamlAuthnRequest()];
    const findings: Finding[] = [];
    const checklist = buildComparisonChecklist(events as any, findings);

    expect(checklist.spIdentity[0].commonKZeroFieldNames).toContain('Client ID');
    expect(checklist.spIdentity[0].commonKZeroFieldNames).toContain('SP Entity ID');
    expect(checklist.acsUrl[0].commonKZeroFieldNames).toContain('ACS URL');
  });
});

describe('enrichFinding', () => {
  it('adds evidence mapping', () => {
    const finding: Finding = {
      id: 'f1',
      ruleId: 'SAML_MISSING_RESPONSE',
      severity: 'error',
      protocol: 'SAML',
      likelyOwner: 'vendor SP',
      title: 'Missing SAMLResponse',
      explanation: 'No SAMLResponse was captured',
      observed: 'SAMLResponse not found',
      expected: 'SAMLResponse present',
      evidence: ['event-url'],
      likelyFix: { kzeroFields: [], vendorFields: [], action: 'Check capture' },
      confidence: 0.88,
      confidenceLevel: 'high',
      eventId: 'evt-request'
    };

    const events = [createSamlAuthnRequest()];
    const enriched = enrichFinding(finding, events as any);

    expect(enriched.notShownInTrace.length).toBeGreaterThan(0);
  });

  it('includes notShownInTrace notes', () => {
    const finding: Finding = {
      id: 'f1',
      ruleId: 'SAML_ACS_RECIPIENT_MISMATCH',
      severity: 'error',
      protocol: 'SAML',
      likelyOwner: 'vendor SP',
      title: 'ACS URL mismatch',
      explanation: 'ACS URL does not match',
      observed: 'https://wrong.com/acs',
      expected: 'https://correct.com/acs',
      evidence: [],
      likelyFix: { kzeroFields: [], vendorFields: [], action: 'Fix URL' },
      confidence: 0.96,
      confidenceLevel: 'high',
      eventId: 'evt-1'
    };

    const events = [createSamlAuthnRequest()];
    const enriched = enrichFinding(finding, events as any);

    expect(enriched.notShownInTrace).toContain('KZero configured expected value is not shown here');
  });
});

describe('classifyNoise', () => {
  it('identifies noise events', () => {
    const events = [createSamlAuthnRequest(), createNoiseEvent(), createNoiseEvent()];
    const result = classifyNoise(events as any);

    expect(result.totalCount).toBe(2);
    expect(result.explanation).toContain('non-auth request');
  });

  it('handles no noise', () => {
    const events = [createSamlAuthnRequest()];
    const result = classifyNoise(events as any);

    expect(result.totalCount).toBe(0);
  });
});

describe('detectInitiationModel', () => {
  it('detects SP-initiated when AuthnRequest present', () => {
    const events = [createSamlAuthnRequest()];
    const model = detectInitiationModel(events as any);

    expect(model).toBe('SP-initiated');
  });
});

describe('buildProtocolGlossary', () => {
  it('provides SAML explainers', () => {
    const glossary = buildProtocolGlossary();

    expect(glossary.whatIsIssuer).toBeDefined();
    expect(glossary.whatIsAcsUrl).toBeDefined();
    expect(glossary.whatIsDestination).toBeDefined();
    expect(glossary.whatIsSamlRequest).toBeDefined();
    expect(glossary.whatIsSamlResponse).toBeDefined();
    expect(glossary.whatIsSpInitiated).toBeDefined();
    expect(glossary.whatIsIdpInitiated).toBeDefined();
  });
});

describe('buildEducationalExport', () => {
  it('builds complete educational export with schema version', () => {
    const events = [createSamlAuthnRequest(), createSamlResponse()];
    const findings: Finding[] = [];
    const export_ = buildEducationalExport(events as any, findings);

    expect(export_.schemaVersion).toBe(SCHEMA_VERSION);
    expect(export_.exportVersion).toBe(EXPORT_VERSION);
    expect(export_.educational).toBeDefined();
    expect(export_.narrative).toBeDefined();
    expect(export_.observedFacts).toBeDefined();
    expect(export_.inferredFindings).toBeDefined();
    expect(export_.manualChecks).toBeDefined();
    expect(export_.learningAids).toBeDefined();
    expect(export_.noiseEvents).toBeDefined();
    expect(export_.notShownInTrace).toBeDefined();
  });

  it('includes key finding from errors', () => {
    const requestEvent = createSamlAuthnRequest();
    const errorEvent = createKzeroError();
    const findings: Finding[] = [
      {
        id: 'f1',
        ruleId: 'SAML_PREAUTHN_CONFIG_ISSUE',
        severity: 'error',
        protocol: 'SAML',
        likelyOwner: 'KZero',
        title: 'KZero rejected the sign-in request',
        explanation: 'Config issue',
        observed: 'HTTP 400',
        expected: 'HTTP 200',
        evidence: [],
        likelyFix: { kzeroFields: [], vendorFields: [], action: 'Fix config' },
        confidence: 0.9,
        confidenceLevel: 'high',
        eventId: 'evt-kzero-error'
      }
    ];

    const export_ = buildEducationalExport([requestEvent, errorEvent] as any, findings);

    expect(export_.educational.flowOutcome).toBe('failure');
    expect(export_.educational.keyFinding).toContain('rejected');
    expect(export_.educational.keyFindingSeverity).toBe('error');
  });

  it('includes observed facts', () => {
    const events = [createSamlAuthnRequest()];
    const findings: Finding[] = [];
    const export_ = buildEducationalExport(events as any, findings);

    expect(export_.observedFacts.length).toBeGreaterThan(0);
    expect(export_.observedFacts[0]).toContain('SAML AuthnRequest');
  });
});

describe('schema versioning', () => {
  it('exports correct schema version', () => {
    expect(SCHEMA_VERSION).toBe('2.0.0');
  });

  it('exports correct export version', () => {
    expect(EXPORT_VERSION).toBe('1.0.0');
  });
});

describe('failed SP-initiated example', () => {
  it('documents failed SP-initiated flow with HTTP 400', () => {
    const events = [createKzeroError()];
    const findings: Finding[] = [
      {
        id: 'f1',
        ruleId: 'SAML_AUTHNREQUEST_REJECTED_BY_KZERO',
        severity: 'error',
        protocol: 'SAML',
        likelyOwner: 'KZero',
        title: 'KZero rejected the sign-in request before sending a SAML response',
        explanation: 'The service provider sent an AuthnRequest, but KZero returned an error.',
        observed: 'KZero SAML endpoint returned HTTP 400',
        expected: 'KZero accepts the AuthnRequest',
        evidence: [],
        likelyFix: {
          kzeroFields: ['Client ID'],
          vendorFields: ['Issuer'],
          action: 'Compare values'
        },
        confidence: 0.98,
        confidenceLevel: 'high',
        eventId: 'evt-kzero-error'
      }
    ];

    const export_ = buildEducationalExport(events as any, findings);

    expect(export_.narrative.initiationModel).toBe('SP-initiated');
    expect(export_.narrative.flowOutcome).toBe('failure');
    expect(export_.notShownInTrace.length).toBeGreaterThan(0);
  });
});

describe('IdP-initiated example', () => {
  it('documents IdP-initiated flow', () => {
    const events = [
      {
        ...createSamlResponse(),
        id: 'evt-response',
        samlResponse: {
          ...createSamlResponse().samlResponse!,
          inResponseTo: undefined
        }
      }
    ];
    const findings: Finding[] = [];

    const export_ = buildEducationalExport(events as any, findings);

    expect(export_.narrative.initiationModel).toBe('IdP-initiated');
    expect(export_.narrative.flowOutcome).toBe('success');
    expect(export_.narrative.initiationModelExplanation).toContain('IdP-initiated');
  });
});
