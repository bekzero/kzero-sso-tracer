import type { NormalizedEvent, NormalizedSamlEvent, Finding, SamlArtifact } from '../shared/models';
import type {
  EnrichedEvent,
  EnrichedFinding,
  FlowNarrative,
  ComparisonChecklist,
  ComparisonChecklistItem,
  ProtocolGlossary,
  SamlFieldExplanation,
  TimelineStep,
  EducationalExport,
  ExportSchemaVersion,
  AuthRelevance,
  MessageDirection,
  MessagePurpose,
  InitiatedBy,
  TracePerspective,
  InitiationModel,
  FlowOutcome
} from '../shared/models';
import { isNoiseEvent } from './filtering';

const EXPORT_VERSION = '1.0.0';
const SCHEMA_VERSION: ExportSchemaVersion = '2.0.0';

const isSamlEvent = (e: NormalizedEvent): e is NormalizedSamlEvent => e.protocol === 'SAML';

const isKzeroHost = (host?: string): boolean => {
  if (!host) return false;
  const h = host.toLowerCase();
  return h.endsWith('auth.kzero.com') || h.includes('.auth.kzero.com') || h.includes('keycloak');
};

const getSamlArtifact = (event: NormalizedSamlEvent): SamlArtifact | undefined => {
  return event.samlRequest ?? event.samlResponse;
};

const explainSamlField = (
  fieldName: string,
  observedValue?: string,
  forRequest = true
): SamlFieldExplanation => {
  const explanations: Record<string, Omit<SamlFieldExplanation, 'fieldName' | 'observedValue'>> = {
    issuer: {
      plainEnglishName: 'Identity',
      whatItMeans: forRequest
        ? 'Who the service provider says it is'
        : 'Who the identity provider says it is',
      whyItMatters: forRequest
        ? 'Must match the SP Entity ID or Client ID configured in KZero'
        : 'Should match the expected IdP entity ID'
    },
    assertionConsumerServiceURL: {
      plainEnglishName: 'Reply URL',
      whatItMeans: 'Where the SP wants the SAML response sent',
      whyItMatters: 'Must match the configured SAML Reply URL or ACS URL in KZero exactly'
    },
    destination: {
      plainEnglishName: 'Target endpoint',
      whatItMeans: forRequest
        ? 'Which IdP endpoint this request is intended for'
        : 'Where the SAML response should be delivered',
      whyItMatters: forRequest
        ? 'Must target the correct KZero SAML endpoint'
        : 'Should match the receiving endpoint'
    },
    protocolBinding: {
      plainEnglishName: 'Response method',
      whatItMeans: 'How the SP wants the SAML response returned',
      whyItMatters: 'HTTP-POST is most common; HTTP-Redirect may fail with some SPs'
    },
    documentSigned: {
      plainEnglishName: 'Request signed',
      whatItMeans: 'Whether the SAML document contains a digital signature',
      whyItMatters: forRequest
        ? 'Some IdPs require signed AuthnRequests; check "Want AuthnRequests Signed" setting'
        : 'Some SPs require signed responses'
    },
    assertionSigned: {
      plainEnglishName: 'Assertion signed',
      whatItMeans: 'Whether the assertion within the SAML response is digitally signed',
      whyItMatters: 'Most SPs require signed assertions; check "Want Assertions Signed" setting'
    },
    forceAuthn: {
      plainEnglishName: 'Force re-authentication',
      whatItMeans: 'Whether the SP requests fresh authentication even if session exists',
      whyItMatters: 'May conflict with existing SSO sessions; verify SP requirements'
    },
    allowCreate: {
      plainEnglishName: 'Allow account creation',
      whatItMeans: 'Whether the SP allows new account creation on first login',
      whyItMatters: 'Maps to "Allow Create" or "Create new users" in KZero config'
    },
    encryptedAssertion: {
      plainEnglishName: 'Encrypted assertion',
      whatItMeans: 'Whether the assertion content is encrypted',
      whyItMatters: 'Requires certificate configuration in both KZero and SP'
    },
    relayState: {
      plainEnglishName: 'Relay state',
      whatItMeans: 'A value that round-trips through the IdP for SP context',
      whyItMatters: 'Must be preserved during the SAML flow; often used for redirect targets'
    },
    inResponseTo: {
      plainEnglishName: 'In response to',
      whatItMeans: 'The ID of the AuthnRequest this response answers',
      whyItMatters: forRequest
        ? 'Request ID that must be included in response'
        : 'Confirms this response matches a specific request; expected in SP-initiated flows'
    },
    audience: {
      plainEnglishName: 'Audience',
      whatItMeans: 'Who the SAML assertion is intended for',
      whyItMatters: forRequest
        ? 'Usually matches the SP Entity ID'
        : 'Should match the SP Entity ID'
    }
  };

  const explanation = explanations[fieldName] ?? {
    plainEnglishName: fieldName,
    whatItMeans: `SAML ${fieldName} field`,
    whyItMatters: 'Used in SAML authentication'
  };

  return {
    fieldName,
    observedValue,
    ...explanation
  };
};

const getFieldExplanations = (
  event: NormalizedSamlEvent,
  forRequest: boolean
): SamlFieldExplanation[] => {
  const artifact = getSamlArtifact(event);
  if (!artifact) return [];

  const fields: SamlFieldExplanation[] = [];

  if (artifact.issuer) {
    fields.push(explainSamlField('issuer', artifact.issuer, forRequest));
  }
  if (artifact.assertionConsumerServiceURL) {
    fields.push(
      explainSamlField(
        'assertionConsumerServiceURL',
        artifact.assertionConsumerServiceURL,
        forRequest
      )
    );
  }
  if (artifact.destination) {
    fields.push(explainSamlField('destination', artifact.destination, forRequest));
  }
  if (artifact.documentSigned !== undefined) {
    fields.push(explainSamlField('documentSigned', String(artifact.documentSigned), forRequest));
  }
  if (artifact.assertionSigned !== undefined) {
    fields.push(explainSamlField('assertionSigned', String(artifact.assertionSigned), forRequest));
  }
  if (artifact.forceAuthn !== undefined) {
    fields.push(explainSamlField('forceAuthn', String(artifact.forceAuthn), forRequest));
  }
  if (artifact.allowCreate !== undefined) {
    fields.push(explainSamlField('allowCreate', String(artifact.allowCreate), forRequest));
  }
  if (artifact.encryptedAssertion !== undefined) {
    fields.push(
      explainSamlField('encryptedAssertion', String(artifact.encryptedAssertion), forRequest)
    );
  }
  if (artifact.audience) {
    fields.push(explainSamlField('audience', artifact.audience, forRequest));
  }
  if (artifact.inResponseTo) {
    fields.push(explainSamlField('inResponseTo', artifact.inResponseTo, forRequest));
  }

  return fields;
};

const enrichSamlEvent = (event: NormalizedSamlEvent): EnrichedEvent => {
  const hasRequest = !!event.samlRequest;
  const _hasResponse = !!event.samlResponse;
  const _artifact = getSamlArtifact(event);

  const messageDirection: MessageDirection = hasRequest ? 'request' : 'response';
  const messagePurpose: MessagePurpose = hasRequest ? 'request-login' : 'return-login-result';
  const initiatedBy: InitiatedBy = hasRequest ? 'SP' : 'IdP';
  const tracePerspective: TracePerspective = isKzeroHost(event.host)
    ? 'incoming-to-KZero'
    : 'outgoing-from-KZero';

  let plainEnglishSummary: string;
  let whyItMatters: string;
  let whatToCheckNext: string;
  let observedVsExpectedNote: string | undefined;

  if (hasRequest) {
    const req = event.samlRequest!;
    plainEnglishSummary = `SAML login request from ${event.host}`;
    whyItMatters = `This asks KZero to authenticate the user. The SP identifies as "${req.issuer ?? 'unknown'}" and requests response at "${req.assertionConsumerServiceURL ?? req.destination ?? 'unknown'}"`;
    whatToCheckNext = `Compare the Issuer and ACS URL to what is configured in the KZero client integration.`;
    if (req.issuer || req.assertionConsumerServiceURL || req.destination) {
      observedVsExpectedNote =
        'This trace shows what the SP sent. The KZero configured expected values are NOT visible in this trace.';
    }
  } else {
    const resp = event.samlResponse!;
    plainEnglishSummary =
      event.statusCode && event.statusCode >= 400
        ? `SAML response from KZero with error (HTTP ${event.statusCode})`
        : `SAML login result from ${event.host}`;
    whyItMatters =
      event.statusCode && event.statusCode >= 400
        ? 'KZero rejected the request before completing login.'
        : `Login result for user "${resp.nameId ?? 'unknown'}". Status: ${resp.nameId ? 'success' : 'no user identity returned'}`;
    whatToCheckNext =
      event.statusCode && event.statusCode >= 400
        ? 'Check the findings for specific configuration mismatches. Compare observed values to KZero config.'
        : 'Verify the user identity matches expectations. Check NameID format mappings.';
    if (event.statusCode && event.statusCode >= 400) {
      observedVsExpectedNote =
        'This trace shows KZero rejected the request. The configured KZero expected values are NOT shown here - you must compare manually.';
    }
  }

  const authRelevance: AuthRelevance =
    event.statusCode && event.statusCode >= 400 ? 'high' : 'high';

  const samlFieldExplanations = getFieldExplanations(event, hasRequest);

  return {
    id: event.id,
    eventId: event.id,
    timestamp: event.timestamp,
    messageDirection,
    messagePurpose,
    initiatedBy,
    tracePerspective,
    plainEnglishSummary,
    whyItMatters,
    whatToCheckNext,
    observedVsExpectedNote,
    authRelevance,
    samlFieldExplanations,
    rawEvent: event
  };
};

const enrichNonSamlEvent = (event: NormalizedEvent): EnrichedEvent => {
  const isNoise = isNoiseEvent(event);
  const authRelevance: AuthRelevance = isNoise ? 'noise' : 'low';

  let plainEnglishSummary: string;
  let whyItMatters: string;
  let whatToCheckNext: string;
  let noiseReason: string | undefined;

  if (isNoise) {
    const url = event.url.toLowerCase();
    if (url.includes('analytics') || url.includes('/collect')) {
      noiseReason = 'Analytics tracking request';
    } else if (url.includes('.css') || url.includes('.js') || url.includes('.woff')) {
      noiseReason = 'Static asset (CSS/JS/Font)';
    } else if (url.includes('/socket') || url.includes('websocket')) {
      noiseReason = 'WebSocket connection for real-time updates';
    } else if (url.includes('health') || url.includes('/ping')) {
      noiseReason = 'Health check or monitoring';
    } else {
      noiseReason = 'Non-auth request detected by path patterns';
    }
    plainEnglishSummary = `Non-auth request (${noiseReason})`;
    whyItMatters = 'This is not part of the SAML authentication flow';
    whatToCheckNext = 'Focus on the SAML-specific requests for diagnosing auth issues';
  } else {
    plainEnglishSummary = `Request to ${event.host}`;
    whyItMatters = 'Adjacent to SAML flow but not SAML-specific';
    whatToCheckNext = 'Check if this request is expected after successful authentication';
  }

  return {
    id: event.id,
    eventId: event.id,
    timestamp: event.timestamp,
    messageDirection: 'request',
    messagePurpose: 'unknown',
    initiatedBy: 'unknown',
    tracePerspective: 'incoming-to-KZero',
    plainEnglishSummary,
    whyItMatters,
    whatToCheckNext,
    authRelevance,
    noiseReason,
    samlFieldExplanations: [],
    rawEvent: event
  };
};

const enrichEvent = (event: NormalizedEvent): EnrichedEvent => {
  if (isSamlEvent(event)) {
    return enrichSamlEvent(event);
  }
  return enrichNonSamlEvent(event);
};

interface NoiseClassification {
  noiseEvents: NormalizedEvent[];
  totalCount: number;
  explanation: string;
}

const classifyNoise = (events: NormalizedEvent[]): NoiseClassification => {
  const noise = events.filter(isNoiseEvent);
  const explanation =
    noise.length === 0
      ? 'No noise requests detected in this trace'
      : `${noise.length} non-auth request(s) detected. These are typically analytics, static assets, or monitoring requests that are unrelated to SAML authentication.`;

  return {
    noiseEvents: noise,
    totalCount: noise.length,
    explanation
  };
};

const detectInitiationModel = (events: NormalizedEvent[]): InitiationModel => {
  const samlEvents = events.filter(isSamlEvent);
  const requestEvent = samlEvents.find((e) => e.samlRequest);
  const responseEvent = samlEvents.find((e) => e.samlResponse);

  if (requestEvent) {
    return 'SP-initiated';
  }

  if (responseEvent?.samlResponse?.inResponseTo) {
    return 'SP-initiated';
  }

  if (responseEvent) {
    return 'IdP-initiated';
  }

  return 'unknown';
};

const buildFlowNarrative = (events: NormalizedEvent[], findings: Finding[]): FlowNarrative => {
  const samlEvents = events.filter(isSamlEvent).sort((a, b) => a.timestamp - b.timestamp);
  const requestEvent = samlEvents.find((e) => e.samlRequest);
  const responseEvent = samlEvents.find((e) => e.samlResponse);
  const kzeroRejection = samlEvents.find(
    (e) => e.statusCode && e.statusCode >= 400 && isKzeroHost(e.host)
  );

  const initiationModel = detectInitiationModel(events);
  const hasErrors = findings.some((f) => f.severity === 'error');
  const flowOutcome: FlowOutcome = hasErrors ? 'failure' : responseEvent ? 'success' : 'incomplete';

  let initiationModelExplanation: string;
  if (initiationModel === 'SP-initiated') {
    initiationModelExplanation =
      'SP-initiated flows start with the service provider sending a SAML AuthnRequest to KZero. The trace should show the incoming request from the SP vendor. Look for the Issuer, ACS URL, and Destination in the request.';
  } else if (initiationModel === 'IdP-initiated') {
    initiationModelExplanation =
      'IdP-initiated flows start from KZero (or another IdP) without an incoming AuthnRequest. No SAMLRequest from the vendor appears in the trace. The flow may begin with a redirect to KZero or a direct application landing.';
  } else {
    initiationModelExplanation =
      'The trace does not clearly show whether this is SP-initiated or IdP-initiated. Check if an AuthnRequest from the SP vendor is visible in the capture.';
  }

  let successIndicator: string | undefined;
  let failureIndicator: string | undefined;

  if (flowOutcome === 'success') {
    successIndicator = `SAMLResponse received from ${responseEvent?.host} with HTTP ${responseEvent?.statusCode}`;
  } else if (flowOutcome === 'failure') {
    if (kzeroRejection) {
      failureIndicator = `KZero SAML endpoint returned HTTP ${kzeroRejection.statusCode} before SAMLResponse was generated`;
    } else {
      failureIndicator = 'Errors detected in the trace - check findings for details';
    }
  }

  const timelineSummary: TimelineStep[] = samlEvents.map((e, idx) => {
    const step: TimelineStep = {
      order: idx + 1,
      timestamp: e.timestamp,
      summary: '',
      detail: '',
      isAuthRelevant: true
    };

    if (e.samlRequest) {
      step.summary = 'SAML AuthnRequest received';
      step.detail = `From ${e.host} with Issuer: "${e.samlRequest.issuer ?? 'not captured'}"`;
    } else if (e.samlResponse) {
      step.summary = 'SAML Response received';
      step.detail =
        e.statusCode && e.statusCode >= 400
          ? `HTTP ${e.statusCode} - login failed`
          : `HTTP ${e.statusCode ?? 'unknown'} - login ${e.samlResponse.nameId ? 'succeeded' : 'returned without user identity'}`;
    }

    return step;
  });

  let plainEnglishFlow = '';
  if (initiationModel === 'SP-initiated' && requestEvent) {
    plainEnglishFlow = `1. App started SSO login\n2. SP sent AuthnRequest to KZero\n`;
    if (kzeroRejection) {
      plainEnglishFlow += `3. KZero returned HTTP ${kzeroRejection.statusCode} - request was REJECTED\n4. No SAMLResponse was generated\n5. Login failed before authentication completed`;
    } else if (responseEvent) {
      plainEnglishFlow += `3. KZero processed the request\n4. SAMLResponse returned to SP\n5. Login completed with user identity: ${responseEvent.samlResponse?.nameId ?? 'unknown'}`;
    } else {
      plainEnglishFlow += `3. KZero processing started (capture may have ended early)`;
    }
  } else if (initiationModel === 'IdP-initiated' && responseEvent) {
    plainEnglishFlow = `1. User arrived at application via IdP (no AuthnRequest in trace)\n2. SAMLResponse received from KZero\n3. Login completed with user identity: ${responseEvent.samlResponse?.nameId ?? 'unknown'}`;
  } else {
    plainEnglishFlow = 'Flow timeline cannot be fully determined from available trace data';
  }

  return {
    initiationModel,
    initiationModelExplanation,
    flowOutcome,
    successIndicator,
    failureIndicator,
    timelineSummary,
    plainEnglishFlow
  };
};

const buildComparisonChecklist = (
  events: NormalizedEvent[],
  _findings: Finding[]
): ComparisonChecklist => {
  const samlEvents = events.filter(isSamlEvent);
  const requestEvent = samlEvents.find((e) => e.samlRequest);
  const responseEvent = samlEvents.find((e) => e.samlResponse);
  const req = requestEvent?.samlRequest;
  const resp = responseEvent?.samlResponse;

  const spIdentity: ComparisonChecklistItem[] = [];
  const acsUrl: ComparisonChecklistItem[] = [];
  const destination: ComparisonChecklistItem[] = [];
  const signedRequest: ComparisonChecklistItem[] = [];

  if (req) {
    if (req.issuer) {
      spIdentity.push({
        fieldGroup: 'SP Entity ID / Issuer',
        observedValue: req.issuer,
        commonKZeroFieldNames: ['Client ID', 'SP Entity ID', 'Issuer', 'Entity ID']
      });
    }
    if (req.assertionConsumerServiceURL) {
      acsUrl.push({
        fieldGroup: 'ACS URL / Reply URL',
        observedValue: req.assertionConsumerServiceURL,
        commonKZeroFieldNames: [
          'ACS URL',
          'SAML Reply URL',
          'Assertion Consumer Service URL',
          'Valid Redirect URI'
        ]
      });
    }
    if (req.destination) {
      destination.push({
        fieldGroup: 'Destination endpoint',
        observedValue: req.destination,
        commonKZeroFieldNames: ['SSO URL', 'SAML Endpoint', 'SingleSignOn Service']
      });
    }
    if (req.documentSigned !== undefined) {
      signedRequest.push({
        fieldGroup: 'Want AuthnRequests Signed',
        observedValue: req.documentSigned,
        commonKZeroFieldNames: [
          'Want AuthnRequests Signed',
          'Signed Request',
          'Require signed AuthnRequest'
        ]
      });
    }
  }

  if (resp) {
    if (!spIdentity.length && resp.audience) {
      spIdentity.push({
        fieldGroup: 'SP Entity ID (from audience)',
        observedValue: resp.audience,
        commonKZeroFieldNames: ['Client ID', 'SP Entity ID', 'Issuer']
      });
    }
  }

  return {
    spIdentity,
    acsUrl,
    destination,
    signedRequest
  };
};

const getNotShownInTrace = (_events: NormalizedEvent[], _findings: Finding[]): string[] => {
  const notShown: string[] = [
    'KZero configured expected ACS URL is not shown in this trace',
    'KZero client alias is not shown in this trace',
    'Whether KZero was configured to require signed AuthnRequests is not directly shown here',
    'This trace shows what the SP sent, not necessarily what KZero expected'
  ];
  return notShown;
};

const enrichFinding = (finding: Finding, events: NormalizedEvent[]): EnrichedFinding => {
  const basedOnObservedFields: string[] = [];
  const notShownInTrace: string[] = getNotShownInTrace(events, []);
  const unsupportedAssumptions: string[] = [];

  if (finding.eventId) {
    const event = events.find((e) => e.id === finding.eventId);
    if (event) {
      if (event.protocol === 'SAML') {
        const samlEvent = event as NormalizedSamlEvent;
        if (samlEvent.samlRequest) {
          basedOnObservedFields.push(
            'samlRequest.issuer',
            'samlRequest.assertionConsumerServiceURL',
            'samlRequest.destination'
          );
          unsupportedAssumptions.push('KZero configured expected Issuer/Entity ID is not visible');
        }
        if (samlEvent.samlResponse) {
          basedOnObservedFields.push(
            'samlResponse.statusCode',
            'samlResponse.issuer',
            'samlResponse.nameId'
          );
        }
      }
      if (event.statusCode) {
        basedOnObservedFields.push(`statusCode: ${event.statusCode}`);
      }
    }
  }

  const isAmbiguous = finding.isAmbiguous ?? false;

  let plainEnglishExplanation = finding.explanation;

  const plainEnglishTitle = finding.title;
  const whyThisIsLikely = `Observed in the trace: ${finding.observed}`;
  const whatYouShouldCheck = finding.likelyFix?.action ?? finding.explanation;

  if (finding.ruleId.includes('MISMATCH') || finding.ruleId.includes('REJECTED')) {
    const mismatchNote =
      'Note: This trace shows what the SP sent. You must compare the observed value to the configured value in KZero.';
    notShownInTrace.push('KZero configured expected value is not shown here');
    plainEnglishExplanation += ' ' + mismatchNote;
  }

  if (isAmbiguous) {
    unsupportedAssumptions.push('Full flow may not be captured');
    plainEnglishExplanation += ' Note: This finding is based on incomplete trace data.';
  }

  if (finding.disqualifyingEvidence?.length) {
    basedOnObservedFields.push(...finding.disqualifyingEvidence);
  }

  return {
    id: finding.id,
    ruleId: finding.ruleId,
    severity: finding.severity,
    protocol: finding.protocol,
    likelyOwner: finding.likelyOwner,
    plainEnglishTitle,
    plainEnglishExplanation,
    whyThisIsLikely,
    whatYouShouldCheck,
    evidence: finding.evidence,
    basedOnObservedFields,
    notShownInTrace,
    unsupportedAssumptions,
    confidence: finding.confidence,
    confidenceLevel: finding.confidenceLevel,
    eventId: finding.eventId
  };
};

const buildProtocolGlossary = (): ProtocolGlossary => {
  return {
    whatIsIssuer:
      'Issuer is who the service provider (SP) or identity provider (IdP) says it is. In SAML requests, this is typically the SP Entity ID or Client ID. In responses, this is the IdP entity ID. Must match exactly what is configured in the other party.',
    whatIsAcsUrl:
      'ACS URL (Assertion Consumer Service URL) is where the SAML response should be sent. Also called "Reply URL" or "SAML Reply URL". Must exactly match what is configured in the SP integration in KZero.',
    whatIsDestination:
      'Destination is which IdP endpoint the request is targeting. For SP-initiated flows, this should be the KZero SAML SSO endpoint URL.',
    whatIsProtocolBinding:
      'Protocol binding specifies how SAML messages are transmitted. HTTP-POST embeds the SAML in form data. HTTP-Redirect encodes it in URL parameters. POST is more common and recommended.',
    whatIsSamlRequest:
      'A SAML Request (AuthnRequest) is an XML document from the SP asking the IdP to authenticate the user. It contains who the SP is (Issuer), where to send the response (ACS URL), and authentication requirements.',
    whatIsSamlResponse:
      'A SAML Response contains the result of authentication. On success, it includes the user identity (NameID), attributes, and assertions. On failure, it may contain error status.',
    whatIsSpInitiated:
      'SP-initiated means the login flow starts at the service provider, which sends an AuthnRequest to the IdP. The trace should show the incoming SAMLRequest from the vendor.',
    whatIsIdpInitiated:
      'IdP-initiated means the login flow starts at the identity provider (KZero) or the user goes directly to the app without an SP AuthnRequest. The trace may not show any SAMLRequest.'
  };
};

const buildEducationalExport = (
  events: NormalizedEvent[],
  findings: Finding[]
): EducationalExport => {
  const samlFindings = findings.filter((f) => f.protocol === 'SAML');
  const errorFindings = samlFindings.filter((f) => f.severity === 'error');
  const warningFindings = samlFindings.filter((f) => f.severity === 'warning');

  const narrative = buildFlowNarrative(events, findings);
  const enrichedEvents = events.map(enrichEvent);
  const enrichedFindings = samlFindings.map((f) => enrichFinding(f, events));
  const noise = classifyNoise(events);
  const manualChecks = buildComparisonChecklist(events, findings);
  const notShown = getNotShownInTrace(events, findings);
  const glossary = buildProtocolGlossary();

  const keyFinding = errorFindings[0] ?? warningFindings[0];
  const keyFindingSeverity = keyFinding?.severity;

  const title =
    narrative.flowOutcome === 'success'
      ? 'SAML login appears successful'
      : narrative.flowOutcome === 'failure'
        ? 'SAML login failed'
        : 'SAML flow incomplete - capture may have ended early';

  const educational = {
    title,
    protocol: 'SAML',
    flowOutcome: narrative.flowOutcome,
    initiationModel: narrative.initiationModel,
    keyFinding: keyFinding?.title,
    keyFindingSeverity
  };

  const observedFacts: string[] = [];

  const requestEvent = events.find((e) => isSamlEvent(e) && (e as NormalizedSamlEvent).samlRequest);
  if (requestEvent) {
    const req = (requestEvent as NormalizedSamlEvent).samlRequest!;
    observedFacts.push(`SAML AuthnRequest received from ${requestEvent.host}`);
    if (req.issuer) {
      observedFacts.push(`SP Issuer in request: ${req.issuer}`);
    }
    if (req.assertionConsumerServiceURL) {
      observedFacts.push(`ACS URL in request: ${req.assertionConsumerServiceURL}`);
    }
    if (req.destination) {
      observedFacts.push(`Destination in request: ${req.destination}`);
    }
  }

  const responseEvent = events.find(
    (e) => isSamlEvent(e) && (e as NormalizedSamlEvent).samlResponse
  );
  if (responseEvent) {
    const resp = (responseEvent as NormalizedSamlEvent).samlResponse!;
    observedFacts.push(`SAML Response received with HTTP ${responseEvent.statusCode ?? 'unknown'}`);
    if (resp.nameId) {
      observedFacts.push(`User identity returned: ${resp.nameId}`);
    }
  }

  const kzeroError = events.find(
    (e) => isSamlEvent(e) && e.statusCode && e.statusCode >= 400 && isKzeroHost(e.host)
  );
  if (kzeroError) {
    observedFacts.push(`KZero endpoint returned HTTP ${kzeroError.statusCode}`);
    observedFacts.push('No SAMLResponse was generated after the error');
  }

  if (!requestEvent && !responseEvent) {
    observedFacts.push('No SAML-specific events detected in trace');
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    exportVersion: EXPORT_VERSION,
    generatedAt: new Date().toISOString(),
    educational,
    narrative,
    observedFacts,
    inferredFindings: enrichedFindings,
    manualChecks,
    learningAids: {
      enrichedEvents,
      protocolGlossary: glossary
    },
    noiseEvents: {
      totalCount: noise.totalCount,
      explanation: noise.explanation
    },
    notShownInTrace: notShown
  };
};

export {
  enrichEvent,
  enrichSamlEvent,
  enrichNonSamlEvent,
  enrichFinding,
  buildFlowNarrative,
  buildComparisonChecklist,
  buildProtocolGlossary,
  buildEducationalExport,
  classifyNoise,
  detectInitiationModel,
  SCHEMA_VERSION,
  EXPORT_VERSION
};
