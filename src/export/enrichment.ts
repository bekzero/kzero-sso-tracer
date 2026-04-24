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
  FlowOutcome,
  AboutThisFile,
  QuickVerdict,
  RecommendedPath,
  WhatHappened,
  WhatHappenedStep,
  VisualCompare,
  ComparisonRow,
  FirstAction,
  SupportSummary
} from '../shared/models';
import { isNoiseEvent } from './filtering';

const EXPORT_VERSION = '1.1.0';
const SCHEMA_VERSION: ExportSchemaVersion = '2.1.0';

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

const KZERO_ADMIN_PATHS = {
  clientId: {
    path: 'KZero Admin → Applications → [your app] → General tab → Details section → Client ID',
    shortPath: 'KZero Admin → Applications → [app] → Client ID',
    whatToFind: "Look for 'Client ID', 'Entity ID', or 'SP Entity ID'"
  },
  acsUrl: {
    path: 'KZero Admin → Applications → [your app] → Settings tab → SAML Settings → Assertion Consumer Service URL',
    shortPath: 'KZero Admin → Applications → [app] → SAML Settings → ACS URL',
    whatToFind: "Look for 'ACS URL', 'Assertion Consumer Service URL', or 'SAML Reply URL'"
  },
  samlEndpoint: {
    path: 'KZero Admin → Applications → [your app] → Settings tab → SAML Settings → SAML endpoints',
    shortPath: 'KZero Admin → Applications → [app] → SAML Settings → Endpoints',
    whatToFind: "Look for 'SAML Endpoint', 'SSO URL', or 'SingleSignOn Service URL'"
  },
  wantSignedRequests: {
    path: 'KZero Admin → Applications → [your app] → Settings tab → SAML Settings → Want AuthnRequests Signed',
    shortPath: 'KZero Admin → Applications → [app] → Want AuthnRequests Signed',
    whatToFind: "Look for 'Want AuthnRequests Signed' or 'Signed Request' toggle"
  }
};

const buildAboutThisFile = (): AboutThisFile => ({
  whatIsThis:
    'A record of a login attempt showing what happened step by step when a user tried to sign in through KZero.',
  whatThisShows:
    'The requests exchanged between your application and KZero, plus any problems that were detected along the way.',
  howToUse:
    "Start with 'quickVerdict' below to see the outcome. Then follow 'recommendedPath' based on whether you need to fix something or learn what happened.",
  estimatedReadTime: '2 minutes'
});

const buildQuickVerdict = (
  narrative: FlowNarrative,
  keyFinding: EnrichedFinding | undefined
): QuickVerdict => {
  const status = narrative.flowOutcome;

  let severityLabel: string;
  let oneSentenceSummary: string;

  if (status === 'success') {
    severityLabel = '✅ SUCCESS';
    oneSentenceSummary = keyFinding
      ? 'Login succeeded. ' + keyFinding.plainEnglishExplanation
      : 'Login appears to have succeeded.';
  } else if (status === 'failure') {
    severityLabel = '🔴 LOGIN FAILED';
    oneSentenceSummary = keyFinding
      ? keyFinding.plainEnglishExplanation
      : 'Login failed - check the findings below for details.';
  } else {
    severityLabel = '⚠️ INCOMPLETE';
    oneSentenceSummary = 'The trace may not have captured the full login flow.';
  }

  return {
    overallStatus: status,
    severityLabel,
    oneSentenceSummary,
    mostCriticalIssue: status === 'failure' ? keyFinding?.plainEnglishTitle : undefined,
    confidence: keyFinding?.confidenceLevel ?? 'medium'
  };
};

const buildRecommendedPath = (narrative: FlowNarrative, findingsCount: number): RecommendedPath => {
  const isFailure = narrative.flowOutcome === 'failure';
  const hasFindings = findingsCount > 0;

  const forNewUsers = hasFindings
    ? [
        "1. Read 'quickVerdict' to see if login worked",
        "2. Read 'whatHappened' to see what steps happened",
        "3. Read 'whatWentWrong[0]' to understand the main issue",
        "4. Check 'whatToCompare' to see what values need verification"
      ]
    : [
        "1. Read 'quickVerdict' to see if login worked",
        "2. Read 'whatHappened' to see what steps happened",
        "3. If login failed, check 'firstAction' for next steps"
      ];

  const forFixers = isFailure
    ? [
        "1. Read 'whatWentWrong[0]' for the main issue",
        "2. Check 'firstAction' for what to do next",
        "3. Verify values in 'whatToCompare' against KZero Admin",
        '4. Retest the login flow'
      ]
    : [
        "1. Review 'whatHappened' to confirm flow is working",
        "2. Check 'whatToCompare' if configuration changes are needed",
        '3. Retest after making changes'
      ];

  const forLearners = [
    "1. Read 'whatHappened.plainEnglishSummary' for the big picture",
    "2. Read 'whatHappened.stepByStep' for detailed flow",
    "3. Browse 'learningAids.protocolGlossary' for term definitions",
    "4. Look at 'learningAids.enrichedEvents' for technical details"
  ];

  return { forNewUsers, forFixers, forLearners };
};

const buildWhatHappened = (events: NormalizedEvent[], narrative: FlowNarrative): WhatHappened => {
  const samlEvents = events.filter(isSamlEvent).sort((a, b) => a.timestamp - b.timestamp);

  const initiationModelPlain =
    narrative.initiationModel === 'SP-initiated'
      ? 'App started the login (SP-initiated)'
      : narrative.initiationModel === 'IdP-initiated'
        ? 'KZero started the login (IdP-initiated)'
        : 'Unknown how login started';

  let plainEnglishSummary: string;
  if (narrative.flowOutcome === 'success') {
    plainEnglishSummary =
      narrative.initiationModel === 'SP-initiated'
        ? 'The app asked KZero to log you in. KZero confirmed your identity and let you in.'
        : 'You were logged in through KZero. The app received confirmation that you are who you say you are.';
  } else if (narrative.flowOutcome === 'failure') {
    plainEnglishSummary =
      narrative.initiationModel === 'SP-initiated'
        ? 'The app asked KZero to log you in, but KZero said no. Something in the configuration does not match.'
        : 'KZero attempted to log you in, but something went wrong. The login was not completed.';
  } else {
    plainEnglishSummary = 'The trace may not have captured the complete login flow.';
  }

  const stepByStep: WhatHappenedStep[] = samlEvents.map((e, idx) => {
    let plainLabel: string;
    let plainDetail: string;

    if (e.samlRequest) {
      const req = e.samlRequest!;
      plainLabel = 'App asked KZero to log you in';
      plainDetail = req.issuer
        ? `App identified as: "${req.issuer}"`
        : 'App sent a login request to KZero';
      if (req.assertionConsumerServiceURL) {
        plainDetail += `, requesting reply to: "${req.assertionConsumerServiceURL}"`;
      }
    } else if (e.samlResponse) {
      const resp = e.samlResponse!;
      if (e.statusCode && e.statusCode >= 400) {
        plainLabel = 'KZero rejected the login request';
        plainDetail = `KZero returned HTTP ${e.statusCode}`;
      } else {
        plainLabel = 'KZero responded with login result';
        plainDetail = resp.nameId
          ? `User logged in as: ${resp.nameId}`
          : `KZero returned HTTP ${e.statusCode ?? 'unknown'}`;
      }
    } else {
      plainLabel = 'Request captured';
      plainDetail = `To ${e.host}`;
    }

    return {
      stepNumber: idx + 1,
      timestamp: e.timestamp,
      plainLabel,
      plainDetail,
      isAuthRelevant: true
    };
  });

  return {
    initiationModel: narrative.initiationModel,
    initiationModelPlain,
    plainEnglishSummary,
    stepByStep
  };
};

const buildVisualCompare = (events: NormalizedEvent[]): VisualCompare => {
  const requestEvent = events.find((e) => isSamlEvent(e) && (e as NormalizedSamlEvent).samlRequest);
  const req = requestEvent ? (requestEvent as NormalizedSamlEvent).samlRequest : undefined;

  const comparisonTable: ComparisonRow[] = [];

  if (req?.issuer) {
    comparisonTable.push({
      fieldName: 'issuer',
      plainFieldName: 'Entity ID (who the app says it is)',
      kzeroExpects: null,
      kzeroExpectsNote: `Check ${KZERO_ADMIN_PATHS.clientId.shortPath}`,
      spSent: req.issuer,
      matchResult: 'unknown',
      matchReason: "Can't verify match - KZero config not shown in trace. Must check KZero Admin."
    });
  }

  if (req?.assertionConsumerServiceURL) {
    comparisonTable.push({
      fieldName: 'assertionConsumerServiceURL',
      plainFieldName: 'Reply URL (where login replies go)',
      kzeroExpects: null,
      kzeroExpectsNote: `Check ${KZERO_ADMIN_PATHS.acsUrl.shortPath}`,
      spSent: req.assertionConsumerServiceURL,
      matchResult: 'unknown',
      matchReason: "Can't verify match - KZero config not shown in trace. Must check KZero Admin."
    });
  }

  if (req?.destination) {
    const isKzeroEndpoint = isKzeroHost(new URL(req.destination).host);
    comparisonTable.push({
      fieldName: 'destination',
      plainFieldName: 'Login endpoint (where request was sent)',
      kzeroExpects: isKzeroEndpoint ? '(configured)' : null,
      kzeroExpectsNote: isKzeroEndpoint
        ? 'Verified KZero endpoint'
        : 'Verify this matches your realm',
      spSent: req.destination,
      matchResult: isKzeroEndpoint ? 'match' : 'unknown',
      matchReason: isKzeroEndpoint
        ? 'Destination targets a known KZero endpoint'
        : 'Verify this matches your realm endpoint'
    });
  }

  if (req?.documentSigned !== undefined) {
    comparisonTable.push({
      fieldName: 'documentSigned',
      plainFieldName: 'Request signed (digital signature)',
      kzeroExpects: null,
      kzeroExpectsNote: `Check ${KZERO_ADMIN_PATHS.wantSignedRequests.shortPath}`,
      spSent: req.documentSigned ? 'Yes - signed' : 'No - not signed',
      matchResult: 'unknown',
      matchReason: "Can't verify if KZero requires signed requests - check KZero Admin"
    });
  }

  const unknownCount = comparisonTable.filter((r) => r.matchResult === 'unknown').length;
  const matchSummary =
    unknownCount === 0
      ? 'All visible values match'
      : `${unknownCount} value(s) need verification against KZero Admin`;

  return {
    quickSummary:
      unknownCount > 0
        ? 'One or more values sent by the app need verification against KZero Admin.'
        : 'All visible values appear correct.',
    comparisonTable,
    matchSummary
  };
};

const buildFirstAction = (
  keyFinding: EnrichedFinding | undefined,
  manualChecks: ComparisonChecklist
): FirstAction => {
  const findingTitle = keyFinding?.plainEnglishTitle ?? 'Configuration mismatch detected';

  if (manualChecks.spIdentity.length > 0) {
    const issuer = manualChecks.spIdentity[0].observedValue;
    return {
      stepNumber: 1 as const,
      findingThisRelatesTo: findingTitle,
      kzeroAdminPath: KZERO_ADMIN_PATHS.clientId.path,
      kzeroAdminPathDetailed: KZERO_ADMIN_PATHS.clientId.path,
      whatToFind: KZERO_ADMIN_PATHS.clientId.whatToFind,
      whatToCompare: `Compare to: ${issuer ?? '[value shown in whatToCompare]'}`,
      whyThisMatters:
        "If the app's Entity ID does not match what KZero expects, KZero will reject the login request before even checking the user's password."
    };
  }

  if (manualChecks.acsUrl.length > 0) {
    const acsUrl = manualChecks.acsUrl[0].observedValue;
    return {
      stepNumber: 1 as const,
      findingThisRelatesTo: findingTitle,
      kzeroAdminPath: KZERO_ADMIN_PATHS.acsUrl.path,
      kzeroAdminPathDetailed: KZERO_ADMIN_PATHS.acsUrl.path,
      whatToFind: KZERO_ADMIN_PATHS.acsUrl.whatToFind,
      whatToCompare: `Compare to: ${acsUrl ?? '[value shown in whatToCompare]'}`,
      whyThisMatters:
        'If the Reply URL does not match, KZero will not be able to send the login confirmation to the correct place.'
    };
  }

  return {
    stepNumber: 1 as const,
    findingThisRelatesTo: findingTitle,
    kzeroAdminPath: KZERO_ADMIN_PATHS.clientId.path,
    kzeroAdminPathDetailed: KZERO_ADMIN_PATHS.clientId.path,
    whatToFind: KZERO_ADMIN_PATHS.clientId.whatToFind,
    whatToCompare: 'Check the values in whatToCompare section',
    whyThisMatters:
      'A configuration mismatch between the app and KZero is preventing login from working.'
  };
};

const buildSupportSummary = (
  events: NormalizedEvent[],
  findings: EnrichedFinding[],
  quickVerdict: QuickVerdict,
  narrative: FlowNarrative
): SupportSummary => {
  const requestEvent = events.find((e) => isSamlEvent(e) && (e as NormalizedSamlEvent).samlRequest);
  const responseEvent = events.find(
    (e) => isSamlEvent(e) && (e as NormalizedSamlEvent).samlResponse
  );
  const req = requestEvent ? (requestEvent as NormalizedSamlEvent).samlRequest : undefined;

  let appInvolved: string | undefined;
  let realmInvolved: string | undefined;

  if (requestEvent) {
    appInvolved = requestEvent.host;
  }
  if (req?.destination) {
    try {
      const url = new URL(req.destination);
      realmInvolved = url.host + url.pathname;
    } catch {
      realmInvolved = req.destination;
    }
  }

  const valuesToShare: Array<{ name: string; value: string }> = [];
  if (req?.issuer) {
    valuesToShare.push({ name: 'Issuer observed in request', value: req.issuer });
  }
  if (req?.assertionConsumerServiceURL) {
    valuesToShare.push({ name: 'ACS URL in request', value: req.assertionConsumerServiceURL });
  }
  if (req?.destination) {
    valuesToShare.push({ name: 'Destination', value: req.destination });
  }
  if (responseEvent?.statusCode) {
    valuesToShare.push({ name: 'HTTP response', value: String(responseEvent.statusCode) });
  }

  const timestamp = new Date().toLocaleString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit'
  });

  const primaryIssue = findings[0]
    ? findings[0].plainEnglishTitle
    : quickVerdict.oneSentenceSummary;

  let copyPasteSummary = `SAML login ${quickVerdict.overallStatus === 'success' ? 'succeeded' : 'failed'} on ${timestamp}.\n\n`;

  if (appInvolved) {
    copyPasteSummary += `App: ${appInvolved}\n`;
  }
  if (realmInvolved) {
    copyPasteSummary += `Realm: ${realmInvolved}\n`;
  }
  copyPasteSummary += `Status: ${quickVerdict.severityLabel}\n\n`;

  if (quickVerdict.overallStatus === 'failure') {
    copyPasteSummary += 'What happened:\n';
    copyPasteSummary += `${narrative.plainEnglishFlow.split('\n').slice(0, 3).join('\n')}\n\n`;
    copyPasteSummary += 'Primary issue:\n';
    copyPasteSummary += `${primaryIssue}\n\n`;
    copyPasteSummary += 'What to check:\n';
    copyPasteSummary += `Verify the values in the trace against KZero Admin settings.\n`;
  }

  return {
    timestamp: new Date().toISOString(),
    appInvolved,
    realmInvolved,
    status: quickVerdict.severityLabel,
    primaryIssue,
    valuesToShare,
    copyPasteSummary
  };
};

const buildEducationalExport = (
  events: NormalizedEvent[],
  findings: Finding[]
): EducationalExport => {
  const samlFindings = findings.filter((f) => f.protocol === 'SAML');

  const narrative = buildFlowNarrative(events, findings);
  const enrichedEvents = events.map(enrichEvent);
  const enrichedFindings = samlFindings.map((f) => enrichFinding(f, events));
  const noise = classifyNoise(events);
  const manualChecks = buildComparisonChecklist(events, findings);
  const notShown = getNotShownInTrace(events, findings);
  const glossary = buildProtocolGlossary();

  const sortedFindings = [...enrichedFindings].sort((a, b) => {
    const severityOrder = { error: 0, warning: 1, info: 2 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  const keyFinding = sortedFindings[0];

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
    keyFinding: keyFinding?.plainEnglishTitle,
    keyFindingSeverity: keyFinding?.severity
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

  const aboutThisFile = buildAboutThisFile();
  const quickVerdict = buildQuickVerdict(narrative, keyFinding);
  const recommendedPath = buildRecommendedPath(narrative, sortedFindings.length);
  const whatHappened = buildWhatHappened(events, narrative);
  const visualCompare = buildVisualCompare(events);
  const firstAction = buildFirstAction(keyFinding, manualChecks);
  const supportSummary = buildSupportSummary(events, sortedFindings, quickVerdict, narrative);

  return {
    schemaVersion: SCHEMA_VERSION,
    exportVersion: EXPORT_VERSION,
    generatedAt: new Date().toISOString(),
    aboutThisFile,
    quickVerdict,
    recommendedPath,
    whatHappened,
    whatWentWrong: sortedFindings,
    whatToCompare: {
      summary: visualCompare.quickSummary,
      visual: visualCompare,
      detailed: manualChecks
    },
    firstAction,
    educational,
    narrative,
    observedFacts,
    learningAids: {
      enrichedEvents,
      protocolGlossary: glossary
    },
    noiseEvents: {
      totalCount: noise.totalCount,
      explanation: noise.explanation
    },
    whatThisFileDoesNotContain: notShown,
    supportSummary
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
