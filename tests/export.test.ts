import { describe, expect, it } from 'vitest';
import { buildSanitizedExport, buildRawExport, buildSummaryExport } from '../src/export';
import type {
  CaptureSession,
  NormalizedSamlEvent,
  NormalizedOidcEvent
} from '../src/shared/models';

const createMockSession = (
  events: CaptureSession['normalizedEvents'],
  findings: CaptureSession['findings'] = []
): CaptureSession => ({
  tabId: 1,
  active: false,
  startedAt: 1000000000000,
  stoppedAt: 1000000001000,
  rawEvents: [],
  normalizedEvents: events,
  findings
});

const createSamlResponseEvent = (
  overrides: Partial<NormalizedSamlEvent> = {}
): NormalizedSamlEvent =>
  ({
    id: 'evt-1',
    tabId: 1,
    timestamp: 1000000000000,
    protocol: 'SAML',
    kind: 'saml-response',
    url: 'https://idp.example.com/saml',
    host: 'idp.example.com',
    method: 'POST',
    statusCode: 200,
    rawRef: 'raw-1',
    artifacts: {
      relayState: 'https://app.example.com/',
      binding: 'post'
    },
    binding: 'post',
    relayState: 'https://app.example.com/',
    samlResponse: {
      encoded: 'base64...',
      issuer: 'https://idp.example.com',
      destination: 'https://app.example.com/acs',
      audience: 'https://app.example.com',
      recipient: 'https://app.example.com/acs',
      nameId: 'user@example.com',
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:email'
    },
    ...overrides
  }) as NormalizedSamlEvent;

describe('buildSummaryExport', () => {
  it('contains auth host summary', () => {
    const session = createMockSession([createSamlResponseEvent()]);
    const result = buildSummaryExport(session);
    expect(result).not.toBeNull();
    expect(result?.authHosts.idpHost).toBe('idp.example.com');
    expect(result?.authHosts.spAppHost).toBe('app.example.com');
    expect(result?.authHosts.protocol).toBe('SAML');
  });

  it('filters to only auth events in summary mode', () => {
    const authEvent = createSamlResponseEvent();
    const networkEvent: NormalizedSamlEvent = {
      ...authEvent,
      id: 'evt-2',
      timestamp: 1000000000500,
      url: 'https://app.example.com/api/users',
      host: 'app.example.com',
      kind: 'network'
    } as any;
    const session = createMockSession([authEvent, networkEvent]);
    const result = buildSummaryExport(session);
    expect(result).not.toBeNull();
    expect(result?.summary.eventCount).toBe(2);
  });
});

describe('buildSanitizedExport', () => {
  it('preserves issuer/audience/destination', () => {
    const session = createMockSession([createSamlResponseEvent()]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const samlEvent = result?.events[0] as NormalizedSamlEvent;
    expect(samlEvent.samlResponse?.issuer).toBe('https://idp.example.com');
    expect(samlEvent.samlResponse?.destination).toBe('https://app.example.com/acs');
    expect(samlEvent.samlResponse?.audience).toBe('https://app.example.com');
  });

  it('redacts email-like NameID', () => {
    const session = createMockSession([createSamlResponseEvent()]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const samlEvent = result?.events[0] as NormalizedSamlEvent;
    expect(samlEvent.samlResponse?.nameId).toBe('us...om');
  });

  it('includes aggregated redaction metadata', () => {
    const session = createMockSession([
      createSamlResponseEvent({
        artifacts: {
          ...createSamlResponseEvent().artifacts,
          client_secret: 'mysecret'
        }
      } as any)
    ]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    expect(result?.metadata.redactionsApplied.length).toBeGreaterThan(0);
    expect(result?.metadata.mode).toBe('sanitized');
  });

  it('filters post-login noise with grace window', () => {
    const authEvent = createSamlResponseEvent();
    const landingEvent: NormalizedSamlEvent = {
      ...authEvent,
      id: 'evt-2',
      timestamp: 1000000000200,
      url: 'https://app.example.com/dashboard',
      host: 'app.example.com',
      kind: 'network'
    } as any;
    const noiseEvent: NormalizedSamlEvent = {
      ...authEvent,
      id: 'evt-3',
      timestamp: 1000000000700,
      url: 'https://www.google-analytics.com/collect',
      host: 'www.google-analytics.com',
      kind: 'network'
    } as any;
    const session = createMockSession([authEvent, landingEvent, noiseEvent]);
    const result = buildSanitizedExport(session, {
      mode: 'sanitized',
      includePostLoginActivity: false
    });
    expect(result).not.toBeNull();
    expect(result?.metadata.authBoundaryDetected).toBe(true);
    expect(result?.metadata.includePostLoginActivity).toBe(false);
  });

  it('sanitized export excludes sensitive fields from findings but preserves likelyFix', () => {
    const session = createMockSession(
      [],
      [
        {
          id: 'finding-1',
          ruleId: 'SAML_NAMEID_MISMATCH',
          severity: 'error',
          protocol: 'SAML',
          likelyOwner: 'KZero',
          title: 'NameID mismatch',
          explanation: 'NameID formats do not align',
          observed: 'user@example.com -> urn:oasis:names:tc:SAML:1.1:nameid-format:email',
          expected: 'Email format with email value',
          evidence: ['https://idp.example.com/saml?SAMLRequest=abc123'],
          confidence: 0.9,
          confidenceLevel: 'high' as const,
          likelyFix: {
            kzeroFields: ['NameIDPolicy Format'],
            vendorFields: ['NameIDFormat'],
            action: 'Align NameID Policy Format with actual principal value mapping'
          }
        }
      ]
    );
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    expect(result?.findings).toHaveLength(1);
    expect(result?.findings[0]).not.toHaveProperty('observed');
    expect(result?.findings[0]).not.toHaveProperty('expected');
    expect(result?.findings[0]).not.toHaveProperty('evidence');
    expect(result?.findings[0].title).toBe('NameID mismatch');
    expect(result?.findings[0].likelyFix).toBeDefined();
    expect(result?.findings[0].likelyFix?.kzeroFields).toEqual(['NameIDPolicy Format']);
    expect(result?.findings[0].likelyFix?.vendorFields).toEqual(['NameIDFormat']);
  });

  it('sanitized export title and explanation are derived from rules, not from user data', () => {
    const session = createMockSession(
      [],
      [
        {
          id: 'finding-2',
          ruleId: 'OIDC_STATE_MISMATCH',
          severity: 'error',
          protocol: 'OIDC',
          likelyOwner: 'browser',
          title: 'State missing or mismatch',
          explanation:
            'State protects against CSRF and must match between authorize request and callback.',
          observed: 'authorize=ab...23, callback=xy...89',
          expected: 'Matching non-empty state values',
          evidence: [],
          confidence: 0.91,
          confidenceLevel: 'high' as const,
          likelyFix: { kzeroFields: [], vendorFields: [], action: 'Check state preservation' }
        }
      ]
    );
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    expect(result?.findings[0].title).toBe('State missing or mismatch');
    expect(result?.findings[0].explanation).toBe(
      'State protects against CSRF and must match between authorize request and callback.'
    );
    const findingAny = result?.findings[0] as any;
    expect(findingAny.observed).toBeUndefined();
    expect(findingAny.expected).toBeUndefined();
  });

  it('sanitized export does not leak sensitive values from observed/expected into any finding fields', () => {
    const session = createMockSession(
      [],
      [
        {
          id: 'finding-3',
          ruleId: 'SAML_NAMEID_FORMAT',
          severity: 'warning',
          protocol: 'SAML',
          likelyOwner: 'user data',
          title: 'Likely wrong NameID format',
          explanation: 'NameID format indicates email but value is not email-like.',
          observed: 'user@company.com -> urn:oasis:names:tc:SAML:1.1:nameid-format:email',
          expected: 'Email NameID format with email value',
          evidence: ['https://idp.example.com/saml?SAMLRequest=secret123'],
          confidence: 0.87,
          confidenceLevel: 'medium' as const,
          likelyFix: {
            kzeroFields: ['NameIDPolicy'],
            vendorFields: ['NameIDFormat'],
            action: 'Align policies'
          }
        }
      ]
    );
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    expect(result?.findings[0].title).toBe('Likely wrong NameID format');
    expect(result?.findings[0].explanation).toBe(
      'NameID format indicates email but value is not email-like.'
    );
    const findingAny = result?.findings[0] as any;
    expect(findingAny.observed).toBeUndefined();
    expect(findingAny.expected).toBeUndefined();
    expect(findingAny.evidence).toBeUndefined();
    expect(result?.findings[0].likelyFix).toBeDefined();
  });

  it('sanitized export does not leak sensitive values from observed/expected into any finding fields', () => {
    const session = createMockSession(
      [],
      [
        {
          id: 'finding-3',
          ruleId: 'SAML_NAMEID_FORMAT',
          severity: 'warning',
          protocol: 'SAML',
          likelyOwner: 'user data',
          title: 'Likely wrong NameID format',
          explanation: 'NameID format indicates email but value is not email-like.',
          observed: 'user@company.com -> urn:oasis:names:tc:SAML:1.1:nameid-format:email',
          expected: 'Email NameID format with email value',
          evidence: ['https://idp.example.com/saml?SAMLRequest=secret123'],
          confidence: 0.87,
          confidenceLevel: 'medium' as const,
          likelyFix: {
            kzeroFields: ['NameIDPolicy'],
            vendorFields: ['NameIDFormat'],
            action: 'Align policies'
          }
        }
      ]
    );
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    expect(result?.findings[0].title).toBe('Likely wrong NameID format');
    expect(result?.findings[0].explanation).toBe(
      'NameID format indicates email but value is not email-like.'
    );
    const findingAny = result?.findings[0] as any;
    expect(findingAny.observed).toBeUndefined();
    expect(findingAny.expected).toBeUndefined();
    expect(findingAny.evidence).toBeUndefined();
    expect(result?.findings[0].likelyFix).toBeDefined();
  });
});

describe('buildRawExport', () => {
  it('exports normalized events (processed artifacts)', () => {
    const session = createMockSession([createSamlResponseEvent()]);
    const result = buildRawExport(session);
    expect(result).not.toBeNull();
    expect(result?.events.length).toBe(1);
    expect(result?.events[0]).toEqual(
      expect.objectContaining({
        protocol: 'SAML',
        kind: 'saml-response'
      })
    );
  });

  it('does not include rawEvents in export payload', () => {
    const session = createMockSession([createSamlResponseEvent()]);
    session.rawEvents = [
      {
        id: 'raw-1',
        tabId: 1,
        timestamp: 1000,
        url: 'http://test.com',
        source: 'devtools-network'
      }
    ] as unknown as import('../src/shared/models').RawCaptureEvent[];

    const result = buildRawExport(session);
    expect(result).not.toBeNull();
    expect(result?.events).toBeDefined();
    expect(result?.events.length).toBe(1);
    expect((result as any).rawEvents).toBeUndefined();
    expect(result?.events[0].id).toBe('evt-1');
  });

  it('includes metadata.mode = raw but no redaction metadata', () => {
    const session = createMockSession([createSamlResponseEvent()]);
    const result = buildRawExport(session);
    expect(result).not.toBeNull();
    expect(result?.metadata.mode).toBe('raw');
    expect(result?.metadata.redactionsApplied).toEqual([]);
    expect(result?.metadata.includePostLoginActivity).toBe(true);
  });
});

const createOidcAuthorizeEvent = (
  overrides: Partial<NormalizedOidcEvent> = {}
): NormalizedOidcEvent =>
  ({
    id: 'evt-oidc-1',
    tabId: 1,
    timestamp: 1000000000000,
    protocol: 'OIDC',
    kind: 'authorize',
    url: 'https://idp.example.com/oauth2/authorize?client_id=app&redirect_uri=https://app.example.com/callback&response_type=code&state=abc123&nonce=xyz789&scope=openid%20profile%20email',
    host: 'idp.example.com',
    method: 'GET',
    statusCode: 200,
    rawRef: 'raw-oidc-1',
    artifacts: {},
    clientId: 'app',
    redirectUri: 'https://app.example.com/callback',
    responseType: 'code',
    scope: 'openid profile email',
    state: 'abc123',
    nonce: 'xyz789',
    code: 'authz-code-123',
    ...overrides
  }) as NormalizedOidcEvent;

const createOidcTokenEvent = (overrides: Partial<NormalizedOidcEvent> = {}): NormalizedOidcEvent =>
  ({
    id: 'evt-oidc-2',
    tabId: 1,
    timestamp: 1000000000500,
    protocol: 'OIDC',
    kind: 'token',
    url: 'https://idp.example.com/oauth2/token',
    host: 'idp.example.com',
    method: 'POST',
    statusCode: 200,
    rawRef: 'raw-oidc-2',
    artifacts: {},
    issuer: 'https://idp.example.com',
    clientId: 'app',
    accessTokenJwt: { header: {}, payload: { sub: 'user123' } },
    idToken: { header: {}, payload: { sub: 'user123', email: 'test@example.com' } },
    codeVerifier: 'pkce-verifier-secret',
    sessionState: 'opaque-session-id',
    ...overrides
  }) as NormalizedOidcEvent;

describe('OIDC sanitized export', () => {
  it('hashes top-level OIDC state', () => {
    const session = createMockSession([createOidcAuthorizeEvent()]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const event = result?.events[0] as NormalizedOidcEvent;
    expect(event.state).toMatch(/^\[hash:[a-f0-9]+\]$/);
  });

  it('hashes top-level OIDC nonce', () => {
    const session = createMockSession([createOidcAuthorizeEvent()]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const event = result?.events[0] as NormalizedOidcEvent;
    expect(event.nonce).toMatch(/^\[hash:[a-f0-9]+\]$/);
  });

  it('hashes top-level OIDC code', () => {
    const session = createMockSession([createOidcAuthorizeEvent()]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const event = result?.events[0] as NormalizedOidcEvent;
    expect(event.code).toMatch(/^\[hash:[a-f0-9]+\]$/);
  });

  it('removes top-level OIDC idToken completely', () => {
    const session = createMockSession([createOidcTokenEvent()]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const event = result?.events[0] as NormalizedOidcEvent;
    expect(event.idToken).toBeUndefined();
  });

  it('removes top-level OIDC accessTokenJwt completely', () => {
    const session = createMockSession([createOidcTokenEvent()]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const event = result?.events[0] as NormalizedOidcEvent;
    expect(event.accessTokenJwt).toBeUndefined();
  });

  it('removes top-level OIDC codeVerifier completely', () => {
    const session = createMockSession([createOidcTokenEvent()]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const event = result?.events[0] as NormalizedOidcEvent;
    expect(event.codeVerifier).toBeUndefined();
  });

  it('preserves config redirectUri in sanitized export', () => {
    const session = createMockSession([createOidcAuthorizeEvent()]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const event = result?.events[0] as NormalizedOidcEvent;
    expect(event.redirectUri).toBe('https://app.example.com/callback');
  });

  it('sanitizes URL query params - removes access_token from URL', () => {
    const event = createOidcAuthorizeEvent({
      url: 'https://idp.example.com/oauth2/authorize?client_id=app&access_token=secret-token&state=abc'
    });
    const session = createMockSession([event]);
    const result = buildSanitizedExport(session);
    expect(result).not.toBeNull();
    const resultEvent = result?.events[0] as NormalizedOidcEvent;
    expect(resultEvent.url).not.toContain('access_token=secret-token');
    expect(resultEvent.url).toContain('state=');
  });

  it('raw mode preserves all top-level OIDC fields', () => {
    const event = createOidcTokenEvent({
      state: 'abc123',
      nonce: 'xyz789',
      code: 'authz-code-123'
    });
    const session = createMockSession([event]);
    const result = buildRawExport(session);
    expect(result).not.toBeNull();
    const eventResult = result?.events[0] as NormalizedOidcEvent;
    expect(eventResult.state).toBe('abc123');
    expect(eventResult.nonce).toBe('xyz789');
    expect(eventResult.code).toBe('authz-code-123');
    expect(eventResult.idToken).toBeDefined();
    expect(eventResult.accessTokenJwt).toBeDefined();
    expect(eventResult.codeVerifier).toBeDefined();
  });
});
