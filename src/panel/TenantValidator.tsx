import { useState, useMemo } from "react";
import type { NormalizedEvent } from "../shared/models";
import { validateTenant, parseMetadata, analyzeOidcError, getAllTenantsInSession, getKzeroHostsInSession, assessTrace } from "../tenantValidator";
import type { TenantScanResult, MetadataParseResult, ErrorAnalysisResult } from "../tenantValidator/types";

interface TenantValidatorProps {
  session: { normalizedEvents: NormalizedEvent[] } | null;
}

type ValidatorTab = "tenant" | "metadata" | "errors";

const MAX_FILE_SIZE = 1024 * 1024;

export const TenantValidator = ({ session }: TenantValidatorProps): JSX.Element => {
  const [activeTab, setActiveTab] = useState<ValidatorTab>("tenant");
  const [tenantInput, setTenantInput] = useState("");
  const [scanResult, setScanResult] = useState<TenantScanResult | null>(null);
  const [_metadataContent, setMetadataContent] = useState<string | null>(null);
  const [metadataResult, setMetadataResult] = useState<MetadataParseResult | null>(null);
  const [errorInput, setErrorInput] = useState("");
  const [errorResult, setErrorResult] = useState<ErrorAnalysisResult | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);

  const events = session?.normalizedEvents ?? [];
  
  const detectedTenants = useMemo(() => {
    if (!events || events.length === 0) return [];
    try {
      return getAllTenantsInSession(events);
    } catch {
      return [];
    }
  }, [events]);
  
  const detectedKzeroHosts = useMemo(() => {
    if (!events || events.length === 0) return [];
    try {
      return getKzeroHostsInSession(events);
    } catch {
      return [];
    }
  }, [events]);

  const assessment = useMemo(
    () => assessTrace({
      events,
      scan: scanResult,
      metadata: metadataResult,
      error: errorResult,
      tenantInput
    }),
    [events, scanResult, metadataResult, errorResult, tenantInput]
  );

  const handleTenantScan = (): void => {
    if (!tenantInput.trim()) return;
    try {
      const result = validateTenant(events, tenantInput);
      setScanResult(result);
    } catch (e) {
      console.error("Tenant scan error:", e);
    }
  };

  const handleFileUpload = (file: File): void => {
    setFileError(null);
    setMetadataResult(null);
    setMetadataContent(null);

    if (file.size > MAX_FILE_SIZE) {
      setFileError(`File too large. Maximum size is 1MB.`);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const content = e.target?.result as string;
        setMetadataContent(content);
        const result = parseMetadata(content);
        setMetadataResult(result);
      } catch (err) {
        console.error("Metadata parse error:", err);
        setFileError("Failed to parse metadata file");
      }
    };
    reader.onerror = () => {
      setFileError("Failed to read file.");
    };
    reader.readAsText(file);
  };

  const handleErrorAnalyze = (): void => {
    if (!errorInput.trim()) return;
    try {
      const result = analyzeOidcError(errorInput);
      setErrorResult(result);
    } catch (e) {
      console.error("Error analyze error:", e);
    }
  };

  const handleFileUploadError = (file: File): void => {
    if (file.size > MAX_FILE_SIZE) {
      setFileError(`File too large. Maximum size is 1MB.`);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setErrorInput((prev) => prev + (prev ? "\n" : "") + content);
    };
    reader.onerror = () => {
      setFileError("Failed to read file.");
    };
    reader.readAsText(file);
  };

  const renderTenantTab = (): JSX.Element => (
    <div className="validator-section">
      <div className="validator-input-row">
        <input
          type="text"
          className="validator-input"
          placeholder="Enter tenant name (e.g., mycompany)"
          value={tenantInput}
          onChange={(e) => setTenantInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleTenantScan()}
        />
        <button className="btn btn-primary" onClick={handleTenantScan} disabled={!tenantInput.trim()}>
          Scan Session
        </button>
      </div>

      {detectedKzeroHosts.length > 0 && (
        <div className="validator-info">
          <strong>KZero Hosts in Session:</strong>
          <ul className="validator-list">
            {detectedKzeroHosts.map((host) => (
              <li key={host} className="mono">{host}</li>
            ))}
          </ul>
        </div>
      )}

      {detectedTenants.length > 0 && (
        <div className="validator-info">
          <strong>Detected Tenants:</strong>
          <div className="validator-tags">
            {detectedTenants.map((tenant) => (
              <button
                key={tenant}
                className="validator-tag"
                onClick={() => {
                  setTenantInput(tenant);
                  const result = validateTenant(events, tenant);
                  setScanResult(result);
                }}
              >
                {tenant}
              </button>
            ))}
          </div>
        </div>
      )}

      {events.length === 0 && (
        <div className="validator-empty">No capture session data. Start a capture to scan events.</div>
      )}

      {scanResult && (
        <div className={`validator-result ${scanResult.hasMismatch ? "has-error" : scanResult.unknownCount > 0 ? "has-warning" : "has-success"}`}>
          <div className="validator-result-head">
            {scanResult.hasMismatch ? (
              <>
                <span className="validator-icon">!</span>
                <strong>{scanResult.mismatches.length} Mismatch{scanResult.mismatches.length !== 1 ? "es" : ""} Found</strong>
              </>
            ) : scanResult.unknownCount > 0 ? (
              <>
                <span className="validator-icon warning">?</span>
                <strong>No matches - {scanResult.unknownCount} event{scanResult.unknownCount !== 1 ? "s" : ""} with unknown tenant</strong>
              </>
            ) : (
              <>
                <span className="validator-icon">OK</span>
                <strong>All events match tenant "{scanResult.inputTenant}"</strong>
              </>
            )}
          </div>
          <div className="validator-result-stats">
            <span>Matches: {scanResult.matchCount}</span>
            <span>Unknown: {scanResult.unknownCount}</span>
            <span>Mismatches: {scanResult.mismatches.length}</span>
          </div>

          {scanResult.unknownCount > 0 && (
            <div className="validator-unknown-warning">
              <p><strong>Warning:</strong> {scanResult.unknownCount} event(s) had no extractable tenant in the URL.</p>
              <p>These events may not be from a KZero realm. Detected tenant: "{detectedTenants[0] || "none"}"</p>
            </div>
          )}

          {scanResult.hasMismatch && (
            <div className="validator-mismatches">
              {scanResult.mismatches.map((mismatch, idx) => (
                <div key={idx} className="validator-mismatch">
                  <div className="validator-mismatch-head">
                    <span className="mono">{mismatch.eventKind}</span>
                    <span className="mono">{mismatch.host}</span>
                  </div>
                  <div className="validator-mismatch-detail">
                    <span className="label">Expected:</span>
                    <span className="mono">{mismatch.inputTenant}</span>
                  </div>
                  <div className="validator-mismatch-detail">
                    <span className="label">Found:</span>
                    <span className="mono">{mismatch.extractedTenant}</span>
                  </div>
                  <div className="validator-mismatch-url mono">{mismatch.url}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );

  const renderMetadataTab = (): JSX.Element => (
    <div className="validator-section">
      <div className="validator-file-area">
        <div className="validator-file-drop">
          <span>Drop metadata file here, or</span>
          <label className="btn btn-ghost">
            Choose File
            <input
              type="file"
              accept=".xml,.json"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFileUpload(file);
              }}
              style={{ display: "none" }}
            />
          </label>
        </div>
        <div className="validator-hint">Accepts: .xml (SAML IdP metadata) or .json (OIDC discovery)</div>
        {fileError && <div className="validator-error">{fileError}</div>}
      </div>

      {metadataResult && metadataResult.type === "error" && (
        <div className="validator-result has-error">
          <div className="validator-result-head">
            <span className="validator-icon">!</span>
            <strong>Parse Error</strong>
          </div>
          <p>{metadataResult.error}</p>
        </div>
      )}

      {metadataResult && metadataResult.type === "oidc" && (
        <div className="validator-result">
          <div className="validator-result-head">
            <span className="validator-icon">OIDC</span>
            <strong>OIDC Discovery Metadata</strong>
          </div>
          <div className="validator-metadata-grid">
            <div className="validator-meta-row">
              <span className="label">Issuer:</span>
              <span className="mono">{metadataResult.data.issuer}</span>
            </div>
            <div className="validator-meta-row">
              <span className="label">Authorization Endpoint:</span>
              <span className="mono">{metadataResult.data.authorizationEndpoint}</span>
            </div>
            <div className="validator-meta-row">
              <span className="label">Token Endpoint:</span>
              <span className="mono">{metadataResult.data.tokenEndpoint}</span>
            </div>
            <div className="validator-meta-row">
              <span className="label">JWKS URI:</span>
              <span className="mono">{metadataResult.data.jwksUri}</span>
            </div>
            {metadataResult.data.userinfoEndpoint && (
              <div className="validator-meta-row">
                <span className="label">Userinfo Endpoint:</span>
                <span className="mono">{metadataResult.data.userinfoEndpoint}</span>
              </div>
            )}
            {metadataResult.data.endSessionEndpoint && (
              <div className="validator-meta-row">
                <span className="label">End Session Endpoint:</span>
                <span className="mono">{metadataResult.data.endSessionEndpoint}</span>
              </div>
            )}
            {metadataResult.data.grantTypesSupported && (
              <div className="validator-meta-row">
                <span className="label">Grant Types:</span>
                <span className="mono">{metadataResult.data.grantTypesSupported.join(", ")}</span>
              </div>
            )}
            {metadataResult.data.scopesSupported && (
              <div className="validator-meta-row">
                <span className="label">Scopes:</span>
                <span className="mono">{metadataResult.data.scopesSupported.join(", ")}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {metadataResult && metadataResult.type === "saml" && (
        <div className="validator-result">
          <div className="validator-result-head">
            <span className="validator-icon">SAML</span>
            <strong>SAML IdP Metadata</strong>
          </div>
          <div className="validator-metadata-grid">
            <div className="validator-meta-row">
              <span className="label">Entity ID:</span>
              <span className="mono">{metadataResult.data.entityId}</span>
            </div>
            {metadataResult.data.singleSignOnServiceUrl && (
              <div className="validator-meta-row">
                <span className="label">SSO URL:</span>
                <span className="mono">{metadataResult.data.singleSignOnServiceUrl}</span>
              </div>
            )}
            {metadataResult.data.singleLogoutServiceUrl && (
              <div className="validator-meta-row">
                <span className="label">SLO URL:</span>
                <span className="mono">{metadataResult.data.singleLogoutServiceUrl}</span>
              </div>
            )}
            <div className="validator-meta-row">
              <span className="label">Name ID Formats:</span>
              <span className="mono">{metadataResult.data.nameIdFormats.join(", ")}</span>
            </div>
            <div className="validator-meta-row">
              <span className="label">Signing Certificates:</span>
              <span className="mono">{metadataResult.data.signingCertificates.length} certificate(s)</span>
            </div>
            <div className="validator-meta-row">
              <span className="label">Encryption Certificates:</span>
              <span className="mono">{metadataResult.data.encryptionCertificates.length} certificate(s)</span>
            </div>
            <div className="validator-meta-row">
              <span className="label">Want Authn Requests Signed:</span>
              <span className="mono">{metadataResult.data.wantAuthnRequestsSigned ? "Yes" : "No"}</span>
            </div>
            <div className="validator-meta-row">
              <span className="label">Want Assertions Signed:</span>
              <span className="mono">{metadataResult.data.wantAssertionsSigned ? "Yes" : "No"}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderErrorsTab = (): JSX.Element => (
    <div className="validator-section">
      <div className="validator-textarea-area">
        <textarea
          className="validator-textarea"
          placeholder="Paste error message here (e.g., 'invalid_grant: Code expired')"
          value={errorInput}
          onChange={(e) => setErrorInput(e.target.value)}
          rows={4}
        />
        <div className="validator-textarea-actions">
          <button className="btn btn-primary" onClick={handleErrorAnalyze} disabled={!errorInput.trim()}>
            Analyze Error
          </button>
          <label className="btn btn-ghost">
            Upload File
            <input
              type="file"
              accept=".txt,.log,.json,.xml"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFileUploadError(file);
              }}
              style={{ display: "none" }}
            />
          </label>
        </div>
      </div>

      {errorResult && (
        <div className={`validator-result ${errorResult.matchedPattern ? "" : "has-warning"}`}>
          <div className="validator-result-head">
            {errorResult.matchedPattern ? (
              <>
                <span className={`validator-icon ${errorResult.matchedPattern.severity === "error" ? "error" : "warning"}`}>
                  {errorResult.matchedPattern.severity === "error" ? "!" : "i"}
                </span>
                <strong>Matched: {errorResult.matchedPattern.cause}</strong>
              </>
            ) : (
              <>
                <span className="validator-icon">?</span>
                <strong>No matching pattern found</strong>
              </>
            )}
          </div>

          {errorResult.matchedPattern && (
            <div className="validator-error-details">
              <div className="validator-error-section">
                <span className="label">Root Cause:</span>
                <p>{errorResult.matchedPattern.cause}</p>
              </div>
              <div className="validator-error-section">
                <span className="label">Suggested Fix:</span>
                <p>{errorResult.matchedPattern.fix}</p>
              </div>
            </div>
          )}

          <div className="validator-suggestions">
            <span className="label">Suggestions:</span>
            <ul>
              {errorResult.suggestions.map((suggestion, idx) => (
                <li key={idx}>{suggestion}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="validator">
      <div className="validator-tabs">
        <button
          className={`validator-tab ${activeTab === "tenant" ? "active" : ""}`}
          onClick={() => setActiveTab("tenant")}
        >
          Tenant Scan
        </button>
        <button
          className={`validator-tab ${activeTab === "metadata" ? "active" : ""}`}
          onClick={() => setActiveTab("metadata")}
        >
          Metadata check
        </button>
        <button
          className={`validator-tab ${activeTab === "errors" ? "active" : ""}`}
          onClick={() => setActiveTab("errors")}
        >
          Analyze errors
        </button>
      </div>

      {assessment.top && (
        <div className="validator-root-cause">
          <div className="validator-root-cause-head">
            <span className={`validator-icon ${assessment.top.confidence === "high" ? "error" : assessment.top.confidence === "medium" ? "warning" : ""}`}>!</span>
            <div>
              <div className="validator-root-cause-kicker">Most likely root cause</div>
              <h3>{assessment.top.title}</h3>
              <p>{assessment.top.summary}</p>
            </div>
          </div>

          <div className="validator-root-cause-grid">
            <div className="validator-root-cause-section">
              <h4>Why we think this</h4>
              <ul>
                {assessment.top.why.map((line, idx) => (
                  <li key={`why-${idx}`}>{line}</li>
                ))}
              </ul>
            </div>
            <div className="validator-root-cause-section">
              <h4>How to fix it</h4>
              <ul>
                {assessment.top.howToFix.map((line, idx) => (
                  <li key={`fix-${idx}`}>{line}</li>
                ))}
              </ul>
            </div>
          </div>

          {assessment.top.evidence.length > 0 && (
            <div className="validator-root-cause-evidence">
              <h4>Evidence captured</h4>
              <ul>
                {assessment.top.evidence.slice(0, 4).map((line, idx) => (
                  <li key={`ev-${idx}`} className="mono">{line}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {activeTab === "tenant" && renderTenantTab()}
      {activeTab === "metadata" && renderMetadataTab()}
      {activeTab === "errors" && renderErrorsTab()}
    </div>
  );
};

export default TenantValidator;
