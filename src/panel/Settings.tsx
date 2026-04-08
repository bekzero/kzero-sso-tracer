import { useState, useEffect } from "react";
import type { Settings, CaptureScope, AISettings } from "../shared/settings";
import { getSettings, saveSettings, resetSettings, isValidHostname, normalizeHostname } from "../shared/settings";
import { getDiscoveredAuthHosts } from "../capture/sessionStore";
import { isAIDisabledByPolicy, setEnterpriseAIPolicy } from "../help/ai/policy";

interface SettingsProps {
  onClose: () => void;
  onSave: (settings: Settings) => void;
}

const SettingsPanel = ({ onClose, onSave }: SettingsProps): JSX.Element => {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saved, setSaved] = useState(false);
  const [newHost, setNewHost] = useState("");
  const [hostError, setHostError] = useState("");
  const [discoveredHosts, setDiscoveredHosts] = useState<string[]>([]);

  useEffect(() => {
    getSettings().then(setSettings);
  }, []);

  useEffect(() => {
    if (settings?.captureScope !== "auth-plus-allowlist") {
      setDiscoveredHosts(getDiscoveredAuthHosts());
    }
  }, [settings?.captureScope]);

  if (!settings) return <div className="settings-loading">Loading settings...</div>;

  const update = (patch: Partial<Settings>): void => {
    const next = { ...settings, ...patch };
    setSettings(next);
    void saveSettings(next);
    onSave(next);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = async (): Promise<void> => {
    const def = await resetSettings();
    setSettings(def);
    onSave(def);
  };

  const handleAddHost = (): void => {
    const normalized = normalizeHostname(newHost);
    if (!isValidHostname(normalized)) {
      setHostError("Invalid hostname");
      return;
    }
    if (settings.allowedHosts.includes(normalized)) {
      setHostError("Host already in allowlist");
      return;
    }
    update({ allowedHosts: [...settings.allowedHosts, normalized] });
    setNewHost("");
    setHostError("");
  };

  const handleRemoveHost = (host: string): void => {
    update({ allowedHosts: settings.allowedHosts.filter(h => h !== host) });
  };

  const handleAddDiscovered = (host: string): void => {
    if (!settings.allowedHosts.includes(host)) {
      update({ allowedHosts: [...settings.allowedHosts, host] });
    }
  };

  const scopeOptions: { value: CaptureScope; label: string; desc: string }[] = [
    { value: "auth-only", label: "Auth-only (recommended)", desc: "Capture only IdP, SP, and auth endpoints" },
    { value: "auth-plus-allowlist", label: "Auth + allowlist", desc: "Auth-only plus custom allowed hosts" },
    { value: "full", label: "Full capture (all URLs)", desc: "Capture everything, larger traces" }
  ];

  return (
    <div className="settings-panel">
      <div className="settings-head">
        <h2>Settings</h2>
        <div className="settings-actions">
          {saved && <span className="settings-saved">Saved</span>}
          <button className="btn btn-ghost" onClick={onClose}>Done</button>
        </div>
      </div>

      <div className="settings-sections">
        <section className="settings-section">
          <h3>Capture Scope</h3>
          <div className="scope-selector">
            {scopeOptions.map(opt => (
              <label key={opt.value} className={`scope-option ${settings.captureScope === opt.value ? "active" : ""}`}>
                <input
                  type="radio"
                  name="captureScope"
                  value={opt.value}
                  checked={settings.captureScope === opt.value}
                  onChange={() => update({ captureScope: opt.value })}
                />
                <div className="scope-option-content">
                  <span className="scope-option-label">{opt.label}</span>
                  <span className="scope-option-desc">{opt.desc}</span>
                  {opt.value === "full" && <span className="scope-warning">⚠️</span>}
                </div>
              </label>
            ))}
          </div>

          {settings.captureScope === "auth-plus-allowlist" && (
            <div className="allowlist-section">
              <h4>Allowed hosts</h4>
              <div className="host-chips">
                {settings.allowedHosts.map(host => (
                  <span key={host} className="host-chip">
                    {host}
                    <button onClick={() => handleRemoveHost(host)} title="Remove">×</button>
                  </span>
                ))}
              </div>
              <div className="host-input-row">
                <input
                  type="text"
                  placeholder="e.g. accounts.zoho.com"
                  value={newHost}
                  onChange={e => { setNewHost(e.target.value); setHostError(""); }}
                  onKeyDown={e => e.key === "Enter" && handleAddHost()}
                />
                <button className="btn btn-sm" onClick={handleAddHost} disabled={!newHost}>Add</button>
              </div>
              {hostError && <div className="host-error">{hostError}</div>}
              {discoveredHosts.length > 0 && (
                <div className="discovered-hosts">
                  <span className="discovered-label">Suggested:</span>
                  {discoveredHosts.filter(h => !settings.allowedHosts.includes(h)).slice(0, 5).map(host => (
                    <button key={host} className="discovered-chip" onClick={() => handleAddDiscovered(host)}>
                      + {host}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </section>

        <section className="settings-section">
          <h3>Capture</h3>
          <label className="settings-row">
            <div className="settings-row-info">
              <span className="settings-row-label">Auto-start on tab switch</span>
              <span className="settings-row-desc">Automatically start capture when you switch to a new tab</span>
            </div>
            <input
              type="checkbox"
              checked={settings.autoStartOnTabSwitch}
              onChange={e => update({ autoStartOnTabSwitch: e.target.checked })}
            />
          </label>
        </section>

        <section className="settings-section">
          <h3>History</h3>
          <label className="settings-row">
            <div className="settings-row-info">
              <span className="settings-row-label">Max saved sessions</span>
              <span className="settings-row-desc">Number of past sessions to keep in history</span>
            </div>
            <select
              value={settings.maxHistoryItems}
              onChange={e => update({ maxHistoryItems: Number(e.target.value) })}
            >
              <option value={10}>10</option>
              <option value={30}>30</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </label>
        </section>

        <section className="settings-section">
          <h3>Privacy</h3>
          <label className="settings-row">
            <div className="settings-row-info">
              <span className="settings-row-label">Redaction level</span>
              <span className="settings-row-desc">How aggressively secrets are masked in views</span>
            </div>
            <select
              value={settings.redactionStrictness}
              onChange={e => update({ redactionStrictness: e.target.value as Settings["redactionStrictness"] })}
            >
              <option value="strict">Strict</option>
              <option value="moderate">Moderate</option>
              <option value="off">Off (show all)</option>
            </select>
          </label>
        </section>

        <section className="settings-section">
          <h3>Interface</h3>
          <label className="settings-row">
            <div className="settings-row-info">
              <span className="settings-row-label">Default detail tab</span>
              <span className="settings-row-desc">Which tab opens first when selecting a finding</span>
            </div>
            <select
              value={settings.defaultDetailTab}
              onChange={e => update({ defaultDetailTab: e.target.value as Settings["defaultDetailTab"] })}
            >
              <option value="fix">Fix steps</option>
              <option value="happened">What happened</option>
              <option value="evidence">Evidence</option>
              <option value="artifacts">Artifacts</option>
              <option value="xml">SAML XML</option>
            </select>
          </label>
        </section>

        <section className="settings-section">
          <h3>Keyboard Shortcuts</h3>
          <div className="shortcut-list">
            <div className="shortcut-row">
              <kbd>Alt+Shift+S</kbd>
              <span>Start / stop capture</span>
            </div>
            <div className="shortcut-row">
              <kbd>Alt+Shift+E</kbd>
              <span>Export session</span>
            </div>
            <div className="shortcut-row">
              <kbd>Alt+Shift+F</kbd>
              <span>Focus search</span>
            </div>
            <div className="shortcut-row">
              <kbd>Alt+Shift+P</kbd>
              <span>Open settings</span>
            </div>
          </div>
          <div className="settings-note">
            You can also customize these in Chrome at <code>chrome://extensions/shortcuts</code>
          </div>
        </section>

        <section className="settings-section">
          <h3>Reset</h3>
          <button className="btn btn-danger" onClick={handleReset}>
            Reset to defaults
          </button>
        </section>

        <section className="settings-section">
          <h3>AI Assistant</h3>
          <p className="settings-note">
            Enable optional AI help powered by OpenAI. Your API key is stored locally and never sent to our servers.
          </p>
          
          {isAIDisabledByPolicy() ? (
            <div className="settings-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "8px" }}>
              <p style={{ color: "var(--err)", fontSize: "13px" }}>
                AI Assistant has been disabled by your organization.
              </p>
              <button 
                className="btn btn-ghost" 
                onClick={() => {
                  setEnterpriseAIPolicy(false);
                  window.location.reload();
                }}
                style={{ fontSize: "12px" }}
              >
                Override (if allowed)
              </button>
            </div>
          ) : (
            <>
              <div className="settings-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "8px" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={settings.ai.enabled}
                    onChange={(e) => update({ 
                      ai: { ...settings.ai, enabled: e.target.checked }
                    })}
                  />
                  <span className="settings-row-label">Enable AI Assistant</span>
                </label>
              </div>

              {settings.ai.enabled && (
                <>
                  <div style={{ marginTop: "12px" }}>
                    <label className="settings-row-label" style={{ display: "block", marginBottom: "6px" }}>
                      OpenAI API Key
                    </label>
                    <input
                      type="password"
                      className="search"
                      style={{ width: "100%", padding: "10px 12px" }}
                      placeholder="sk-..."
                      value={settings.ai.apiKey}
                      onChange={(e) => update({ 
                        ai: { ...settings.ai, apiKey: e.target.value }
                      })}
                    />
                    <p className="settings-note" style={{ marginTop: "6px" }}>
                      Your API key is stored locally in Chrome. We never see or store it.
                    </p>
                  </div>

                  <div className="settings-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: "8px", marginTop: "12px" }}>
                    <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={settings.ai.includeFindings}
                        onChange={(e) => update({ 
                          ai: { ...settings.ai, includeFindings: e.target.checked }
                        })}
                      />
                      <span className="settings-row-label">Include current findings in AI context</span>
                    </label>
                    <p className="settings-note" style={{ marginTop: "0" }}>
                      When enabled, AI can see your current findings to provide more relevant help.
                    </p>
                  </div>
                </>
              )}
            </>
          )}
        </section>

        <section className="settings-section">
          <h3>Enterprise Policy</h3>
          <p className="settings-note">
            Administrative controls for this extension.
          </p>
          <div className="settings-row">
            <div className="settings-row-info">
              <span className="settings-row-label">AI Assistant</span>
              <span className="settings-row-desc">
                {isAIDisabledByPolicy() ? "Disabled by policy" : "Allowed"}
              </span>
            </div>
            {!isAIDisabledByPolicy() && (
              <button 
                className="btn btn-ghost" 
                onClick={() => {
                  setEnterpriseAIPolicy(true);
                }}
                style={{ fontSize: "12px", padding: "6px 12px" }}
              >
                Disable AI
              </button>
            )}
          </div>
        </section>
      </div>
    </div>
  );
};

export default SettingsPanel;
