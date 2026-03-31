import { useState, useEffect } from "react";
import type { Settings } from "../shared/settings";
import { getSettings, saveSettings, resetSettings } from "../shared/settings";

interface SettingsProps {
  onClose: () => void;
  onSave: (settings: Settings) => void;
}

const SettingsPanel = ({ onClose, onSave }: SettingsProps): JSX.Element => {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    getSettings().then(setSettings);
  }, []);

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
      </div>
    </div>
  );
};

export default SettingsPanel;
