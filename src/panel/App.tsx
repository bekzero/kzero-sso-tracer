import { useEffect, useMemo, useRef, useState } from "react";
import { buildSanitizedExport, buildRawExport, buildSummaryExport } from "../export";
import { downloadHar } from "../export/harExport";
import { downloadFindingsCsv, downloadSummaryCsv } from "../export/csvExport";
import { downloadShareableTrace, copyShareableLink } from "../export/shareableExport";
import type {
  CaptureHistoryItem,
  CaptureSession,
  Finding,
  NormalizedEvent,
  NormalizedOidcEvent,
  NormalizedSamlEvent,
  Owner,
  Severity,
  ExportMode
} from "../shared/models";
import { mask, redactRecord } from "../shared/redaction";
import { RULE_CATALOG, getRuleDoc } from "../shared/ruleCatalog";
import { buildTraceContext } from "../recipes/context";
import { buildFixRecipe } from "../recipes/buildRecipe";
import type { FixRecipe } from "../recipes/types";
import { labelVariants } from "../mappings/uiLabelAliases";
import { getFieldMapping } from "../mappings/fieldMappings";
import { KZeroWordmark } from "./KZeroLogo";
import type { Settings } from "../shared/settings";
import { getSettings, saveSettings } from "../shared/settings";
import Compare from "./Compare";
import SettingsPanel from "./Settings";
import ConfirmDialog from "./ConfirmDialog";

interface AppProps {
  mode?: "devtools" | "sidepanel";
}

type TargetTab = { id: number; title?: string; url?: string };

const getTabId = (mode: "devtools" | "sidepanel"): number => {
  if (mode === "sidepanel") return -1;
  try {
    return chrome.devtools.inspectedWindow.tabId;
  } catch {
    const tabParam = new URLSearchParams(location.search).get("tabId");
    return Number(tabParam ?? -1);
  }
};

const severityWeight = (s: Severity): number => (s === "error" ? 3 : s === "warning" ? 2 : 1);

const formatTime = (ts: number): string => new Date(ts).toLocaleTimeString();
const formatDate = (ts?: number): string => (ts ? new Date(ts).toLocaleString() : "-");

const copyText = async (value: string): Promise<void> => navigator.clipboard.writeText(value);

type UiFieldScanValue = { found: boolean; value?: string; kind?: string };

const isSensitiveField = (label: string): boolean =>
  /secret|token|authorization code|code verifier|private key/i.test(label);

const displayValue = (value: string, raw: boolean, sensitive: boolean): string => {
  if (raw) return value;
  if (sensitive) return mask(value, 2, 2);
  return value;
};

const classNames = (...parts: Array<string | false | undefined>): string => parts.filter(Boolean).join(" ");

const Pill = ({ tone, children }: { tone: string; children: string }): JSX.Element => (
  <span className={classNames("pill", `pill-${tone}`)}>{children}</span>
);

const SeverityPill = ({ severity }: { severity: Severity }): JSX.Element => {
  const label = severity === "error" ? "Problem" : severity === "warning" ? "Warning" : "Notice";
  return <Pill tone={severity}>{label}</Pill>;
};

const OwnerPill = ({ owner }: { owner: Owner }): JSX.Element => {
  const tone = owner === "KZero" ? "kzero" : owner === "vendor SP" ? "vendor" : owner;
  return <Pill tone={tone.replace(/\s/g, "-")}>{owner}</Pill>;
};

const CONFIDENCE_LABELS = {
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence"
};

const ConfidenceBadge = ({ level }: { level: "high" | "medium" | "low" }): JSX.Element => {
  return <span className={`confidence-badge confidence-${level}`}>{CONFIDENCE_LABELS[level]}</span>;
};

const AmbiguityBadge = (): JSX.Element => (
  <span className="ambiguity-badge">Needs more context</span>
);

const ProtocolPill = ({ protocol }: { protocol: string }): JSX.Element => <Pill tone="protocol">{protocol}</Pill>;

const commonPrefixLen = (a: string, b: string): number => {
  const max = Math.min(a.length, b.length);
  let i = 0;
  while (i < max && a[i] === b[i]) i++;
  return i;
};

const commonSuffixLen = (a: string, b: string, prefixLen: number): number => {
  const max = Math.min(a.length, b.length) - prefixLen;
  let i = 0;
  while (i < max && a[a.length - 1 - i] === b[b.length - 1 - i]) i++;
  return i;
};

const DiffLine = ({ label, observed, expected }: { label: string; observed: string; expected: string }): JSX.Element => {
  const prefix = commonPrefixLen(observed, expected);
  const suffix = commonSuffixLen(observed, expected, prefix);
  const oMid = observed.slice(prefix, observed.length - suffix);
  const eMid = expected.slice(prefix, expected.length - suffix);
  const pre = observed.slice(0, prefix);
  const suf = observed.slice(observed.length - suffix);
  const preE = expected.slice(0, prefix);
  const sufE = expected.slice(expected.length - suffix);

  return (
    <div className="diff">
      <div className="diff-label">{label}</div>
      <div className="diff-rows">
        <div className="diff-row">
          <span className="diff-tag">Observed</span>
          <code>
            {pre}
            {oMid ? <mark className="diff-mark">{oMid}</mark> : null}
            {suf}
          </code>
        </div>
        <div className="diff-row">
          <span className="diff-tag">Expected</span>
          <code>
            {preE}
            {eMid ? <mark className="diff-mark">{eMid}</mark> : null}
            {sufE}
          </code>
        </div>
      </div>
    </div>
  );
};

const getAllFieldExpectations = (recipe: FixRecipe): Array<{ field: string; expected?: string }> => {
  return recipe.sections.flatMap(s => s.fieldExpectations ?? []);
};

const PreFlightChecklist = ({ recipe, uiScan, fieldExpectations }: { 
  recipe: FixRecipe; 
  uiScan?: { results: Record<string, { found: boolean; value?: string }> };
  fieldExpectations?: Array<{ field: string; expected?: string }>;
}): JSX.Element => {
  const allExpectations = fieldExpectations ?? getAllFieldExpectations(recipe);
  
  const items = [
    ...recipe.sections
      .filter((s) => s.owner === "KZero" && s.kzeroFields?.length)
      .flatMap((s) => s.kzeroFields.map((f) => ({ label: f, source: "KZero" as const }))),
    ...recipe.sections
      .filter((s) => s.owner === "vendor SP" && s.vendorFields?.length)
      .flatMap((s) => s.vendorFields.map((f) => ({ label: f, source: "Vendor" as const })))
  ];

  if (items.length === 0) return <></>;

  const getFieldStatus = (field: string): { status: "match" | "mismatch" | "pending"; value?: string } => {
    if (!uiScan?.results) return { status: "pending" };
    
    const expectation = allExpectations.find(e => e.field === field);
    const variants = labelVariants(field);
    const found = variants.find(v => uiScan.results[v]?.found);
    const result = found ? uiScan.results[found] : uiScan.results[field];
    
    if (!result || !result.found) {
      return { status: "pending" };
    }
    
    if (expectation?.expected) {
      const match = result.value === expectation.expected;
      return { status: match ? "match" : "mismatch", value: result.value };
    }
    
    return { status: "pending", value: result.value };
  };

  const matchCount = items.filter(i => getFieldStatus(i.label).status === "match").length;
  const mismatchCount = items.filter(i => getFieldStatus(i.label).status === "mismatch").length;
  const pendingCount = items.filter(i => getFieldStatus(i.label).status === "pending").length;

  return (
    <div className="preflight">
      <div className="preflight-head">
        <span className="preflight-icon">📋</span>
        Field Status
        <span className="preflight-summary">
          {matchCount > 0 && <span className="status-match">✅ {matchCount}</span>}
          {mismatchCount > 0 && <span className="status-mismatch">❌ {mismatchCount}</span>}
          {pendingCount > 0 && <span className="status-pending">⏳ {pendingCount}</span>}
        </span>
      </div>
      <ul className="preflight-list">
        {items.map((item) => {
          const { status, value } = getFieldStatus(item.label);
          return (
            <li key={item.label} className="preflight-item">
              <div className={`preflight-status preflight-status-${status}`}>
                {status === "match" && "✅"}
                {status === "mismatch" && "❌"}
                {status === "pending" && "⏳"}
              </div>
              <span className="preflight-label">{item.label}</span>
              <span className="preflight-source">{item.source === "KZero" ? "KZero" : "Vendor"}</span>
              {value && <span className="preflight-value" title={value}>{value.length > 20 ? value.slice(0, 20) + "..." : value}</span>}
            </li>
          );
        })}
      </ul>
    </div>
  );
};

export const App = ({ mode = "sidepanel" }: AppProps): JSX.Element => {
  const [session, setSession] = useState<CaptureSession | null>(null);
  const [tabId, setTabId] = useState<number>(() => getTabId(mode));
  const [messagingTabId, setMessagingTabId] = useState<number>(() => getTabId(mode));
  const [targetTab, setTargetTab] = useState<TargetTab | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [leftTab, setLeftTab] = useState<"timeline" | "history" | "findings" | "detail" | "compare">("findings");
  const [detailTab, setDetailTab] = useState<"fix" | "happened" | "evidence" | "artifacts" | "xml">("happened");
  const [search, setSearch] = useState("");
  const [ruleFilter, setRuleFilter] = useState("");
  const [showRaw, setShowRaw] = useState(false);
  const [history, setHistory] = useState<CaptureHistoryItem[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [isPopup, setIsPopup] = useState(false);
  const [isNarrow, setIsNarrow] = useState(false);
  const [uiScan, setUiScan] = useState<{ results: Record<string, UiFieldScanValue> }>({ results: {} });
  const [onboardingDone, setOnboardingDone] = useState(false);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showCompare, setShowCompare] = useState(false);
  const [showTabPicker, setShowTabPicker] = useState(false);
  const [availableTabs, setAvailableTabs] = useState<Array<{ id: number; title: string; url: string }>>([]);
  type ExportFormat = "json" | "har" | "csv" | "csv-summary" | "shareable" | "shareable-link";
  const [pendingExport, setPendingExport] = useState<ExportFormat | null>(null);
  const [pendingInjection, setPendingInjection] = useState<{ labels: string[] } | null>(null);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const exportMenuRef = useRef<HTMLDivElement>(null);
  const [exportMode, setExportMode] = useState<ExportMode>("sanitized");
  const [includePostLogin, setIncludePostLogin] = useState(false);
  const [showRawWarning, setShowRawWarning] = useState(false);

  const narrowTab = leftTab;
  const openPopup = (): void => {
    chrome.windows.create({
      url: chrome.runtime.getURL("panel.html"),
      type: "popup",
      width: 1100,
      height: 800
    });
  };

  const openTabPicker = (): void => {
    chrome.tabs.query({}, (tabs) => {
      const filteredTabs = tabs
        .filter(tab => tab.id && tab.url && !tab.url.startsWith("chrome://") && !tab.url.startsWith("about:"))
        .map(tab => ({ id: tab.id!, title: tab.title || "Untitled", url: tab.url! }));
      setAvailableTabs(filteredTabs);
      setShowTabPicker(true);
    });
  };

  const switchToTab = (newTabId: number): void => {
    chrome.tabs.get(newTabId, (tab) => {
      if (tab?.id && tab?.url) {
        const realTabId = tab.id;
        setMessagingTabId(realTabId);
        setTabId(realTabId);
        setTargetTab({ id: realTabId, title: tab.title || "Untitled", url: tab.url });
        chrome.runtime.sendMessage({ type: "SET_TAB", tabId: realTabId });
      }
    });
    setShowTabPicker(false);
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setIsPopup(params.get("popup") === "1");
    const saved = sessionStorage.getItem("onboardingDone");
    setOnboardingDone(saved === "1");
    void getSettings().then(setSettings);
  }, []);

  useEffect(() => {
    const handler = (e: MouseEvent): void => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setExportMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  useEffect(() => {
    const checkWidth = (): void => setIsNarrow(window.innerWidth < 900);
    checkWidth();
    window.addEventListener("resize", checkWidth);
    return () => window.removeEventListener("resize", checkWidth);
  }, []);

  useEffect(() => {
    if (mode === "sidepanel" && tabId === -1) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          const realTabId = tabs[0].id;
          setMessagingTabId(realTabId);
          setTabId(realTabId);
          setTargetTab({ id: realTabId, title: tabs[0].title, url: tabs[0].url });
        }
      });
    }
  }, [mode, tabId]);

  useEffect(() => {
    if (messagingTabId < 0 || !chrome.runtime?.id) return;

    const handler = (msg: unknown): void => {
      const message = msg as Record<string, unknown>;
      if (message.type === "SESSION_UPDATE") {
        const incomingSession = message.session as CaptureSession | null;
        if (incomingSession) setSession(incomingSession);
      }
      if (message.type === "UI_SCAN_RESULT") {
        setUiScan({ results: (message.results as Record<string, UiFieldScanValue>) ?? {} });
      }
      if (message.type === "TAB_UPDATE") {
        setTargetTab(message.tab as TargetTab);
      }
      if (message.type === "COMMAND") {
        const cmd = message.command as string;
        if (cmd === "toggle-capture") {
          session?.active ? stopCapture() : startCapture();
        } else if (cmd === "export-session") {
          if (session) void doExport("json");
        } else if (cmd === "focus-search") {
          (document.querySelector(".search") as HTMLInputElement)?.focus();
        } else if (cmd === "open-settings") {
          setShowSettings(true);
        }
      }
    };

    const port = chrome.runtime.connect({ name: "kzero-panel" });
    port.postMessage({ type: "PANEL_INIT", tabId: messagingTabId });
    port.onMessage.addListener(handler);
    port.onDisconnect.addListener(() => {
      port.onMessage.removeListener(handler);
    });

    const rc = (msg: unknown): void => {
      const message = msg as Record<string, unknown>;
      if (message.type === "SESSION_UPDATE") {
        const incomingSession = message.session as CaptureSession | null;
        if (incomingSession) setSession(incomingSession);
      }
      if (message.type === "UI_SCAN_RESULT") {
        setUiScan({ results: (message.results as Record<string, UiFieldScanValue>) ?? {} });
      }
    };
    chrome.runtime.onMessage.addListener(rc);

    return () => {
      port.onMessage.removeListener(handler);
      chrome.runtime.onMessage.removeListener(rc);
      port.disconnect();
    };
  }, [messagingTabId]);

  useEffect(() => {
    chrome.runtime.sendMessage({ type: "GET_HISTORY" }, (resp) => {
      if (resp?.history) setHistory(resp.history as CaptureHistoryItem[]);
    });
  }, []);

  useEffect(() => {
    if (selectedFinding && mode === "devtools" && messagingTabId >= 0) {
      const mapping = getFieldMapping(selectedFinding.ruleId);
      const fieldLabels = [...mapping.kzeroFields, ...mapping.vendorFields];
      if (fieldLabels.length > 0) {
        requestUiScan(fieldLabels);
      }
    }
  }, [selectedFindingId]);

  const loadHistory = (id: string): void => {
    chrome.runtime.sendMessage({ type: "LOAD_HISTORY_ITEM", itemId: id }, (resp) => {
      if (resp?.session) {
        setSession(resp.session as CaptureSession);
        setSelectedHistoryId(id);
      }
    });
  };

  const startCapture = (): void => {
    setSession(null);
    setSelectedEventId(null);
    setSelectedFindingId(null);
    setUiScan({ results: {} });
    chrome.runtime.sendMessage({ type: "START_CAPTURE", tabId: messagingTabId });
  };

  const stopCapture = (): void => {
    setSession((prev) => (prev ? { ...prev, active: false } : null));
    chrome.runtime.sendMessage({ type: "STOP_CAPTURE", tabId: messagingTabId });
  };

  const doExport = async (format: ExportFormat): Promise<void> => {
    if (!session) return;
    switch (format) {
      case "json": {
        let data;
        if (exportMode === "raw") {
          data = buildRawExport(session);
        } else if (exportMode === "summary") {
          data = buildSummaryExport(session);
        } else {
          data = buildSanitizedExport(session, { mode: exportMode, includePostLoginActivity: includePostLogin });
        }
        if (!data) return;
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `kzero-trace-${session.tabId}-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        break;
      }
      case "har":
        downloadHar(session);
        break;
      case "csv":
        downloadFindingsCsv(session);
        break;
      case "csv-summary":
        downloadSummaryCsv(session);
        break;
      case "shareable":
        downloadShareableTrace(session);
        break;
      case "shareable-link":
        await copyShareableLink(session);
        break;
    }
  };

  const clearSession = (): void => {
    setSession(null);
    setSelectedEventId(null);
    setSelectedFindingId(null);
    chrome.runtime.sendMessage({ type: "CLEAR_SESSION", tabId: messagingTabId });
  };

  const clearHistory = (): void => {
    chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => {
      setHistory([]);
    });
  };

  const requestUiScan = (labels: string[]): void => {
    if (messagingTabId < 0) return;
    chrome.runtime.sendMessage({ type: "REQUEST_UI_SCAN", tabId: messagingTabId, labels });
  };

  const requestUiHighlight = (labels: string[]): void => {
    if (messagingTabId < 0) return;
    chrome.runtime.sendMessage({ type: "REQUEST_UI_HIGHLIGHT", tabId: messagingTabId, labels });
  };

  const dismissOnboarding = (): void => {
    setOnboardingDone(true);
    sessionStorage.setItem("onboardingDone", "1");
  };

  const filteredEvents = useMemo(() => {
    if (!session) return [];
    let events = [...session.normalizedEvents].reverse();
    if (search) {
      const q = search.toLowerCase();
      events = events.filter(
        (e) =>
          e.kind.toLowerCase().includes(q) ||
          e.host.toLowerCase().includes(q) ||
          e.url.toLowerCase().includes(q) ||
          JSON.stringify(e.artifacts).toLowerCase().includes(q)
      );
    }
    return events;
  }, [session, search]);

  const filteredFindings = useMemo(() => {
    if (!session) return [];
    let findings = [...session.findings];
    if (ruleFilter) findings = findings.filter((f) => f.ruleId === ruleFilter);
    if (search) {
      const q = search.toLowerCase();
      findings = findings.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.explanation.toLowerCase().includes(q) ||
          f.evidence.some((e) => e.toLowerCase().includes(q))
      );
    }
    return findings.sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity));
  }, [session, ruleFilter, search]);

  const topDiagnosis = useMemo(() => {
    if (!session?.findings.length) return null;
    return session.findings.reduce((worst, f) =>
      severityWeight(f.severity) > severityWeight(worst.severity) ? f : worst
    );
  }, [session]);

  const selectedEvent = useMemo(
    () => filteredEvents.find((e) => e.id === selectedEventId) ?? null,
    [filteredEvents, selectedEventId]
  );

  const selectedFinding = useMemo(
    () => filteredFindings.find((f) => f.id === selectedFindingId) ?? null,
    [filteredFindings, selectedFindingId]
  );

  const selectedEventForFinding = useMemo((): NormalizedEvent | null => {
    if (!selectedFinding?.eventId || !session) return null;
    return session.normalizedEvents.find((e) => e.id === selectedFinding.eventId) ?? null;
  }, [selectedFinding, session]);

  const traceContext = useMemo(
    () => buildTraceContext(session),
    [session]
  );

  const recipe = useMemo(
    () => (selectedFinding ? buildFixRecipe(selectedFinding, traceContext) : null),
    [selectedFinding, traceContext]
  );

  const ruleDoc = useMemo(
    () => (selectedFinding ? getRuleDoc(selectedFinding.ruleId) : null),
    [selectedFinding]
  );

  const getKeyFields = (event: NormalizedEvent | null): Array<{ k: string; v: string }> => {
    if (!event) return [];
    const a = event.artifacts;
    if (event.protocol === "SAML") {
      const e = a as NormalizedSamlEvent["artifacts"];
      return [
        e.SAMLRequest && { k: "SAMLRequest", v: e.SAMLRequest },
        e.SAMLResponse && { k: "SAMLResponse", v: e.SAMLResponse },
        e.RelayState && { k: "RelayState", v: e.RelayState },
        e.Issuer && { k: "Issuer", v: e.Issuer },
        e.Destination && { k: "Destination", v: e.Destination },
        e.AssertionConsumerServiceURL && { k: "ACS URL", v: e.AssertionConsumerServiceURL },
        e.Audience && { k: "Audience", v: e.Audience },
        e.NameID && { k: "NameID", v: e.NameID },
        e.InResponseTo && { k: "InResponseTo", v: e.InResponseTo },
      ].filter(Boolean) as Array<{ k: string; v: string }>;
    }
    if (event.protocol === "OIDC") {
      const e = a as NormalizedOidcEvent["artifacts"];
      return [
        e.code && { k: "code", v: e.code },
        e.state && { k: "state", v: e.state },
        e.nonce && { k: "nonce", v: e.nonce },
        e.access_token && { k: "access_token", v: e.access_token },
        e.id_token && { k: "id_token", v: e.id_token },
        e.iss && { k: "iss", v: e.iss },
        e.aud && { k: "aud", v: e.aud },
        e.client_id && { k: "client_id", v: e.client_id },
        e.redirect_uri && { k: "redirect_uri", v: e.redirect_uri },
      ].filter(Boolean) as Array<{ k: string; v: string }>;
    }
    return Object.entries(a).slice(0, 10).map(([k, v]) => ({ k, v: String(v) }));
  };

  const xmlRows = useMemo((): Array<{ id: string; path: string; value: string; highlight?: boolean }> => {
    if (!selectedEvent || selectedEvent.protocol !== "SAML") return [];
    const a = (selectedEvent as NormalizedSamlEvent).artifacts;
    const xml = a.decodedXml;
    if (!xml) return [];
    const rows: Array<{ id: string; path: string; value: string; highlight?: boolean }> = [];
    const importantPaths = [
      { path: "//saml:Issuer/text()", label: "Issuer" },
      { path: "//saml:Subject/saml:NameID/text()", label: "NameID" },
      { path: "//saml:Conditions/@Audience", label: "Audience" },
      { path: "//saml:Conditions/@NotBefore", label: "NotBefore" },
      { path: "//saml:Conditions/@NotOnOrAfter", label: "NotOnOrAfter" },
      { path: "//saml:AuthnStatement/@SessionIndex", label: "SessionIndex" },
      { path: "//saml:AttributeStatement/saml:Attribute[@Name='email']/saml:AttributeValue/text()", label: "email" },
      { path: "//saml:Assertion/saml:Signature/signedInfo", label: "Signed" },
      { path: "//samlp:StatusCode/@Value", label: "StatusCode" },
    ];
    const highlights = selectedFinding?.ruleId === "SAML_ISSUER_MISMATCH"
      ? ["Issuer"]
      : selectedFinding?.ruleId === "SAML_AUDIENCE_MISMATCH"
      ? ["Audience"]
      : selectedFinding?.ruleId === "SAML_NAMEID_MISMATCH"
      ? ["NameID"]
      : [];

    const nsMap: Record<string, string> = {
      saml: "urn:oasis:names:tc:SAML:2.0:assertion",
      samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
      ds: "http://www.w3.org/2000/09/xmldsig#"
    };

    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(xml, "text/xml");
      const resolver = {
        lookupNamespaceURI: (prefix: string) => nsMap[prefix] ?? null
      };

      importantPaths.forEach(({ path, label }) => {
        try {
          const result = doc.evaluate(path, doc, resolver as (prefix: string) => string | null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
          for (let i = 0; i < result.snapshotLength; i++) {
            const node = result.snapshotItem(i);
            if (node) {
              rows.push({
                id: `${label}-${i}`,
                path,
                value: node.textContent ?? "",
                highlight: highlights.includes(label)
              });
            }
          }
        } catch { /* skip failed xpath */ }
      });
    } catch { /* xml parse error */ }

    return rows;
  }, [selectedEvent, selectedFinding]);

  const tabTitle = targetTab?.title ?? (tabId >= 0 ? `Tab ${tabId}` : "No tab selected");

  if (!onboardingDone) {
    return (
      <div className="onboarding">
        <div className="onboarding-header">
          <KZeroWordmark />
          <h1>SSO Tracer</h1>
          <p className="onboarding-subtitle">Debug SAML and OIDC login issues in your KZero Passwordless environment.</p>
        </div>
        <div className="steps-list">
          <div className="step">
            <span className="step-num">1</span>
            <div className="step-content">
              <strong>Select your target</strong>
              <p>Open the vendor login page in this tab, then click <span className="code">Use current tab</span> to target it.</p>
            </div>
          </div>
          <div className="step">
            <span className="step-num">2</span>
            <div className="step-content">
              <strong>Start capture</strong>
              <p>Click <span className="code">Start</span> to begin recording, then complete your login flow.</p>
            </div>
          </div>
          <div className="step">
            <span className="step-num">3</span>
            <div className="step-content">
              <strong>Review findings</strong>
              <p>Each issue includes a plain-English explanation and step-by-step fix instructions.</p>
            </div>
          </div>
        </div>
        <div className="onboarding-cta">
          <button className="btn btn-primary" onClick={dismissOnboarding}>Get started</button>
          <p className="onboarding-hint">Press Alt+Shift+S to toggle capture anytime</p>
        </div>
      </div>
    );
  }

  const wideLayout = (
    <>
      <div className="layout-3pane">
        <section className="pane pane-nav">
          <div className="pane-head">
            <div className="tab-row">
              <button className={classNames("tab", leftTab === "timeline" && "active")} onClick={() => setLeftTab("timeline")}>Timeline</button>
              <button className={classNames("tab", leftTab === "history" && "active")} onClick={() => setLeftTab("history")}>History</button>
              {history.length >= 2 && (
                <button className={classNames("tab", leftTab === "compare" && "active")} onClick={() => setLeftTab("compare")}>Compare</button>
              )}
            </div>
          </div>
          {leftTab === "timeline" ? (
            <ul className="list">
              {filteredEvents.map((event) => (
                <li key={event.id} className={classNames("row", `row-protocol-${event.protocol.toLowerCase()}`, selectedEvent?.id === event.id && "active")} onClick={() => setSelectedEventId(event.id)}>
                  <div className="row-main">
                    <div className="row-title">
                      <ProtocolPill protocol={event.protocol} />
                      <span className="mono">{event.kind}</span>
                    </div>
                    <div className="row-sub mono">{event.host}</div>
                  </div>
                  <div className="row-meta mono">
                    <span>{formatTime(event.timestamp)}</span>
                    <span className={classNames("http", (event.statusCode ?? 0) >= 400 && "http-bad")}>{event.statusCode ?? "-"}</span>
                  </div>
                </li>
              ))}
            </ul>
          ) : null}
          {leftTab === "history" && history.length > 0 && (
            <div className="pane-actions">
              <button className="btn btn-ghost btn-sm" onClick={clearHistory}>Clear history</button>
            </div>
          )}
        </section>

        <section className="pane pane-findings">
          <div className="pane-head">
            <h2>Findings</h2>
            {session?.active && (
              <div className="live-badge">
                <span className="live-dot" />
                LIVE
              </div>
            )}
          </div>
          {session?.findings.length === 0 && !session.active && (
            <div className="empty">Start capture, run a login, and stop to see findings here.</div>
          )}
          {session?.findings.length === 0 && session.active && (
            <div className="empty">Capturing... run the login flow now.</div>
          )}
          {session?.findings.length === 0 && !session && (
            <div className="empty">Click Start to begin capturing.</div>
          )}
          {session?.findings && session.findings.length > 0 && (
            <>
              {topDiagnosis ? (
                <div style={{ padding: "0 12px 8px" }}>
                  <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 6, fontWeight: 500, textTransform: "uppercase", letterSpacing: "0.06em" }}>Most critical</div>
                  <div className="top-card" onClick={() => { setSelectedFindingId(topDiagnosis.id); setDetailTab("happened"); }}>
                    <div className="top-title">
                      <SeverityPill severity={topDiagnosis.severity} />
                      <OwnerPill owner={topDiagnosis.likelyOwner} />
                      <span className="top-text">{topDiagnosis.title}</span>
                    </div>
                    <div className="top-sub">{topDiagnosis.explanation}</div>
                  </div>
                </div>
              ) : null}
              {session.findings.length > 1 && (
                <div className="severity-legend" style={{ margin: "0 12px 8px" }}>
                  <span><span style={{ color: "var(--err)" }}>●</span> <strong>Problem</strong> — needs fixing</span>
                  <span><span style={{ color: "var(--warn)" }}>●</span> <strong>Warning</strong> — may cause issues</span>
                  <span><span style={{ color: "var(--info)" }}>●</span> <strong>Notice</strong> — FYI only</span>
                </div>
              )}
              <ul className="list">
                {filteredFindings.map((finding) => (
                  <li key={finding.id} className={classNames("row", `finding-${finding.severity}`, selectedFinding?.id === finding.id && "active")}
                    onClick={() => { setSelectedFindingId(finding.id); setDetailTab("happened"); }}>
                    <div className="row-main">
                      <div className="row-title">
                        <SeverityPill severity={finding.severity} />
                        <OwnerPill owner={finding.likelyOwner} />
                        <span className="row-text">{finding.title}</span>
                      </div>
                      <div className="row-sub">{finding.explanation.slice(0, 65)}{finding.explanation.length > 65 ? "..." : ""}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>

        <section className="pane pane-detail">
          <div className="pane-head">
            <h2>Detail</h2>
            <div className="tab-row">
              <button className={classNames("tab", detailTab === "fix" && "active")} onClick={() => setDetailTab("fix")}>Fix steps</button>
              <button className={classNames("tab", detailTab === "happened" && "active")} onClick={() => setDetailTab("happened")}>What happened</button>
              <button className={classNames("tab", detailTab === "evidence" && "active")} onClick={() => setDetailTab("evidence")}>Evidence</button>
              <button className={classNames("tab", detailTab === "artifacts" && "active")} onClick={() => setDetailTab("artifacts")}>Artifacts</button>
              <button className={classNames("tab", detailTab === "xml" && "active")} onClick={() => setDetailTab("xml")}>SAML XML</button>
            </div>
          </div>
          <div className="detail">
            {selectedFinding ? (
              <>
                <div className="detail-head">
                  <div className="detail-title">
                    <SeverityPill severity={selectedFinding.severity} />
                    <OwnerPill owner={selectedFinding.likelyOwner} />
                    {selectedFinding.confidenceLevel && <ConfidenceBadge level={selectedFinding.confidenceLevel} />}
                    {selectedFinding.isAmbiguous && <AmbiguityBadge />}
                    <span>{selectedFinding.title}</span>
                  </div>
                  <div className="detail-meta mono">
                    {selectedFinding.protocol !== "unknown" ? selectedFinding.protocol : ""}{selectedFinding.protocol !== "unknown" ? " · " : ""}{selectedFinding.likelyOwner}
                  </div>
                </div>

                {detailTab === "fix" ? (
                  recipe ? (
                    <>
                      <PreFlightChecklist recipe={recipe} />
                      {(() => {
                        const allFields = [...new Set(recipe.sections.flatMap((s) => [...(s.kzeroFields ?? []), ...(s.fieldExpectations?.map((e) => e.field) ?? [])]))];
                        if (allFields.length === 0) return null;
                        const fieldStatuses = allFields.map((field) => {
                          const section = recipe.sections.find((s) => (s.kzeroFields ?? []).includes(field) || s.fieldExpectations?.some((e) => e.field === field));
                          const expectation = section?.fieldExpectations?.find((e) => e.field === field);
                          const variants = labelVariants(field);
                          const result = variants.find((v) => uiScan.results[v]?.found) ? uiScan.results[variants.find((v) => uiScan.results[v]?.found)!] : uiScan.results[field];
                          const match = expectation?.expected && result?.found ? (result.value ?? "") === expectation.expected : undefined;
                          return { field, match, found: result?.found };
                        });
                        const matchCount = fieldStatuses.filter((f) => f.match === true).length;
                        const mismatchCount = fieldStatuses.filter((f) => f.match === false).length;
                        const pendingCount = fieldStatuses.filter((f) => f.match === undefined).length;
                        if (matchCount === 0 && mismatchCount === 0 && pendingCount === 0) return null;
                        return (
                          <div className="diff-summary-card">
                            <div className="diff-summary-header">
                              <span className="diff-summary-title">Field Scan Summary</span>
                              <div className="diff-summary-stats">
                                {matchCount > 0 && <span className="status-match">✅ {matchCount} match{matchCount !== 1 ? "es" : ""}</span>}
                                {mismatchCount > 0 && <span className="status-mismatch">❌ {mismatchCount} mismatch{mismatchCount !== 1 ? "es" : ""}</span>}
                                {pendingCount > 0 && <span className="status-pending">⏳ {pendingCount} pending</span>}
                              </div>
                            </div>
                            {mismatchCount > 0 && (
                              <div className="diff-summary-items">
                                {fieldStatuses.filter((f) => f.match === false).map((f) => (
                                  <div key={f.field} className="diff-summary-item" onClick={() => requestUiHighlight(labelVariants(f.field))} style={{ cursor: "pointer" }}>
                                    <span className="diff-summary-item-field">{f.field}</span>
                                    <span className="diff-summary-item-status mismatch">❌ mismatch</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })()}
                      <div className="sections">
                        {recipe.sections.map((section) => (
                          <div key={section.title} className="section">
                            <div className="section-title">
                              <OwnerPill owner={section.owner} />
                              <span>{section.title}</span>
                            </div>
                            {section.kzeroFields?.length ? (
                              <div className="fields mono">KZero fields: {section.kzeroFields.join(", ")}</div>
                            ) : null}
                            {section.vendorFields?.length ? (
                              <div className="fields mono">Vendor fields: {section.vendorFields.join(", ")}</div>
                            ) : null}
                            <ol className="steps">
                              {section.bullets.map((b, idx) => (
                                <li key={`${section.title}-${idx}`}>{b}</li>
                              ))}
                            </ol>
                            {mode === "devtools" && tabId >= 0 && section.kzeroFields?.length ? (
                              <div className="field-check">
                                <div className="field-check-head">
                                  <span className="mono">Check these fields on the current page</span>
                                  <button className="btn btn-ghost" onClick={() => {
                                    const labels = [...new Set([...(section.kzeroFields ?? []), ...(section.fieldExpectations?.map((e) => e.field) ?? [])])];
                                    requestUiScan(labels);
                                  }}>Check fields</button>
                                </div>
                                <table className="check-table">
                                  <thead><tr><th>Field</th><th>Expected</th><th>Current</th><th></th></tr></thead>
                                  <tbody>
                                    {[...new Set([...(section.kzeroFields ?? []), ...(section.fieldExpectations?.map((e) => e.field) ?? [])])].map((field) => {
                                      const expected = section.fieldExpectations?.find((e) => e.field === field)?.expected;
                                      const variants = labelVariants(field);
                                      const firstFound = variants.find((v) => uiScan.results[v]?.found);
                                      const result = firstFound ? uiScan.results[firstFound] : uiScan.results[field];
                                      const sensitive = Boolean(section.fieldExpectations?.find((e) => e.field === field)?.sensitive) || isSensitiveField(field);
                                      const rawCurrent = result?.found ? result.value ?? "" : "";
                                      const current = result ? result.found ? displayValue(rawCurrent, showRaw, sensitive) : "(not found)" : "(not checked)";
                                      const expectedShown = expected ? displayValue(expected, showRaw, sensitive) : "-";
                                      const match = expected && result?.found ? (result.value ?? "") === expected : undefined;
                                      return (
                                        <tr key={`${section.title}-${field}`}>
                                          <td className="mono">{field}</td>
                                          <td className="mono">{expectedShown}</td>
                                          <td className={classNames("mono", match === false && "bad")}>{current}</td>
                                          <td><button className="mini" onClick={() => requestUiHighlight(variants)}>Locate</button></td>
                                        </tr>
                                      );
                                    })}
                                  </tbody>
                                </table>
                                <div className="note">Tip: open the KZero Passwordless admin screen for this tenant in this same tab, then click <span className="mono">Check fields</span>.</div>
                              </div>
                            ) : null}
                            {section.copySnippets?.length ? (
                              <div className="copy-row">
                                {section.copySnippets.map((snip) => (
                                  <button key={snip.label} className="btn btn-ghost" onClick={() => copyText(showRaw ? snip.value : snip.sensitive ? "***" : snip.value)}
                                    title={snip.sensitive && !showRaw ? "Enable Raw values to copy" : "Copy"}>Copy: {snip.label}</button>
                                ))}
                              </div>
                            ) : null}
                          </div>
                        ))}
                      </div>
                      <div className="section">
                        <div className="section-title">
                          <Pill tone="verify">VERIFY</Pill>
                          <span>Verify</span>
                        </div>
                        <ol className="steps">
                          {recipe.verify.map((b, idx) => (
                            <li key={`verify-${idx}`}>{b}</li>
                          ))}
                        </ol>
                      </div>
                    </>
                  ) : (
                    <div className="empty">
                      <div className="note">No step-by-step guide available for this finding yet.</div>
                      <div className="note">Try the <strong>What Happened</strong> tab for a plain-English explanation.</div>
                      <div className="note">Try the <strong>Evidence</strong> tab to see the raw data.</div>
                    </div>
                  )
                ) : null}

                {detailTab === "happened" ? (
                  <>
                    {recipe ? <PreFlightChecklist recipe={recipe} uiScan={uiScan} /> : null}
                    <div className="sections">
                      <div className="section">
                        <div className="section-title">
                          <Pill tone="note">WHAT HAPPENED</Pill>
                          <span>Explanation</span>
                        </div>
                        <div className="note" style={{ fontSize: 13, lineHeight: 1.6 }}>{selectedFinding.explanation}</div>
                        {ruleDoc ? (
                          <div className="note mono" style={{ marginTop: 8 }}>Why it matters: {ruleDoc.why}</div>
                        ) : null}
                      </div>
                      {selectedFinding.observed && selectedFinding.expected ? (
                        <div className="section">
                          <div className="section-title">
                            <Pill tone="evidence">COMPARISON</Pill>
                            <span>Expected vs observed</span>
                          </div>
                          <DiffLine label="Mismatch" observed={selectedFinding.observed} expected={selectedFinding.expected} />
                        </div>
                      ) : null}
                    </div>
                  </>
                ) : null}

                {detailTab === "evidence" ? (
                  <div className="sections">
                    <div className="section">
                      <div className="section-title">
                        <Pill tone="evidence">EVIDENCE</Pill>
                        <span>Evidence</span>
                      </div>
                      <ul className="evidence">
                        {selectedFinding.evidence.map((e, idx) => (
                          <li key={`e-${idx}`} className="mono">{e}</li>
                        ))}
                      </ul>
                      <div className="copy-row">
                        <button className="btn btn-ghost" onClick={() => copyText(JSON.stringify(selectedFinding, null, 2))}>Copy finding as JSON</button>
                      </div>
                    </div>
                    {recipe ? (
                      <div className="section">
                        <div className="section-title">
                          <Pill tone="next">NEXT</Pill>
                          <span>If still failing, capture this</span>
                        </div>
                        <ul className="evidence">
                          {recipe.nextEvidence.map((e, idx) => (
                            <li key={`n-${idx}`}>{e}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                  </div>
                ) : null}

                {detailTab === "artifacts" ? (
                  <div className="sections">
                    <div className="section">
                      <div className="section-title">
                        <Pill tone="artifact">ARTIFACTS</Pill>
                        <span>Key fields</span>
                      </div>
                      <table className="kv">
                        <tbody>
                          {getKeyFields(selectedEventForFinding).map(({ k, v }) => (
                            <tr key={k}>
                              <td className="kv-k mono">{k}</td>
                              <td className="kv-v mono">
                                <span>{v}</span>
                                <button className="mini" onClick={() => copyText(v)} title="Copy">Copy</button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="section">
                      <div className="section-title">
                        <Pill tone="raw">RAW</Pill>
                        <span>Normalized artifacts (redacted by default)</span>
                      </div>
                      <pre className="pre">
                        {JSON.stringify(selectedEventForFinding ? (showRaw ? selectedEventForFinding.artifacts : redactRecord(selectedEventForFinding.artifacts)) : {}, null, 2)}
                      </pre>
                    </div>
                  </div>
                ) : null}

                {detailTab === "xml" ? (
                  <div className="sections">
                    <div className="section">
                      <div className="section-title">
                        <Pill tone="xml">XML</Pill>
                        <span>SAML XPath inspector</span>
                      </div>
                      {xmlRows.length ? (
                        <div className="xpath">
                          {xmlRows.map((row) => (
                            <div key={row.id} className={classNames("xpath-row", row.highlight && "xpath-highlight")}>
                              <code className="mono">{row.path}</code>
                              <span className="mono">{showRaw ? row.value : String(redactRecord({ value: row.value }).value)}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="empty">No decoded SAML XML available for the selected event.</div>
                      )}
                    </div>
                  </div>
                ) : null}
              </>
            ) : (
              <div className="empty">Select a finding from the list to see details.</div>
            )}
          </div>
        </section>
      </div>
      {leftTab === "compare" && (
        <Compare
          history={history.map(h => ({ ...h, session: h.session ?? { tabId: h.tabId, active: false, rawEvents: [], normalizedEvents: [], findings: [] } }))}
          onClose={() => setShowCompare(false)}
        />
      )}
    </>
  );

  const narrowLayout = (
    <>
      <div className="narrow-tabs">
        <button className={classNames("tab", narrowTab === "timeline" && "active")} onClick={() => setLeftTab("timeline")}>Timeline</button>
        <button className={classNames("tab", narrowTab === "history" && "active")} onClick={() => setLeftTab("history")}>History</button>
        <button className={classNames("tab", narrowTab === "findings" && "active")} onClick={() => setLeftTab("findings")}>Findings</button>
        <button className={classNames("tab", narrowTab === "detail" && "active")} onClick={() => setLeftTab("detail")}>Detail</button>
        {history.length >= 2 && (
          <button className={classNames("tab", narrowTab === "compare" && "active")} onClick={() => setLeftTab("compare")}>Compare</button>
        )}
      </div>

      {narrowTab === "timeline" || narrowTab === "history" ? (
        <section className="pane pane-fill">
          <div className="pane-head">
            <div className="tab-row">
              <button className={classNames("tab", leftTab === "timeline" && "active")} onClick={() => setLeftTab("timeline")}>Timeline</button>
              <button className={classNames("tab", leftTab === "history" && "active")} onClick={() => setLeftTab("history")}>History</button>
            </div>
          </div>
          {leftTab === "timeline" ? (
            <ul className="list">
              {filteredEvents.map((event) => (
                <li key={event.id} className={classNames("row", `row-protocol-${event.protocol.toLowerCase()}`, selectedEvent?.id === event.id && "active")} onClick={() => setSelectedEventId(event.id)}>
                  <div className="row-main">
                    <div className="row-title">
                      <ProtocolPill protocol={event.protocol} />
                      <span className="mono">{event.kind}</span>
                    </div>
                    <div className="row-sub mono">{event.host}</div>
                  </div>
                  <div className="row-meta mono">
                    <span>{formatTime(event.timestamp)}</span>
                    <span className={classNames("http", (event.statusCode ?? 0) >= 400 && "http-bad")}>{event.statusCode ?? "-"}</span>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <ul className="list">
              {history.map((item) => (
                <li key={item.id} className={classNames("row", selectedHistoryId === item.id && "active")} onClick={() => void loadHistory(item.id)}>
                  <div className="row-main">
                    <div className="row-title"><span className="mono">{formatDate(item.startedAt)}</span></div>
                    <div className="row-sub">
                      <span className="mono">{item.protocolHints.join("/") || "-"}</span>
                      <span className="dot" />
                      <span className="mono">{item.findingCount} findings</span>
                    </div>
                  </div>
                  <div className="row-meta mono">Tab {item.tabId}</div>
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}

      {narrowTab === "findings" ? (
        <section className="pane pane-fill">
          <div className="pane-head"><h2>Findings</h2>{session?.active && <div className="live-badge"><span className="live-dot" />LIVE</div>}</div>
          {session?.findings.length === 0 && !session.active && <div className="empty">Start capture, run a login, and stop to see findings here.</div>}
          {session?.findings && session.findings.length > 0 && (
            <>
              {topDiagnosis ? (
                <div style={{ padding: "0 12px 8px" }}>
                  <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 6, fontWeight: 500, textTransform: "uppercase", letterSpacing: "0.06em" }}>Most critical</div>
                  <div className="top-card" onClick={() => { setSelectedFindingId(topDiagnosis.id); setLeftTab("detail"); }}>
                    <div className="top-title">
                      <SeverityPill severity={topDiagnosis.severity} />
                      <OwnerPill owner={topDiagnosis.likelyOwner} />
                      <span className="top-text">{topDiagnosis.title}</span>
                    </div>
                    <div className="top-sub">{topDiagnosis.explanation}</div>
                  </div>
                </div>
              ) : null}
              {session.findings.length > 1 && (
                <div className="severity-legend" style={{ margin: "0 12px 8px" }}>
                  <span><span style={{ color: "var(--err)" }}>●</span> <strong>Problem</strong></span>
                  <span><span style={{ color: "var(--warn)" }}>●</span> <strong>Warning</strong></span>
                  <span><span style={{ color: "var(--info)" }}>●</span> <strong>Notice</strong></span>
                </div>
              )}
              <ul className="list">
                {filteredFindings.map((finding) => (
                  <li key={finding.id} className={classNames("row", `finding-${finding.severity}`, selectedFinding?.id === finding.id && "active")}
                    onClick={() => { setSelectedFindingId(finding.id); setLeftTab("detail"); }}>
                    <div className="row-main">
                      <div className="row-title">
                        <SeverityPill severity={finding.severity} />
                        <OwnerPill owner={finding.likelyOwner} />
                        <span className="row-text">{finding.title}</span>
                      </div>
                      <div className="row-sub">{finding.explanation.slice(0, 65)}{finding.explanation.length > 65 ? "..." : ""}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      ) : null}

      {narrowTab === "detail" ? (
        <section className="pane pane-fill">
          <div className="pane-head">
            <h2>Detail</h2>
            <div className="tab-row">
              <button className={classNames("tab", detailTab === "fix" && "active")} onClick={() => setDetailTab("fix")}>Fix steps</button>
              <button className={classNames("tab", detailTab === "happened" && "active")} onClick={() => setDetailTab("happened")}>What happened</button>
              <button className={classNames("tab", detailTab === "evidence" && "active")} onClick={() => setDetailTab("evidence")}>Evidence</button>
              <button className={classNames("tab", detailTab === "artifacts" && "active")} onClick={() => setDetailTab("artifacts")}>Artifacts</button>
            </div>
          </div>
          <div className="detail">
            {selectedFinding ? (
              <>
                <div className="detail-head">
                  <div className="detail-title">
                    <SeverityPill severity={selectedFinding.severity} />
                    <OwnerPill owner={selectedFinding.likelyOwner} />
                    {selectedFinding.confidenceLevel && <ConfidenceBadge level={selectedFinding.confidenceLevel} />}
                    {selectedFinding.isAmbiguous && <AmbiguityBadge />}
                    <span>{selectedFinding.title}</span>
                  </div>
                </div>

                {detailTab === "fix" ? (
                  recipe ? (
                    <>
                      <PreFlightChecklist recipe={recipe} />
                      <div className="sections">
                        {recipe.sections.map((section) => (
                          <div key={section.title} className="section">
                            <div className="section-title">
                              <OwnerPill owner={section.owner} />
                              <span>{section.title}</span>
                            </div>
                            {section.kzeroFields?.length ? (
                              <div className="fields mono">KZero fields: {section.kzeroFields.join(", ")}</div>
                            ) : null}
                            {section.vendorFields?.length ? (
                              <div className="fields mono">Vendor fields: {section.vendorFields.join(", ")}</div>
                            ) : null}
                            <ol className="steps">
                              {section.bullets.map((b, idx) => (
                                <li key={`${section.title}-${idx}`}>{b}</li>
                              ))}
                            </ol>
                            {section.links?.length ? (
                              <div className="links-row">
                                {section.links.map((link, idx) => (
                                  <a key={`link-${idx}`} href={link.url} target="_blank" rel="noopener noreferrer" className="doc-link">
                                    {link.label}
                                  </a>
                                ))}
                              </div>
                            ) : null}
                            {section.copySnippets?.length ? (
                              <div className="copy-row">
                                {section.copySnippets.map((snip) => (
                                  <button key={snip.label} className="btn btn-ghost" onClick={() => copyText(showRaw ? snip.value : snip.sensitive ? "***" : snip.value)}>
                                    Copy: {snip.label}
                                  </button>
                                ))}
                              </div>
                            ) : null}
                          </div>
                        ))}
                      </div>
                      <div className="section">
                        <div className="section-title">
                          <Pill tone="verify">VERIFY</Pill>
                          <span>Verify</span>
                        </div>
                        <ol className="steps">
                          {recipe.verify.map((b, idx) => (
                            <li key={`verify-${idx}`}>{b}</li>
                          ))}
                        </ol>
                      </div>
                    </>
                  ) : (
                    <div className="empty">
                      <div className="note">No step-by-step guide available yet.</div>
                      <div className="note">Try <strong>What Happened</strong> for an explanation.</div>
                    </div>
                  )
                ) : null}

                {detailTab === "happened" ? (
                  <>
                    {recipe ? <PreFlightChecklist recipe={recipe} uiScan={uiScan} /> : null}
                    <div className="sections">
                      <div className="section">
                        <div className="section-title">
                          <Pill tone="note">WHAT HAPPENED</Pill>
                          <span>Explanation</span>
                        </div>
                        <div className="note" style={{ fontSize: 13, lineHeight: 1.6 }}>{selectedFinding.explanation}</div>
                        {ruleDoc ? (
                          <div className="note mono" style={{ marginTop: 8 }}>Why it matters: {ruleDoc.why}</div>
                        ) : null}
                      </div>
                      {selectedFinding.observed && selectedFinding.expected ? (
                        <div className="section">
                          <div className="section-title">
                            <Pill tone="evidence">COMPARISON</Pill>
                            <span>Expected vs observed</span>
                          </div>
                          <DiffLine label="Mismatch" observed={selectedFinding.observed} expected={selectedFinding.expected} />
                        </div>
                      ) : null}
                    </div>
                  </>
                ) : null}

                {detailTab === "evidence" ? (
                  <div className="sections">
                    <div className="section">
                      <div className="section-title">
                        <Pill tone="evidence">EVIDENCE</Pill>
                        <span>Evidence</span>
                      </div>
                      <ul className="evidence">
                        {selectedFinding.evidence.map((e, idx) => (
                          <li key={`e-${idx}`} className="mono">{e}</li>
                        ))}
                      </ul>
                      <div className="copy-row">
                        <button className="btn btn-ghost" onClick={() => copyText(JSON.stringify(selectedFinding, null, 2))}>Copy finding as JSON</button>
                      </div>
                    </div>
                    {recipe ? (
                      <div className="section">
                        <div className="section-title">
                          <Pill tone="next">NEXT</Pill>
                          <span>If still failing, capture this</span>
                        </div>
                        <ul className="evidence">
                          {recipe.nextEvidence.map((e, idx) => (
                            <li key={`n-${idx}`}>{e}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                  </div>
                ) : null}

                {detailTab === "artifacts" ? (
                  <div className="sections">
                    <div className="section">
                      <div className="section-title">
                        <Pill tone="artifact">ARTIFACTS</Pill>
                        <span>Key fields</span>
                      </div>
                      <table className="kv">
                        <tbody>
                          {getKeyFields(selectedEventForFinding).map(({ k, v }) => (
                            <tr key={k}>
                              <td className="kv-k mono">{k}</td>
                              <td className="kv-v mono">
                                <span>{v}</span>
                                <button className="mini" onClick={() => copyText(v)} title="Copy">Copy</button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="section">
                      <div className="section-title">
                        <Pill tone="raw">RAW</Pill>
                        <span>Normalized artifacts (redacted by default)</span>
                      </div>
                      <pre className="pre">
                        {JSON.stringify(selectedEventForFinding ? (showRaw ? selectedEventForFinding.artifacts : redactRecord(selectedEventForFinding.artifacts)) : {}, null, 2)}
                      </pre>
                    </div>
                  </div>
                ) : null}
              </>
            ) : (
              <div className="empty">Select a finding from the list to see details.</div>
            )}
          </div>
        </section>
      ) : null}

      {narrowTab === "compare" ? (
        <section className="pane pane-fill">
          <Compare
            history={history.map(h => ({ ...h, session: h.session ?? { tabId: h.tabId, active: false, rawEvents: [], normalizedEvents: [], findings: [] } }))}
            onClose={() => setShowCompare(false)}
          />
        </section>
      ) : null}
    </>
  );

  return (
    <div className="app-root">
      <header className="header-section">
        <div className="header-top">
          <KZeroWordmark height={28} />
          <button
            className="btn-icon-only"
            onClick={() => setShowSettings(true)}
            title="Settings (Alt+Shift+P)"
            aria-label="Settings"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"></circle>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
          </button>
          {settings && (
            <span className="scope-indicator">
              {settings.captureScope === "auth-only" && "Auth-only"}
              {settings.captureScope === "auth-plus-allowlist" && "Auth + allowlist"}
              {settings.captureScope === "full" && "Full capture"}
            </span>
          )}
        </div>
        <div className="page-indicator">
          <h1>KZero Passwordless SSO Tracer</h1>
          <div className="current-tab-display">
            <span className="current-tab-label">View:</span>
            <button 
              className={classNames("tab-pill", narrowTab === "timeline" && "active")} 
              onClick={() => setLeftTab("timeline")}
            >
              Timeline
            </button>
            <button 
              className={classNames("tab-pill", narrowTab === "history" && "active")} 
              onClick={() => setLeftTab("history")}
            >
              History
            </button>
            <button 
              className={classNames("tab-pill", narrowTab === "findings" && "active")} 
              onClick={() => setLeftTab("findings")}
            >
              Findings
            </button>
            <button 
              className={classNames("tab-pill", narrowTab === "detail" && "active")} 
              onClick={() => setLeftTab("detail")}
            >
              Detail
            </button>
          </div>
        </div>
        <div className="browser-tab-info">
          <span className="tab-info-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
              <line x1="3" y1="9" x2="21" y2="9"></line>
            </svg>
          </span>
          <div className="tab-picker-container">
            <button className="tab-picker-button" onClick={openTabPicker} title="Switch tab">
              <span className="tab-info-url" title={targetTab?.url ?? "No tab selected"}>
                {targetTab?.url ? new URL(targetTab.url).hostname : "No tab selected"}
              </span>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="6 9 12 15 18 9"></polyline>
              </svg>
            </button>
            {showTabPicker && (
              <div className="tab-picker-dropdown">
                <div className="tab-picker-header">Switch to tab</div>
                {availableTabs.length === 0 ? (
                  <div className="tab-picker-empty">No tabs available</div>
                ) : (
                  availableTabs.map(tab => (
                    <button
                      key={tab.id}
                      className={classNames("tab-picker-item", targetTab?.id === tab.id && "active")}
                      onClick={() => switchToTab(tab.id)}
                    >
                      <span className="tab-picker-title">{tab.title}</span>
                      <span className="tab-picker-host">{tab.url ? new URL(tab.url).hostname : ""}</span>
                    </button>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      </header>

      <div className="toolbar-row">
        <div className="toolbar-search">
          <input
            className="search"
            placeholder="Search findings and events..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="toolbar-actions">
          <button
            className={classNames("btn", session?.active ? "btn-stop" : "btn-start")}
            onClick={session?.active ? stopCapture : startCapture}
            title={session?.active ? "Stop capture (S)" : "Start capture (S)"}
          >
            {session?.active ? "Stop" : "Start"}
          </button>
          {session && (
            <button className="btn btn-ghost" onClick={clearSession} title="Clear current session">Clear</button>
          )}
          {session && settings && settings.captureScope !== "auth-only" && (
            <span className={`scope-indicator scope-${settings.captureScope.replace("_", "-")}`}>
              {settings.captureScope === "auth-plus-allowlist" ? "Auth + allowlist" : "Full capture"}
            </span>
          )}
          {session && (
            <div className="export-menu" ref={exportMenuRef}>
              <button className="btn btn-ghost" onClick={() => setExportMenuOpen(o => !o)} title="Export session">
                Export
              </button>
              {exportMenuOpen && (
                <div className="export-dropdown">
                  <div className="export-mode-selector">
                    <label className="export-mode-label">Export mode:</label>
                    <select 
                      className="export-mode-select" 
                      value={exportMode} 
                      onChange={(e) => {
                        const mode = e.target.value as ExportMode;
                        if (mode === "raw") {
                          setShowRawWarning(true);
                        } else {
                          setExportMode(mode);
                        }
                      }}
                    >
                      <option value="summary">Summary (safest)</option>
                      <option value="sanitized">Sanitized trace (recommended)</option>
                      <option value="raw">Full raw trace (sensitive)</option>
                    </select>
                  </div>
                  {exportMode === "sanitized" && (
                    <label className="export-option">
                      <input 
                        type="checkbox" 
                        checked={includePostLogin} 
                        onChange={(e) => setIncludePostLogin(e.target.checked)} 
                      />
                      Include post-login activity
                    </label>
                  )}
                  <div className="export-divider" />
                  <button onClick={() => { setExportMenuOpen(false); setPendingExport("json"); }}>Download JSON</button>
                  <button onClick={() => { setExportMenuOpen(false); setPendingExport("har"); }}>HAR (browser DevTools)</button>
                  <button onClick={() => { setExportMenuOpen(false); setPendingExport("csv"); }}>CSV (findings only)</button>
                  <button onClick={() => { setExportMenuOpen(false); setPendingExport("csv-summary"); }}>CSV (summary)</button>
                  <button onClick={() => { setExportMenuOpen(false); setPendingExport("shareable"); }}>Shareable trace (.txt)</button>
                  <button onClick={() => { setExportMenuOpen(false); setPendingExport("shareable-link"); }}>Shareable link (clipboard)</button>
                </div>
              )}
            </div>
          )}
          {history.length >= 2 && (
            <button className="btn btn-ghost" onClick={() => setShowCompare(true)} title="Compare two sessions">Compare</button>
          )}
          {session?.active && (
            <div className="live-badge">
              <span className="live-dot" />
              LIVE
            </div>
          )}
          {isNarrow && (
            <button className="btn btn-ghost" onClick={openPopup} title="Open in new window">Pop out</button>
          )}
        </div>
      </div>

      <div className="toolbar-secondary">
        <div className="filter-row">
          <label className="filter-label">Filter:</label>
          <select className="filter-select" value={ruleFilter} onChange={(e) => setRuleFilter(e.target.value)}>
            <option value="">All findings</option>
            {RULE_CATALOG.map((r) => (
              <option key={r.ruleId} value={r.ruleId}>{r.ruleId}</option>
            ))}
          </select>
          <label className="filter-label">Raw:</label>
          <input type="checkbox" checked={showRaw} onChange={(e) => setShowRaw(e.target.checked)} />
        </div>
        {selectedFinding?.eventId && (
          <span className="event-badge">
            Linked event: {selectedFinding.eventId}
          </span>
        )}
      </div>

      <main className={classNames("main", isNarrow ? "main-narrow" : "main-wide")}>
        {showCompare ? (
          <Compare
            history={history.map(h => ({ ...h, session: h.session ?? { tabId: h.tabId, active: false, rawEvents: [], normalizedEvents: [], findings: [] } }))}
            onClose={() => setShowCompare(false)}
          />
        ) : isNarrow ? narrowLayout : wideLayout}
      </main>

      {showSettings && settings && (
        <div className="modal-overlay" onClick={e => { if (e.target === e.currentTarget) setShowSettings(false); }}>
          <SettingsPanel
            onClose={() => setShowSettings(false)}
            onSave={setSettings}
          />
        </div>
      )}

      {pendingExport && session && (
        <ConfirmDialog
          title="Export session?"
          message="This will export the current session including all captured events and findings. The file will be saved to your downloads folder."
          confirmLabel="Export"
          onConfirm={async () => {
            const fmt = pendingExport;
            setPendingExport(null);
            await doExport(fmt);
          }}
          onCancel={() => setPendingExport(null)}
        />
      )}

      {showRawWarning && (
        <ConfirmDialog
          title="Export full raw trace?"
          message="⚠️ This export contains complete authentication data including raw SAML/XML payloads, full tokens and secrets, and user identifiers. This should only be shared with trusted internal teams for troubleshooting. Continue with Full raw export?"
          confirmLabel="Export Full Raw"
          onConfirm={() => {
            setShowRawWarning(false);
            setExportMode("raw");
            setPendingExport("json");
          }}
          onCancel={() => setShowRawWarning(false)}
        />
      )}

      {pendingInjection && (
        <ConfirmDialog
          title="Scan page fields?"
          message="This will inject a scanner into the current tab to read visible form field labels and values. No data leaves your browser."
          confirmLabel="Scan"
          onConfirm={() => {
            const labels = pendingInjection.labels;
            setPendingInjection(null);
            requestUiScan(labels);
          }}
          onCancel={() => setPendingInjection(null)}
        />
      )}

      {settings && !settings.hasSeenScopeNotice && onboardingDone && (
        <div className="scope-notice-banner">
          <span>Capture scope is now configurable. Recommended default is Auth-only for smaller, safer traces. Your current setting was preserved.</span>
          <button className="btn btn-sm btn-primary" onClick={() => {
            saveSettings({ ...settings, captureScope: "auth-only", hasSeenScopeNotice: true });
            setSettings({ ...settings, captureScope: "auth-only", hasSeenScopeNotice: true });
          }}>Switch to Auth-only</button>
          <button className="btn btn-sm btn-ghost" onClick={() => {
            saveSettings({ ...settings, hasSeenScopeNotice: true });
            setSettings({ ...settings, hasSeenScopeNotice: true });
          }}>Keep Full Capture</button>
        </div>
      )}

    </div>
  );
};
