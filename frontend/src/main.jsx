
function renderBadgeList(value) {
  const items = Array.isArray(value) ? value : [];

  if (items.length === 0) {
    return <span className="muted">Not classified</span>;
  }

  return (
    <div className="badge-list">
      {items.map(item => (
        <span key={item} className="role-badge">{item}</span>
      ))}
    </div>
  );
}


function formatAuditCurrentStateValue(value) {
  if (value === null || value === undefined || value === "") return "";

  if (Array.isArray(value)) {
    return value.map(formatAuditCurrentStateValue).filter(Boolean).join("\n");
  }

  if (typeof value === "object") {
    const preferred = [
      "policy_id",
      "document_id",
      "evidence_id",
      "finding_id",
      "filename",
      "collector",
      "asset_id",
      "title",
      "name",
      "severity",
      "status",
      "collected_at",
      "created_at"
    ];

    const parts = [];

    for (const key of preferred) {
      if (value[key] !== null && value[key] !== undefined && value[key] !== "") {
        parts.push(`${key}: ${formatAuditCurrentStateValue(value[key])}`);
      }
    }

    if (parts.length > 0) {
      return parts.join(" | ");
    }

    return Object.entries(value)
      .map(([key, itemValue]) => `${key}: ${formatAuditCurrentStateValue(itemValue)}`)
      .join(" | ");
  }

  return isTimestampValue(value) ? formatDateTime(value) : String(value);
}

function formatAuditCurrentState(currentState) {
  if (!currentState || typeof currentState !== "object") return "";

  return Object.entries(currentState)
    .map(([key, value]) => {
      const rendered = formatAuditCurrentStateValue(value);
      return `${key}: ${rendered || "None"}`;
    })
    .join("\n");
}

function normalizeAuditRecommendations(items) {
  return (items || []).map((item) => ({
    ...item,
    current_state: formatAuditCurrentState(item.current_state)
  }));
}


function renderAnyValue(value) {
  if (value === null || value === undefined || value === "") return "";

  if (Array.isArray(value)) {
    if (value.length === 0) return "";
    return (
      <ul className="modal-value-list">
        {value.map((item, index) => (
          <li key={index}>{renderAnyValue(item)}</li>
        ))}
      </ul>
    );
  }

  if (typeof value === "object") {
    return (
      <div className="modal-object-value">
        {Object.entries(value).map(([key, itemValue]) => (
          <div key={key} className="modal-object-row">
            <span className="modal-object-key">{key}:</span>{" "}
            <span className="modal-object-detail">{renderAnyValue(itemValue)}</span>
          </div>
        ))}
      </div>
    );
  }

  return isTimestampValue(value) ? formatDateTime(value) : String(value);
}


function renderCurrentStateValue(value) {
  if (value === null || value === undefined || value === "") {
    return "";
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "";
    }

    return (
      <div className="current-state-array">
        {value.map((item, index) => {
          if (typeof item === "object" && item !== null) {
            return (
              <div key={index} className="current-state-array-object">
                {Object.entries(item).map(([k, v]) => (
                  <div key={k} className="current-state-array-row">
                    <strong>{k}:</strong> {renderCurrentStateValue(v)}
                  </div>
                ))}
              </div>
            );
          }

          return (
            <div key={index} className="current-state-list-item">
              {renderCurrentStateValue(item)}
            </div>
          );
        })}
      </div>
    );
  }

  if (typeof value === "object") {
    const label =
      value.evidence_id ||
      value.finding_id ||
      value.policy_id ||
      value.document_id ||
      value.control_id ||
      value.filename ||
      value.name ||
      value.title ||
      value.collector ||
      "";

    const details = Object.entries(value)
      .filter(([key, itemValue]) => {
        if (itemValue === null || itemValue === undefined || itemValue === "") return false;
        if (["raw", "content", "payload"].includes(key)) return false;
        return true;
      })
      .map(([key, itemValue]) => {
        if (typeof itemValue === "object") {
          return `${key}: ${JSON.stringify(itemValue)}`;
        }
        return `${key}: ${itemValue}`;
      });

    return (
      <div className="current-state-object">
        {label && <div className="current-state-object-title">{label}</div>}
        {details.map((line, index) => (
          <div key={index} className="current-state-object-detail">
            {line}
          </div>
        ))}
      </div>
    );
  }

  return isTimestampValue(value) ? formatDateTime(value) : String(value);
}

function renderCurrentState(currentState) {
  if (!currentState || typeof currentState !== "object") {
    return "";
  }

  return (
    <div className="current-state-rendered">
      {Object.entries(currentState).map(([key, value]) => (
        <div key={key} className="current-state-section">
          <div className="current-state-key">{key}:</div>
          <div className="current-state-value">
            {renderCurrentStateValue(value)}
          </div>
        </div>
      ))}
    </div>
  );
}




import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import ContinuousComplianceState from "./pages/continuous-compliance/ContinuousComplianceState.jsx";
import IAM from "./pages/IAM";
import UserManagement from "./pages/UserManagement";
import AccessReviews from "./pages/AccessReviews";
import AuthGate from "./AuthGate";
import { API, apiFetch } from "./auth";
import { formatDateTime, isTimestampValue } from "./dateTime";
import { hasCapability } from "./capabilities";
import { downloadCsv } from "./tableTools";
import { PaginationControls, SortableHeader, useTableView } from "./tableView";


function normalizeComplianceScores(scorePayload) {
  if (!scorePayload) return [];

  const preferredOrder = ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"];

  let rawItems = [];

  if (Array.isArray(scorePayload)) {
    rawItems = scorePayload;
  } else if (Array.isArray(scorePayload.scores)) {
    rawItems = scorePayload.scores;
  } else if (Array.isArray(scorePayload.framework_scores)) {
    rawItems = scorePayload.framework_scores;
  } else if (scorePayload.framework_scores && typeof scorePayload.framework_scores === "object") {
    rawItems = Object.entries(scorePayload.framework_scores).map(([framework, value]) => ({
      framework,
      ...(value || {})
    }));
  } else if (typeof scorePayload === "object") {
    rawItems = Object.entries(scorePayload)
      .filter(([key, value]) => value && typeof value === "object")
      .map(([framework, value]) => ({
        framework,
        ...(value || {})
      }));
  }

  const byFramework = {};

  rawItems.forEach((item) => {
    const framework = item.framework || item.name || item.id;
    if (!framework) return;

    byFramework[framework] = {
      framework,
      score:
        item.score ??
        item.readiness_score ??
        item.compliance_score ??
        item.value ??
        0,
      status:
        item.status ??
        item.readiness_status ??
        item.audit_status ??
        "unknown"
    };
  });

  return Object.values(byFramework).sort((a, b) => {
    const ai = preferredOrder.indexOf(a.framework);
    const bi = preferredOrder.indexOf(b.framework);

    if (ai === -1 && bi === -1) return a.framework.localeCompare(b.framework);
    if (ai === -1) return 1;
    if (bi === -1) return -1;

    return ai - bi;
  });
}



const DASHBOARD_CACHE_KEY = "compliance_manager_dashboard_cache_v1";
const ACTIVE_PAGE_KEY = "compliance_manager_active_page_v1";
const VALID_PAGES = new Set([
  "dashboard",
  "iam",
  "assets",
  "collectors",
  "changelog",
  "users",
  "access-reviews"
]);

const CHANGELOG_COLUMNS = [
  { key: "timestamp", label: "Timestamp" },
  { key: "event_type", label: "Event Type" },
  { key: "asset_id", label: "Asset" },
  { key: "summary", label: "Summary" },
  { key: "note", label: "Note" },
  { key: "jira_url", label: "Jira Ticket" },
  { key: "actions", label: "Actions", sortable: false }
];

function loadActivePage() {
  try {
    const page = sessionStorage.getItem(ACTIVE_PAGE_KEY);
    return VALID_PAGES.has(page) ? page : "dashboard";
  } catch {
    return "dashboard";
  }
}

function loadDashboardCache() {
  try {
    return JSON.parse(localStorage.getItem(DASHBOARD_CACHE_KEY) || "null");
  } catch {
    return null;
  }
}

function saveDashboardCache(data) {
  try {
    localStorage.setItem(DASHBOARD_CACHE_KEY, JSON.stringify({
      ...data,
      cached_at: new Date().toISOString()
    }));
  } catch {
    // Ignore browser storage failures.
  }
}

const ASSET_ROLE_OPTIONS = [
  "application_server",
  "web_automation_server",
  "web_automation_orchestrator_server",
  "web_server",
  "database_server",
  "monitoring_server",
  "central_log_server",
  "siem_server",
  "ci_cd_server",
  "identity_provider",
  "sftp_server",
  "storage_server",
  "container_host",
  "jumpbox",
  "backup_server",
  "vulnerability_scanner",
  "firewall",
  "dns_server",
  "mail_server"
];

const DATA_CLASSIFICATION_OPTIONS = [
  "pci",
  "pii",
  "financial",
  "confidential",
  "internal",
  "public"
];

function toggleListValue(list, value) {
  const current = Array.isArray(list) ? list : [];
  return current.includes(value)
    ? current.filter(item => item !== value)
    : [...current, value];
}


function groupByAsset(items) {
  return items.reduce((acc, item) => {
    const asset = item.asset || item.asset_id || "unknown";
    if (!acc[asset]) acc[asset] = [];
    acc[asset].push(item);
    return acc;
  }, {});
}

function extractCollectorName(title) {
  const match = title?.match(/collector failed: (.+)$/i);
  return match ? match[1].trim() : null;
}

function filterStaleFindings(findings, evidence) {
  const validEvidenceMap = new Set(
    evidence
      .filter(item => item.validated === true)
      .map(item => `${item.asset_id}:${item.collector}`)
  );

  return findings.filter(finding => {
    const collectorName = extractCollectorName(finding.title);

    if (!collectorName) {
      return true;
    }

    const key = `${finding.asset_id}:${collectorName}`;
    return !validEvidenceMap.has(key);
  });
}

function formatCell(value) {
  if (value === null || value === undefined) return "";

  if (isTimestampValue(value)) return formatDateTime(value);

  if (Array.isArray(value)) {
    if (value.length === 0) return "None";

    return value.map(item => {
      if (item === null || item === undefined) return "";

      if (typeof item === "object") {
        return Object.entries(item)
          .filter(([, v]) => v !== null && v !== undefined && v !== "")
          .map(([k, v]) => `${k}: ${isTimestampValue(v) ? formatDateTime(v) : typeof v === "object" ? JSON.stringify(v) : String(v)}`)
          .join(" | ");
      }

      return String(item);
    }).join("\n");
  }

  if (typeof value === "object") {
    return Object.entries(value)
      .map(([k, v]) => `${k}: ${isTimestampValue(v) ? formatDateTime(v) : Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)}`)
      .join("\n");
  }

  return String(value);
}

function DetailList({ items, emptyText }) {
  if (!items || items.length === 0) {
    return <span className="muted">{emptyText || "None"}</span>;
  }

  return (
    <ul className="detail-list">
      {items.map((item, idx) => (
        <li key={idx}>
          {Object.entries(item).map(([key, value]) => (
            <div key={key}>
              <strong>{key}:</strong> {formatCell(value)}
            </div>
          ))}
        </li>
      ))}
    </ul>
  );
}

function ControlReadinessDetails({ record }) {
  return (
    <div className="control-detail-view">
      <h3>{record.control_id} — {record.title}</h3>

      <div className="detail-grid">
        <div><strong>Domain:</strong> {record.domain}</div>
        <div><strong>Status:</strong> {record.status}</div>
        <div><strong>Score:</strong> {record.score}</div>
      </div>

      <h4>Policies</h4>
      <DetailList items={record.policies || []} emptyText="No mapped policies" />

      <h4>Validated Evidence</h4>
      <DetailList items={record.evidence || []} emptyText="No validated evidence" />

      <h4>Framework Mappings</h4>
      <pre className="detail-pre">{JSON.stringify(record.framework_mappings || {}, null, 2)}</pre>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <section className="card">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function DataTable({
  columns,
  rows,
  emptyText = "No records found.",
  exportFilename = "dashboard-data.csv"
}) {
  const [query, setQuery] = useState("");
  const searchableColumns = columns.filter(column => column.key !== "actions");
  const table = useTableView(rows, query, columns);

  return (
    <>
    <div className="table-toolbar">
      <input
        type="search"
        value={query}
        onChange={event => setQuery(event.target.value)}
        placeholder="Search this table"
        aria-label="Search this table"
      />
      <span className="muted">{table.filteredRows.length} of {(rows || []).length}</span>
      <button
        className="secondary"
        disabled={table.filteredRows.length === 0}
        onClick={() => downloadCsv(exportFilename, searchableColumns, table.sortedRows)}
      >
        Export CSV
      </button>
    </div>
    <table>
      <thead>
        <tr>
          {columns.map(col => <SortableHeader key={col.key} column={col} sort={table.sort} onSort={table.toggleSort} />)}
        </tr>
      </thead>
      <tbody>
        {table.filteredRows.length === 0 ? (
          <tr>
            <td colSpan={columns.length}>{emptyText}</td>
          </tr>
        ) : (
          table.pagedRows.map((row, idx) => (
            <tr key={idx}>
              {columns.map(col => (
                <td key={col.key}>
                  {col.render
                    ? col.render(row)
                    : renderCurrentStateValue(row[col.key])}
                </td>
              ))}
            </tr>
          ))
        )}
      </tbody>
    </table>
    <PaginationControls {...table} total={table.sortedRows.length} visibleCount={table.pagedRows.length} />
    </>
  );
}

function GroupedRecords({ rows, noun, onOpen }) {
  const [query, setQuery] = useState("");
  const keys = [...new Set((rows || []).flatMap(row => Object.keys(row || {})))];
  const columns = keys.map(key => ({ key, label: key }));
  const table = useTableView(rows, query, columns);
  const groupedRows = Object.entries(groupByAsset(table.sortedRows)).map(([asset, items]) => ({ asset, items }));
  const groupColumns = [{ key: "asset", label: "Asset" }, { key: "count", label: "Records", sortValue: row => row.items.length }];
  const groups = useTableView(groupedRows, "", groupColumns, { key: "asset", direction: "asc" });

  return (
    <>
      <div className="table-toolbar">
        <input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder={`Search ${noun.toLowerCase()}`} />
        <span className="muted">{table.filteredRows.length} of {(rows || []).length}</span>
        <button className="secondary" disabled={!table.filteredRows.length} onClick={() => downloadCsv(`${noun.toLowerCase()}.csv`, columns, table.sortedRows)}>Export CSV</button>
      </div>
      {groups.filteredRows.length === 0 ? <p className="muted">No matching records.</p> : groups.pagedRows.map(({ asset, items }) => (
        <button key={asset} style={{ display: "block", marginBottom: "10px" }} onClick={() => onOpen(asset, items)}>
          {asset} ({items.length})
        </button>
      ))}
      <PaginationControls {...groups} total={groups.sortedRows.length} visibleCount={groups.pagedRows.length} />
    </>
  );
}

function App({ currentUser, onLogout }) {
  const canManage = hasCapability(currentUser, "manage_dashboard");
  const canGenerateReports = hasCapability(currentUser, "generate_reports");
  const canExportAuditData = hasCapability(currentUser, "export_audit_data");
  const canEditChangelog = hasCapability(currentUser, "edit_changelog");
  const canManageUsers = hasCapability(currentUser, "manage_users");
  const canReviewAccess = hasCapability(currentUser, "review_access");
  const canManageAccessReviews = hasCapability(currentUser, "manage_access_reviews");
  const canViewIam = hasCapability(currentUser, "view_iam");
  const [health, setHealth] = useState(null);
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [modalData, setModalData] = useState(null);
  const [modalTitle, setModalTitle] = useState("");
  const [packageUpdateConfirm, setPackageUpdateConfirm] = useState(null);
  const [bulkPackageUpdateConfirm, setBulkPackageUpdateConfirm] = useState(null);
  const [scores, setScores] = useState({});
  const [environments, setEnvironments] = useState(["all"]);
  const [selectedEnvironment, setSelectedEnvironment] = useState("all");
  const [collectors, setCollectors] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [collectorCoverage, setCollectorCoverage] = useState(null);
  const [documents, setDocuments] = useState([]);
  const [controls, setControls] = useState([]);
  const [controlReadiness, setControlReadiness] = useState({ summary: {}, framework_scores: {}, controls: [] });
  const [auditReadiness, setAuditReadiness] = useState({ frameworks: [] });
  const [remediations, setRemediations] = useState([]);
  const [policyFile, setPolicyFile] = useState(null);
  const [policyScope, setPolicyScope] = useState("");
  const [documentFile, setDocumentFile] = useState(null);
  const [documentScope, setDocumentScope] = useState("");
  const [replacePolicyFiles, setReplacePolicyFiles] = useState({});
  const [replaceDocumentFiles, setReplaceDocumentFiles] = useState({});
  const [mappingModal, setMappingModal] = useState(null);
  const [selectedMappings, setSelectedMappings] = useState({});
  const [chatMessage, setChatMessage] = useState("");
  const [chatResponse, setChatResponse] = useState("");

  const emptyAgentForm = {
    asset_id: "",
    hostname: "",
    address: "",
    username: "",
    password: "",
    port: 22,
    environment: "test",
    os_family: "ubuntu",
    asset_roles: [],
    data_classification: []
  };

  const [showDeployModal, setShowDeployModal] = useState(false);
  const [activePage, setActivePage] = useState(loadActivePage);
  const cacheHydratedRef = useRef(false);
  const [assetDetails, setAssetDetails] = useState({ assets: [] });
  const [assetDetailsLoaded, setAssetDetailsLoaded] = useState(false);
  const [assetDetailsLoading, setAssetDetailsLoading] = useState(false);
  const [assetDetailsError, setAssetDetailsError] = useState("");
  const [changelogEvents, setChangelogEvents] = useState([]);
  const [changelogQuery, setChangelogQuery] = useState("");
  const changelogTable = useTableView(
    changelogEvents,
    changelogQuery,
    CHANGELOG_COLUMNS,
    { key: "timestamp", direction: "desc" }
  );
  const [changelogNoteDrafts, setChangelogNoteDrafts] = useState({});
  const [agentLifecycle, setAgentLifecycle] = useState([]);
  const [agentMode, setAgentMode] = useState("deploy");
  const [agentForm, setAgentForm] = useState(emptyAgentForm);
  const [dashboardLoadState, setDashboardLoadState] = useState({});

  function updateDashboardCache(partial) {
    saveDashboardCache({
      ...(loadDashboardCache() || {}),
      ...partial
    });
  }

  async function refreshDashboard(signal) {
    if (!cacheHydratedRef.current) {
      const cached = loadDashboardCache();

      if (cached) {
        setHealth(cached.health || { status: "cached" });
        setAssets(Array.isArray(cached.assets) ? cached.assets : []);
        setFindings(Array.isArray(cached.findings) ? cached.findings : []);
        setEvidence(Array.isArray(cached.evidence) ? cached.evidence : []);
        setScores(cached.scores || {});
        setCollectors(Array.isArray(cached.collectors) ? cached.collectors : []);
        setEnvironments(Array.isArray(cached.environments) ? cached.environments : ["all"]);
        setPolicies(Array.isArray(cached.policies) ? cached.policies : []);
        setDocuments(Array.isArray(cached.documents) ? cached.documents : []);
        setRemediations(Array.isArray(cached.remediations) ? cached.remediations : []);
        setControls(Array.isArray(cached.controls) ? cached.controls : []);
        setControlReadiness(cached.controlReadiness || { summary: {}, framework_scores: {}, controls: [] });
        setAuditReadiness(cached.auditReadiness || { frameworks: [] });
        setCollectorCoverage(cached.collectorCoverage || { summary: {}, collectors: [] });
        setAgentLifecycle(Array.isArray(cached.agentLifecycle) ? cached.agentLifecycle : []);
        setAssetDetails(cached.assetDetails || { assets: [] });
      }

      cacheHydratedRef.current = true;
    }

    const requestJson = async (path) => {
      const response = await apiFetch(`${API}${path}`, { signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    };

    const load = async (key, request, apply) => {
      setDashboardLoadState(state => ({ ...state, [key]: { status: "loading" } }));
      try {
        const data = await request();
        if (!signal?.aborted) {
          apply(data);
          setDashboardLoadState(state => ({ ...state, [key]: { status: "ready" } }));
        }
      } catch (error) {
        if (error.name === "AbortError") throw error;
        console.error(`Failed to load dashboard resource: ${key}`, error);
        setDashboardLoadState(state => ({
          ...state,
          [key]: { status: "error", error: String(error.message || error) }
        }));
      }
    };

    const tasks = [
      load("system", () => requestJson("/api/health"), data => { setHealth(data); updateDashboardCache({ health: data }); }),
      load("assets", () => requestJson("/api/assets/"), data => { const rows = Array.isArray(data) ? data : []; setAssets(rows); updateDashboardCache({ assets: rows }); }),
      load("findings", () => Promise.all([requestJson("/api/findings/"), requestJson("/api/evidence/")]), ([findingData, evidenceData]) => { const evidenceRows = Array.isArray(evidenceData) ? evidenceData : []; const rows = filterStaleFindings(Array.isArray(findingData) ? findingData : [], evidenceRows); setFindings(rows); setEvidence(evidenceRows); updateDashboardCache({ findings: rows, evidence: evidenceRows }); }),
      load("scores", () => Promise.all([requestJson(`/api/compliance/score?environment=${selectedEnvironment}`), requestJson("/api/compliance/control-readiness/")]), ([scoreData, readinessData]) => { const readiness = readinessData || { summary: {}, framework_scores: {}, controls: [] }; const merged = { ...(scoreData || {}), ...(readiness.framework_scores || {}) }; setScores(merged); setControlReadiness(readiness); updateDashboardCache({ scores: merged, controlReadiness: readiness }); }),
      load("collectors", () => requestJson("/api/collector-mappings/"), data => { const rows = data.collectors || []; setCollectors(rows); updateDashboardCache({ collectors: rows }); }),
      load("environments", () => requestJson("/api/compliance/environments"), data => { const rows = data.environments || ["all"]; setEnvironments(rows); updateDashboardCache({ environments: rows }); }),
      load("policies", () => requestJson("/api/policies/"), data => { const rows = Array.isArray(data) ? data : []; setPolicies(rows); updateDashboardCache({ policies: rows }); }),
      load("documents", () => requestJson("/api/documents/"), data => { const rows = Array.isArray(data) ? data : []; setDocuments(rows); updateDashboardCache({ documents: rows }); }),
      load("remediations", () => requestJson("/api/remediations/"), data => { const rows = Array.isArray(data) ? data : []; setRemediations(rows); updateDashboardCache({ remediations: rows }); }),
      load("controls", () => requestJson("/api/controls/"), data => { const rows = Array.isArray(data) ? data : []; setControls(rows); updateDashboardCache({ controls: rows }); }),
      load("audit readiness", () => requestJson("/api/audit-readiness/"), data => { const value = data || { frameworks: [] }; setAuditReadiness(value); updateDashboardCache({ auditReadiness: value }); }),
      load("coverage", () => requestJson("/api/collector-coverage/"), data => { const value = data || { summary: {}, collectors: [] }; setCollectorCoverage(value); updateDashboardCache({ collectorCoverage: value }); }),
      load("agent lifecycle", () => requestJson("/api/agent-lifecycle/"), data => { const rows = data.assets || []; setAgentLifecycle(rows); updateDashboardCache({ agentLifecycle: rows }); })
    ];

    await Promise.allSettled(tasks);
  }

  async function loadAssetDetails(signal) {
    setAssetDetailsLoading(true);
    setAssetDetailsError("");
    try {
      const response = await apiFetch(`${API}/api/asset-details/`, {
        signal
      });
      if (!response.ok) {
        throw new Error(
          `Asset Details returned HTTP ${response.status}`
        );
      }
      setAssetDetails(await response.json());
      setAssetDetailsLoaded(true);
    } catch (error) {
      if (error.name !== "AbortError") {
        console.error("Failed to load asset details", error);
        setAssetDetailsError(String(error));
      }
    } finally {
      if (!signal?.aborted) {
        setAssetDetailsLoading(false);
      }
    }
  }

  async function loadCollectors(signal) {
    const response = await apiFetch(`${API}/api/collector-mappings/`, {
      signal
    });
    if (!response.ok) {
      throw new Error(
        `Collector mappings returned HTTP ${response.status}`
      );
    }
    const data = await response.json();
    setCollectors(data.collectors || []);
  }

  async function loadChangelog(signal) {
    try {
      const response = await apiFetch(
        `${API}/api/changelog/`,
        { signal }
      );

      if (!response.ok) {
        setChangelogEvents([]);
        return;
      }

      const data = await response.json();
      const events = Array.isArray(data.events)
        ? data.events
        : [];

      setChangelogEvents(events);

      setChangelogNoteDrafts(
        Object.fromEntries(
          events
            .filter(event => event.event_id)
            .map(event => [
              event.event_id,
              {
                note: event.note || "",
                jira_url: event.jira_url || ""
              }
            ])
        )
      );
    } catch (error) {
      if (error.name !== "AbortError") {
        console.error(
          "Failed to load changelog",
          error
        );
        setChangelogEvents([]);
      }
    }
  }

  function updateChangelogNoteDraft(
    eventId,
    field,
    value
  ) {
    setChangelogNoteDrafts(previous => ({
      ...previous,
      [eventId]: {
        note:
          previous[eventId]?.note
          ?? "",
        jira_url:
          previous[eventId]?.jira_url
          ?? "",
        [field]: value
      }
    }));
  }

  async function saveChangelogNote(event) {
    if (!event.event_id) {
      alert(
        "This changelog event does not have a valid event ID."
      );
      return;
    }

    const draft =
      changelogNoteDrafts[event.event_id]
      || {
        note: event.note || "",
        jira_url: event.jira_url || ""
      };

    let response;

    try {
      response = await apiFetch(
        `${API}/api/changelog/${encodeURIComponent(
          event.event_id
        )}/note`,
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            note: draft.note || "",
            jira_url: draft.jira_url || ""
          })
        }
      );
    } catch (error) {
      alert(
        `Unable to save the changelog note: ${
          error.message
        }`
      );
      return;
    }

    let data = {};

    try {
      data = await response.json();
    } catch {
      data = {};
    }

    if (!response.ok) {
      const detail =
        typeof data.detail === "string"
          ? data.detail
          : JSON.stringify(
              data.detail || data,
              null,
              2
            );

      alert(
        detail
        || "Unable to save the changelog note."
      );
      return;
    }

    setChangelogEvents(previous =>
      previous.map(item =>
        item.event_id === event.event_id
          ? {
              ...item,
              note: data.note || "",
              jira_url: data.jira_url || ""
            }
          : item
      )
    );

    setChangelogNoteDrafts(previous => ({
      ...previous,
      [event.event_id]: {
        note: data.note || "",
        jira_url: data.jira_url || ""
      }
    }));

    alert(
      data.note || data.jira_url
        ? "Changelog note saved."
        : "Changelog note cleared."
    );
  }

  async function refresh(signal) {
    if (activePage === "assets") {
      return loadAssetDetails(signal);
    }
    if (activePage === "collectors") {
      return loadCollectors(signal);
    }
    if (activePage === "changelog") {
      return loadChangelog(signal);
    }
    if (activePage === "iam") {
      return;
    }
    return refreshDashboard(signal);
  }

  async function runCollectors(asset_id) {
    const res = await apiFetch(`${API}/api/collectors/run`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ asset_id })
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  function openAgentModal(mode, asset = null) {
    setAgentMode(mode);

    if (asset) {
      setAgentForm({
        ...emptyAgentForm,
        asset_id: asset.asset_id || "",
        hostname: asset.hostname || "",
        address: asset.address || "",
        username: asset.ssh_user || asset.username || "",
        password: "",
        port: asset.ssh_port || asset.port || ((asset.os_family || "").toLowerCase().includes("win") ? 5985 : 22),
        environment: asset.environment || "test",
        os_family: asset.os_family || "ubuntu",
        asset_roles: Array.isArray(asset.asset_roles) ? asset.asset_roles : [],
        data_classification: Array.isArray(asset.data_classification) ? asset.data_classification : []
      });
    } else {
      setAgentForm({ ...emptyAgentForm });
    }

    setShowDeployModal(true);
  }

  async function submitAgentAction() {
    if (agentMode === "deploy") return deployAgent();
    if (agentMode === "update") return updateAgent();
    if (agentMode === "upgrade") return upgradeAgent();
  }


  async function saveAssetClassification(assetId) {
    if (!assetId) return;

    await apiFetch(`${API}/api/agents/${assetId}/classification`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        asset_roles: agentForm.asset_roles || [],
        data_classification: agentForm.data_classification || []
      })
    });
  }

async function deployAgent() {
    const payload = {
      ...agentForm,
      port: Number(agentForm.port),
      role: [agentForm.os_family || "ubuntu", "managed_target"],
      compliance_scope: ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"],
      os_family: agentForm.os_family || "ubuntu",
      asset_roles: [],
      data_classification: []
    };

    const res = await apiFetch(`${API}/api/agents/deploy`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await saveAssetClassification(agentForm.asset_id);
    setShowDeployModal(false);
    setAgentForm({ ...emptyAgentForm });
    await refresh();
  }

  async function updateAgent() {
    const payload = {
      ...agentForm,
      port: Number(agentForm.port),
      role: [agentForm.os_family || "ubuntu", "managed_target"],
      compliance_scope: ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"]
    };

    const res = await apiFetch(`${API}/api/agents/${agentForm.asset_id}`, {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await saveAssetClassification(agentForm.asset_id);
    setShowDeployModal(false);
    setAgentForm({ ...emptyAgentForm });
    await refresh();
  }

  async function upgradeAgent() {
    const payload = {
      ...agentForm,
      port: Number(agentForm.port),
      role: [agentForm.os_family || "ubuntu", "managed_target"],
      compliance_scope: ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"]
    };

    const res = await apiFetch(`${API}/api/agents/${agentForm.asset_id}/upgrade`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await saveAssetClassification(agentForm.asset_id);
    setShowDeployModal(false);
    setAgentForm({ ...emptyAgentForm });
    await refresh();
  }

  async function removeAgent(asset_id) {
    if (!confirm(`Remove compliance agent from ${asset_id}? Existing evidence and findings will be retained.`)) {
      return;
    }

    const res = await apiFetch(`${API}/api/agents/${asset_id}`, {
      method: "DELETE"
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await refresh();
  }


  function requestPackageUpdate(assetId, pkg) {
    if (!pkg || pkg.update_available !== "yes") return;

    setPackageUpdateConfirm({
      asset_id: assetId,
      package_name: pkg.name,
      installed_version: pkg.installed_version,
      latest_candidate: pkg.latest_candidate,
      was_held: pkg.held === "yes"
    });
  }

  async function confirmPackageUpdate() {
    if (!packageUpdateConfirm) return;

    const res = await apiFetch(`${API}/api/package-updates/upgrade`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        asset_id: packageUpdateConfirm.asset_id,
        package_name: packageUpdateConfirm.package_name,
        was_held: packageUpdateConfirm.was_held
      })
    });

    const data = await res.json();

    if (!res.ok) {
      alert(data.detail || "Package update failed");
      return;
    }

    const collectionResponse = await apiFetch(`${API}/api/collectors/run`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        asset_id: packageUpdateConfirm.asset_id,
        collectors: ["package_inventory"]
      })
    });

    const collectionData =
      await collectionResponse.json()
        .catch(() => ({}));

    const failedCollectors = (
      collectionData.results || []
    ).filter(
      result => result.status !== "completed"
    );

    if (
      !collectionResponse.ok
      || failedCollectors.length > 0
    ) {
      const failureSummary =
        failedCollectors.length > 0
          ? failedCollectors
              .map(
                result =>
                  `${result.collector}: ${result.status}`
              )
              .join(", ")
          : (
              collectionData.detail
              || collectionResponse.statusText
              || "Unknown collector failure"
            );

      alert(
        `Package update succeeded, but evidence refresh failed: ${
          failureSummary
        }`
      );

      setPackageUpdateConfirm(null);
      setModalData(null);
      await loadChangelog();
      await loadAssetDetails();
      return;
    }

    const packageName =
      packageUpdateConfirm.package_name;

    setPackageUpdateConfirm(null);
    setModalData(null);

    await loadChangelog();
    await loadAssetDetails();

    alert(
      `Package update succeeded for ${packageName}.`
    );
  }


  function requestBulkPackageUpdate(assetId, includeHeld) {
    setBulkPackageUpdateConfirm({
      asset_id: assetId,
      include_held: includeHeld
    });
  }

  async function confirmBulkPackageUpdate() {
    if (!bulkPackageUpdateConfirm) return;

    const res = await apiFetch(`${API}/api/package-updates/upgrade-all`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        asset_id: bulkPackageUpdateConfirm.asset_id,
        include_held: bulkPackageUpdateConfirm.include_held
      })
    });

    const data = await res.json();

    if (!res.ok) {
      alert(data.detail || "Bulk package update failed");
      return;
    }

    const collectionResponse = await apiFetch(`${API}/api/collectors/run`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        asset_id: bulkPackageUpdateConfirm.asset_id,
        collectors: ["package_inventory"]
      })
    });

    const collectionData =
      await collectionResponse.json()
        .catch(() => ({}));

    const failedCollectors = (
      collectionData.results || []
    ).filter(
      result => result.status !== "completed"
    );

    if (
      !collectionResponse.ok
      || failedCollectors.length > 0
    ) {
      const failureSummary =
        failedCollectors.length > 0
          ? failedCollectors
              .map(
                result =>
                  `${result.collector}: ${result.status}`
              )
              .join(", ")
          : (
              collectionData.detail
              || collectionResponse.statusText
              || "Unknown collector failure"
            );

      alert(
        `Bulk package update succeeded, but evidence refresh failed: ${
          failureSummary
        }`
      );

      setBulkPackageUpdateConfirm(null);
      await loadChangelog();
      await loadAssetDetails();
      return;
    }

    const includedHeldPackages =
      bulkPackageUpdateConfirm.include_held;

    setBulkPackageUpdateConfirm(null);

    await loadChangelog();
    await loadAssetDetails();

    alert(
      includedHeldPackages
        ? "Bulk package update succeeded, including held packages."
        : "Bulk package update succeeded, excluding held packages."
    );
  }

  async function analyzeEvidence() {
    const res = await apiFetch(`${API}/api/evidence-analysis/analyze`, {
      method: "POST"
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  async function sendChat() {
    const res = await apiFetch(`${API}/api/chat/`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ message: chatMessage, thread_id: "gui" })
    }).then(r => r.json());

    if (res.referenced_assets && res.referenced_assets.length > 0 && (res.response || "").endsWith(":")) {
      setChatResponse(`${res.response}\n\n${res.referenced_assets.map(a => `- ${a.asset_id} | ${a.hostname} | ${a.address} | ${a.environment} | ${(a.role || []).join(", ")}`).join("\n")}`);
    } else {
      setChatResponse(res.response || JSON.stringify(res, null, 2));
    }
  }

  async function openUploadMappingModal() {
    if (!policyFile) {
      alert("Select a policy document first.");
      return;
    }

    const suggestion = await apiFetch(`${API}/api/policies/suggest-mappings`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        filename: policyFile.name,
        scope: policyScope
      })
    }).then(r => r.json());

    const selected = {};
    for (const control of suggestion.controls || controls) {
      selected[control.control_id] = (suggestion.suggested_control_ids || []).includes(control.control_id);
    }

    setSelectedMappings(selected);
    setMappingModal({
      mode: "upload",
      title: `Confirm mappings for ${policyFile.name}`,
      file: policyFile,
      scope: policyScope,
      controls: suggestion.controls || controls
    });
  }

  async function openReplaceMappingModal(policy) {
    const file = replacePolicyFiles[policy.policy_id];

    if (!file) {
      alert("Select a replacement file first.");
      return;
    }

    const selected = {};
    for (const control of controls) {
      selected[control.control_id] = (policy.mapped_controls || []).includes(control.control_id);
    }

    setSelectedMappings(selected);
    setMappingModal({
      mode: "replace",
      title: `Confirm mappings for replacement: ${policy.filename}`,
      policy_id: policy.policy_id,
      file,
      scope: policy.scope || "",
      controls
    });
  }

  async function resuggestPolicyMappings() {
    if (!mappingModal) return;

    const suggestion = await apiFetch(`${API}/api/policies/suggest-mappings`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        filename: mappingModal.file?.name || "",
        scope: mappingModal.scope || ""
      })
    }).then(r => r.json());

    const selected = {};
    for (const control of suggestion.controls || controls) {
      selected[control.control_id] = (suggestion.suggested_control_ids || []).includes(control.control_id);
    }

    setSelectedMappings(selected);
    setMappingModal({
      ...mappingModal,
      controls: suggestion.controls || controls
    });
  }

  function selectedControlIds() {
    return Object.entries(selectedMappings)
      .filter(([, value]) => value === true)
      .map(([key]) => key);
  }

  async function confirmPolicyMapping() {
    if (!mappingModal) return;

    const form = new FormData();
    form.append("file", mappingModal.file);
    form.append("scope", mappingModal.scope || "");
    form.append("mapped_controls", JSON.stringify(selectedControlIds()));

    let url = `${API}/api/policies/upload`;
    let method = "POST";

    if (mappingModal.mode === "replace") {
      url = `${API}/api/policies/${mappingModal.policy_id}/replace`;
      method = "PUT";
    }

    if (mappingModal.mode === "document-upload") {
      url = `${API}/api/documents/upload`;
      method = "POST";
    }

    if (mappingModal.mode === "document-replace") {
      url = `${API}/api/documents/${mappingModal.document_id}/replace`;
      method = "PUT";
    }

    const res = await apiFetch(url, {
      method,
      body: form
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));

    setPolicyFile(null);
    setPolicyScope("");
    setDocumentFile(null);
    setDocumentScope("");
    setMappingModal(null);
    setSelectedMappings({});

    if (mappingModal.policy_id) {
      setReplacePolicyFiles({ ...replacePolicyFiles, [mappingModal.policy_id]: null });
    }

    if (mappingModal.document_id) {
      setReplaceDocumentFiles({ ...replaceDocumentFiles, [mappingModal.document_id]: null });
    }

    await refresh();
  }

  async function editExistingPolicyMappings(policy) {
    const selected = {};
    for (const control of controls) {
      selected[control.control_id] = (policy.mapped_controls || []).includes(control.control_id);
    }

    setSelectedMappings(selected);
    setMappingModal({
      mode: "edit",
      title: `Edit mappings for ${policy.filename}`,
      policy_id: policy.policy_id,
      controls
    });
  }

  async function confirmExistingPolicyMappingEdit() {
    if (!mappingModal) return;

    let url = `${API}/api/policies/${mappingModal.policy_id}/mappings`;

    if (mappingModal.mode === "document-edit") {
      url = `${API}/api/documents/${mappingModal.document_id}/mappings`;
    }

    const res = await apiFetch(url, {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        mapped_controls: selectedControlIds()
      })
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));

    setMappingModal(null);
    setSelectedMappings({});
    await refresh();
  }

  async function openDocumentMappingModal() {
    if (!documentFile) {
      alert("Select a supporting document first.");
      return;
    }

    const suggestion = await apiFetch(`${API}/api/documents/suggest-mappings`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        filename: documentFile.name,
        scope: documentScope
      })
    }).then(r => r.json());

    const selected = {};
    for (const control of suggestion.controls || controls) {
      selected[control.control_id] = (suggestion.suggested_control_ids || []).includes(control.control_id);
    }

    setSelectedMappings(selected);
    setMappingModal({
      mode: "document-upload",
      title: `Confirm mappings for ${documentFile.name}`,
      file: documentFile,
      scope: documentScope,
      controls: suggestion.controls || controls
    });
  }

  async function openReplaceDocumentMappingModal(document) {
    const file = replaceDocumentFiles[document.document_id];

    if (!file) {
      alert("Select a replacement file first.");
      return;
    }

    const selected = {};
    for (const control of controls) {
      selected[control.control_id] = (document.mapped_controls || []).includes(control.control_id);
    }

    setSelectedMappings(selected);
    setMappingModal({
      mode: "document-replace",
      title: `Confirm mappings for replacement: ${document.filename}`,
      document_id: document.document_id,
      file,
      scope: document.scope || "",
      controls
    });
  }

  async function editExistingDocumentMappings(document) {
    const selected = {};
    for (const control of controls) {
      selected[control.control_id] = (document.mapped_controls || []).includes(control.control_id);
    }

    setSelectedMappings(selected);
    setMappingModal({
      mode: "document-edit",
      title: `Edit mappings for ${document.filename}`,
      document_id: document.document_id,
      controls
    });
  }

  async function deleteDocument(documentId) {
    if (!confirm(`Delete document ${documentId}? This will remove its control mappings.`)) {
      return;
    }

    const res = await apiFetch(`${API}/api/documents/${documentId}`, {
      method: "DELETE"
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  async function deletePolicy(policyId) {
    if (!confirm(`Delete policy ${policyId}? This will remove its control mappings.`)) {
      return;
    }

    const res = await apiFetch(`${API}/api/policies/${policyId}`, {
      method: "DELETE"
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  useEffect(() => {
    try {
      sessionStorage.setItem(ACTIVE_PAGE_KEY, activePage);
    } catch {
      // Ignore browser storage failures.
    }

    const controller = new AbortController();
    refresh(controller.signal).catch(error => {
      if (error.name !== "AbortError") {
        console.error("Failed to refresh active view", error);
      }
    });
    return () => controller.abort();
  }, [activePage, selectedEnvironment]);

  return (
    <main>
      <header className="im-hero">
          <div className="im-brand-row">
            <img
              src="/brand/full-logo-animation-01.gif"
              alt="Iteration Matrix"
              className="im-logo-gif"
            />
            <div>
              <h1>Compliance Manager</h1>
              <p>Central control plane for agents, evidence, findings, compliance scoring, and reporting.</p>
            </div>
          </div>
          <div className="im-grid-accent"></div>
          <div className="actions">
          <button onClick={refresh}>Refresh</button>
          <label className="environment-filter">
            Environment:
            <select value={selectedEnvironment} onChange={e => setSelectedEnvironment(e.target.value)}>
              {environments.map(env => <option key={env} value={env}>{env}</option>)}
            </select>
          </label>
          {canManage && <button onClick={analyzeEvidence}>Analyze Evidence Into Findings</button>}
          <span className="signed-in-user">
            {currentUser.display_name} ({currentUser.role})
          </span>
          <button className="secondary" onClick={onLogout}>Sign out</button>
        </div>
        </header>

      <div className="grid">
        {Object.entries(dashboardLoadState).some(([, state]) => state.status === "error") && (
          <div className="dashboard-load-errors" role="status">
            <strong>Some dashboard sections could not be refreshed.</strong>
            {Object.entries(dashboardLoadState)
              .filter(([, state]) => state.status === "error")
              .map(([name, state]) => <span key={name}>{name}: {state.error}</span>)}
          </div>
        )}
        <Section title="System">
          <p>Status: {health?.status || "loading"}</p>
        </Section>

        <Section title="Compliance Scores">
        <table>
          <thead>
            <tr>
              <th>Framework</th>
              <th>Score</th>
              <th>Status</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody>
            {normalizeComplianceScores(scores).length === 0 ? (
              <tr>
                <td colSpan="4">No records found.</td>
              </tr>
            ) : (
              normalizeComplianceScores(scores).map((r) => (
                <tr key={r.framework}>
                  <td>{r.framework}</td>
                  <td>{r.score}</td>
                  <td>{r.status}</td>
                  <td>
                    {canGenerateReports ? <><a href={`${API}/api/reports/${r.framework}`} target="_blank">Generate</a>
                    {' '}
                    <a href={`${API}/api/reports/${r.framework}/package`} target="_blank">Download ZIP</a>
                    {' '}
                    <a href={`${API}/api/reports/${r.framework}/pdf`} target="_blank">Download PDF</a></> : <span className="muted">Read only</span>}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </Section>


        <div className="page-tabs">
          <button className={activePage === "dashboard" ? "active" : ""} onClick={() => setActivePage("dashboard")}>Dashboard</button>

{canViewIam && (
  <button
    className={activePage === "iam" ? "active" : ""}
    onClick={() => setActivePage("iam")}
  >
    IAM
  </button>
)}

          <button className={activePage === "assets" ? "active" : ""} onClick={() => setActivePage("assets")}>Asset Details</button>
          <button className={activePage === "collectors" ? "active" : ""} onClick={() => setActivePage("collectors")}>Collectors</button>
          <button className={activePage === "changelog" ? "active" : ""} onClick={() => setActivePage("changelog")}>Changelog</button>
          {canManageUsers && (
            <button className={activePage === "users" ? "active" : ""} onClick={() => setActivePage("users")}>Users</button>
          )}
          {canReviewAccess && (
            <button className={activePage === "access-reviews" ? "active" : ""} onClick={() => setActivePage("access-reviews")}>Access Reviews</button>
          )}
        </div>


{activePage === "iam" && canViewIam && (
  <IAM canCollect={canManage} />
)}

{activePage === "users" && canManageUsers && (
  <UserManagement currentUser={currentUser} />
)}

{activePage === "access-reviews" && canReviewAccess && (
  <AccessReviews currentUser={currentUser} canManage={canManageAccessReviews} />
)}

{activePage === "dashboard" && (
        <>
        <Section title={`Assets (${assets.length})`}>
          {canManage && <div className="section-actions">
            <button onClick={() => openAgentModal("deploy")}>Deploy Agent</button>
          </div>}

          <DataTable
            columns={[
              { key: "asset_id", label: "Asset ID" },
              { key: "hostname", label: "Hostname" },
              { key: "address", label: "Address" },
              { key: "environment", label: "Environment" },
              { key: "asset_roles", label: "Server Classifications", render: r => renderBadgeList(r.asset_roles || []) },
              { key: "data_classification", label: "Data Classification", render: r => renderBadgeList(r.data_classification || []) },
              { key: "agent_status", label: "Agent Status" },
              ...(canManage ? [{ key: "actions", label: "Actions", render: r => (
                <select
                  className="asset-action-select"
                  defaultValue=""
                  onChange={e => {
                    const action = e.target.value;
                    e.target.value = "";

                    if (action === "collect") runCollectors(r.asset_id);
                    if (action === "update") openAgentModal("update", r);
                    if (action === "upgrade") openAgentModal("upgrade", r);
                    if (action === "remove") removeAgent(r.asset_id);
                  }}
                >
                  <option value="" disabled>Choose action</option>
                  <option value="collect">Run Collectors</option>
                  <option value="update">Update Agent</option>
                  <option value="upgrade">Upgrade Agent</option>
                  <option value="remove">Remove Agent</option>
                </select>
              ) }] : [])
            ]}
            rows={assets}
          />
        </Section>

        <Section title="Audit Readiness">
          <DataTable
            columns={[
              { key: "framework", label: "Framework" },
              { key: "readiness", label: "Readiness", render: r => r.summary?.readiness || "Unknown" },
              { key: "estimated_audit_outcome", label: "Estimated Audit Outcome", render: r => r.summary?.estimated_audit_outcome || "Unknown" },
              { key: "high_risk", label: "High Risk", render: r => r.summary?.high_risk || 0 },
              { key: "moderate_risk", label: "Moderate", render: r => r.summary?.moderate_risk || 0 },
              { key: "low_risk", label: "Low", render: r => r.summary?.low_risk || 0 },
              { key: "actions", label: "Actions", render: r => (
                <button
                  onClick={() => {
                    setModalTitle(`Audit Readiness: ${r.framework}`);
                    setModalData(normalizeAuditRecommendations(r.recommendations || []));
                  }}
                >
                  View Suggestions
                </button>
              ) }
            ]}
            rows={auditReadiness.frameworks || []}
          />
        </Section>

        <Section title={`Current Findings (${findings.length})`}>
          <GroupedRecords rows={findings} noun="Findings" onOpen={(asset, items) => {
            setModalTitle(`Findings for ${asset}`);
            setModalData(items);
          }} />
        </Section>


        {collectorCoverage && Array.isArray(collectorCoverage.collectors) && collectorCoverage.collectors.length > 0 && (
          <Section title="Collector Coverage Gaps">
            <p>
              These collectors are expected to run against every deployed managed asset. A missing collector run means the dashboard cannot claim environment-wide validation for the related control.
            </p>

            <div className="stats-grid">
              <div className="stat">
                <span>Fully Covered</span>
                <strong>{collectorCoverage.summary?.covered ?? 0}</strong>
              </div>
              <div className="stat">
                <span>Coverage Gaps</span>
                <strong>{collectorCoverage.summary?.coverage_gap ?? 0}</strong>
              </div>
              <div className="stat">
                <span>Collector Failures</span>
                <strong>{collectorCoverage.summary?.collector_failures ?? 0}</strong>
              </div>
            </div>

            <DataTable
              columns={[
                { key: "title", label: "Collector" },
                { key: "control_id", label: "Control" },
                { key: "status", label: "Status" },
                {
                  key: "covered_assets",
                  label: "Covered Assets",
                  render: (value) => Array.isArray(value) && value.length ? value.join(", ") : "-"
                },
                {
                  key: "missing_assets",
                  label: "Missing Assets",
                  render: (value) => Array.isArray(value) && value.length ? value.join(", ") : "-"
                },
                {
                  key: "failed_assets",
                  label: "Failed Assets",
                  render: (value) => Array.isArray(value) && value.length ? value.join(", ") : "-"
                }
              ]}
              rows={collectorCoverage.collectors}
            />
          </Section>
        )}

        <Section title={`Current Evidence (${evidence.length})`}>
          <GroupedRecords rows={evidence} noun="Evidence" onOpen={(asset, items) => {
            setModalTitle(`Evidence for ${asset}`);
            setModalData(items);
          }} />
        </Section>

        <Section title={`Policies (${policies.length})`}>
          {canManage && <div className="policy-upload-modal-panel">
            <div className="policy-upload-field">
              <label>Policy Document</label>
              <input
                type="file"
                onChange={e => setPolicyFile(e.target.files[0] || null)}
              />
            </div>

            <div className="policy-upload-field">
              <label>Policy Scope</label>
              <textarea
                value={policyScope}
                onChange={e => setPolicyScope(e.target.value)}
                placeholder="Describe what this policy covers. Example: access control, MFA, user provisioning, logging, vulnerability management, incident response, backup and recovery."
                rows={4}
              />
            </div>

            <div className="policy-upload-actions">
              <button onClick={openUploadMappingModal}>
                Upload Policy / Select Control Mappings
              </button>
            </div>
          </div>}

          <DataTable
            columns={[
              { key: "policy_id", label: "Policy ID" },
              { key: "filename", label: "Document" },
              { key: "mapped_controls", label: "Controls", render: r => (r.mapped_controls || []).join(", ") },
              { key: "mapped_frameworks", label: "Frameworks", render: r => Object.keys(r.mapped_frameworks || {}).sort().join(", ") },
              { key: "actions", label: "Actions", render: r => (
                <select
                  className="asset-action-select"
                  defaultValue=""
                  onChange={e => {
                    const action = e.target.value;
                    e.target.value = "";

                    if (action === "download") window.open(`${API}/api/policies/${r.policy_id}/download`, "_blank");
                    if (action === "edit") editExistingPolicyMappings(r);
                    if (action === "replace") {
                      alert("Choose the replacement file in the row file selector first, then run Replace.");
                    }
                    if (action === "remove") deletePolicy(r.policy_id);
                    if (action === "details") {
                      setModalTitle(`Policy Details: ${r.filename}`);
                      setModalData([r]);
                    }
                  }}
                >
                  <option value="" disabled>Choose action</option>
                  <option value="details">View Details</option>
                  <option value="download">Download</option>
                  {canManage && <option value="edit">Edit Mappings</option>}
                  {canManage && <option value="remove">Remove</option>}
                </select>
              ) }
            ]}
            rows={policies}
          />
        </Section>

        <Section title={`Documents (${documents.length})`}>
          {canManage && <div className="policy-upload-modal-panel">
            <div className="policy-upload-field">
              <label>Supporting Document</label>
              <input
                type="file"
                onChange={e => setDocumentFile(e.target.files[0] || null)}
              />
            </div>

            <div className="policy-upload-field">
              <label>Document Scope</label>
              <textarea
                value={documentScope}
                onChange={e => setDocumentScope(e.target.value)}
                placeholder="Describe what this document supports. Example: risk register, risk analysis, backup report, SIEM report, access review, vendor review, vulnerability scan."
                rows={4}
              />
            </div>

            <div className="policy-upload-actions">
              <button onClick={openDocumentMappingModal}>
                Upload Document / Select Control Mappings
              </button>
            </div>
          </div>}

          <DataTable
            columns={[
              { key: "document_id", label: "Document ID" },
              { key: "filename", label: "Document" },
              { key: "mapped_controls", label: "Controls", render: r => (r.mapped_controls || []).join(", ") },
              { key: "mapped_frameworks", label: "Frameworks", render: r => Object.keys(r.mapped_frameworks || {}).sort().join(", ") },
              { key: "actions", label: "Actions", render: r => (
                <select
                  className="asset-action-select"
                  defaultValue=""
                  onChange={e => {
                    const action = e.target.value;
                    e.target.value = "";

                    if (action === "download") window.open(`${API}/api/documents/${r.document_id}/download`, "_blank");
                    if (action === "edit") editExistingDocumentMappings(r);
                    if (action === "remove") deleteDocument(r.document_id);
                    if (action === "details") {
                      setModalTitle(`Document Details: ${r.filename}`);
                      setModalData([r]);
                    }
                  }}
                >
                  <option value="" disabled>Choose action</option>
                  <option value="details">View Details</option>
                  <option value="download">Download</option>
                  {canManage && <option value="edit">Edit Mappings</option>}
                  {canManage && <option value="remove">Remove</option>}
                </select>
              ) }
            ]}
            rows={documents}
          />
        </Section>

        <Section title={`Remediations / Suggestions (${remediations.reduce((sum, item) => sum + item.count, 0)})`}>
          <DataTable
            columns={[
              { key: "asset_id", label: "Asset" },
              { key: "count", label: "Remediations / Suggestions" },
              { key: "details", label: "Details", render: r => (
                <button
                  onClick={() => {
                    setModalTitle(`Remediations for ${r.asset_id}`);
                    setModalData(r.remediations || []);
                  }}
                >
                  Expanded View
                </button>
              ) }
            ]}
            rows={remediations}
          />
        </Section>

        <Section title={`Control Readiness (${controlReadiness.summary?.total_controls || 0})`}>
          <div className="readiness-summary">
            <span>Validated: {controlReadiness.summary?.validated || 0}</span>
            <span>Documented: {controlReadiness.summary?.documented || 0}</span>
            <span>Missing: {controlReadiness.summary?.missing || 0}</span>
          </div>

          <DataTable
            columns={[
              { key: "control_id", label: "Control ID" },
              { key: "title", label: "Title" },
              { key: "domain", label: "Domain" },
              { key: "status", label: "Status", render: r => <span className={`status-pill ${r.status}`}>{r.status}</span> },
              { key: "score", label: "Score" },
              { key: "policy_count", label: "Policies" },
              { key: "evidence_count", label: "Evidence" },
              { key: "details", label: "Details", render: r => (
                <button
                  onClick={() => {
                    setModalTitle(`Control Readiness: ${r.control_id}`);
                    setModalData([
                      {
                        control_id: r.control_id,
                        title: r.title,
                        domain: r.domain,
                        status: r.status,
                        score: r.score,
                        policies: r.policies || [],
                        evidence: r.evidence || [],
                        framework_mappings: r.framework_mappings || {}
                      }
                    ]);
                  }}
                >
                  View
                </button>
              ) }
            ]}
            rows={controlReadiness.controls || []}
          />
        </Section>


        </>
        )}

        {activePage === "assets" && (
          <>
            {assetDetailsLoading && assetDetailsLoaded && (
              <p className="view-status">Refreshing Asset Details…</p>
            )}

            {assetDetailsError && (
              <div className="view-error">{assetDetailsError}</div>
            )}

            <Section title="System Resources">
              <DataTable
                columns={[
                  { key: "asset_id", label: "Asset ID" },
                  { key: "hostname", label: "Hostname" },
                  { key: "environment", label: "Environment" },
                  { key: "cpu_cores", label: "CPU Cores Allocated", render: r => r.resources?.cpu_cores || "Unknown" },
                  {
                    key: "memory_total_mb",
                    label: "Memory Allocated GB",
                    render: r => {
                      const val = r.resources?.memory_total_mb;

                      if (!val || val === "Unknown") {
                        return "Unknown";
                      }

                      const gb = (parseFloat(val) / 1024).toFixed(2);

                      return `${gb} GB`;
                    }
                  },
                  { key: "disk_total", label: "Root Disk Allocated", render: r => r.resources?.disk_total || "Unknown" }
                ]}
                rows={assetDetails.assets || []}
                emptyText={
                  assetDetailsLoading && !assetDetailsLoaded
                    ? "Loading asset resources…"
                    : "No asset resources found."
                }
              />
            </Section>

            <Section title={`Asset Details (${assetDetails.assets?.length || 0})`}>
              <DataTable
                columns={[
                  { key: "asset_id", label: "Asset ID" },
                  { key: "hostname", label: "Hostname" },
                  { key: "environment", label: "Environment" },
                  { key: "os_family", label: "OS Family" },
                  { key: "os_name", label: "OS" },
                  { key: "os_version", label: "OS Version" },
                  { key: "kernel_version", label: "Kernel" },
                  { key: "package_count", label: "Packages" },
                  { key: "packages_with_updates", label: "Updates Available" },
                  { key: "packages_unknown_latest", label: "Unknown Latest" },
                  { key: "held_packages", label: "Held Packages" },
                  {
                    key: "details",
                    label: "Actions",
                    render: (r) => (
                      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                        {canManage && <button
                          onClick={() => {
                            setModalTitle(`Asset Details: ${r.asset_id}`);
                            setModalData(r.packages || []);
                          }}
                        >
                          Packages
                        </button>}

                        {canManage && <button
                          disabled={(r.packages_with_updates || 0) === 0}
                          style={{
                            opacity: (r.packages_with_updates || 0) > 0 ? 1 : 0.4,
                            cursor: (r.packages_with_updates || 0) > 0 ? "pointer" : "not-allowed"
                          }}
                          onClick={() => requestBulkPackageUpdate(r.asset_id, false)}
                        >
                          Update All Except Held
                        </button>}

                        {canManage && <button
                          disabled={(r.packages_with_updates || 0) === 0}
                          style={{
                            opacity: (r.packages_with_updates || 0) > 0 ? 1 : 0.4,
                            cursor: (r.packages_with_updates || 0) > 0 ? "pointer" : "not-allowed"
                          }}
                          onClick={() => requestBulkPackageUpdate(r.asset_id, true)}
                        >
                          Update All Including Held
                        </button>}
                      </div>
                    )
                  }
                ]}
                rows={assetDetails.assets || []}
                emptyText={
                  assetDetailsLoading && !assetDetailsLoaded
                    ? "Loading asset details…"
                    : "No asset details found."
                }
              />
            </Section>
          </>
        )}

        {activePage === "changelog" && (
          <Section title={`Changelog (${changelogEvents.length})`}>
            <div className="table-toolbar">
              <input type="search" value={changelogQuery} onChange={event => setChangelogQuery(event.target.value)} placeholder="Search changelog" />
              <span className="muted">{changelogTable.filteredRows.length} of {changelogEvents.length}</span>
              {canExportAuditData && <button className="secondary" disabled={!changelogEvents.length} onClick={() => downloadCsv(
                "changelog.csv",
                [
                  { key: "timestamp", label: "Timestamp" },
                  { key: "event_type", label: "Event Type" },
                  { key: "asset_id", label: "Asset" },
                  { key: "summary", label: "Summary" },
                  { key: "note", label: "Note" },
                  { key: "jira_url", label: "Jira Ticket" }
                ],
                changelogTable.sortedRows
              )}>Export Filtered CSV</button>}
            </div>
            {canExportAuditData && <div className="section-actions">
              <a
                href={`${API}/api/changelog/user-group-export`}
                download="user-group-changes.csv"
              >
                Export User/Group Changes
              </a>
            </div>}

            <table>
              <thead>
                <tr>{CHANGELOG_COLUMNS.map(column => <SortableHeader key={column.key} column={column} sort={changelogTable.sort} onSort={changelogTable.toggleSort} />)}</tr>
              </thead>
              <tbody>
                {changelogTable.filteredRows.length === 0 ? (
                  <tr>
                    <td colSpan="7">
                      No changelog events recorded.
                    </td>
                  </tr>
                ) : (
                  changelogTable.pagedRows.map((event, idx) => {
                    const draft =
                      changelogNoteDrafts[event.event_id]
                      || {
                        note: event.note || "",
                        jira_url: event.jira_url || ""
                      };

                    return (
                      <tr key={event.event_id || idx}>
                        <td>{formatDateTime(event.timestamp, "-")}</td>
                        <td>{event.event_type || "-"}</td>
                        <td>{event.asset_id || "-"}</td>
                        <td>{event.summary || "-"}</td>
                        <td>
                          {canEditChangelog ? <textarea
                            value={draft.note}
                            maxLength={4000}
                            placeholder="Add an audit note"
                            style={{
                              minWidth: "220px",
                              minHeight: "58px",
                              resize: "vertical"
                            }}
                            onChange={change =>
                              updateChangelogNoteDraft(
                                event.event_id,
                                "note",
                                change.target.value
                              )
                            }
                          /> : (event.note || "-")}
                        </td>
                        <td>
                          {canEditChangelog && <input
                            type="url"
                            value={draft.jira_url}
                            maxLength={2048}
                            placeholder="https://.../browse/ISSUE-123"
                            style={{
                              minWidth: "260px"
                            }}
                            onChange={change =>
                              updateChangelogNoteDraft(
                                event.event_id,
                                "jira_url",
                                change.target.value
                              )
                            }
                          />}

                          {event.jira_url && (
                            <div style={{ marginTop: "6px" }}>
                              <a
                                href={event.jira_url}
                                target="_blank"
                                rel="noreferrer"
                              >
                                Open Jira ticket
                              </a>
                            </div>
                          )}
                        </td>
                        <td>
                          {canEditChangelog ? <button
                            disabled={!event.event_id}
                            onClick={() =>
                              saveChangelogNote(event)
                            }
                          >
                            Save
                          </button> : <span className="muted">Read only</span>}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
            <PaginationControls {...changelogTable} total={changelogTable.sortedRows.length} visibleCount={changelogTable.pagedRows.length} />
          </Section>
        )}

        {activePage === "collectors" && (
        <Section title={`Collectors (${collectors.length})`}>
          <DataTable
            columns={[
              { key: "name", label: "Collector" },
              { key: "control_ids", label: "Controls", render: r => (r.control_ids || []).join(", ") },
              { key: "mapped_controls", label: "Mapped", render: r => (r.mapped_controls || []).length },
              { key: "unmapped_control_ids", label: "Unmapped", render: r => (r.unmapped_control_ids || []).join(", ") || "None" },
              { key: "details", label: "Details", render: r => (
                <button
                  onClick={() => {
                    setModalTitle(`Collector Mapping: ${r.name}`);
                    setModalData(r.mapped_controls || []);
                  }}
                >
                  View
                </button>
              ) }
            ]}
            rows={collectors}
          />
        </Section>


        )}

        {activePage === "dashboard" && canManage && (
        <Section title="Chat">
          <textarea value={chatMessage} onChange={e => setChatMessage(e.target.value)} placeholder="Discuss assets, findings, evidence, or compliance..." />
          <button onClick={sendChat}>Send</button>
          <pre>{chatResponse}</pre>
        </Section>
        )}
      </div>

      {showDeployModal && canManage && (
        <div className="modal-backdrop">
          <div className="modal">
            <div className="modal-header">
              <h2>{agentMode === "deploy" ? "Deploy Agent" : agentMode === "update" ? "Update Agent" : "Upgrade Agent"}</h2>
              <button className="secondary" onClick={() => setShowDeployModal(false)}>Close</button>
            </div>

            <p className="modal-note">
              Enter temporary SSH credentials for this action. Passwords are never stored by the platform. Deploy installs the compliance-agent key, Update changes host metadata, and Upgrade redeploys the current agent while retaining existing findings, evidence, and mappings.
            </p>

            <label>Asset ID</label>
            <input value={agentForm.asset_id} onChange={e => setAgentForm({...agentForm, asset_id: e.target.value})} placeholder="test_vm" />


            <label>Operating System</label>
            <select
              value={agentForm.os_family || "ubuntu"}
              onChange={e => {
                const os = e.target.value;

                setAgentForm({
                  ...agentForm,
                  os_family: os,
                  port: os === "windows" ? 5985 : 22,
                  username: os === "windows"
                    ? "Administrator"
                    : agentForm.username
                });
              }}
            >
              <option value="ubuntu">Ubuntu / Linux</option>
              <option value="windows">Windows</option>
            </select>

            <label>Hostname</label>
            <input value={agentForm.hostname} onChange={e => setAgentForm({...agentForm, hostname: e.target.value})} placeholder="testing" />

            <label>Hostname/IP Address</label>
            <input value={agentForm.address} onChange={e => setAgentForm({...agentForm, address: e.target.value})} placeholder="192.168.1.124" />

            <label>{agentForm.os_family === "windows" ? "Windows Username" : "SSH Username"}</label>
            <input value={agentForm.username} onChange={e => setAgentForm({...agentForm, username: e.target.value})} placeholder="test" />

            <label>{agentForm.os_family === "windows" ? "Windows Password" : "SSH Password"}</label>
            <input type="password" value={agentForm.password} onChange={e => setAgentForm({...agentForm, password: e.target.value})} />

            <label>{agentForm.os_family === "windows" ? "WinRM Port" : "SSH Port"}</label>
            <input value={agentForm.port} onChange={e => setAgentForm({...agentForm, port: e.target.value})} placeholder="22" />

            <label>Environment</label>
            <select value={agentForm.environment} onChange={e => setAgentForm({...agentForm, environment: e.target.value})}>
              <option value="test">test</option>
              <option value="dev">dev</option>
              <option value="qa">qa</option>
              <option value="staging">staging</option>
              <option value="production">production</option>
            </select>

              <label>Server Classifications</label>
              <div className="checkbox-grid">
                {ASSET_ROLE_OPTIONS.map(role => (
                  <label key={role} className="checkbox-pill">
                    <input
                      type="checkbox"
                      checked={(agentForm.asset_roles || []).includes(role)}
                      onChange={() => setAgentForm({
                        ...agentForm,
                        asset_roles: toggleListValue(agentForm.asset_roles, role)
                      })}
                    />
                    {role}
                  </label>
                ))}
              </div>

              <label>Data Classification</label>
              <div className="checkbox-grid">
                {DATA_CLASSIFICATION_OPTIONS.map(item => (
                  <label key={item} className="checkbox-pill">
                    <input
                      type="checkbox"
                      checked={(agentForm.data_classification || []).includes(item)}
                      onChange={() => setAgentForm({
                        ...agentForm,
                        data_classification: toggleListValue(agentForm.data_classification, item)
                      })}
                    />
                    {item}
                  </label>
                ))}
              </div>


            <div className="modal-actions">
              <button onClick={submitAgentAction}>{agentMode === "deploy" ? "Deploy Agent" : agentMode === "update" ? "Update Agent" : "Upgrade Agent"}</button>
              <button className="secondary" onClick={() => setShowDeployModal(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {mappingModal && canManage && (
        <div className="modal-backdrop">
          <div className="modal large-modal">
            <div className="modal-header">
              <h2>{mappingModal.title}</h2>
              <button className="secondary" onClick={() => setMappingModal(null)}>Close</button>
            </div>

            <p className="modal-note">
              Confirm the controls this policy supports. Automatic suggestions are only a starting point; the selected controls are what will be saved.
            </p>

            <div className="modal-actions">
              {mappingModal.mode !== "edit" && (
                <button className="secondary" onClick={resuggestPolicyMappings}>Re-suggest From Scope</button>
              )}
              <button
                className="secondary"
                onClick={() => {
                  const next = {};
                  for (const control of mappingModal.controls || controls) {
                    next[control.control_id] = true;
                  }
                  setSelectedMappings(next);
                }}
              >
                Select All
              </button>
              <button
                className="secondary"
                onClick={() => {
                  const next = {};
                  for (const control of mappingModal.controls || controls) {
                    next[control.control_id] = false;
                  }
                  setSelectedMappings(next);
                }}
              >
                Clear All
              </button>
            </div>

            <div className="mapping-list">
              {(mappingModal.controls || controls).map(control => (
                <label key={control.control_id} className="mapping-row">
                  <input
                    type="checkbox"
                    checked={selectedMappings[control.control_id] === true}
                    onChange={e => setSelectedMappings({
                      ...selectedMappings,
                      [control.control_id]: e.target.checked
                    })}
                  />
                  <span>
                    <strong>{control.control_id}</strong> — {control.title}
                    {control.domain ? <em> ({control.domain})</em> : null}
                  </span>
                </label>
              ))}
            </div>

            <div className="modal-actions">
              <button onClick={(mappingModal.mode === "edit" || mappingModal.mode === "document-edit") ? confirmExistingPolicyMappingEdit : confirmPolicyMapping}>
                Save Confirmed Mappings
              </button>
              <button className="secondary" onClick={() => setMappingModal(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}



      {bulkPackageUpdateConfirm && canManage && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: "rgba(0,0,0,0.5)",
          zIndex: 1100
        }}>
          <div style={{
            background: "#fff",
            margin: "10% auto",
            padding: "20px",
            width: "650px",
            maxWidth: "90%",
            borderRadius: "8px"
          }}>
            <h2>Confirm Bulk Package Update</h2>

            <p>
              Confirm bulk package update on asset <strong>{bulkPackageUpdateConfirm.asset_id}</strong>.
            </p>

            <table border="1" width="100%" style={{ borderCollapse: "collapse" }}>
              <tbody>
                <tr>
                  <th style={{ padding: "8px" }}>Asset</th>
                  <td style={{ padding: "8px" }}>{bulkPackageUpdateConfirm.asset_id}</td>
                </tr>
                <tr>
                  <th style={{ padding: "8px" }}>Mode</th>
                  <td style={{ padding: "8px" }}>
                    {bulkPackageUpdateConfirm.include_held
                      ? "Update all packages, including held packages"
                      : "Update all packages except held packages"}
                  </td>
                </tr>
              </tbody>
            </table>

            {bulkPackageUpdateConfirm.include_held ? (
              <p>
                Held packages will be temporarily unheld, upgraded, and then held again after the update completes.
              </p>
            ) : (
              <p>
                Held packages will remain held and will not be upgraded.
              </p>
            )}

            <div className="modal-actions">
              <button onClick={confirmBulkPackageUpdate}>Confirm</button>
              <button className="secondary" onClick={() => setBulkPackageUpdateConfirm(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}


      {packageUpdateConfirm && canManage && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: "rgba(0,0,0,0.5)",
          zIndex: 1100
        }}>
          <div style={{
            background: "#fff",
            margin: "10% auto",
            padding: "20px",
            width: "600px",
            maxWidth: "90%",
            borderRadius: "8px"
          }}>
            <h2>Confirm Package Update</h2>

            <table border="1" width="100%" style={{ borderCollapse: "collapse" }}>
              <tbody>
                <tr><th style={{ padding: "8px" }}>Asset</th><td style={{ padding: "8px" }}>{packageUpdateConfirm.asset_id}</td></tr>
                <tr><th style={{ padding: "8px" }}>Package</th><td style={{ padding: "8px" }}>{packageUpdateConfirm.package_name}</td></tr>
                <tr><th style={{ padding: "8px" }}>Installed</th><td style={{ padding: "8px" }}>{packageUpdateConfirm.installed_version}</td></tr>
                <tr><th style={{ padding: "8px" }}>Target</th><td style={{ padding: "8px" }}>{packageUpdateConfirm.latest_candidate}</td></tr>
                <tr><th style={{ padding: "8px" }}>Held</th><td style={{ padding: "8px" }}>{packageUpdateConfirm.was_held ? "yes" : "no"}</td></tr>
              </tbody>
            </table>

            {packageUpdateConfirm.was_held && (
              <p>
                This package is currently held. The update will temporarily unhold it, perform the upgrade, and reapply the hold.
              </p>
            )}

            <div className="modal-actions">
              <button onClick={confirmPackageUpdate}>Confirm</button>
              <button className="secondary" onClick={() => setPackageUpdateConfirm(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}


      {modalData && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: "rgba(0,0,0,0.5)",
          zIndex: 1000
        }}>
          <div style={{
            background: "#fff",
            margin: "5% auto",
            padding: "20px",
            width: "90%",
            maxHeight: "80%",
            overflow: "auto",
            borderRadius: "8px"
          }}>
            <h2>{modalTitle}</h2>

            <button
              onClick={() => setModalData(null)}
              style={{ marginBottom: "15px" }}
            >
              Close
            </button>

            {modalTitle.startsWith("Control Readiness:") && modalData.length === 1 ? (
              <ControlReadinessDetails record={modalData[0]} />
            ) : modalTitle.startsWith("Asset Details:") ? (
              <table border="1" width="100%" style={{ borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    <th style={{ padding: "8px", background: "#f0f0f0" }}>Package</th>
                    <th style={{ padding: "8px", background: "#f0f0f0" }}>Installed Version</th>
                    <th style={{ padding: "8px", background: "#f0f0f0" }}>Latest Candidate</th>
                    <th style={{ padding: "8px", background: "#f0f0f0" }}>Held</th>
                    <th style={{ padding: "8px", background: "#f0f0f0" }}>Update Available</th>
                    <th style={{ padding: "8px", background: "#f0f0f0" }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {modalData.map((pkg, idx) => (
                    <tr key={idx}>
                      <td style={{ padding: "8px" }}>{pkg.name}</td>
                      <td style={{ padding: "8px" }}>{pkg.installed_version}</td>
                      <td style={{ padding: "8px" }}>{pkg.latest_candidate}</td>
                      <td style={{ padding: "8px" }}>{pkg.held || "no"}</td>
                      <td style={{ padding: "8px" }}>{pkg.update_available}</td>
                      <td style={{ padding: "8px" }}>
                        <button
                          disabled={pkg.update_available !== "yes"}
                          style={{
                            opacity: pkg.update_available === "yes" ? 1 : 0.4,
                            cursor: pkg.update_available === "yes" ? "pointer" : "not-allowed"
                          }}
                          onClick={() => {
                            const assetId = modalTitle.replace("Asset Details: ", "");
                            requestPackageUpdate(assetId, pkg);
                          }}
                        >
                          Update
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <table border="1" width="100%" style={{ borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {Object.keys(modalData[0] || {}).map(key => (
                      <th key={key} style={{ padding: "8px", background: "#f0f0f0" }}>
                        {key}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {modalData.map((row, idx) => (
                    <tr key={idx}>
                      {Object.values(row).map((val, i) => (
                        <td key={i} style={{ padding: "8px", whiteSpace: "pre-line" }}>
                          {formatCell(val)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
          <ContinuousComplianceState />

          <section className="panel">
            <h2>Agent Lifecycle</h2>
            <p className="muted">
              Agent versioning, collector integrity validation, manifest status, and drift monitoring.
            </p>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Hostname</th>
                    <th>Address</th>
                    <th>Agent Version</th>
                    <th>Expected Version</th>
                    <th>Status</th>
                    <th>Manifest</th>
                    <th>Collector Drift</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {agentLifecycle.map((a) => (
                    <tr key={a.asset_id}>
                      <td>{a.asset_id}</td>
                      <td>{a.hostname || ""}</td>
                      <td>{a.address || ""}</td>
                      <td>{a.agent_version || "Unknown"}</td>
                      <td>{a.expected_agent_version || "Unknown"}</td>
                      <td>{a.agent_current ? "Current" : "Outdated"}</td>
                      <td>{a.collector_manifest_version || "Missing"}</td>
                      <td>{a.collector_drift_detected === false ? "No Drift" : "Drift / Unknown"}</td>
                      <td>{formatDateTime(a.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

</main>
  );
}

createRoot(document.getElementById("root")).render(
  <AuthGate>
    {({ user, logout }) => <App currentUser={user} onLogout={logout} />}
  </AuthGate>
);
