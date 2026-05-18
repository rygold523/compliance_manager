import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

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
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function Section({ title, children }) {
  return (
    <section className="card">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function DataTable({ columns, rows }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{columns.map(c => <th key={c.key}>{c.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan={columns.length}>No records found.</td></tr>
          ) : rows.map((row, idx) => (
            <tr key={row.id || row.policy_id || row.evidence_id || row.finding_id || row.asset_id || idx}>
              {columns.map(c => (
                <td key={c.key}>{c.render ? c.render(row) : formatCell(row[c.key])}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function App() {
  const [health, setHealth] = useState(null);
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [modalData, setModalData] = useState(null);
  const [modalTitle, setModalTitle] = useState("");
  const [scores, setScores] = useState({});
  const [environments, setEnvironments] = useState(["all"]);
  const [selectedEnvironment, setSelectedEnvironment] = useState("all");
  const [collectors, setCollectors] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [controls, setControls] = useState([]);
  const [remediations, setRemediations] = useState([]);
  const [policyFile, setPolicyFile] = useState(null);
  const [policyScope, setPolicyScope] = useState("");
  const [replacePolicyFiles, setReplacePolicyFiles] = useState({});
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
    environment: "test"
  };

  const [showDeployModal, setShowDeployModal] = useState(false);
  const [agentMode, setAgentMode] = useState("deploy");
  const [agentForm, setAgentForm] = useState(emptyAgentForm);

  async function refresh() {
    const [h, a, f, e, s, c, env, p, r, ctrl] = await Promise.all([
      fetch(`${API}/api/health`).then(r => r.json()),
      fetch(`${API}/api/assets/`).then(r => r.json()),
      fetch(`${API}/api/findings/`).then(r => r.json()),
      fetch(`${API}/api/evidence/`).then(r => r.json()),
      fetch(`${API}/api/compliance/score?environment=${selectedEnvironment}`).then(r => r.json()),
      fetch(`${API}/api/collectors/`).then(r => r.json()),
      fetch(`${API}/api/compliance/environments`).then(r => r.json()),
      fetch(`${API}/api/policies/`).then(r => r.json()).catch(() => []),
      fetch(`${API}/api/remediations/`).then(r => r.json()).catch(() => []),
      fetch(`${API}/api/controls/`).then(r => r.json()).catch(() => [])
    ]);

    const filteredFindings = filterStaleFindings(Array.isArray(f) ? f : [], Array.isArray(e) ? e : []);

    setHealth(h);
    setAssets(Array.isArray(a) ? a : []);
    setFindings(filteredFindings);
    setEvidence(Array.isArray(e) ? e : []);
    setScores(s || {});
    setCollectors(c.collectors || []);
    setEnvironments(env.environments || ["all"]);
    setPolicies(Array.isArray(p) ? p : []);
    setRemediations(Array.isArray(r) ? r : []);
    setControls(Array.isArray(ctrl) ? ctrl : []);
  }

  async function runCollectors(asset_id) {
    const res = await fetch(`${API}/api/collectors/run`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ asset_id })
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  function openAgentModal(mode, asset = null) {
    setAgentMode(mode);

    if (mode === "deploy") {
      setAgentForm({ ...emptyAgentForm });
    } else {
      setAgentForm({
        asset_id: asset?.asset_id || "",
        hostname: asset?.hostname || "",
        address: asset?.address || "",
        username: "",
        password: "",
        port: asset?.ssh_port || 22,
        environment: asset?.environment || "test"
      });
    }

    setShowDeployModal(true);
  }

  async function submitAgentAction() {
    if (agentMode === "deploy") return deployAgent();
    if (agentMode === "update") return updateAgent();
    if (agentMode === "upgrade") return upgradeAgent();
  }

  async function deployAgent() {
    const payload = {
      ...agentForm,
      port: Number(agentForm.port),
      role: ["ubuntu", "managed_target"],
      compliance_scope: ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"]
    };

    const res = await fetch(`${API}/api/agents/deploy`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    setShowDeployModal(false);
    setAgentForm({ ...emptyAgentForm });
    await refresh();
  }

  async function updateAgent() {
    const payload = {
      ...agentForm,
      port: Number(agentForm.port),
      role: ["ubuntu", "managed_target"],
      compliance_scope: ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"]
    };

    const res = await fetch(`${API}/api/agents/${agentForm.asset_id}`, {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    setShowDeployModal(false);
    setAgentForm({ ...emptyAgentForm });
    await refresh();
  }

  async function upgradeAgent() {
    const payload = {
      ...agentForm,
      port: Number(agentForm.port),
      role: ["ubuntu", "managed_target"],
      compliance_scope: ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"]
    };

    const res = await fetch(`${API}/api/agents/${agentForm.asset_id}/upgrade`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    setShowDeployModal(false);
    setAgentForm({ ...emptyAgentForm });
    await refresh();
  }

  async function removeAgent(asset_id) {
    if (!confirm(`Remove compliance agent from ${asset_id}? Existing evidence and findings will be retained.`)) {
      return;
    }

    const res = await fetch(`${API}/api/agents/${asset_id}`, {
      method: "DELETE"
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  async function analyzeEvidence() {
    const res = await fetch(`${API}/api/evidence-analysis/analyze`, {
      method: "POST"
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  async function sendChat() {
    const res = await fetch(`${API}/api/chat/`, {
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

    const suggestion = await fetch(`${API}/api/policies/suggest-mappings`, {
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

    const suggestion = await fetch(`${API}/api/policies/suggest-mappings`, {
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

    const res = await fetch(url, {
      method,
      body: form
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));

    setPolicyFile(null);
    setPolicyScope("");
    setMappingModal(null);
    setSelectedMappings({});
    setReplacePolicyFiles({ ...replacePolicyFiles, [mappingModal.policy_id]: null });

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

    const res = await fetch(`${API}/api/policies/${mappingModal.policy_id}/mappings`, {
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

  async function deletePolicy(policyId) {
    if (!confirm(`Delete policy ${policyId}? This will remove its control mappings.`)) {
      return;
    }

    const res = await fetch(`${API}/api/policies/${policyId}`, {
      method: "DELETE"
    }).then(r => r.json());

    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  useEffect(() => { refresh(); }, [selectedEnvironment]);

  return (
    <main>
      <header>
        <h1>Compliance Manager</h1>
        <p>Central control plane for agents, evidence, findings, compliance scoring, and reporting.</p>
        <div className="actions">
          <button onClick={refresh}>Refresh</button>
          <label className="environment-filter">
            Environment:
            <select value={selectedEnvironment} onChange={e => setSelectedEnvironment(e.target.value)}>
              {environments.map(env => <option key={env} value={env}>{env}</option>)}
            </select>
          </label>
          <button onClick={analyzeEvidence}>Analyze Evidence Into Findings</button>
        </div>
      </header>

      <div className="grid">
        <Section title="System">
          <p>Status: {health?.status || "loading"}</p>
        </Section>

        <Section title="Compliance Scores">
          <DataTable
            columns={[
              { key: "label", label: "Framework" },
              { key: "readiness_score", label: "Score" },
              { key: "status", label: "Status" },
              { key: "report", label: "Report", render: r => <a href={`${API}/api/reports/${r.framework}`} target="_blank">Generate</a> }
            ]}
            rows={Object.entries(scores).map(([framework, s]) => ({ framework, ...s }))}
          />
        </Section>

        <Section title={`Assets (${assets.length})`}>
          <div className="section-actions">
            <button onClick={() => openAgentModal("deploy")}>Deploy Agent</button>
          </div>

          <DataTable
            columns={[
              { key: "asset_id", label: "Asset ID" },
              { key: "hostname", label: "Hostname" },
              { key: "address", label: "Address" },
              { key: "environment", label: "Environment" },
              { key: "agent_status", label: "Agent Status" },
              { key: "actions", label: "Actions", render: r => (
                <div className="row-actions">
                  <button onClick={() => runCollectors(r.asset_id)}>Run Collectors</button>
                  <button onClick={() => openAgentModal("update", r)}>Update Agent</button>
                  <button onClick={() => openAgentModal("upgrade", r)}>Upgrade Agent</button>
                  <button className="danger" onClick={() => removeAgent(r.asset_id)}>Remove Agent</button>
                </div>
              ) }
            ]}
            rows={assets}
          />
        </Section>

        <Section title={`Current Findings (${findings.length})`}>
          {Object.entries(groupByAsset(findings)).map(([asset, items]) => (
            <button
              key={asset}
              style={{ display: "block", marginBottom: "10px" }}
              onClick={() => {
                setModalTitle(`Findings for ${asset}`);
                setModalData(items);
              }}
            >
              {asset} ({items.length})
            </button>
          ))}
        </Section>

        <Section title={`Current Evidence (${evidence.length})`}>
          {Object.entries(groupByAsset(evidence)).map(([asset, items]) => (
            <button
              key={asset}
              style={{ display: "block", marginBottom: "10px" }}
              onClick={() => {
                setModalTitle(`Evidence for ${asset}`);
                setModalData(items);
              }}
            >
              {asset} ({items.length})
            </button>
          ))}
        </Section>

        <Section title={`Policies (${policies.length})`}>
          <div className="section-actions policy-upload">
            <input
              type="file"
              onChange={e => setPolicyFile(e.target.files[0] || null)}
            />
            <input
              value={policyScope}
              onChange={e => setPolicyScope(e.target.value)}
              placeholder="Policy scope: access control, logging, vulnerability management, incident response..."
            />
            <button onClick={openUploadMappingModal}>Select / Confirm Mappings</button>
          </div>

          <DataTable
            columns={[
              { key: "policy_id", label: "Policy ID" },
              { key: "filename", label: "Document" },
              { key: "scope", label: "Scope" },
              { key: "mapped_controls", label: "Mapped Controls", render: r => (r.mapped_controls || []).join(", ") },
              { key: "mapped_frameworks", label: "Mapped Frameworks", render: r => Object.keys(r.mapped_frameworks || {}).join(", ") },
              { key: "updated_at", label: "Updated" },
              { key: "actions", label: "Actions", render: r => (
                <div className="row-actions">
                  <a href={`${API}/api/policies/${r.policy_id}/download`} target="_blank">Download</a>
                  <button onClick={() => editExistingPolicyMappings(r)}>Edit Mappings</button>
                  <input
                    type="file"
                    onChange={e => setReplacePolicyFiles({ ...replacePolicyFiles, [r.policy_id]: e.target.files[0] || null })}
                  />
                  <button onClick={() => openReplaceMappingModal(r)}>Replace</button>
                  <button className="danger" onClick={() => deletePolicy(r.policy_id)}>Remove</button>
                </div>
              ) }
            ]}
            rows={policies}
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

        <Section title={`Controls (${controls.length})`}>
          <DataTable
            columns={[
              { key: "control_id", label: "Control ID" },
              { key: "title", label: "Title" },
              { key: "domain", label: "Domain" },
              { key: "framework_mappings", label: "Frameworks", render: r => Object.keys(r.framework_mappings || {}).join(", ") }
            ]}
            rows={controls}
          />
        </Section>

        <Section title={`Collectors (${collectors.length})`}>
          <DataTable
            columns={[
              { key: "name", label: "Collector" },
              { key: "control_ids", label: "Controls", render: r => (r.control_ids || []).join(", ") }
            ]}
            rows={collectors}
          />
        </Section>

        <Section title="Chat">
          <textarea value={chatMessage} onChange={e => setChatMessage(e.target.value)} placeholder="Discuss assets, findings, evidence, or compliance..." />
          <button onClick={sendChat}>Send</button>
          <pre>{chatResponse}</pre>
        </Section>
      </div>

      {showDeployModal && (
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

            <label>Hostname</label>
            <input value={agentForm.hostname} onChange={e => setAgentForm({...agentForm, hostname: e.target.value})} placeholder="testing" />

            <label>Hostname/IP Address</label>
            <input value={agentForm.address} onChange={e => setAgentForm({...agentForm, address: e.target.value})} placeholder="192.168.1.124" />

            <label>SSH Username</label>
            <input value={agentForm.username} onChange={e => setAgentForm({...agentForm, username: e.target.value})} placeholder="test" />

            <label>SSH Password</label>
            <input type="password" value={agentForm.password} onChange={e => setAgentForm({...agentForm, password: e.target.value})} />

            <label>SSH Port</label>
            <input value={agentForm.port} onChange={e => setAgentForm({...agentForm, port: e.target.value})} placeholder="22" />

            <label>Environment</label>
            <select value={agentForm.environment} onChange={e => setAgentForm({...agentForm, environment: e.target.value})}>
              <option value="test">test</option>
              <option value="dev">dev</option>
              <option value="qa">qa</option>
              <option value="staging">staging</option>
              <option value="production">production</option>
            </select>

            <div className="modal-actions">
              <button onClick={submitAgentAction}>{agentMode === "deploy" ? "Deploy Agent" : agentMode === "update" ? "Update Agent" : "Upgrade Agent"}</button>
              <button className="secondary" onClick={() => setShowDeployModal(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {mappingModal && (
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
              <button onClick={mappingModal.mode === "edit" ? confirmExistingPolicyMappingEdit : confirmPolicyMapping}>
                Save Confirmed Mappings
              </button>
              <button className="secondary" onClick={() => setMappingModal(null)}>Cancel</button>
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
                      <td key={i} style={{ padding: "8px" }}>
                        {formatCell(val)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
