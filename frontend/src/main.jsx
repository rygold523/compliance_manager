import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

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
            <tr key={row.id || row.evidence_id || row.finding_id || row.asset_id || idx}>
              {columns.map(c => (
                <td key={c.key}>{c.render ? c.render(row) : row[c.key]}</td>
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
  const [scores, setScores] = useState({});
  const [collectors, setCollectors] = useState([]);
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
    const [h, a, f, e, s, c] = await Promise.all([
      fetch(`${API}/api/health`).then(r => r.json()),
      fetch(`${API}/api/assets/`).then(r => r.json()),
      fetch(`${API}/api/findings/`).then(r => r.json()),
      fetch(`${API}/api/evidence/`).then(r => r.json()),
      fetch(`${API}/api/compliance/score`).then(r => r.json()),
      fetch(`${API}/api/collectors/`).then(r => r.json())
    ]);

    setHealth(h);
    setAssets(a);
    setFindings(f);
    setEvidence(e);
    setScores(s);
    setCollectors(c.collectors || []);
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
    if (agentMode === "deploy") {
      return deployAgent();
    }

    if (agentMode === "update") {
      return updateAgent();
    }

    if (agentMode === "upgrade") {
      return upgradeAgent();
    }
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

  useEffect(() => { refresh(); }, []);

  return (
    <main>
      <header>
        <h1>Compliance Manager</h1>
        <p>Central control plane for agents, evidence, findings, compliance scoring, and reporting.</p>
        <div className="actions">
          <button onClick={refresh}>Refresh</button>
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

        <Section title={`Findings (${findings.length})`}>
          <DataTable
            columns={[
              { key: "finding_id", label: "Finding ID" },
              { key: "asset_id", label: "Asset" },
              { key: "severity", label: "Severity" },
              { key: "control_id", label: "Control" },
              { key: "status", label: "Status" },
              { key: "title", label: "Title" }
            ]}
            rows={findings}
          />
        </Section>

        <Section title={`Evidence (${evidence.length})`}>
          <DataTable
            columns={[
              { key: "evidence_id", label: "Evidence ID" },
              { key: "asset_id", label: "Asset" },
              { key: "collector", label: "Collector" },
              { key: "control_id", label: "Control" },
              { key: "validated", label: "Validated", render: r => r.validated ? "Yes" : "No" },
              { key: "created_at", label: "Created" }
            ]}
            rows={evidence}
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
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
