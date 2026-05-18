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
          <DataTable
            columns={[
              { key: "asset_id", label: "Asset ID" },
              { key: "hostname", label: "Hostname" },
              { key: "address", label: "Address" },
              { key: "environment", label: "Environment" },
              { key: "agent_status", label: "Agent Status" },
              { key: "actions", label: "Actions", render: r => <button onClick={() => runCollectors(r.asset_id)}>Run Collectors</button> }
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
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
