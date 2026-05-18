import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

function Section({ title, children }) {
  return <section className="card"><h2>{title}</h2>{children}</section>;
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
  const [agentForm, setAgentForm] = useState({ asset_id: "", hostname: "", address: "", username: "", password: "", port: 22, environment: "test" });

  async function refresh() {
    const [h, a, f, e, s, c] = await Promise.all([
      fetch(`${API}/api/health`).then(r => r.json()),
      fetch(`${API}/api/assets/`).then(r => r.json()),
      fetch(`${API}/api/findings/`).then(r => r.json()),
      fetch(`${API}/api/evidence/`).then(r => r.json()),
      fetch(`${API}/api/compliance/score`).then(r => r.json()),
      fetch(`${API}/api/collectors/`).then(r => r.json())
    ]);
    setHealth(h); setAssets(a); setFindings(f); setEvidence(e); setScores(s); setCollectors(c.collectors || []);
  }

  async function deployAgent() {
    const payload = { ...agentForm, port: Number(agentForm.port), role: ["ubuntu", "managed_target"], compliance_scope: ["pci_dss","soc2","nist_800_53","iso_27001","iso_27002"] };
    const res = await fetch(`${API}/api/agents/deploy`, { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload) }).then(r => r.json());
    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  async function runCollectors(asset_id) {
    const res = await fetch(`${API}/api/collectors/run`, { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ asset_id }) }).then(r => r.json());
    alert(JSON.stringify(res, null, 2));
    await refresh();
  }

  async function sendChat() {
    const res = await fetch(`${API}/api/chat/`, { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ message: chatMessage, thread_id: "gui" }) }).then(r => r.json());
    if (res.referenced_assets && res.referenced_assets.length > 0 && (res.response || "").endsWith(":")) {
      setChatResponse(`${res.response}\n\n${res.referenced_assets.map(a => `- ${a.asset_id} | ${a.hostname} | ${a.address} | ${a.environment} | ${(a.role || []).join(", ")}`).join("\n")}`);
    } else {
      setChatResponse(res.response || JSON.stringify(res, null, 2));
    }
  }

  async function importSampleFinding() {
    await fetch(`${API}/api/findings/import`, { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ finding_id: `F-${Date.now()}`, asset_id: assets[0]?.asset_id || "unknown", source: "manual", title: "Sample critical OpenSSL CVE", description: "Example imported vulnerability.", severity: "critical", cve: "CVE-2024-0000", finding_type: "cve", raw: {} }) });
    await refresh();
  }

  useEffect(() => { refresh(); }, []);

  return (
    <main>
      <header><h1>Compliance Manager</h1><p>Central control plane for agents, evidence, findings, compliance scoring, and reporting.</p></header>
      <div className="grid">
        <Section title="System"><p>Status: {health?.status || "loading"}</p><button onClick={refresh}>Refresh</button></Section>
        <Section title="Assets"><p>{assets.length} asset(s)</p><ul>{assets.map(a => <li key={a.id}>{a.asset_id} — {a.environment} — {a.address}<br/><button onClick={() => runCollectors(a.asset_id)}>Run Evidence Collectors</button></li>)}</ul></Section>
        <Section title="Findings"><p>{findings.length} finding(s)</p><button onClick={importSampleFinding}>Import Sample Finding</button><ul>{findings.map(f => <li key={f.id}>{f.finding_id} — {f.severity} — {f.control_id}</li>)}</ul></Section>
        <Section title="Evidence"><p>{evidence.length} evidence item(s)</p><ul>{evidence.slice(0, 15).map(e => <li key={e.id}>{e.evidence_id} — {e.asset_id} — {e.collector || e.source} — {e.control_id}</li>)}</ul></Section>
        <Section title="Compliance Scores">{Object.entries(scores).map(([fw, s]) => <div key={fw} className="score"><strong>{s.label}</strong>: {s.readiness_score}% — {s.status}<br/><a href={`${API}/api/reports/${fw}`} target="_blank">Generate Report</a></div>)}</Section>
        <Section title="Agent Deployment">
          <input placeholder="Asset ID" value={agentForm.asset_id} onChange={e => setAgentForm({...agentForm, asset_id: e.target.value})} />
          <input placeholder="Hostname" value={agentForm.hostname} onChange={e => setAgentForm({...agentForm, hostname: e.target.value})} />
          <input placeholder="IP Address" value={agentForm.address} onChange={e => setAgentForm({...agentForm, address: e.target.value})} />
          <input placeholder="Username" value={agentForm.username} onChange={e => setAgentForm({...agentForm, username: e.target.value})} />
          <input placeholder="Password" type="password" value={agentForm.password} onChange={e => setAgentForm({...agentForm, password: e.target.value})} />
          <input placeholder="Port" value={agentForm.port} onChange={e => setAgentForm({...agentForm, port: e.target.value})} />
          <select value={agentForm.environment} onChange={e => setAgentForm({...agentForm, environment: e.target.value})}><option value="test">test</option><option value="dev">dev</option><option value="qa">qa</option><option value="staging">staging</option><option value="production">production</option></select>
          <button onClick={deployAgent}>Deploy Agent</button>
        </Section>
        <Section title="Collectors"><p>{collectors.length} collector(s) available</p><ul>{collectors.map(c => <li key={c.name}>{c.name}</li>)}</ul></Section>
        <Section title="Chat"><textarea value={chatMessage} onChange={e => setChatMessage(e.target.value)} placeholder="Discuss assets, findings, evidence, or compliance..." /><button onClick={sendChat}>Send</button><pre>{chatResponse}</pre></Section>
      </div>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
