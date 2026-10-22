import React, { useCallback, useEffect, useState } from "react";
import { API, apiFetch } from "../auth";

export default function FrameworkManagement() {
  const [frameworks, setFrameworks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await apiFetch(`${API}/api/admin/frameworks`, { method: "GET", headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(`Framework registry request failed (HTTP ${response.status}).`);
      const payload = await response.json();
      if (!Array.isArray(payload.frameworks)) throw new Error("Invalid framework registry response.");
      setFrameworks(payload.frameworks);
    } catch (err) { setError(err.message || "Unable to retrieve framework registry."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  async function toggle(framework) {
    const enabled = !framework.enabled;
    if (!window.confirm(`${enabled ? "Enable" : "Disable"} ${framework.label}? Historical evidence and reports will be retained. ${enabled && !framework.assessment_ready ? "This framework does not yet support assessments or reports." : ""}`)) return;
    setBusy(framework.id);
    setError("");
    setMessage("");
    try {
      const response = await apiFetch(`${API}/api/admin/frameworks/${encodeURIComponent(framework.id)}`, {
        method: "PUT", headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ enabled }),
      });
      if (!response.ok) throw new Error(`Unable to update framework (HTTP ${response.status}).`);
      const payload = await response.json();
      if (!Array.isArray(payload.frameworks)) throw new Error("Invalid framework update response.");
      setFrameworks(payload.frameworks);
      setMessage(`${framework.label} ${enabled ? "enabled" : "disabled"}.`);
    } catch (err) { setError(err.message || "Framework update failed."); }
    finally { setBusy(""); }
  }

  return (
    <section className="card" aria-label="Framework Management">
      <h2>Framework Management</h2>
      <p className="muted">Administrators may enable or disable any framework. Enabled frameworks without assessment support are not scored or reported as compliant. Requirement-source updates are not yet available.</p>
      <div className="section-actions"><button type="button" className="secondary" onClick={refresh} disabled={loading || !!busy}>{loading ? "Loading…" : "Refresh registry"}</button></div>
      {error && <p role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}
      {!loading && frameworks.length > 0 && (
        <div style={{ overflowX: "auto" }}><table><thead><tr><th>Framework</th><th>Enabled</th><th>Assessment</th><th>Management</th></tr></thead>
          <tbody>{frameworks.map(framework => (
            <tr key={framework.id}>
              <td>{framework.label} <span className="muted">({framework.id})</span></td>
              <td>{framework.enabled ? "Yes" : "No"}</td>
              <td>{framework.assessment_ready ? "Supported" : "Not yet supported"}</td>
              <td><button type="button" className="secondary" disabled={loading || !!busy} onClick={() => toggle(framework)}>{busy === framework.id ? "Saving…" : framework.enabled ? "Disable" : "Enable"}</button></td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
      <p className="muted">All actions communicate only with this dashboard's API. No external compliance publisher is contacted.</p>
    </section>
  );
}
