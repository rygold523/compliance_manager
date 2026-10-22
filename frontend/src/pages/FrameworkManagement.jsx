import React, { useCallback, useEffect, useState } from "react";
import { API, apiFetch } from "../auth";

const jsonText = (value) => JSON.stringify(value, null, 2);
const frameworkPath = (id) => `${API}/api/admin/frameworks/${encodeURIComponent(id)}`;
const reqPath = (id) => `${frameworkPath(id)}/requirements`;

async function request(url, options = {}) {
  const response = await apiFetch(url, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });
  const contentType = response.headers.get("content-type") || "";
  let payload = null;
  if (contentType.includes("application/json")) {
    try { payload = await response.json(); } catch { /* Invalid JSON handled below. */ }
  }
  if (!response.ok) {
    const detail = payload?.detail;
    const message = typeof detail === "string" ? detail : detail ? jsonText(detail) : `HTTP ${response.status}`;
    throw new Error(`Request failed: ${message}`);
  }
  if (payload === null) throw new Error("The server returned an invalid or empty JSON response.");
  return payload;
}

function parseObject(text, label) {
  let value;
  try { value = JSON.parse(text); } catch { throw new Error(`${label} must contain valid JSON.`); }
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error(`${label} must be a JSON object.`);
  }
  return value;
}

function parseRequirements(text) {
  let value;
  try { value = JSON.parse(text); } catch { throw new Error("Requirements must contain valid JSON."); }
  if (!Array.isArray(value) || value.length < 1 || value.length > 10000 ||
      value.some((item) => !item || Array.isArray(item) || typeof item !== "object")) {
    throw new Error("Requirements must be an array of 1–10,000 JSON objects.");
  }
  return value;
}

export default function FrameworkManagement() {
  const [frameworks, setFrameworks] = useState([]);
  const [selected, setSelected] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState("");
  const [requirementsJson, setRequirementsJson] = useState("[]");
  const [sourceJson, setSourceJson] = useState("{}");
  const [reason, setReason] = useState("");
  const [fromVersion, setFromVersion] = useState("");
  const [toVersion, setToVersion] = useState("");
  const [comparison, setComparison] = useState(null);
  const [updateResult, setUpdateResult] = useState(null);

  const refreshFrameworks = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await request(`${API}/api/admin/frameworks`);
      if (!Array.isArray(data.frameworks)) throw new Error("Invalid framework registry response.");
      setFrameworks(data.frameworks);
      setSelected((current) => current && data.frameworks.some((f) => f.id === current) ? current : (data.frameworks[0]?.id || ""));
    } catch (err) { setError(err.message || "Unable to load frameworks."); }
    finally { setLoading(false); }
  }, []);

  const refreshStatus = useCallback(async (id) => {
    if (!id) { setStatus(null); return; }
    const data = await request(reqPath(id));
    if (!Array.isArray(data.versions) || !Array.isArray(data.audit_gaps)) {
      throw new Error("Invalid requirements lifecycle response.");
    }
    setStatus(data);
  }, []);

  useEffect(() => { refreshFrameworks(); }, [refreshFrameworks]);
  useEffect(() => {
    let active = true;
    setStatus(null);
    setComparison(null);
    setUpdateResult(null);
    setFromVersion("");
    setToVersion("");
    if (!selected) return () => { active = false; };
    request(reqPath(selected)).then((data) => {
      if (!active) return;
      if (!Array.isArray(data.versions) || !Array.isArray(data.audit_gaps)) throw new Error("Invalid lifecycle response.");
      setStatus(data);
    }).catch((err) => { if (active) setError(err.message); });
    return () => { active = false; };
  }, [selected]);

  async function execute(label, operation, after) {
    if (busy) return;
    setBusy(label);
    setError("");
    setMessage("");
    try {
      const result = await operation();
      if (after) await after(result);
      setMessage(`${label} completed successfully.`);
    } catch (err) { setError(err.message || `${label} failed.`); }
    finally { setBusy(""); }
  }

  async function toggle(framework) {
    const enabled = !framework.enabled;
    if (!window.confirm(`${enabled ? "Enable" : "Disable"} ${framework.label}? Historical evidence and reports will be retained. ${enabled && !framework.assessment_ready ? "This framework does not yet support assessments or reports." : ""}`)) return;
    await execute("Framework update", () => request(frameworkPath(framework.id), {
      method: "PUT", body: jsonText({ enabled }),
    }), (data) => {
      if (!Array.isArray(data.frameworks)) throw new Error("Invalid framework update response.");
      setFrameworks(data.frameworks);
    });
  }

  async function stage(event) {
    event.preventDefault();
    if (!selected) return;
    let payload;
    try {
      if (!version.trim() || version.length > 80) throw new Error("Version must be between 1 and 80 characters.");
      payload = { version: version.trim(), requirements: parseRequirements(requirementsJson), source: parseObject(sourceJson, "Source") };
    } catch (err) { setError(err.message); return; }
    if (!window.confirm(`Stage version ${payload.version} for ${selected}? This writes a new immutable requirements version.`)) return;
    await execute("Requirements staging", () => request(`${reqPath(selected)}/stage`, {
      method: "POST", body: jsonText(payload),
    }), async () => { await refreshStatus(selected); setVersion(""); });
  }

  async function transition(action, targetVersion) {
    const explanation = reason.trim();
    if (!explanation || explanation.length > 2048) { setError("Enter a reason of 1–2048 characters before changing lifecycle state."); return; }
    if (!window.confirm(`${action.toUpperCase()} version ${targetVersion} for ${selected}? This changes requirements lifecycle metadata. It does not recalculate assessments or compliance scores.`)) return;
    await execute(`${action} ${targetVersion}`, () => request(`${reqPath(selected)}/${encodeURIComponent(targetVersion)}/${action}`, {
      method: "POST", body: jsonText({ reason: explanation }),
    }), async () => { await refreshStatus(selected); setReason(""); setComparison(null); });
  }

  async function compare(event) {
    event.preventDefault();
    if (!fromVersion || !toVersion) { setError("Select both versions to compare."); return; }
    const params = new URLSearchParams({ from_version: fromVersion, to_version: toVersion });
    await execute("Version comparison", () => request(`${reqPath(selected)}/compare?${params}`), (data) => setComparison(data));
  }

  async function checkUpdates(all = false) {
    const url = all ? `${API}/api/admin/frameworks/requirements/check-all-updates` : `${reqPath(selected)}/check-updates`;
    await execute(all ? "All-framework update check" : "Framework update check", () => request(url, { method: "POST" }), (data) => setUpdateResult(data));
  }

  const versions = status?.versions || [];
  const gaps = status?.audit_gaps || [];
  const selectedFramework = frameworks.find((item) => item.id === selected);
  const blocked = !!busy || loading;

  return (
    <section className="card" aria-label="Framework Management">
      <h2>Framework Management</h2>
      <p className="muted">Administrators manage framework availability and offline requirements versions. Publishing requirements metadata does not automatically update assessment mappings, evidence, or compliance scores.</p>
      <div className="section-actions">
        <button type="button" className="secondary" onClick={refreshFrameworks} disabled={blocked}>{loading ? "Loading…" : "Refresh frameworks"}</button>
        <button type="button" className="secondary" onClick={() => execute("Requirements refresh", () => request(reqPath(selected)), (data) => {
          if (!Array.isArray(data.versions) || !Array.isArray(data.audit_gaps)) throw new Error("Invalid lifecycle response.");
          setStatus(data);
        })} disabled={blocked || !selected}>Refresh requirements</button>
      </div>
      {error && <p role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}
      {!loading && frameworks.length === 0 && <p>No frameworks are available.</p>}
      {frameworks.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead><tr><th>Framework</th><th>Enabled</th><th>Assessment</th><th>Management</th></tr></thead>
            <tbody>{frameworks.map((framework) => (
              <tr key={framework.id}>
                <td>{framework.label} <span className="muted">({framework.id})</span></td>
                <td>{framework.enabled ? "Yes" : "No"}</td>
                <td>{framework.assessment_ready ? "Supported" : "Not yet supported"}</td>
                <td><button type="button" className="secondary" disabled={blocked} onClick={() => toggle(framework)}>{busy === "Framework update" ? "Saving…" : framework.enabled ? "Disable" : "Enable"}</button></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}

      <h3>Requirements lifecycle</h3>
      <label htmlFor="requirements-framework">Framework</label>{" "}
      <select id="requirements-framework" value={selected} onChange={(e) => { setSelected(e.target.value); setError(""); setMessage(""); }} disabled={blocked}>
        {frameworks.map((f) => <option key={f.id} value={f.id}>{f.label} ({f.id})</option>)}
      </select>
      {selectedFramework && <p className="muted">Selected: {selectedFramework.label}. Published version: {status?.published_version || "None"}.</p>}
      {selected && !status && <p className="muted">Loading requirements status or awaiting a successful refresh.</p>}
      {status && (
        <>
          <h4>Available versions</h4>
          {versions.length === 0 ? <p>No requirements versions have been staged.</p> : (
            <div style={{ overflowX: "auto" }}><table>
              <thead><tr><th>Version</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
              <tbody>{versions.map((item) => (
                <tr key={item.version}>
                  <td>{item.version}</td>
                  <td>{item.status || "Unknown"}</td>
                  <td>{item.created_at || "—"}</td>
                  <td>
                    <button type="button" className="secondary" disabled={blocked || gaps.length > 0 || item.status !== "staged"} onClick={() => transition("approve", item.version)}>Approve</button>{" "}
                    <button type="button" className="secondary" disabled={blocked || gaps.length > 0 || item.status !== "approved"} onClick={() => transition("publish", item.version)}>Publish</button>{" "}
                    <button type="button" className="secondary" disabled={blocked || gaps.length > 0 || item.status !== "approved" || item.version === status.published_version} onClick={() => transition("rollback", item.version)}>Rollback to version</button>
                  </td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
          <label htmlFor="requirements-reason">Required reason for approval, publication, rollback, or audit reconciliation</label>
          <textarea id="requirements-reason" rows={2} maxLength={2048} value={reason} onChange={(e) => setReason(e.target.value)} disabled={blocked} placeholder="Describe the reason and authorization for this change" style={{ display: "block", width: "100%" }} />
          <h4>Lifecycle audit gaps</h4>
          {gaps.length === 0 ? <p>No staging audit gaps reported.</p> : (
            <>
              <p role="alert">Unreconciled staging audit gaps block lifecycle transitions and version comparisons.</p>
              <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{jsonText(gaps)}</pre>
              {gaps.map((gap, index) => {
                const target = typeof gap === "string" ? gap : gap?.version;
                return target && versions.some((item) => item.version === target) ? (
                  <button key={`${target}-${index}`} type="button" className="secondary" disabled={blocked} onClick={() => transition("reconcile-audit", target)}>Reconcile audit for {target}</button>
                ) : null;
              })}
            </>
          )}
        </>
      )}

      <h4>Stage requirements version</h4>
      <p className="muted">Stage only reviewed, trusted requirement data. JSON source metadata must satisfy the backend registry's validation rules.</p>
      <form onSubmit={stage}>
        <label htmlFor="requirements-version">New version identifier</label>
        <input id="requirements-version" value={version} maxLength={80} onChange={(e) => setVersion(e.target.value)} disabled={blocked} required />
        <label htmlFor="requirements-source">Source metadata (JSON object)</label>
        <textarea id="requirements-source" rows={4} value={sourceJson} onChange={(e) => setSourceJson(e.target.value)} disabled={blocked} style={{ display: "block", width: "100%", fontFamily: "monospace" }} />
        <label htmlFor="requirements-data">Requirements (JSON array of objects)</label>
        <textarea id="requirements-data" rows={8} value={requirementsJson} onChange={(e) => setRequirementsJson(e.target.value)} disabled={blocked} style={{ display: "block", width: "100%", fontFamily: "monospace" }} />
        <button type="submit" disabled={blocked || !selected}>Stage version</button>
      </form>

      <h4>Compare requirements versions</h4>
      <form onSubmit={compare}>
        <label htmlFor="compare-from">From version</label>{" "}
        <select id="compare-from" value={fromVersion} onChange={(e) => setFromVersion(e.target.value)} disabled={blocked} required>
          <option value="">Select version</option>
          {versions.map((item) => <option key={item.version} value={item.version}>{item.version}</option>)}
        </select>{" "}
        <label htmlFor="compare-to">To version</label>{" "}
        <select id="compare-to" value={toVersion} onChange={(e) => setToVersion(e.target.value)} disabled={blocked} required>
          <option value="">Select version</option>
          {versions.map((item) => <option key={item.version} value={item.version}>{item.version}</option>)}
        </select>{" "}
        <button type="submit" disabled={blocked || gaps.length > 0 || versions.length === 0}>Compare versions</button>
      </form>
      {comparison !== null && <><h4>Comparison result</h4><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{jsonText(comparison)}</pre></>}

      <h4>Check for requirements source updates</h4>
      <p className="muted">Update checks discover source changes. They do not stage, approve, or publish new versions.</p>
      <div className="section-actions">
        <button type="button" className="secondary" disabled={blocked || !selected} onClick={() => checkUpdates(false)}>Check selected framework</button>{" "}
        <button type="button" className="secondary" disabled={blocked} onClick={() => checkUpdates(true)}>Check all frameworks</button>
      </div>
      {updateResult !== null && <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{jsonText(updateResult)}</pre>}
      <p className="muted">All actions use this dashboard's authenticated API. No compliance publisher is contacted by this interface.</p>
    </section>
  );
}
