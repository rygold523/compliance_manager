import React, { useEffect, useState } from "react";

function apiUrl(path) {
  const host = window.location.hostname || "localhost";
  return `http://${host}:8000${path}`;
}


function badgeClass(status) {
  if (status === "current" || status === "valid" || status === "within_compliance") {
    return "cc-status-badge cc-status-current";
  }

  if (status === "stale") {
    return "cc-status-badge cc-status-stale";
  }

  if (status === "action_required") {
    return "cc-status-badge cc-status-action";
  }

  return "cc-status-badge cc-status-unknown";
}

export default function ContinuousComplianceState() {
  const [state, setState] = useState({ summary: {}, domains: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadState() {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(apiUrl("/api/v2/continuous-compliance/state/domains"));
      if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`);
      }

      const data = await response.json();
      setState(data);
    } catch (err) {
      setError(err.message || "Failed to load continuous compliance state.");
    } finally {
      setLoading(false);
    }
  }

  async function markCurrent(domain) {
    await fetch(apiUrl("/api/v2/continuous-compliance/state/domains/mark-current"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        domain,
        marked_by: "dashboard",
        status: "current",
        note: "Marked current from dashboard."
      })
    });

    await loadState();
  }

  useEffect(() => {
    loadState();
  }, []);

  if (loading) {
    return <div className="cc-state-panel">Loading continuous compliance state...</div>;
  }

  if (error) {
    return <div className="cc-state-panel cc-error">Continuous compliance state unavailable: {error}</div>;
  }

  return (
    <section className="cc-state-panel">
      <div className="cc-state-header">
        <div>
          <h2>Continuous Compliance Operations</h2>
          <p>
            Current operating state for regulatory monitoring, messaging controls,
            evidence freshness, drift, incidents, and vendor validation.
          </p>
        </div>

        <button className="cc-refresh-button" onClick={loadState}>
          Refresh
        </button>
      </div>

      <div className="cc-summary-row">
        <div>Current: {state.summary?.current || 0}</div>
        <div>Action Required: {state.summary?.action_required || 0}</div>
        <div>Stale: {state.summary?.stale || 0}</div>
        <div>Unknown: {state.summary?.unknown || 0}</div>
      </div>

      <div className="cc-state-grid">
        {state.domains.map((domain) => (
          <div className="cc-state-card" key={domain.domain}>
            <div className="cc-card-top">
              <h3>{domain.domain}</h3>
              <span className={badgeClass(domain.status)}>
                {domain.status.replace("_", " ")}
              </span>
            </div>

            <p>{domain.status_reason}</p>

            <div className="cc-card-meta">
              <div>Controls: {domain.total_controls}</div>
              <div>Required Actions: {domain.required_actions}</div>
              <div>Readiness: {domain.readiness_score}%</div>
              <div>Last Checked: {domain.last_checked_at ? new Date(domain.last_checked_at).toLocaleString() : "Never"}</div>
            </div>

            <button className="cc-mark-button" onClick={() => markCurrent(domain.domain)}>
              Mark Current
            </button>
          </div>
        ))}
      </div>
    </section>
  );
}
