#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

echo "[+] Adding continuous compliance state and action tracking..."

mkdir -p backend/app/continuous_compliance/services/state
mkdir -p backend/app/continuous_compliance/services/actions

cat > backend/app/continuous_compliance/migrations/002_continuous_compliance_state_actions.sql <<'SQL'
CREATE TABLE IF NOT EXISTS continuous_compliance_domain_status (
    id UUID PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(64) NOT NULL DEFAULT 'unknown',
    status_reason TEXT,
    required_actions INTEGER DEFAULT 0,
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_marked_current_at TIMESTAMP WITH TIME ZONE,
    marked_current_by VARCHAR(255),
    next_review_due_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS continuous_compliance_action_items (
    id UUID PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    control_id VARCHAR(128),
    title VARCHAR(512) NOT NULL,
    description TEXT,
    severity VARCHAR(64) DEFAULT 'medium',
    status VARCHAR(64) DEFAULT 'open',
    source VARCHAR(128),
    due_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE,
    closed_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_cc_domain_status_domain
ON continuous_compliance_domain_status(domain);

CREATE INDEX IF NOT EXISTS idx_cc_action_items_domain
ON continuous_compliance_action_items(domain);

CREATE INDEX IF NOT EXISTS idx_cc_action_items_status
ON continuous_compliance_action_items(status);
SQL

cat > backend/app/continuous_compliance/services/state/domain_status.py <<'PY'
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from app.continuous_compliance.services.reporting.summary import build_domain_summary


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_domain_statuses() -> List[Dict[str, Any]]:
    """
    Lightweight state model.

    This intentionally starts as 'unknown' until automation evidence,
    freshness checks, or human review confirms the domain state.
    """
    domains = build_domain_summary()

    statuses = []

    for item in domains:
        domain = item.get("domain")

        statuses.append({
            "id": str(uuid4()),
            "domain": domain,
            "status": "unknown",
            "status_reason": "No automated validation or governance review has confirmed this domain yet.",
            "required_actions": 1,
            "last_checked_at": utcnow_iso(),
            "last_marked_current_at": None,
            "marked_current_by": None,
            "next_review_due_at": None,
            "readiness_score": item.get("readiness_score", 0),
            "total_controls": item.get("total_controls", 0),
        })

    return statuses


def summarize_status_counts(statuses: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "current": 0,
        "valid": 0,
        "within_compliance": 0,
        "action_required": 0,
        "stale": 0,
        "unknown": 0,
    }

    for item in statuses:
        status = item.get("status", "unknown")
        if status in counts:
            counts[status] += 1
        else:
            counts["unknown"] += 1

    return counts
PY

cat > backend/app/continuous_compliance/api/state_routes.py <<'PY'
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from app.continuous_compliance.services.state.domain_status import (
    default_domain_statuses,
    summarize_status_counts,
)

router = APIRouter(
    prefix="/api/v2/continuous-compliance/state",
    tags=["continuous-compliance-state"],
)


class MarkCurrentRequest(BaseModel):
    domain: str
    marked_by: Optional[str] = "system"
    status: Optional[str] = "current"
    note: Optional[str] = None


@router.get("/domains")
def domain_state():
    statuses = default_domain_statuses()

    return {
        "summary": summarize_status_counts(statuses),
        "domains": statuses,
    }


@router.post("/domains/mark-current")
def mark_domain_current(payload: MarkCurrentRequest):
    """
    Placeholder governance action.

    This confirms the API contract without changing existing workflows.
    Persistence can be added after the UI behavior is validated.
    """
    now = datetime.now(timezone.utc).isoformat()

    return {
        "accepted": True,
        "domain": payload.domain,
        "status": payload.status,
        "marked_by": payload.marked_by,
        "marked_current_at": now,
        "note": payload.note,
    }
PY

MAIN_FILE="backend/app/main.py"

python3 <<'PY'
from pathlib import Path

path = Path("backend/app/main.py")
content = path.read_text()

import_line = "from app.continuous_compliance.api.state_routes import router as continuous_compliance_state_router"
router_line = "app.include_router(continuous_compliance_state_router)"

if import_line not in content:
    lines = content.splitlines()
    insert_idx = 0

    for idx, line in enumerate(lines):
        if line.startswith("from app.continuous_compliance.api."):
            insert_idx = idx + 1

    lines.insert(insert_idx, import_line)
    content = "\n".join(lines)

if router_line not in content:
    marker = "app.include_router(continuous_compliance_reporting_router)"
    if marker in content:
        content = content.replace(marker, marker + "\n" + router_line)
    else:
        content += "\n" + router_line + "\n"

path.write_text(content)
print("[+] State router wired.")
PY

cat > frontend/src/pages/continuous-compliance/ContinuousComplianceState.jsx <<'JSX'
import React, { useEffect, useState } from "react";

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
      const response = await fetch("/api/v2/continuous-compliance/state/domains");
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
    await fetch("/api/v2/continuous-compliance/state/domains/mark-current", {
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
JSX

python3 <<'PY'
from pathlib import Path
import re

main_path = Path("frontend/src/main.jsx")
content = main_path.read_text()

import_line = 'import ContinuousComplianceState from "./pages/continuous-compliance/ContinuousComplianceState.jsx";'

if import_line not in content:
    lines = content.splitlines()
    last_import_idx = -1

    for idx, line in enumerate(lines):
        if line.startswith("import "):
            last_import_idx = idx

    if last_import_idx >= 0:
        lines.insert(last_import_idx + 1, import_line)
    else:
        lines.insert(0, import_line)

    content = "\n".join(lines)

static_component_pattern = r'\nfunction ContinuousComplianceOperationsSection\(\) \{.*?\n\}'

content = re.sub(
    static_component_pattern,
    '',
    content,
    flags=re.DOTALL
)

content = content.replace(
    "<ContinuousComplianceOperationsSection />",
    "<ContinuousComplianceState />"
)

main_path.write_text(content)
print("[+] Frontend state component wired.")
PY

cat >> frontend/src/style.css <<'CSS'

/* Continuous Compliance State */
.cc-state-panel {
  margin-top: 24px;
}

.cc-state-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}

.cc-state-header h2 {
  margin-bottom: 8px;
}

.cc-state-header p {
  margin-top: 0;
}

.cc-summary-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin: 16px 0;
}

.cc-summary-row div {
  border: 1px solid #d8dee4;
  border-radius: 10px;
  padding: 10px 12px;
  background: #ffffff;
  font-size: 14px;
}

.cc-state-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 16px;
}

.cc-state-card {
  border: 1px solid #d8dee4;
  border-radius: 12px;
  padding: 16px;
  background: #ffffff;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.cc-card-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.cc-state-card h3 {
  margin: 0;
  font-size: 16px;
}

.cc-state-card p {
  color: #57606a;
  font-size: 14px;
  line-height: 1.4;
}

.cc-card-meta {
  display: grid;
  gap: 4px;
  font-size: 13px;
  color: #57606a;
  margin: 12px 0;
}

.cc-status-badge {
  border-radius: 999px;
  padding: 4px 8px;
  font-size: 12px;
  text-transform: capitalize;
  white-space: nowrap;
}

.cc-status-current {
  background: #dafbe1;
  color: #116329;
}

.cc-status-action {
  background: #fff8c5;
  color: #7d4e00;
}

.cc-status-stale {
  background: #ffebe9;
  color: #82071e;
}

.cc-status-unknown {
  background: #eaeef2;
  color: #57606a;
}

.cc-refresh-button,
.cc-mark-button {
  border: 1px solid #d8dee4;
  border-radius: 8px;
  padding: 8px 10px;
  background: #f6f8fa;
  cursor: pointer;
}

.cc-mark-button {
  margin-top: 8px;
}
CSS

echo "[+] Applying DB migration..."
sudo docker exec -i aivuln-postgres psql -U aivuln -d aivuln < backend/app/continuous_compliance/migrations/002_continuous_compliance_state_actions.sql

echo "[+] State and action tracking added."
