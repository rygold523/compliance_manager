#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

cp "$MAIN_FILE" "${MAIN_FILE}.bak.current_state_render.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

helper = r'''
function renderCurrentStateValue(value) {
  if (value === null || value === undefined || value === "") {
    return "";
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "";
    }

    return value.map((item, index) => (
      <div key={index} className="current-state-list-item">
        {renderCurrentStateValue(item)}
      </div>
    ));
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

  return String(value);
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
'''

if "function renderCurrentStateValue(value)" not in content:
    insert_after = "function normalizeComplianceScores(scorePayload)"
    idx = content.find(insert_after)

    if idx == -1:
        content = helper + "\n" + content
    else:
        content = helper + "\n" + content

# Replace common broken current_state render patterns.
replacements = {
    "{r.current_state}": "{renderCurrentState(r.current_state)}",
    "{item.current_state}": "{renderCurrentState(item.current_state)}",
    "{row.current_state}": "{renderCurrentState(row.current_state)}",
    "{readiness.current_state}": "{renderCurrentState(readiness.current_state)}",
    "{framework.current_state}": "{renderCurrentState(framework.current_state)}",
    "{JSON.stringify(r.current_state)}": "{renderCurrentState(r.current_state)}",
    "{JSON.stringify(item.current_state)}": "{renderCurrentState(item.current_state)}",
    "{JSON.stringify(row.current_state)}": "{renderCurrentState(row.current_state)}",
    "{JSON.stringify(readiness.current_state)}": "{renderCurrentState(readiness.current_state)}",
    "{JSON.stringify(framework.current_state)}": "{renderCurrentState(framework.current_state)}",
}

for old, new in replacements.items():
    content = content.replace(old, new)

path.write_text(content)

print("[+] Current state rendering helper added.")
PY

cat >> frontend/src/style.css <<'CSS'

/* Audit Readiness Current State Rendering */
.current-state-rendered {
  display: grid;
  gap: 8px;
  font-size: 13px;
  line-height: 1.35;
}

.current-state-section {
  border-bottom: 1px solid #d8dbe3;
  padding-bottom: 8px;
}

.current-state-section:last-child {
  border-bottom: 0;
}

.current-state-key {
  font-weight: 700;
  color: #050505;
  margin-bottom: 3px;
}

.current-state-value {
  color: #30363d;
}

.current-state-list-item {
  margin-bottom: 6px;
  padding-left: 8px;
  border-left: 3px solid #d000ff;
}

.current-state-object {
  margin-bottom: 6px;
}

.current-state-object-title {
  font-weight: 700;
  color: #9b00d9;
}

.current-state-object-detail {
  color: #57606a;
  word-break: break-word;
}
CSS

echo "[+] Checking current_state references:"
grep -n "current_state\|renderCurrentState" "$MAIN_FILE" || true

echo "[+] Audit readiness current_state rendering patched."
