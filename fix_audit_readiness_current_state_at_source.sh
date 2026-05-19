#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

cp "$MAIN_FILE" "${MAIN_FILE}.bak.audit_current_state_source.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

helper = r'''
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

  return String(value);
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
'''

if "function formatAuditCurrentStateValue(value)" not in content:
    content = helper + "\n" + content

old = "setModalData(r.recommendations || []);"
new = "setModalData(normalizeAuditRecommendations(r.recommendations || []));"

if old not in content:
    raise SystemExit("ERROR: Could not locate audit readiness setModalData line.")

content = content.replace(old, new, 1)

path.write_text(content)

print("[+] Audit readiness current_state normalized before modal rendering.")
PY

cat >> frontend/src/style.css <<'CSS'

/* Preserve formatted audit readiness current_state text */
td {
  white-space: pre-line;
}
CSS

echo "[+] Verification:"
grep -n "formatAuditCurrentState\|normalizeAuditRecommendations\|setModalData(normalizeAuditRecommendations" "$MAIN_FILE"
