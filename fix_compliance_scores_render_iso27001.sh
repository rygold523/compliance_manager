#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

if [ ! -f "$MAIN_FILE" ]; then
  echo "ERROR: $MAIN_FILE not found"
  exit 1
fi

cp "$MAIN_FILE" "${MAIN_FILE}.bak.fix_iso27001_render.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

helper = r'''
function normalizeComplianceScores(scorePayload) {
  if (!scorePayload) return [];

  const preferredOrder = ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"];

  let rawItems = [];

  if (Array.isArray(scorePayload)) {
    rawItems = scorePayload;
  } else if (Array.isArray(scorePayload.scores)) {
    rawItems = scorePayload.scores;
  } else if (Array.isArray(scorePayload.framework_scores)) {
    rawItems = scorePayload.framework_scores;
  } else if (scorePayload.framework_scores && typeof scorePayload.framework_scores === "object") {
    rawItems = Object.entries(scorePayload.framework_scores).map(([framework, value]) => ({
      framework,
      ...(value || {})
    }));
  } else if (typeof scorePayload === "object") {
    rawItems = Object.entries(scorePayload)
      .filter(([key, value]) => value && typeof value === "object")
      .map(([framework, value]) => ({
        framework,
        ...(value || {})
      }));
  }

  const byFramework = {};

  rawItems.forEach((item) => {
    const framework = item.framework || item.name || item.id;
    if (!framework) return;

    byFramework[framework] = {
      framework,
      score:
        item.score ??
        item.readiness_score ??
        item.compliance_score ??
        item.value ??
        0,
      status:
        item.status ??
        item.readiness_status ??
        item.audit_status ??
        "unknown"
    };
  });

  return Object.values(byFramework).sort((a, b) => {
    const ai = preferredOrder.indexOf(a.framework);
    const bi = preferredOrder.indexOf(b.framework);

    if (ai === -1 && bi === -1) return a.framework.localeCompare(b.framework);
    if (ai === -1) return 1;
    if (bi === -1) return -1;

    return ai - bi;
  });
}
'''

if "function normalizeComplianceScores(scorePayload)" not in content:
    lines = content.splitlines()
    insert_idx = 0

    for idx, line in enumerate(lines):
        if line.startswith("const API") or line.startswith("function "):
            insert_idx = idx
            break

    lines.insert(insert_idx, helper)
    content = "\n".join(lines)

# Replace common table source patterns without touching unrelated logic.
replacements = {
    "complianceScores.map(": "normalizeComplianceScores(complianceScores).map(",
    "scores.map(": "normalizeComplianceScores(scores).map(",
    "complianceScore.map(": "normalizeComplianceScores(complianceScore).map(",
}

for old, new in replacements.items():
    if old in content and new not in content:
        content = content.replace(old, new)

path.write_text(content)

print("[+] Added compliance score normalization helper.")
PY

echo "[+] Showing relevant score rendering lines:"
grep -n "normalizeComplianceScores\|Compliance Scores\|Download ZIP\|Generate" "$MAIN_FILE" || true

echo "[+] Done."
