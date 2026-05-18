#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

cp "$MAIN_FILE" "${MAIN_FILE}.bak.force_iso27001_scores.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path
import re

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

# Ensure normalizer exists.
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
    const framework = item.framework || item.id || item.name;
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
    content = helper + "\n" + content

match = re.search(r'<Section title="Compliance Scores">(?P<body>.*?)</Section>', content, re.DOTALL)
if not match:
    raise SystemExit("ERROR: Could not locate Compliance Scores section.")

body = match.group("body")

# Detect the score variable used by the existing block.
candidate_vars = [
    "complianceScores",
    "scores",
    "complianceScore",
    "scoreData",
    "scoreRows",
]

data_var = None

for var in candidate_vars:
    if re.search(rf'\b{var}\b', body):
        data_var = var
        break

if not data_var:
    # Fall back to the most likely state name in the full file.
    state_match = re.search(r'const\s*\[\s*(\w*score\w*|\w*scores\w*)\s*,\s*set\w+\s*\]\s*=\s*useState', content, re.IGNORECASE)
    if state_match:
        data_var = state_match.group(1)

if not data_var:
    raise SystemExit("ERROR: Could not detect compliance score state variable.")

new_section = f'''<Section title="Compliance Scores">
        <table>
          <thead>
            <tr>
              <th>Framework</th>
              <th>Score</th>
              <th>Status</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody>
            {{normalizeComplianceScores({data_var}).length === 0 ? (
              <tr>
                <td colSpan="4">No records found.</td>
              </tr>
            ) : (
              normalizeComplianceScores({data_var}).map((r) => (
                <tr key={{r.framework}}>
                  <td>{{r.framework}}</td>
                  <td>{{r.score}}</td>
                  <td>{{r.status}}</td>
                  <td>
                    <a href={{`${{API}}/api/reports/${{r.framework}}`}} target="_blank">Generate</a>
                    {{' '}}
                    <a href={{`${{API}}/api/reports/${{r.framework}}/package`}} target="_blank">Download ZIP</a>
                  </td>
                </tr>
              ))
            )}}
          </tbody>
        </table>
      </Section>'''

content = content[:match.start()] + new_section + content[match.end():]

path.write_text(content)

print(f"[+] Compliance Scores section now renders normalized rows from: {data_var}")
PY

grep -n "Compliance Scores\|normalizeComplianceScores\|iso_27001" "$MAIN_FILE" | head -80

echo "[+] Done."
