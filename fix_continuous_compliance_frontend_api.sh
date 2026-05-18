#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
FILE="$REPO_DIR/frontend/src/pages/continuous-compliance/ContinuousComplianceState.jsx"

cd "$REPO_DIR"

cp "$FILE" "${FILE}.bak.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path

path = Path("/opt/ai-vulnerability-management/frontend/src/pages/continuous-compliance/ContinuousComplianceState.jsx")
content = path.read_text()

api_helper = '''
function apiUrl(path) {
  const host = window.location.hostname || "localhost";
  return `http://${host}:8000${path}`;
}
'''

if "function apiUrl(path)" not in content:
    content = content.replace('import React, { useEffect, useState } from "react";', 'import React, { useEffect, useState } from "react";\n' + api_helper)

content = content.replace(
    'fetch("/api/v2/continuous-compliance/state/domains")',
    'fetch(apiUrl("/api/v2/continuous-compliance/state/domains"))'
)

content = content.replace(
    'fetch("/api/v2/continuous-compliance/state/domains/mark-current",',
    'fetch(apiUrl("/api/v2/continuous-compliance/state/domains/mark-current"),'
)

path.write_text(content)
print("[+] Frontend API URL corrected to backend port 8000.")
PY

echo "[+] Done."
