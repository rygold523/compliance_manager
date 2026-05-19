#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

cp "$MAIN_FILE" "${MAIN_FILE}.bak.audit_modal_values.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

if "{row[key]}" in content:
    content = content.replace("{row[key]}", "{renderCurrentStateValue(row[key])}")

if "{modalData[0][key]}" in content:
    content = content.replace("{modalData[0][key]}", "{renderCurrentStateValue(modalData[0][key])}")

if "{value}" in content and "Object.entries(item).map(([key, value])" in content:
    content = content.replace("{value}", "{renderCurrentStateValue(value)}")

path.write_text(content)

print("[+] Patched modal object value rendering.")
PY

echo "[+] Modal render block after patch:"
nl -ba "$MAIN_FILE" | sed -n '1288,1325p'
