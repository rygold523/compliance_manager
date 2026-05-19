#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

echo "[+] Patching policy/document list APIs to compute frameworks live..."

cp backend/app/api/policies.py "backend/app/api/policies.py.bak.livefw.$(date +%Y%m%d_%H%M%S)"
cp backend/app/api/documents.py "backend/app/api/documents.py.bak.livefw.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path
import re

for target in [
    Path("backend/app/api/policies.py"),
    Path("backend/app/api/documents.py"),
]:
    content = target.read_text()

    # Ensure helper import exists.
    if "framework_mappings_for_controls" not in content:
        content = content.replace(
            "from app.services.control_catalog import",
            "from app.services.control_catalog import framework_mappings_for_controls,"
        )

    # Replace stale mapped_frameworks assignment with live computation where record has mapped_controls.
    content = re.sub(
        r'record\["mapped_frameworks"\]\s*=\s*mapping\["frameworks"\]',
        'record["mapped_frameworks"] = framework_mappings_for_controls(record.get("mapped_controls") or [])',
        content
    )

    # Replace API response construction stale mapping fallback.
    content = content.replace(
        '"mapped_frameworks": mapping["frameworks"],',
        '"mapped_frameworks": framework_mappings_for_controls(record.get("mapped_controls") or selected or []),'
    )

    # Patch any direct return object that uses stored frameworks.
    content = content.replace(
        '"mapped_frameworks": record.get("mapped_frameworks", {}),',
        '"mapped_frameworks": framework_mappings_for_controls(record.get("mapped_controls") or []),'
    )

    content = content.replace(
        '"mapped_frameworks": record.get("frameworks", {}),',
        '"mapped_frameworks": framework_mappings_for_controls(record.get("mapped_controls") or []),'
    )

    target.write_text(content)
    print(f"[+] Patched {target}")
PY

echo "[+] Verifying API code references:"
grep -n "mapped_frameworks\|framework_mappings_for_controls" backend/app/api/policies.py backend/app/api/documents.py

echo "[+] Rebuilding backend..."
sudo docker compose build backend
sudo docker compose up -d backend

echo "[+] Testing policy/document APIs:"
curl -s http://localhost:8000/api/policies/ | jq '.[0]'
curl -s http://localhost:8000/api/documents/ | jq '.[1]'

echo "[+] Done."
