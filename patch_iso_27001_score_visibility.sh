#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

echo "[+] Patching ISO 27001 visibility in backend/frontend active files..."

echo "[+] Current iso references:"
grep -R "iso_27002\|iso_27001" -n backend/app frontend/src framework_mappings controls 2>/dev/null || true

echo "[+] Creating ISO 27001 mapping file if missing..."
mkdir -p framework_mappings

cat > framework_mappings/iso_27001.yml <<'YAML'
framework: iso_27001
name: ISO 27001
description: ISO/IEC 27001 Information Security Management System readiness mapping.
inherits_from: iso_27002
controls:
  - control_id: AC-01
  - control_id: AC-02
  - control_id: SI-01
  - control_id: VM-01
  - control_id: IR-01
  - control_id: CM-01
  - control_id: SMS-COMP-01
  - control_id: REG-MON-01
  - control_id: DRIFT-01
  - control_id: EVID-FRESH-01
YAML

echo "[+] Adding iso_27001 anywhere framework lists contain iso_27002..."

python3 <<'PY'
from pathlib import Path
import re

targets = []
for root in ["backend/app", "frontend/src"]:
    for path in Path(root).rglob("*"):
        if path.is_file() and not ".bak." in path.name and path.suffix in [".py", ".jsx", ".js", ".json", ".yml", ".yaml"]:
            text = path.read_text(errors="ignore")
            if "iso_27002" in text and "iso_27001" not in text:
                targets.append(path)

for path in targets:
    text = path.read_text(errors="ignore")
    original = text

    # Python/JS arrays: ["iso_27002"] or 'iso_27002'
    text = text.replace('"iso_27002"', '"iso_27002", "iso_27001"')
    text = text.replace("'iso_27002'", "'iso_27002', 'iso_27001'")

    # YAML list entries
    text = text.replace("- iso_27002", "- iso_27002\n      - iso_27001")

    if text != original:
        path.write_text(text)
        print(f"[+] Patched {path}")

print("[+] Files requiring patch:", len(targets))
PY

echo "[+] Explicitly checking common framework hardcoding locations..."
grep -R "pci_dss.*soc2.*nist_800_53.*iso_27002\|frameworks.*iso_27002\|iso_27002" -n backend/app frontend/src 2>/dev/null || true

echo "[+] Done. Rebuild backend and frontend."
