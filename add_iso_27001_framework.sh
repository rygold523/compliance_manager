#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

echo "[+] Adding ISO 27001 framework support..."

mkdir -p framework_mappings

if [ ! -f framework_mappings/iso_27001.yml ]; then

cat > framework_mappings/iso_27001.yml <<'YAML'
framework: iso_27001

description: >
  ISO/IEC 27001 Information Security Management System (ISMS)
  framework mappings.

controls:
  - control_id: AC-01
    name: Multi-Factor Authentication
    clauses:
      - "5.17"
      - "8.5"

  - control_id: AC-02
    name: Centralized Identity Management
    clauses:
      - "5.15"
      - "5.16"

  - control_id: SI-01
    name: Centralized Logging and Monitoring
    clauses:
      - "8.15"
      - "8.16"

  - control_id: VM-01
    name: Vulnerability Management
    clauses:
      - "8.8"

  - control_id: IR-01
    name: Incident Response
    clauses:
      - "5.24"
      - "5.25"
      - "5.26"

  - control_id: CM-01
    name: Configuration Management
    clauses:
      - "8.9"

  - control_id: SMS-COMP-01
    name: Messaging Compliance Governance
    clauses:
      - "5.31"
      - "5.32"

  - control_id: REG-MON-01
    name: Regulatory Intelligence Monitoring
    clauses:
      - "5.31"

  - control_id: DRIFT-01
    name: Compliance Drift Detection
    clauses:
      - "8.16"

  - control_id: EVID-FRESH-01
    name: Evidence Freshness Validation
    clauses:
      - "5.35"
YAML

fi

python3 <<'PY'
from pathlib import Path

controls_file = Path("controls/internal/continuous_compliance_controls.yml")

if controls_file.exists():
    content = controls_file.read_text()

    if "iso_27001" not in content:
        content = content.replace(
            "- iso_27002",
            "- iso_27002\n      - iso_27001"
        )

        controls_file.write_text(content)
        print("[+] Added iso_27001 mappings to internal controls.")
PY

python3 <<'PY'
from pathlib import Path
import re

main_file = Path("backend/app/continuous_compliance/services/reporting/summary.py")

content = main_file.read_text()

if "iso_27001" not in content:
    print("[+] ISO 27001 framework mapping now available via control mappings.")
else:
    print("[+] ISO 27001 already referenced.")
PY

echo "[+] ISO 27001 framework support added."
