#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"

cd "$REPO_DIR"

echo "[+] Adding continuous compliance reporting layer..."

mkdir -p controls/internal
mkdir -p backend/app/continuous_compliance/services/reporting
mkdir -p backend/app/continuous_compliance/schemas
mkdir -p frontend/src/components/continuous-compliance
mkdir -p frontend/src/pages/continuous-compliance

cat > controls/internal/continuous_compliance_controls.yml <<'YAML'
controls:
  - control_id: SMS-COMP-01
    title: Messaging Compliance Governance
    domain: Messaging Compliance
    description: Validates SMS messaging compliance controls, suppression handling, consent management, evidence freshness, and operational monitoring.
    maps_to:
      - pci_dss
      - soc2
      - nist_800_53
      - iso_27002
    evidence_policy: evidence-policies/SMS-COMP-01.yml

  - control_id: TWILIO-VAL-01
    title: Twilio Control Plane Validation
    domain: Vendor / Control Plane Validation
    description: Validates Twilio control-plane configuration, A2P status, opt-out handling, quiet-hour protections, and production parity.
    maps_to:
      - soc2
      - nist_800_53
      - iso_27002

  - control_id: REG-MON-01
    title: Regulatory Intelligence Monitoring
    domain: Regulatory Monitoring
    description: Monitors FCC, TCPA, CTIA, A2P, CASL, and vendor compliance guidance for operational changes and governance review.
    maps_to:
      - soc2
      - iso_27002

  - control_id: DRIFT-01
    title: Compliance Drift Detection
    domain: Compliance Drift
    description: Detects stale evidence, expired approvals, failed collectors, operational drift, and baseline deviations.
    maps_to:
      - pci_dss
      - soc2
      - nist_800_53
      - iso_27002

  - control_id: EVID-FRESH-01
    title: Evidence Freshness Validation
    domain: Evidence Freshness
    description: Validates evidence freshness requirements and operational defensibility.
    maps_to:
      - pci_dss
      - soc2
      - iso_27002

  - control_id: INCIDENT-MON-01
    title: Messaging Incident Monitoring
    domain: Incident Monitoring
    description: Monitors messaging incidents including suppression failures, opt-out violations, rejection spikes, and delivery failures.
    maps_to:
      - pci_dss
      - soc2
YAML

cat > backend/app/continuous_compliance/schemas/reporting.py <<'PY'
from pydantic import BaseModel
from typing import List, Optional


class ComplianceDomainSummary(BaseModel):
    domain: str
    total_controls: int
    satisfied_controls: int
    deficient_controls: int
    stale_controls: int
    open_findings: int
    readiness_score: float


class ComplianceControlStatus(BaseModel):
    control_id: str
    title: str
    domain: str
    status: str
    evidence_coverage: Optional[float] = None
    freshness_status: Optional[str] = None
    open_findings: int = 0
    mapped_frameworks: List[str] = []
PY

cat > backend/app/continuous_compliance/services/reporting/summary.py <<'PY'
import yaml
from pathlib import Path
from typing import Any, Dict, List


CONTROL_FILE = Path("controls/internal/continuous_compliance_controls.yml")


def load_internal_controls() -> List[Dict[str, Any]]:
    if not CONTROL_FILE.exists():
        return []

    with open(CONTROL_FILE, "r") as handle:
        data = yaml.safe_load(handle) or {}

    return data.get("controls", [])


def build_domain_summary() -> List[Dict[str, Any]]:
    controls = load_internal_controls()

    domains = {}

    for control in controls:
        domain = control.get("domain", "Unknown")

        if domain not in domains:
            domains[domain] = {
                "domain": domain,
                "total_controls": 0,
                "satisfied_controls": 0,
                "deficient_controls": 0,
                "stale_controls": 0,
                "open_findings": 0,
                "readiness_score": 100.0,
            }

        domains[domain]["total_controls"] += 1

    return list(domains.values())


def build_control_inventory() -> List[Dict[str, Any]]:
    controls = load_internal_controls()

    inventory = []

    for control in controls:
        inventory.append({
            "control_id": control.get("control_id"),
            "title": control.get("title"),
            "domain": control.get("domain"),
            "status": "unknown",
            "evidence_coverage": None,
            "freshness_status": None,
            "open_findings": 0,
            "mapped_frameworks": control.get("maps_to", []),
        })

    return inventory
PY

cat > backend/app/continuous_compliance/api/reporting_routes.py <<'PY'
from fastapi import APIRouter

from app.continuous_compliance.services.reporting.summary import (
    build_control_inventory,
    build_domain_summary,
)

router = APIRouter(
    prefix="/api/v2/continuous-compliance/reporting",
    tags=["continuous-compliance-reporting"],
)


@router.get("/domains")
def reporting_domains():
    return {
        "domains": build_domain_summary()
    }


@router.get("/controls")
def reporting_controls():
    return {
        "controls": build_control_inventory()
    }
PY

MAIN_FILE="backend/app/main.py"

if ! grep -q "continuous_compliance_reporting_router" "$MAIN_FILE"; then

python3 <<'PY'
from pathlib import Path

path = Path("backend/app/main.py")
content = path.read_text()

import_line = (
    "from app.continuous_compliance.api.reporting_routes "
    "import router as continuous_compliance_reporting_router"
)

if import_line not in content:
    lines = content.splitlines()

    inserted = False

    for idx, line in enumerate(lines):
        if line.startswith("from app.continuous_compliance.api.routes"):
            lines.insert(idx + 1, import_line)
            inserted = True
            break

    if not inserted:
        lines.insert(0, import_line)

    content = "\n".join(lines)

router_line = "app.include_router(continuous_compliance_reporting_router)"

if router_line not in content:
    insert_after = "app.include_router(continuous_compliance_router)"

    if insert_after in content:
        content = content.replace(
            insert_after,
            insert_after + "\n" + router_line
        )
    else:
        content += "\n" + router_line + "\n"

path.write_text(content)

print("[+] Reporting router wired successfully.")
PY

fi

cat > frontend/src/pages/continuous-compliance/OperationalCompliance.jsx <<'JSX'
import React from "react";

export default function OperationalCompliance() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold">
        Continuous Compliance Operations
      </h1>

      <div className="mt-6 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Regulatory Monitoring</h2>
          <p className="text-sm text-gray-500 mt-2">
            FCC, TCPA, CTIA, CASL, A2P, and vendor monitoring.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Messaging Compliance</h2>
          <p className="text-sm text-gray-500 mt-2">
            Suppression, opt-out handling, quiet-hour enforcement, and consent validation.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Compliance Drift</h2>
          <p className="text-sm text-gray-500 mt-2">
            Detect stale evidence, failed collectors, and baseline drift.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Evidence Freshness</h2>
          <p className="text-sm text-gray-500 mt-2">
            Operational evidence validity and review cadence tracking.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Incident Monitoring</h2>
          <p className="text-sm text-gray-500 mt-2">
            Messaging incidents, rejection spikes, suppression failures, and opt-out violations.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Vendor Validation</h2>
          <p className="text-sm text-gray-500 mt-2">
            Twilio control-plane and external provider validation.
          </p>
        </div>

      </div>
    </div>
  );
}
JSX

echo "[+] Continuous compliance reporting layer added."
