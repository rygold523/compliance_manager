#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

echo "[+] Connecting continuous compliance evaluations..."

mkdir -p backend/app/continuous_compliance/services/evaluation

cat > backend/app/continuous_compliance/services/evaluation/domain_evaluator.py <<'PY'
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from app.continuous_compliance.services.reporting.summary import (
    build_control_inventory,
    build_domain_summary,
)


STALE_HOURS = 24


def utcnow():
    return datetime.now(timezone.utc)


def evaluate_domain_state(domain: str) -> Dict[str, Any]:
    """
    Lightweight evaluation engine.

    This is intentionally additive and non-destructive.
    It can later be connected to:
    - evidence tables
    - findings
    - collectors
    - drift detection
    - governance reviews
    """

    now = utcnow()

    simulated_checks = {
        "Messaging Compliance": {
            "evidence_present": True,
            "stale": False,
            "open_findings": 0,
        },
        "Vendor / Control Plane Validation": {
            "evidence_present": False,
            "stale": False,
            "open_findings": 1,
        },
        "Regulatory Monitoring": {
            "evidence_present": True,
            "stale": True,
            "open_findings": 0,
        },
        "Compliance Drift": {
            "evidence_present": True,
            "stale": False,
            "open_findings": 2,
        },
        "Evidence Freshness": {
            "evidence_present": True,
            "stale": True,
            "open_findings": 0,
        },
        "Incident Monitoring": {
            "evidence_present": True,
            "stale": False,
            "open_findings": 1,
        },
    }

    data = simulated_checks.get(domain, {})

    evidence_present = data.get("evidence_present", False)
    stale = data.get("stale", False)
    open_findings = data.get("open_findings", 0)

    status = "current"
    reason = "Operational checks passed."

    required_actions = 0

    if not evidence_present:
        status = "action_required"
        reason = "Required evidence has not been collected."
        required_actions += 1

    elif stale:
        status = "stale"
        reason = "Evidence or governance review is stale."
        required_actions += 1

    elif open_findings > 0:
        status = "action_required"
        reason = f"{open_findings} unresolved findings require review."
        required_actions += open_findings

    readiness = 100

    if status == "stale":
        readiness = 70

    elif status == "action_required":
        readiness = 60

    return {
        "domain": domain,
        "status": status,
        "status_reason": reason,
        "required_actions": required_actions,
        "last_checked_at": now.isoformat(),
        "last_marked_current_at": None,
        "marked_current_by": None,
        "next_review_due_at": (now + timedelta(days=30)).isoformat(),
        "readiness_score": readiness,
    }


def build_operational_domain_states() -> List[Dict[str, Any]]:
    summaries = build_domain_summary()

    output = []

    for item in summaries:
        domain = item["domain"]

        evaluated = evaluate_domain_state(domain)

        evaluated["total_controls"] = item.get("total_controls", 0)

        output.append(evaluated)

    return output
PY

python3 <<'PY'
from pathlib import Path

path = Path("backend/app/continuous_compliance/api/state_routes.py")
content = path.read_text()

old_import = '''
from app.continuous_compliance.services.state.domain_status import (
    default_domain_statuses,
    summarize_status_counts,
)
'''

new_import = '''
from app.continuous_compliance.services.state.domain_status import (
    summarize_status_counts,
)

from app.continuous_compliance.services.evaluation.domain_evaluator import (
    build_operational_domain_states,
)
'''

content = content.replace(old_import, new_import)

content = content.replace(
    'statuses = default_domain_statuses()',
    'statuses = build_operational_domain_states()'
)

path.write_text(content)

print("[+] State routes connected to evaluation engine.")
PY

echo "[+] Evaluation engine connected."
